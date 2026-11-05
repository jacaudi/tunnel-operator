/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"
	"time"

	"github.com/jacaudi/wireguard-operator/api/v1alpha1"
	"github.com/jacaudi/wireguard-operator/internal/agent"
	"github.com/jacaudi/wireguard-operator/internal/ipam"
	"github.com/jacaudi/wireguard-operator/internal/resources"

	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

// Standard condition types for Wireguard
const (
	ConditionReady       = "Ready"
	ConditionProgressing = "Progressing"
	ConditionDegraded    = "Degraded"
)

// WireguardReconciler reconciles a Wireguard object
type WireguardReconciler struct {
	client.Client
	Scheme               *runtime.Scheme
	AgentImage           string
	AgentImagePullPolicy corev1.PullPolicy

	// APIReader reads straight from the apiserver. It serves the reads the manager's filtered Pod cache
	// cannot: the cache holds only pods labelled for injection, so the gateway pods are invisible to Client.
	APIReader client.Reader

	// Resource builders
	secretBuilder     *resources.SecretBuilder
	serviceBuilder    *resources.ServiceBuilder
	deploymentBuilder *resources.DeploymentBuilder
	ipAllocator       *ipam.Allocator
}

// getWireguardPeers returns the peers, in any namespace, whose gatewayKey is req.
func (r *WireguardReconciler) getWireguardPeers(ctx context.Context, req ctrl.Request) (*v1alpha1.WireguardPeerList, error) {
	peers := &v1alpha1.WireguardPeerList{}
	if err := r.List(ctx, peers); err != nil {
		return nil, err
	}

	relatedPeers := &v1alpha1.WireguardPeerList{}

	for _, peer := range peers.Items {
		if gatewayKey(&peer) == req.NamespacedName {
			relatedPeers.Items = append(relatedPeers.Items, peer)
		}
	}

	return relatedPeers, nil
}

// serverIdentity is what a client needs to reach this server.
type serverIdentity struct {
	Endpoint  string
	PublicKey string
}

// updateStatus records cond on the Wireguard wg names. wg is the object this reconcile fetched and
// rendered: cond.ObservedGeneration is wg's generation, never that of the copy re-read here for a
// fresh resourceVersion, so a spec patch that lands mid-reconcile cannot be reported as observed.
// A non-nil identity sets status.endpoint and status.publicKey in the same write; nil leaves them.
func (r *WireguardReconciler) updateStatus(ctx context.Context, wg *v1alpha1.Wireguard, cond metav1.Condition, identity *serverIdentity) error {
	latest := &v1alpha1.Wireguard{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(wg), latest); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}

	// Ensure transition time and observed generation are set
	if cond.LastTransitionTime.IsZero() {
		cond.LastTransitionTime = metav1.Now()
	}
	cond.ObservedGeneration = wg.Generation

	meta.SetStatusCondition(&latest.Status.Conditions, cond)

	// A Ready condition, of either status, is written only once every apply in the reconcile has
	// succeeded, so it also clears a Degraded left by an earlier failure. It must ride in this same
	// write: a separate updateStatus call for Degraded would set the summary below to Error, and a
	// second write that hits a Conflict is swallowed, so the clearing could be lost without trace.
	if cond.Type == ConditionReady {
		meta.SetStatusCondition(&latest.Status.Conditions, metav1.Condition{
			Type:               ConditionDegraded,
			Status:             metav1.ConditionFalse,
			Reason:             "Reconciled",
			Message:            "All owned resources applied",
			ObservedGeneration: cond.ObservedGeneration,
		})
	}

	// Backward-compatible summary fields derived from condition type
	switch cond.Type {
	case ConditionReady:
		latest.Status.Status = v1alpha1.Pending
		if cond.Status == metav1.ConditionTrue {
			latest.Status.Status = v1alpha1.Ready
		}
	case ConditionDegraded:
		latest.Status.Status = v1alpha1.Error
	default:
		latest.Status.Status = v1alpha1.Pending
	}
	latest.Status.Message = cond.Message
	if identity != nil {
		latest.Status.Endpoint = identity.Endpoint
		latest.Status.PublicKey = identity.PublicKey
	}

	if err := r.Status().Update(ctx, latest); err != nil {
		if errors.IsNotFound(err) || errors.IsConflict(err) {
			// Object deleted or updated concurrently; ignore and let reconcile retry
			return nil
		}
		return err
	}
	return nil
}

// effectivePeerCIDR4 returns the effective IPv4 peer CIDR for a Wireguard instance.
func effectivePeerCIDR4(wg *v1alpha1.Wireguard) string {
	if wg.Spec.PeerCIDR != "" {
		return wg.Spec.PeerCIDR
	}
	return ipam.DefaultPeerCIDR4
}

// admittedKeys returns the public key each peer is listed under in wg's current state.json, keyed
// by the peer's namespace/name: the keys the server is serving now. It is empty before the Secret
// exists or when its state is unreadable, and it fails when the Secret cannot be read.
func (r *WireguardReconciler) admittedKeys(ctx context.Context, wg *v1alpha1.Wireguard) (map[types.NamespacedName]string, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(wg), secret); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	var state agent.State
	if err := json.Unmarshal(secret.Data["state.json"], &state); err != nil {
		// Nothing is listed: this pass rewrites state.json from the peers it admits.
		return nil, nil
	}
	keys := make(map[types.NamespacedName]string, len(state.Peers))
	for i := range state.Peers {
		keys[client.ObjectKeyFromObject(&state.Peers[i])] = state.Peers[i].Spec.PublicKey
	}
	return keys, nil
}

// reconcilePeers lists the peers of wg, records a not-ready status on those the server cannot
// admit, releases the peers that lose a public key (PublicKeyConflict), clears unusable addresses,
// releases the addresses of dedupe losers (AddressConflict),
// allocates and readies the rest, and returns the peers admitted in this pass, as written: keyed
// and holding a status.address.
func (r *WireguardReconciler) reconcilePeers(ctx context.Context, req ctrl.Request, wg *v1alpha1.Wireguard) ([]v1alpha1.WireguardPeer, error) {
	// Read first: a Secret that cannot be read stops the pass before any peer status is written.
	current, err := r.admittedKeys(ctx, wg)
	if err != nil {
		return nil, err
	}
	peers, err := r.getWireguardPeers(ctx, req)
	if err != nil {
		return nil, err
	}
	admitted, err := r.admitPeers(ctx, wg, peers.Items)
	if err != nil {
		return nil, err
	}
	// A peer whose key another peer holds, the one the server's current state lists under that key
	// or else the oldest, is neither allocated nor returned, so the server never lists two peers
	// under one key.
	admitted, keyLosers := dedupePublicKeys(admitted, current)
	if err := r.releaseLosers(ctx, keyLosers, func(l conflictLoser) notReady { return publicKeyConflict(l.Winner) }); err != nil {
		return nil, err
	}
	cidr4 := effectivePeerCIDR4(wg)
	// An address the allocator could not have handed out on this server is treated as unallocated;
	// allocatePeers writes a fresh one in its one status write.
	for i := range admitted {
		if addr := admitted[i].Status.Address; addr != "" && !addressUsable(addr, cidr4) {
			admitted[i].Status.Address = ""
		}
	}
	// Losers are neither allocated nor returned: their status write triggers the pass that
	// re-allocates them, and the winners' addresses stay reserved because usedIps is computed from keep.
	keep, losers := dedupeAddresses(admitted)
	if err := r.releaseLosers(ctx, losers, func(l conflictLoser) notReady { return addressConflict(l.Peer.Status.Address, l.Winner) }); err != nil {
		return nil, err
	}
	return r.allocatePeers(ctx, cidr4, keep)
}

// admitPeers records a not-ready status on every peer wg cannot admit, because its namespace is not
// allowed or its key is unusable, and returns the others, in input order.
func (r *WireguardReconciler) admitPeers(ctx context.Context, wg *v1alpha1.Wireguard, peers []v1alpha1.WireguardPeer) ([]v1alpha1.WireguardPeer, error) {
	var admitted []v1alpha1.WireguardPeer
	for _, peer := range peers {
		nr, problem := namespaceNotAllowed(wg, &peer)
		if !problem {
			nr, problem = admissionProblem(&peer)
		}
		if !problem {
			admitted = append(admitted, peer)
			continue
		}
		// A skipped peer is this peer's retry, not the loop's: whoever won the write, or the
		// deletion, also emits a watch event, which re-enqueues the Wireguard.
		if err := r.markPeerNotReady(ctx, &peer, nr); err != nil && !skipPeerWrite(err) {
			return nil, err
		}
	}
	return admitted, nil
}

// allocatePeers gives each peer without a status.address the first free address in cidr4 and
// marks each peer ready in the same status write. It returns every peer that holds a persisted
// address at the end of the pass, as written: those that needed no write, those whose write
// succeeded, and those that already held an address but whose readiness write was skipped. A
// peer AllocateIP cannot serve gets addressPoolExhausted(cidr4) instead, and the loop continues.
func (r *WireguardReconciler) allocatePeers(ctx context.Context, cidr4 string, peers []v1alpha1.WireguardPeer) ([]v1alpha1.WireguardPeer, error) {
	usedIps4 := r.ipAllocator.GetUsedIPs(cidr4, &v1alpha1.WireguardPeerList{Items: peers})

	var allocated []v1alpha1.WireguardPeer
	for _, peer := range peers {
		isNew := peer.Status.Address == ""
		if isNew {
			ip, allocErr := r.ipAllocator.AllocateIP(cidr4, usedIps4)
			if allocErr != nil {
				// A full pool is this peer's state, not the pass's: the others still get served.
				if err := r.markPeerNotReady(ctx, &peer, addressPoolExhausted(cidr4)); err != nil && !skipPeerWrite(err) {
					return nil, err
				}
				continue
			}
			peer.Status.Address = ip
			// Reserved even if the write below is lost to a Conflict, so the next peer in this
			// pass cannot take the same address.
			usedIps4 = append(usedIps4, ip)
		} else if peer.Status.Status == v1alpha1.Ready && meta.FindStatusCondition(peer.Status.Conditions, ConditionReady) == nil {
			// Already admitted and ready: nothing to write.
			allocated = append(allocated, peer)
			continue
		}

		peer.Status.Status = v1alpha1.Ready
		peer.Status.Message = "Peer configured"
		meta.RemoveStatusCondition(&peer.Status.Conditions, ConditionReady)
		if err := r.Status().Update(ctx, &peer); err != nil {
			if !skipPeerWrite(err) {
				return nil, err
			}
			// A new address that failed to persist is not the peer's address yet; an address the
			// peer already held is, so it stays.
			if !isNew {
				allocated = append(allocated, peer)
			}
			continue
		}
		allocated = append(allocated, peer)
	}
	return allocated, nil
}

// releaseLosers records conflict(loser) on each loser, which clears its status.address.
func (r *WireguardReconciler) releaseLosers(ctx context.Context, losers []conflictLoser, conflict func(conflictLoser) notReady) error {
	for _, l := range losers {
		if err := r.markPeerNotReady(ctx, &l.Peer, conflict(l)); err != nil && !skipPeerWrite(err) {
			return err
		}
	}
	return nil
}

// syncPeerIdentity copies id and wg's spec.localCIDRs into the status of each peer, which a client
// in another namespace reads instead of the Wireguard. A peer that already carries them is not
// written; a skipped write is the peer's retry, as in admitPeers.
func (r *WireguardReconciler) syncPeerIdentity(ctx context.Context, wg *v1alpha1.Wireguard, id serverIdentity, peers []v1alpha1.WireguardPeer) error {
	for i := range peers {
		peer := &peers[i]
		if peer.Status.Endpoint == id.Endpoint && peer.Status.ServerPublicKey == id.PublicKey && slices.Equal(peer.Status.LocalCIDRs, wg.Spec.LocalCIDRs) {
			continue
		}
		peer.Status.Endpoint = id.Endpoint
		peer.Status.ServerPublicKey = id.PublicKey
		peer.Status.LocalCIDRs = slices.Clone(wg.Spec.LocalCIDRs)
		if err := r.Status().Update(ctx, peer); err != nil && !skipPeerWrite(err) {
			return err
		}
	}
	return nil
}

// markPeerNotReady records nr on peer with one status write, skipped when peerStatusMatches.
func (r *WireguardReconciler) markPeerNotReady(ctx context.Context, peer *v1alpha1.WireguardPeer, nr notReady) error {
	if peerStatusMatches(peer, nr) {
		return nil
	}
	peer.Status.Status = nr.Status
	peer.Status.Message = nr.Message
	// A not-ready peer (not admitted, or a dedupe loser) releases its address and the gateway identity.
	peer.Status.Address = ""
	peer.Status.Endpoint = ""
	peer.Status.ServerPublicKey = ""
	peer.Status.LocalCIDRs = nil
	meta.SetStatusCondition(&peer.Status.Conditions, metav1.Condition{
		Type:               ConditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             nr.Reason,
		Message:            nr.ConditionMessage,
		ObservedGeneration: peer.Generation,
	})
	err := r.Status().Update(ctx, peer)
	if errors.IsInvalid(err) {
		// A status write rejected by whole-object validation must not stop the server's sync.
		ctrllog.FromContext(ctx).Error(err, "Cannot record the status of a peer", "peer", peer.Name)
		return nil
	}
	return err
}

// markPeersWireguardNotFound records WireguardNotFound on every peer whose gatewayKey is req.
func (r *WireguardReconciler) markPeersWireguardNotFound(ctx context.Context, req ctrl.Request) error {
	peers, err := r.getWireguardPeers(ctx, req)
	if err != nil {
		return err
	}
	nr := wireguardNotFound(req.Name, req.Namespace)
	for i := range peers.Items {
		if err := r.markPeerNotReady(ctx, &peers.Items[i], nr); err != nil {
			if skipPeerWrite(err) {
				continue
			}
			return err
		}
	}
	return nil
}

// applyDeployment applies dep after clearing a defaulted spec.strategy.rollingUpdate from the live
// Deployment. The apiserver defaults that block for a RollingUpdate Deployment and no field manager
// owns it, so Server-Side Apply of strategy Recreate cannot prune it and validation rejects the apply
// ("may not be specified when strategy `type` is 'Recreate'"). The merge patch runs once per such
// Deployment; a missing Deployment needs none.
func (r *WireguardReconciler) applyDeployment(ctx context.Context, dep *appsv1.Deployment) error {
	key := client.ObjectKeyFromObject(dep)
	live := &appsv1.Deployment{}
	switch err := r.Get(ctx, key, live); {
	case errors.IsNotFound(err):
		// Nothing to migrate: the apply creates the Deployment.
	case err != nil:
		return fmt.Errorf("read Deployment %s for the strategy migration: %w", key, err)
	case live.Spec.Strategy.RollingUpdate != nil:
		patch := client.RawPatch(types.MergePatchType, []byte(`{"spec":{"strategy":{"type":"Recreate","rollingUpdate":null}}}`))
		if err := r.Patch(ctx, live, patch); err != nil {
			return fmt.Errorf("clear rollingUpdate on Deployment %s: %w", key, err)
		}
	}
	return r.applyOwned(ctx, dep)
}

// specProblem returns the Degraded reason and message for a spec the operator cannot render, or an
// empty reason when it can. It checks, in order: peerCIDR, the probe address in peerCIDR, localCIDRs,
// their overlap, the probe address in localCIDRs, spec.gluetun.env, then the keys of each Secret
// spec.gluetun.envFrom references. A referenced Secret that does not exist is skipped; the kubelet
// reports it on the pod. err is any other failure to read a Secret.
func (r *WireguardReconciler) specProblem(ctx context.Context, wg *v1alpha1.Wireguard) (reason, message string, err error) {
	if err := validatePeerCIDR(effectivePeerCIDR4(wg)); err != nil {
		return ReasonInvalidPeerCIDR, err.Error(), nil
	}
	if err := probeAddressInPeerCIDR(effectivePeerCIDR4(wg)); err != nil {
		return ReasonProbeAddressInPeerCIDR, err.Error(), nil
	}
	if err := validateLocalCIDRs(wg.Spec.LocalCIDRs); err != nil {
		return ReasonInvalidLocalCIDRs, err.Error(), nil
	}
	if err := peerCIDROverlap(effectivePeerCIDR4(wg), wg.Spec.LocalCIDRs); err != nil {
		return ReasonPeerCIDROverlapsLocalCIDRs, err.Error(), nil
	}
	if err := probeAddressInLocalCIDRs(wg.Spec.LocalCIDRs); err != nil {
		return ReasonProbeAddressInLocalCIDRs, err.Error(), nil
	}
	if name := reservedInEnv(wg.Spec.Gluetun.Env); name != "" {
		return ReasonReservedGluetunEnv, fmt.Sprintf("spec.gluetun.env sets %s, which the operator renders", name), nil
	}
	for i, src := range wg.Spec.Gluetun.EnvFrom {
		if src.SecretRef == nil {
			continue
		}
		secret := &corev1.Secret{}
		key := types.NamespacedName{Name: src.SecretRef.Name, Namespace: wg.Namespace}
		if err := r.Get(ctx, key, secret); errors.IsNotFound(err) {
			continue
		} else if err != nil {
			return "", "", fmt.Errorf("read Secret %s referenced by spec.gluetun.envFrom[%d]: %w", key.Name, i, err)
		}
		if name := reservedInKeys(src.Prefix, slices.Collect(maps.Keys(secret.Data))); name != "" {
			return ReasonReservedGluetunEnv, fmt.Sprintf("Secret %s, referenced by spec.gluetun.envFrom[%d], sets %s, which the operator renders", key.Name, i, name), nil
		}
	}
	return "", "", nil
}

//+kubebuilder:rbac:groups=vpn.wireguard-operator.io,resources=wireguards,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=vpn.wireguard-operator.io,resources=wireguards/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=vpn.wireguard-operator.io,resources=wireguards/finalizers,verbs=update
// +kubebuilder:rbac:groups=vpn.wireguard-operator.io,resources=wireguardpeers,verbs=get;list;watch
// +kubebuilder:rbac:groups=vpn.wireguard-operator.io,resources=wireguardpeers/status,verbs=get;update;patch

//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="apps",resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="apps",resources=pods,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
//+kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Wireguard object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.10.0/pkg/reconcile
func (r *WireguardReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)

	log.Info("loaded the following wireguard image:" + r.AgentImage)

	wireguard := &v1alpha1.Wireguard{}
	log.Info(req.Name)
	err := r.Get(ctx, req.NamespacedName, wireguard)
	if err != nil {
		if errors.IsNotFound(err) {
			// The Wireguard is gone: record WireguardNotFound on the peers that still name it.
			log.Info("wireguard resource not found; marking its peers WireguardNotFound")
			return ctrl.Result{}, r.markPeersWireguardNotFound(ctx, req)
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get wireguard")
		return ctrl.Result{}, err
	}

	log.Info("processing " + wireguard.Name)

	if wireguard.Status.Status == "" {
		err = r.updateStatus(ctx, wireguard, metav1.Condition{Type: ConditionProgressing, Status: metav1.ConditionTrue, Reason: "FetchingStatus", Message: "Fetching Wireguard status"}, nil)

		if err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}

	// A spec the operator cannot render stays Degraded until the spec changes, and that edit triggers
	// the next reconcile. A Secret it references is not watched, so the check is also re-run after a minute.
	if reason, msg, err := r.specProblem(ctx, wireguard); err != nil {
		return ctrl.Result{}, err
	} else if reason != "" {
		return ctrl.Result{RequeueAfter: time.Minute}, r.updateStatus(ctx, wireguard, metav1.Condition{Type: ConditionDegraded, Status: metav1.ConditionTrue, Reason: reason, Message: msg}, nil)
	}

	// service
	//
	// Every field the builder renders converges. The server-assigned clusterIP survives because
	// the builder never renders it, so the operator never takes ownership of the allocation.
	desiredSvc, err := r.serviceBuilder.ForWireguard(wireguard)
	if err != nil {
		return r.failDegraded(ctx, wireguard, err, "ServiceBuildFailed", "Failed to build service")
	}
	if err := r.applyOwned(ctx, desiredSvc); err != nil {
		return r.failDegraded(ctx, wireguard, err, "ServiceApplyFailed", "Failed to apply service")
	}
	if err := clusterIPOutside(desiredSvc.Name, desiredSvc.Spec.ClusterIP, wireguard.Spec.LocalCIDRs); err != nil {
		return ctrl.Result{RequeueAfter: time.Minute}, r.updateStatus(ctx, wireguard, metav1.Condition{Type: ConditionDegraded, Status: metav1.ConditionTrue, Reason: ReasonClusterIPOutsideLocalCIDRs, Message: err.Error()}, nil)
	}

	// peers
	//
	// Admitted and allocated before the Secret is rendered, so a new peer reaches state.json in the
	// reconcile that allocates it.
	admitted, err := r.reconcilePeers(ctx, req, wireguard)
	if err != nil {
		return ctrl.Result{}, err
	}
	log.Info("Updated related peers", "wireguard.Namespace", wireguard.Namespace, "wireguard.Name", wireguard.Name)

	// fetch secret
	secret := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{Name: wireguard.Name, Namespace: wireguard.Namespace}, secret)
	// secret already created
	if err == nil {
		privateKey := string(secret.Data["privateKey"])

		state := desiredState(wireguard, privateKey, admitted)

		b, err := json.Marshal(state)
		if err != nil {
			log.Error(err, "Failed to save state to secret")
			return ctrl.Result{}, err
		}

		if !bytes.Equal(b, secret.Data["state.json"]) {
			log.Info("Updating secret with new config")
			publicKey := string(secret.Data["publicKey"])

			updatedSecret, err := r.secretBuilder.ForWireguard(wireguard, b, privateKey, publicKey)
			if err != nil {
				log.Error(err, "Failed to build secret with new config")
				return ctrl.Result{}, err
			}
			if err := r.Update(ctx, updatedSecret); err != nil {
				log.Error(err, "Failed to update secret with new config")
				return ctrl.Result{}, err
			}

			pods := &corev1.PodList{}
			if err := r.APIReader.List(ctx, pods, client.InNamespace(wireguard.Namespace), client.MatchingLabels{"app": "wireguard", "instance": wireguard.Name}); err != nil {
				log.Error(err, "Failed to fetch list of pods")
				return ctrl.Result{}, err
			}

			for _, pod := range pods.Items {
				if pod.Annotations == nil {
					pod.Annotations = make(map[string]string)
				}
				// this is needed to force k8s to push the new secret to the pod
				pod.Annotations["wgConfigLastUpdated"] = time.Now().Format("2006-01-02T15-04-05")
				if err := r.Update(ctx, &pod); err != nil {
					if errors.IsConflict(err) {
						// ignore conflict; we'll see the updated pod on next reconcile
					} else {
						log.Error(err, "Failed to update pod")
						return ctrl.Result{}, err
					}
				}

				log.Info("updated pod")
			}

		}

	}
	// secret not yet created
	if err != nil && errors.IsNotFound(err) {

		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Error(err, "Failed to generate private key")
			return ctrl.Result{}, err
		}

		privateKey := key.String()
		publicKey := key.PublicKey().String()

		state := desiredState(wireguard, privateKey, admitted)

		b, err := json.Marshal(state)
		if err != nil {
			log.Error(err, "Failed to save state to secret")
			return ctrl.Result{}, err
		}

		secret, err := r.secretBuilder.ForWireguard(wireguard, b, privateKey, publicKey)
		if err != nil {
			log.Error(err, "Failed to build secret", "wireguard.Name", wireguard.Name)
			return ctrl.Result{}, err
		}

		log.Info("Creating a new secret", "secret.Namespace", secret.Namespace, "secret.Name", secret.Name)

		if err := r.Create(ctx, secret); err != nil {
			log.Error(err, "Failed to create new secret", "secret.Namespace", secret.Namespace, "secret.Name", secret.Name)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	} else if err != nil {
		log.Error(err, "Failed to get secret")
		return ctrl.Result{}, err
	}

	// deployment
	//
	// The Deployment is built once and applied by applyDeployment, which may first clear a defaulted
	// rollingUpdate. The apiserver diffs the applied field set against the stored object, so every
	// field the builder renders converges without a bespoke drift check.
	desiredDep, err := r.deploymentBuilder.ForWireguard(wireguard)
	if err != nil {
		return r.failDegraded(ctx, wireguard, err, "DeploymentBuildFailed", "Failed to build deployment")
	}
	if err := r.applyDeployment(ctx, desiredDep); err != nil {
		return r.failDegraded(ctx, wireguard, err, "DeploymentApplyFailed", "Failed to apply deployment")
	}

	// desiredSvc holds the apiserver's response to the apply, so it carries the assigned ClusterIP.
	identity := &serverIdentity{
		Endpoint:  net.JoinHostPort(desiredSvc.Spec.ClusterIP, strconv.Itoa(resources.WireguardPort)),
		PublicKey: string(secret.Data["publicKey"]),
	}

	if err := r.syncPeerIdentity(ctx, wireguard, *identity, admitted); err != nil {
		return ctrl.Result{}, err
	}

	// desiredDep holds the apiserver's response to the apply, so it carries the Deployment's current
	// status. No requeue: Owns(&appsv1.Deployment{}) re-enqueues on every Deployment status change.
	if msg := rolloutProblem(desiredDep); msg != "" {
		return ctrl.Result{}, r.updateStatus(ctx, wireguard, metav1.Condition{Type: ConditionReady, Status: metav1.ConditionFalse, Reason: ReasonDeploymentNotReady, Message: msg}, identity)
	}

	return ctrl.Result{}, r.updateStatus(ctx, wireguard, metav1.Condition{Type: ConditionReady, Status: metav1.ConditionTrue, Reason: "Active", Message: "VPN is active!"}, identity)
}

// SetupWithManager sets up the controller with the Manager.
func (r *WireguardReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize resource builders
	r.secretBuilder = resources.NewSecretBuilder(r.Scheme)
	r.serviceBuilder = resources.NewServiceBuilder(r.Scheme)
	r.deploymentBuilder = resources.NewDeploymentBuilder(r.Scheme, r.AgentImage, r.AgentImagePullPolicy)
	r.ipAllocator = ipam.NewAllocator()

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.Wireguard{}).
		Watches(&v1alpha1.WireguardPeer{}, handler.EnqueueRequestsFromMapFunc(wireguardForPeer)).
		Owns(&corev1.Service{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
