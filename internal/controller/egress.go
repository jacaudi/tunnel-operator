package controllers

import (
	"context"
	"fmt"
	"slices"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/agent"
	"github.com/jacaudi/tunnel-operator/internal/resources"

	corev1 "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The PortForwarding condition the operator records on each peer eligible for the forwarded port: True
// with ReasonHeld on the holder, False with ReasonHeldByAnotherPeer on the others.
const (
	ConditionPortForwarding = "PortForwarding"
	ReasonHeld              = "Held"
	ReasonHeldByAnotherPeer = "HeldByAnotherPeer"
)

// ownerInfo is what a peer's own pod grants it. Both are false unless the peer is verified: controlled by
// the live pod of its own name.
type ownerInfo struct {
	cycle         bool // the pod is labelled resources.LabelCycle=resources.CycleAllowedValue
	forwardedPort bool // the pod is labelled resources.LabelForwardedPort=resources.ForwardedPortValue
}

// ownerOf reads the pod peer is named for through r, which must not be the filtered Pod cache, and
// returns what its labels grant. The peer is verified only when its controller is a Pod of the peer's
// own name and of the live pod's UID, and the pod is not terminating: a peer is user-writable, so a
// forged one that points at a labelled pod, or reuses its name under another UID, gains nothing. A
// missing pod is an unverified owner, not an error.
func ownerOf(ctx context.Context, r client.Reader, peer v1alpha1.WireguardPeer) (ownerInfo, error) {
	ctl := metav1.GetControllerOf(&peer)
	if ctl == nil || ctl.APIVersion != "v1" || ctl.Kind != "Pod" || ctl.Name != peer.Name {
		return ownerInfo{}, nil
	}
	pod := &corev1.Pod{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(&peer), pod); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return ownerInfo{}, nil
		}
		return ownerInfo{}, fmt.Errorf("read pod %s/%s that owns its peer: %w", peer.Namespace, peer.Name, err)
	}
	if ctl.UID != pod.UID || !pod.DeletionTimestamp.IsZero() {
		return ownerInfo{}, nil
	}
	return ownerInfo{
		cycle:         pod.Labels[resources.LabelCycle] == resources.CycleAllowedValue,
		forwardedPort: pod.Labels[resources.LabelForwardedPort] == resources.ForwardedPortValue,
	}, nil
}

// electHolder returns the candidate that holds the forwarded port, or nil when there is none. The peer
// named current (a namespace/name) keeps it while it is still a candidate; otherwise the oldest peer
// wins, then the lower name, then the lower namespace (the order of older()). The holder is identified
// by name, never by tunnel address: a replacement peer can be allocated a departed holder's address.
func electHolder(current string, candidates []*v1alpha1.WireguardPeer) *v1alpha1.WireguardPeer {
	if i := slices.IndexFunc(candidates, func(p *v1alpha1.WireguardPeer) bool {
		return client.ObjectKeyFromObject(p).String() == current
	}); i >= 0 {
		return candidates[i]
	}
	var winner *v1alpha1.WireguardPeer
	for _, c := range candidates {
		if winner == nil || older(c, winner) {
			winner = c
		}
	}
	return winner
}

// desiredEgress renders the agent's Egress for wg from the admitted peers and the labels on their
// verified pods, read through r.APIReader. currentHolder is the namespace/name in the Secret's current
// state.json (Egress.ForwardedPortPeerName). Its second result maps each candidate peer's namespace/name
// to its PortForwarding reason, ReasonHeld or ReasonHeldByAnotherPeer. A failed pod read is an error:
// treating it as unverified would drop a live permission or hand the port over.
func (r *WireguardReconciler) desiredEgress(ctx context.Context, wg *v1alpha1.Wireguard, admitted []v1alpha1.WireguardPeer, currentHolder string) (agent.Egress, map[string]string, error) {
	egress := agent.Egress{CycleRequestedAt: wg.Annotations[resources.AnnotationCycleRequestedAt]}
	if pf := wg.Spec.Gluetun.PortForwarding; pf != nil {
		egress.StaticPort = pf.StaticPort
	}
	if st := wg.Status.Egress; st != nil {
		egress.LastHandledAnnotation = st.LastHandledAnnotation
	}

	var candidates []*v1alpha1.WireguardPeer
	for i := range admitted {
		peer := &admitted[i]
		owner, err := ownerOf(ctx, r.APIReader, *peer)
		if err != nil {
			return agent.Egress{}, nil, err
		}
		if owner.cycle {
			egress.CycleAllowed = append(egress.CycleAllowed, peer.Status.Address)
		}
		if owner.forwardedPort {
			candidates = append(candidates, peer)
		}
	}
	slices.Sort(egress.CycleAllowed)

	var holderKey string
	if holder := electHolder(currentHolder, candidates); holder != nil {
		holderKey = client.ObjectKeyFromObject(holder).String()
		egress.ForwardedPortPeer, egress.ForwardedPortPeerName = holder.Status.Address, holderKey
	}

	var reasons map[string]string
	if len(candidates) > 0 {
		reasons = make(map[string]string, len(candidates))
	}
	for _, c := range candidates {
		key := client.ObjectKeyFromObject(c).String()
		reason := ReasonHeldByAnotherPeer
		if key == holderKey {
			reason = ReasonHeld
		}
		reasons[key] = reason
	}
	return egress, reasons, nil
}

// syncPortForwarding records on each of peers the PortForwarding condition reasons names for it, and
// removes it from a peer reasons does not name, which has stopped being eligible. A peer that already
// carries the condition is not written; a skipped write is the peer's retry, as in syncPeerIdentity.
func (r *WireguardReconciler) syncPortForwarding(ctx context.Context, peers []v1alpha1.WireguardPeer, reasons map[string]string) error {
	holder := heldPeer(reasons)
	for i := range peers {
		peer := &peers[i]
		reason, eligible := reasons[client.ObjectKeyFromObject(peer).String()]
		var changed bool
		if eligible {
			changed = meta.SetStatusCondition(&peer.Status.Conditions, portForwardingCondition(reason, holder, peer.Generation))
		} else {
			changed = meta.RemoveStatusCondition(&peer.Status.Conditions, ConditionPortForwarding)
		}
		if !changed {
			continue
		}
		if err := r.Status().Update(ctx, peer); err != nil && !skipPeerWrite(err) {
			return err
		}
	}
	return nil
}

// portForwardingCondition is the condition for a peer with reason, where holder is the namespace/name
// of the peer that holds the port.
func portForwardingCondition(reason, holder string, generation int64) metav1.Condition {
	cond := metav1.Condition{
		Type:               ConditionPortForwarding,
		Status:             metav1.ConditionTrue,
		Reason:             reason,
		Message:            "This peer holds the forwarded port",
		ObservedGeneration: generation,
	}
	if reason == ReasonHeldByAnotherPeer {
		cond.Status = metav1.ConditionFalse
		cond.Message = fmt.Sprintf("The forwarded port is held by peer %s", holder)
	}
	return cond
}
