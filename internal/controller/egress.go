package controllers

import (
	"cmp"
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

// ownerInfo is what a peer's own pod grants it. cycle and forwardedPort are set only when verified.
type ownerInfo struct {
	verified      bool // the peer is controlled by the live pod of its own name
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
		verified:      true,
		cycle:         pod.Labels[resources.LabelCycle] == resources.CycleAllowedValue,
		forwardedPort: pod.Labels[resources.LabelForwardedPort] == resources.ForwardedPortValue,
	}, nil
}

// candidate is a peer eligible for the forwarded port: verified, labelled and admitted.
type candidate struct {
	address         string // the peer's status.address, as the agent matches it
	created         metav1.Time
	name, namespace string
}

// electHolder returns the address of the peer that holds the forwarded port. The current holder keeps it
// while it is still a candidate; otherwise the oldest peer wins, then the lower name, then the lower
// namespace (the order of older()). It returns "" when there is no candidate.
func electHolder(current string, candidates []candidate) string {
	if len(candidates) == 0 {
		return ""
	}
	if slices.ContainsFunc(candidates, func(c candidate) bool { return c.address == current }) {
		return current
	}
	return slices.MinFunc(candidates, func(a, b candidate) int {
		return cmp.Or(a.created.Compare(b.created.Time), cmp.Compare(a.name, b.name), cmp.Compare(a.namespace, b.namespace))
	}).address
}

// desiredEgress renders the agent's Egress for wg from the admitted peers and the labels on their
// verified pods, read through r.APIReader. currentHolder is the ForwardedPortPeer of the Secret's
// current state.json. Its second result maps each candidate peer's namespace/name to its PortForwarding
// reason, ReasonHeld or ReasonHeldByAnotherPeer. A failed pod read is an error: treating it as
// unverified would drop a live permission or hand the port over.
func (r *WireguardReconciler) desiredEgress(ctx context.Context, wg *v1alpha1.Wireguard, admitted []v1alpha1.WireguardPeer, currentHolder string) (agent.Egress, map[string]string, error) {
	egress := agent.Egress{CycleRequestedAt: wg.Annotations[resources.AnnotationCycleRequestedAt]}
	if pf := wg.Spec.Gluetun.PortForwarding; pf != nil {
		egress.StaticPort = pf.StaticPort
	}
	if st := wg.Status.Egress; st != nil {
		egress.LastHandledAnnotation = st.LastHandledAnnotation
	}

	var candidates []candidate
	for _, peer := range admitted {
		owner, err := ownerOf(ctx, r.APIReader, peer)
		if err != nil {
			return agent.Egress{}, nil, err
		}
		if owner.cycle {
			egress.CycleAllowed = append(egress.CycleAllowed, peer.Status.Address)
		}
		if owner.forwardedPort {
			candidates = append(candidates, candidate{address: peer.Status.Address, created: peer.CreationTimestamp, name: peer.Name, namespace: peer.Namespace})
		}
	}
	slices.Sort(egress.CycleAllowed)
	egress.ForwardedPortPeer = electHolder(currentHolder, candidates)

	var reasons map[string]string
	if len(candidates) > 0 {
		reasons = make(map[string]string, len(candidates))
	}
	for _, c := range candidates {
		reason := ReasonHeldByAnotherPeer
		if c.address == egress.ForwardedPortPeer {
			reason = ReasonHeld
		}
		reasons[c.namespace+"/"+c.name] = reason
	}
	return egress, reasons, nil
}

// syncPortForwarding records on each of peers the PortForwarding condition reasons names for it, and
// removes it from a peer reasons does not name, which has stopped being eligible. A peer that already
// carries the condition is not written; a skipped write is the peer's retry, as in syncPeerIdentity.
func (r *WireguardReconciler) syncPortForwarding(ctx context.Context, peers []v1alpha1.WireguardPeer, reasons map[string]string) error {
	var holder string
	for peer, reason := range reasons {
		if reason == ReasonHeld {
			holder = peer
		}
	}
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
