package controllers

import (
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/agent/egress"
	"github.com/jacaudi/tunnel-operator/internal/ipam"
	"github.com/jacaudi/tunnel-operator/internal/resources"

	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// egressUpdate is what the Ready path records under status.egressAPI and status.egress, in the same
// write as the Ready condition.
type egressUpdate struct {
	EgressAPI         string        // status.egressAPI
	ForwardedPortPeer string        // status.egress.forwardedPortPeer: the holder's namespace/name, "" when none
	Report            *EgressReport // the agent's report; nil when the poll was skipped or failed
}

// egressAPIURL is the egress API URL attached pods call: the server's tunnel address, the first host of
// the effective peer CIDR, on resources.EgressAPIPort.
func egressAPIURL(wg *v1alpha1.Wireguard) (string, error) {
	prefix, err := netip.ParsePrefix(effectivePeerCIDR4(wg))
	if err != nil {
		return "", fmt.Errorf("egress API URL: %w", err)
	}
	addr, err := ipam.ServerAddress(prefix)
	if err != nil {
		return "", fmt.Errorf("egress API URL: %w", err)
	}
	return "http://" + net.JoinHostPort(addr.String(), strconv.Itoa(resources.EgressAPIPort)), nil
}

// heldPeer returns the namespace/name of the peer that reasons, from desiredEgress, names ReasonHeld, or ""
// when no candidate holds the port.
func heldPeer(reasons map[string]string) string {
	for peer, reason := range reasons {
		if reason == ReasonHeld {
			return peer
		}
	}
	return ""
}

// applyEgress records u on st. The forwarded-port holder is always written. The rest of status.egress is
// written only from a report, so a skipped or failed poll leaves it as it was; the report's cycle replaces
// the stored one only when it has a finish time. status.egress is absent while nothing is known, and the
// Cycled condition mirrors the stored cycle: True when it Succeeded, False with its reason otherwise.
func applyEgress(st *v1alpha1.WireguardStatus, generation int64, u *egressUpdate) {
	st.EgressAPI = u.EgressAPI
	e := cmp.Or(st.Egress, &v1alpha1.EgressStatus{})
	e.ForwardedPortPeer = u.ForwardedPortPeer
	if rep := u.Report; rep != nil {
		e.ExitIP, e.ForwardedPort, e.LastHandledAnnotation = rep.ExitIP, rep.ForwardedPort, rep.LastHandledAnnotation
		// The CRD requires finishedAt, so a cycle without one must never reach the apiserver. Truncating
		// keeps what is stored identical from one poll to the next.
		if c := rep.LastCycle; c != nil && !c.FinishedAt.IsZero() {
			cycle := *c
			cycle.FinishedAt = metav1.NewTime(c.FinishedAt.Truncate(time.Second))
			e.LastCycle = &cycle
		}
	}

	st.Egress = e
	if *e == (v1alpha1.EgressStatus{}) {
		st.Egress = nil
	}
	if c := e.LastCycle; c != nil {
		meta.SetStatusCondition(&st.Conditions, cycledCondition(*c, generation))
	}
}

// cycledCondition mirrors cycle: True when it Succeeded, False with its reason otherwise. The agent's data
// must not reach the apiserver unchecked, which rejects a condition whose reason is not an identifier and
// then fails every status write: the reason is kept only when it is one the agent defines, else Unknown, and
// the message names no agent-supplied text (the trigger can be a 256 KiB annotation value).
func cycledCondition(cycle v1alpha1.CycleResult, generation int64) metav1.Condition {
	cond := metav1.Condition{
		Type:               ConditionCycled,
		Status:             metav1.ConditionFalse,
		Reason:             "Unknown",
		Message:            "The last VPN cycle ended with a reason the operator does not recognise",
		ObservedGeneration: generation,
	}
	if slices.Contains(cycleReasons, cycle.Reason) {
		cond.Reason = cycle.Reason
		cond.Message = "The last VPN cycle ended " + cycle.Reason
	}
	if cycle.Reason == egress.ReasonSucceeded {
		cond.Status = metav1.ConditionTrue
	}
	return cond
}

// cycleReasons are the reasons a cycle ends with, which the agent defines.
var cycleReasons = []string{egress.ReasonSucceeded, egress.ReasonIPUnchanged, egress.ReasonEmptyIP, egress.ReasonTimeout, egress.ReasonGluetunError}
