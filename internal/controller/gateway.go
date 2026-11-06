package controllers

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/jacaudi/tunnel-operator/internal/resources"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// Degraded reasons the operator records on a Wireguard whose spec it cannot render.
const (
	// ReasonInvalidPeerCIDR: spec.peerCIDR is not a canonical IPv4 prefix of /30 or shorter.
	ReasonInvalidPeerCIDR = "InvalidPeerCIDR"
	// ReasonProbeAddressInPeerCIDR: spec.peerCIDR contains resources.PeerProbeAddress.
	ReasonProbeAddressInPeerCIDR = "ProbeAddressInPeerCIDR"
	// ReasonInvalidLocalCIDRs: a spec.localCIDRs entry is not a canonical IPv4 prefix.
	ReasonInvalidLocalCIDRs = "InvalidLocalCIDRs"
	// ReasonPeerCIDROverlapsLocalCIDRs: spec.peerCIDR overlaps a spec.localCIDRs entry.
	ReasonPeerCIDROverlapsLocalCIDRs = "PeerCIDROverlapsLocalCIDRs"
	// ReasonProbeAddressInLocalCIDRs: a spec.localCIDRs entry contains resources.PeerProbeAddress.
	ReasonProbeAddressInLocalCIDRs = "ProbeAddressInLocalCIDRs"
	// ReasonClusterIPOutsideLocalCIDRs: the server Service's ClusterIP is in no spec.localCIDRs entry.
	ReasonClusterIPOutsideLocalCIDRs = "ClusterIPOutsideLocalCIDRs"
	// ReasonReservedGluetunEnv: spec.gluetun.env or a Secret it references sets a variable the operator renders.
	ReasonReservedGluetunEnv = "ReservedGluetunEnv"
)

// Ready=False reasons the operator records on a Wireguard.
const (
	// ReasonDeploymentNotReady: the Deployment rendered from this generation has not rolled out.
	ReasonDeploymentNotReady = "DeploymentNotReady"
)

// validateLocalCIDRs returns nil when every entry is a canonical IPv4 prefix (no host bits set),
// and an error naming the first entry that is not.
func validateLocalCIDRs(cidrs []string) error {
	for i, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("localCIDRs[%d] %q is not a CIDR: %w", i, c, err)
		}
		if !p.Addr().Is4() {
			return fmt.Errorf("localCIDRs[%d] %q is not an IPv4 prefix", i, c)
		}
		if p != p.Masked() {
			return fmt.Errorf("localCIDRs[%d] %q has host bits set; use %s", i, c, p.Masked())
		}
	}
	return nil
}

// peerCIDROverlap returns an error naming the first localCIDRs entry that overlaps peerCIDR. Both
// must already be valid.
func peerCIDROverlap(peerCIDR string, localCIDRs []string) error {
	// An unparseable prefix is the zero Prefix, which overlaps nothing; callers validate first.
	peer, _ := netip.ParsePrefix(peerCIDR)
	for i, c := range localCIDRs {
		if local, _ := netip.ParsePrefix(c); peer.Overlaps(local) {
			return fmt.Errorf("peerCIDR %s overlaps localCIDRs[%d] %s; peer addresses must lie outside the cluster's networks", peerCIDR, i, c)
		}
	}
	return nil
}

// probeAddr is resources.PeerProbeAddress, parsed once at package initialization.
var probeAddr = netip.MustParseAddr(resources.PeerProbeAddress)

// probeAddressInLocalCIDRs returns an error naming the first localCIDRs entry that contains
// resources.PeerProbeAddress. Every entry must already be valid.
func probeAddressInLocalCIDRs(localCIDRs []string) error {
	for i, c := range localCIDRs {
		// An unparseable prefix is the zero Prefix, which contains nothing; callers validate first.
		if local, _ := netip.ParsePrefix(c); local.Contains(probeAddr) {
			return fmt.Errorf("localCIDRs[%d] %s contains %s, the address the gateway's readiness check routes through the tunnel; it is reserved for documentation (RFC 5737), so no cluster network should hold it", i, c, resources.PeerProbeAddress)
		}
	}
	return nil
}

// probeAddressInPeerCIDR returns an error when peerCIDR contains resources.PeerProbeAddress.
// peerCIDR must already be valid.
func probeAddressInPeerCIDR(peerCIDR string) error {
	// An unparseable prefix is the zero Prefix, which contains nothing; callers validate first.
	if peer, _ := netip.ParsePrefix(peerCIDR); peer.Contains(probeAddr) {
		return fmt.Errorf("peerCIDR %s contains %s, the address the gateway's readiness check routes through the tunnel; it is reserved for documentation (RFC 5737), so choose a peer range that does not hold it", peerCIDR, resources.PeerProbeAddress)
	}
	return nil
}

// clusterIPOutside returns an error when clusterIP lies in no localCIDRs entry: clients route
// everything outside localCIDRs into the tunnel, including the gateway's own Service.
func clusterIPOutside(service, clusterIP string, localCIDRs []string) error {
	if ip, err := netip.ParseAddr(clusterIP); err == nil {
		for _, c := range localCIDRs {
			if p, err := netip.ParsePrefix(c); err == nil && p.Contains(ip) {
				return nil
			}
		}
	}
	//nolint:staticcheck // ST1005: "Service" is the Kubernetes kind, and the message is recorded verbatim as a condition message
	return fmt.Errorf("Service %s has ClusterIP %s, which is in no localCIDRs entry; add the cluster's Service CIDR to localCIDRs", service, clusterIP)
}

// isReservedGluetunEnv reports whether the operator renders the gluetun variable name.
func isReservedGluetunEnv(name string) bool {
	return slices.ContainsFunc(resources.ReservedGluetunEnv(nil), func(e corev1.EnvVar) bool { return e.Name == name })
}

// reservedInEnv returns the name of the first env entry that the operator renders, or "".
func reservedInEnv(env []corev1.EnvVar) string {
	for _, e := range env {
		if isReservedGluetunEnv(e.Name) {
			return e.Name
		}
	}
	return ""
}

// reservedInKeys returns prefix+key for the first key, in sorted order, whose prefixed name the
// operator renders, or "".
func reservedInKeys(prefix string, keys []string) string {
	for _, k := range slices.Sorted(slices.Values(keys)) {
		if isReservedGluetunEnv(prefix + k) {
			return prefix + k
		}
	}
	return ""
}

// rolloutProblem returns "" when dep has rolled out the spec it carries: the Deployment controller
// has observed its generation, and its updated and ready replicas both equal spec.replicas (1 when
// unset). Otherwise it returns why not.
func rolloutProblem(dep *appsv1.Deployment) string {
	if dep.Status.ObservedGeneration < dep.Generation {
		return fmt.Sprintf("Deployment %s is not rolled out: generation %d not yet observed", dep.Name, dep.Generation)
	}
	want := int32(1)
	if dep.Spec.Replicas != nil {
		want = *dep.Spec.Replicas
	}
	if ready, updated := dep.Status.ReadyReplicas, dep.Status.UpdatedReplicas; ready != want || updated != want {
		return fmt.Sprintf("Deployment %s is not rolled out: %d/%d ready, %d/%d updated", dep.Name, ready, want, updated, want)
	}
	return ""
}
