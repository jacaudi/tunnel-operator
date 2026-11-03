package resources

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

const (
	// EgressInterface is gluetun's tunnel to the VPN provider; the agent forwards peer traffic into it.
	EgressInterface = "tun0"
	// WgInterface is the WireGuard link the agent owns.
	WgInterface = "wg0"
	// TunnelMTU is the MTU of gluetun's tunnel (gluetun's own v3.41 default, pinned because later
	// versions default to path-MTU discovery).
	TunnelMTU = 1320
	// Keepalive is the client's persistent keepalive: it keeps the client's conntrack and kube-proxy state
	// for the server's ClusterIP alive and starts the first handshake as soon as the peer is configured.
	Keepalive = 25 * time.Second
	// GluetunHealthAddress is where gluetun's health server listens; the agent's /health polls it.
	GluetunHealthAddress = "127.0.0.1:9999"
	// GluetunImage is the gluetun release the operator runs, pinned by digest.
	GluetunImage = "ghcr.io/qdm12/gluetun:v3.41.3@sha256:fa19cc76b2af13d57a8d3dc3066f2ada061b1c761b8aecf989b3877c0486e027"

	// gluetunRuleTable is the routing table gluetun's WireGuard mode installs its `ip rule` for; a
	// rule left by an abrupt exit makes gluetun's next start fail with "file exists".
	gluetunRuleTable = 51820
)

// ReservedGluetunEnv returns the gluetun variables the operator renders, in a fixed order. The
// server's routing depends on each value, so spec.gluetun may not set any of them.
func ReservedGluetunEnv(localCIDRs []string) []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: "VPN_TYPE", Value: "wireguard"},
		{Name: "VPN_INTERFACE", Value: EgressInterface},
		{Name: "FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT", Value: "on"},
		{Name: "FIREWALL_INPUT_PORTS", Value: fmt.Sprintf("%d,%d", WireguardPort, HTTPPort)},
		{Name: "FIREWALL_OUTBOUND_SUBNETS", Value: strings.Join(localCIDRs, ",")},
		{Name: "HEALTH_SERVER_ADDRESS", Value: GluetunHealthAddress},
		{Name: "WIREGUARD_MTU", Value: strconv.Itoa(TunnelMTU)},
	}
}

// The server pod's fail-closed routing (design §3.5).
const (
	// PeerTable routes peerCIDR back to wg0.
	PeerTable = 51821
	// PeerRulePref is PeerTable's ip rule, ahead of gluetun's rules (98-101), so provider replies for a
	// peer reach wg0 instead of re-entering the tunnel.
	PeerRulePref = 90
	// BlackholeTable holds only a blackhole default route.
	BlackholeTable = 51822
	// BlackholePref sends everything that arrived on wg0 to BlackholeTable once gluetun's tunnel table
	// (rule 101) did not route it. This is the fail-closed rule.
	BlackholePref = 102
	// ReassertInterval is how often the agent re-asserts its routes, rules and iptables rules.
	ReassertInterval = 10 * time.Second
	// PeerProbeAddress is the destination the agent's readiness check routes as if a peer had sent it: RFC 5737 TEST-NET-1, never a real host and outside the peerCIDR and every localCIDRs entry the operator accepts. No packet is sent.
	PeerProbeAddress = "192.0.2.1"
)
