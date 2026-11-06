package sidecar

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	meta "k8s.io/apimachinery/pkg/api/meta"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/resources"
)

// errWaiting marks a configuration the operator has not finished publishing yet.
var errWaiting = errors.New("waiting for the operator")

// Tunnel is the client's WireGuard configuration, read from its WireguardPeer's status.
type Tunnel struct {
	Address    netip.Prefix   // the peer's status.address, as a /32
	ServerKey  wgtypes.Key    // the peer's status.serverPublicKey
	Endpoint   netip.AddrPort // the peer's status.endpoint
	LocalCIDRs []netip.Prefix // the peer's status.localCIDRs, masked, in status order
}

// desiredTunnel returns the Tunnel for peer. While peer lacks status.address, status.endpoint,
// status.serverPublicKey or status.localCIDRs it returns an error wrapping errWaiting; a value that
// does not parse is a plain error.
func desiredTunnel(peer *v1alpha1.WireguardPeer) (Tunnel, error) {
	switch {
	case peer.Status.Address == "":
		return Tunnel{}, fmt.Errorf("%w: WireguardPeer %s has no status.address%s", errWaiting, peer.Name, notReadyWhy(peer))
	case peer.Status.Endpoint == "":
		return Tunnel{}, fmt.Errorf("%w: WireguardPeer %s has no status.endpoint", errWaiting, peer.Name)
	case peer.Status.ServerPublicKey == "":
		return Tunnel{}, fmt.Errorf("%w: WireguardPeer %s has no status.serverPublicKey", errWaiting, peer.Name)
	case len(peer.Status.LocalCIDRs) == 0:
		return Tunnel{}, fmt.Errorf("%w: WireguardPeer %s has no status.localCIDRs", errWaiting, peer.Name)
	}

	addr, err := netip.ParseAddr(peer.Status.Address)
	if err != nil {
		return Tunnel{}, fmt.Errorf("parse status.address %q of WireguardPeer %s: %w", peer.Status.Address, peer.Name, err)
	}
	if !addr.Is4() {
		return Tunnel{}, fmt.Errorf("status.address %q of WireguardPeer %s is not IPv4", peer.Status.Address, peer.Name)
	}
	endpoint, err := netip.ParseAddrPort(peer.Status.Endpoint)
	if err != nil {
		return Tunnel{}, fmt.Errorf("parse status.endpoint %q of WireguardPeer %s: %w", peer.Status.Endpoint, peer.Name, err)
	}
	serverKey, err := wgtypes.ParseKey(peer.Status.ServerPublicKey)
	if err != nil {
		return Tunnel{}, fmt.Errorf("parse status.serverPublicKey of WireguardPeer %s: %w", peer.Name, err)
	}
	cidrs, err := parseLocalCIDRs(peer)
	if err != nil {
		return Tunnel{}, err
	}

	return Tunnel{
		Address:    netip.PrefixFrom(addr, 32),
		ServerKey:  serverKey,
		Endpoint:   endpoint,
		LocalCIDRs: cidrs,
	}, nil
}

// notReadyWhy returns " (Ready=False <reason>: <message>)" when the operator has recorded why it has not
// admitted peer, such as NamespaceNotAllowed, WireguardNotFound or PublicKeyConflict, and "" otherwise.
// The operator writes Ready only as False and removes it when it admits the peer.
func notReadyWhy(peer *v1alpha1.WireguardPeer) string {
	// "Ready" is the condition type the operator writes; internal/controller cannot be imported here.
	c := meta.FindStatusCondition(peer.Status.Conditions, "Ready")
	if c == nil {
		return ""
	}
	return fmt.Sprintf(" (Ready=%s %s: %s)", c.Status, c.Reason, c.Message)
}

// parseLocalCIDRs returns peer's status.localCIDRs, masked, in status order.
func parseLocalCIDRs(peer *v1alpha1.WireguardPeer) ([]netip.Prefix, error) {
	cidrs := make([]netip.Prefix, 0, len(peer.Status.LocalCIDRs))
	for _, c := range peer.Status.LocalCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("parse status.localCIDRs entry %q of WireguardPeer %s: %w", c, peer.Name, err)
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("status.localCIDRs entry %q of WireguardPeer %s covers every address, so nothing would go through the tunnel", c, peer.Name)
		}
		cidrs = append(cidrs, p.Masked())
	}
	return cidrs, nil
}

// deviceConfig returns the configuration that gives dev (nil when the device has no state yet) the
// private key key and exactly one peer for t: the server's key, t.Endpoint, AllowedIPs 0.0.0.0/0 and
// resources.Keepalive. It returns false when dev already matches, so a pass never resets a live session.
func deviceConfig(dev *wgtypes.Device, key wgtypes.Key, t Tunnel) (wgtypes.Config, bool) {
	allowed := []net.IPNet{{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}}
	if deviceMatches(dev, key, t, allowed) {
		return wgtypes.Config{}, false
	}
	return wgtypes.Config{
		PrivateKey:   &key,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   t.ServerKey,
			Endpoint:                    net.UDPAddrFromAddrPort(t.Endpoint),
			PersistentKeepaliveInterval: new(resources.Keepalive),
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  allowed,
		}},
	}, true
}

// deviceMatches reports whether dev already has private key key and exactly the one peer deviceConfig
// would give it.
func deviceMatches(dev *wgtypes.Device, key wgtypes.Key, t Tunnel, allowed []net.IPNet) bool {
	if dev == nil || dev.PrivateKey != key || len(dev.Peers) != 1 {
		return false
	}
	p := dev.Peers[0]
	if p.PublicKey != t.ServerKey || p.Endpoint == nil || p.PersistentKeepaliveInterval != resources.Keepalive {
		return false
	}
	ap := p.Endpoint.AddrPort()
	if netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()) != t.Endpoint {
		return false
	}
	return len(p.AllowedIPs) == 1 && p.AllowedIPs[0].String() == allowed[0].String()
}

// handshakeMaxAge is how old the last handshake may be for the startup check: WireGuard rejects a
// session older than 180 s.
const handshakeMaxAge = 180 * time.Second

// checkDevice returns nil when dev has exactly one peer whose last handshake is less than
// handshakeMaxAge old at now, and an error naming what is missing otherwise.
func checkDevice(dev *wgtypes.Device, now time.Time) error {
	if n := len(dev.Peers); n != 1 {
		return fmt.Errorf("%s has %d peers, want 1", dev.Name, n)
	}
	last := dev.Peers[0].LastHandshakeTime
	if last.IsZero() {
		return fmt.Errorf("%s has not completed a handshake with its peer", dev.Name)
	}
	if age := now.Sub(last); age >= handshakeMaxAge {
		return fmt.Errorf("%s's last handshake was %s ago, more than %s", dev.Name, age.Round(time.Second), handshakeMaxAge)
	}
	return nil
}
