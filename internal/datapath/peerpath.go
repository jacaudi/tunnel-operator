package datapath

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"

	"github.com/jacaudi/tunnel-operator/internal/resources"
)

var peerProbe = netip.MustParseAddr(resources.PeerProbeAddress)

// CheckPeerPath returns nil when the kernel would forward a packet from a peer address in peerCIDR, arriving on wg0 for resources.PeerProbeAddress, into gluetun's tunnel, and an error naming the answer otherwise. It sends no packet.
func CheckPeerPath(peerCIDR string) error {
	p, err := netip.ParsePrefix(peerCIDR)
	if err != nil {
		return fmt.Errorf("parse peerCIDR %q: %w", peerCIDR, err)
	}
	src, err := peerProbeSource(p)
	if err != nil {
		return err
	}
	dev, err := lookupPeerPath(peerProbe, src)
	return judgePeerPath(peerProbe, src, dev, err)
}

// peerProbeSource returns the second host of p, a peer address. It is never the first host: that is the
// server's own wg0 address, and the kernel rejects a local source arriving on wg0.
func peerProbeSource(p netip.Prefix) (netip.Addr, error) {
	src := p.Masked().Addr().Next().Next()
	if !p.Contains(src) {
		return netip.Addr{}, fmt.Errorf("peerCIDR %s has no second host for the peer-path probe", p)
	}
	return src, nil
}

// judgePeerPath turns the kernel's route lookup (the device it chose, or its error) into the readiness verdict.
func judgePeerPath(probe, src netip.Addr, dev string, err error) error {
	switch {
	case errors.Is(err, unix.EINVAL):
		// The kernel returns EINVAL for an RTN_BLACKHOLE result.
		return fmt.Errorf("peer path: %s from %s arriving on %s is blackholed (no tunnel route)", probe, src, resources.WgInterface)
	case err != nil:
		return fmt.Errorf("peer path: look up %s from %s arriving on %s: %w", probe, src, resources.WgInterface, err)
	case dev != resources.EgressInterface:
		return fmt.Errorf("peer path: %s from %s arriving on %s routes via %s, not %s", probe, src, resources.WgInterface, dev, resources.EgressInterface)
	}
	return nil
}
