//go:build linux

package datapath

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"

	"github.com/jacaudi/tunnel-operator/internal/resources"
)

// lookupPeerPath asks the kernel which device a packet from src arriving on wg0 for probe would leave
// by, the same lookup as `ip route get <probe> from <src> iif wg0`. The kernel's error is returned
// unwrapped so judgePeerPath can see EINVAL.
func lookupPeerPath(probe, src netip.Addr) (string, error) {
	routes, err := netlink.RouteGetWithOptions(net.IP(probe.AsSlice()), &netlink.RouteGetOptions{
		Iif:     resources.WgInterface,
		SrcAddr: net.IP(src.AsSlice()),
	})
	if err != nil {
		return "", err
	}
	if len(routes) == 0 {
		return "", errors.New("no route returned")
	}
	idx := routes[0].LinkIndex
	link, err := netlink.LinkByIndex(idx)
	if err != nil {
		return "", fmt.Errorf("look up link %d: %w", idx, err)
	}
	return link.Attrs().Name, nil
}
