//go:build linux

package sidecar

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ensureRoutes applies planRoutes to the main table. In order, it replaces each localCIDRs route,
// replaces the default route with one via wg0, deletes each stale route, and deletes every IPv6
// default route. Deleting a route that is already gone is not an error.
func ensureRoutes(wgIndex int, localCIDRs []netip.Prefix) error {
	listed, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}
	have := make([]route, 0, len(listed))
	for _, r := range listed {
		have = append(have, toRoute(r))
	}

	plan, err := planRoutes(have, wgIndex, localCIDRs)
	if err != nil {
		return err
	}

	for _, p := range plan.Local {
		err := netlink.RouteReplace(&netlink.Route{
			Dst: ipNet(p), Gw: net.IP(plan.Gw.AsSlice()), LinkIndex: plan.GwLink,
			Protocol: routeProtocol, Table: unix.RT_TABLE_MAIN,
		})
		if err != nil {
			return fmt.Errorf("replace route %s via %s: %w", p, plan.Gw, err)
		}
	}

	// Dst is the explicit 0.0.0.0/0: routeHandle rejects a route whose Dst, Src and Gw are all nil.
	err = netlink.RouteReplace(&netlink.Route{
		Dst: &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}, LinkIndex: wgIndex,
		Scope: netlink.SCOPE_LINK, Protocol: routeProtocol, Table: unix.RT_TABLE_MAIN,
	})
	if err != nil {
		return fmt.Errorf("replace the default route via wg0: %w", err)
	}

	if err := deleteStale(plan.Stale); err != nil {
		return err
	}
	return deleteIPv6Defaults()
}

// routesVia reports whether the kernel's route to dst leaves through the link linkIndex.
func routesVia(dst netip.Addr, linkIndex int) (bool, error) {
	routes, err := netlink.RouteGet(net.IP(dst.AsSlice()))
	if err != nil {
		return false, fmt.Errorf("route get %s: %w", dst, err)
	}
	return len(routes) > 0 && routes[0].LinkIndex == linkIndex, nil
}

// toRoute converts a netlink route to a route: a nil Dst is 0.0.0.0/0, a Dst that does not convert is
// the zero (invalid) Prefix, never a default route, and a nil Gw is the zero Addr.
func toRoute(r netlink.Route) route {
	out := route{
		Dst:       netip.PrefixFrom(netip.IPv4Unspecified(), 0),
		LinkIndex: r.LinkIndex,
		Priority:  r.Priority,
		Protocol:  int(r.Protocol),
		Scope:     uint8(r.Scope),
	}
	if r.Dst != nil {
		out.Dst = netip.Prefix{}
		ones, _ := r.Dst.Mask.Size()
		if addr, ok := netip.AddrFromSlice(r.Dst.IP); ok {
			out.Dst = netip.PrefixFrom(addr.Unmap(), ones)
		}
	}
	if gw, ok := netip.AddrFromSlice(r.Gw); ok {
		out.Gw = gw.Unmap()
	}
	return out
}

// deleteStale deletes each route in stale from the main table, ignoring one that is already gone.
func deleteStale(stale []route) error {
	for _, r := range stale {
		// netlink's routeHandle always writes msg.Scope, so the delete must carry the route's own scope
		// or a gateway-less "default dev X scope link" would not match and would stay.
		del := &netlink.Route{
			Dst: ipNet(r.Dst), LinkIndex: r.LinkIndex, Priority: r.Priority, Protocol: netlink.RouteProtocol(r.Protocol),
			Scope: netlink.Scope(r.Scope), Table: unix.RT_TABLE_MAIN,
		}
		if r.Gw.IsValid() {
			del.Gw = net.IP(r.Gw.AsSlice())
		}
		if err := netlink.RouteDel(del); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("delete route %s: %w", r.Dst, err)
		}
	}
	return nil
}

// deleteIPv6Defaults deletes every IPv6 default route in the main table, ignoring one already gone.
// A kernel with no IPv6 stack (ipv6.disable=1) refuses the dump or the delete with EOPNOTSUPP or
// EAFNOSUPPORT: it has no IPv6 default to delete, so those errnos are treated like a route already gone.
func deleteIPv6Defaults() error {
	listed, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if noIPv6Stack(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}
	for _, r := range listed {
		// With ipv6.disable=1 an AF_INET6 dump can fall back to an all-family dump: never delete an IPv4 route.
		if (r.Dst != nil && r.Dst.IP.To4() != nil) || (r.Gw != nil && r.Gw.To4() != nil) {
			continue
		}
		if r.Dst != nil {
			if ones, _ := r.Dst.Mask.Size(); ones != 0 {
				continue
			}
		}
		del := &netlink.Route{
			Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}, Gw: r.Gw,
			LinkIndex: r.LinkIndex, Priority: r.Priority, Scope: r.Scope, Table: unix.RT_TABLE_MAIN,
		}
		if err := netlink.RouteDel(del); err != nil && !errors.Is(err, unix.ESRCH) && !noIPv6Stack(err) {
			return fmt.Errorf("delete IPv6 default route: %w", err)
		}
	}
	return nil
}

// ipNet returns p as the *net.IPNet netlink takes.
func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// noIPv6Stack reports whether err says the kernel has no IPv6 stack.
func noIPv6Stack(err error) bool {
	return errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EAFNOSUPPORT)
}
