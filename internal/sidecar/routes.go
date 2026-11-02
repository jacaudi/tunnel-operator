package sidecar

import (
	"errors"
	"net/netip"
	"slices"
)

// routeProtocol marks the routes the client installs (rtnetlink protocol 151, which no routing daemon
// in iproute2's rt_protos uses), so a later pass finds the CNI gateway after the default route has
// moved to wg0 and removes only routes it installed.
const routeProtocol = 151

// route is the part of a main-table IPv4 route the client's routing decisions read.
type route struct {
	Dst       netip.Prefix // 0.0.0.0/0 for a default route
	Gw        netip.Addr   // the zero Addr when the route has no gateway
	LinkIndex int
	Priority  int
	Protocol  int
	Scope     uint8 // netlink.Scope's underlying type: a delete must name the route's scope (decision 2)
}

// routePlan is the change that sends localCIDRs via the CNI gateway and everything else via wg0.
type routePlan struct {
	Gw     netip.Addr     // the CNI gateway
	GwLink int            // the link the gateway is reached on (eth0)
	Local  []netip.Prefix // replace each with a route via Gw on GwLink, protocol routeProtocol
	Stale  []route        // delete each, after the default route has been replaced
}

// planRoutes returns the plan for the main table's IPv4 routes have, the wg0 link index wgIndex and
// localCIDRs. The gateway is that of a default route not on wg0 that has one; failing that (the
// default is already wg0, after a restart), that of the first route with protocol routeProtocol and
// a gateway. Stale is every default route not on wg0 and every routeProtocol route whose Dst is
// neither the default nor equal to an entry of localCIDRs, in have's order.
func planRoutes(have []route, wgIndex int, localCIDRs []netip.Prefix) (routePlan, error) {
	plan := routePlan{Local: localCIDRs}

	gw := slices.IndexFunc(have, func(r route) bool { return isDefault(r) && r.LinkIndex != wgIndex && r.Gw.IsValid() })
	if gw < 0 {
		gw = slices.IndexFunc(have, func(r route) bool { return r.Protocol == routeProtocol && r.Gw.IsValid() })
	}
	if gw < 0 {
		return routePlan{}, errors.New("no CNI gateway: the main table has no default route via a gateway outside wg0 and no route this client installed")
	}
	plan.Gw, plan.GwLink = have[gw].Gw, have[gw].LinkIndex

	for _, r := range have {
		switch {
		case isDefault(r):
			if r.LinkIndex != wgIndex {
				plan.Stale = append(plan.Stale, r)
			}
		case r.Protocol == routeProtocol && !slices.Contains(localCIDRs, r.Dst):
			plan.Stale = append(plan.Stale, r)
		}
	}
	return plan, nil
}

func isDefault(r route) bool { return r.Dst.Bits() == 0 }
