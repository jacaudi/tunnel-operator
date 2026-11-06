//go:build linux

package datapath

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/jacaudi/tunnel-operator/internal/resources"
)

// ensureRouting installs the peerCIDR route in table 51821 and the blackhole default in table 51822 with
// RouteReplace (a route for an earlier peerCIDR is not removed), and makes the two ip rules exactly the
// desired ones.
func ensureRouting(p netip.Prefix) error {
	wg, err := netlink.LinkByName(resources.WgInterface)
	if err != nil {
		return fmt.Errorf("look up %s: %w", resources.WgInterface, err)
	}

	peerRoute := &netlink.Route{
		LinkIndex: wg.Attrs().Index,
		Dst:       &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())},
		Table:     resources.PeerTable,
		Scope:     netlink.SCOPE_LINK,
	}
	if err := netlink.RouteReplace(peerRoute); err != nil {
		return fmt.Errorf("replace route in table %d: %w", resources.PeerTable, err)
	}

	blackhole := &netlink.Route{
		Dst:   &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
		Table: resources.BlackholeTable,
		Type:  unix.RTN_BLACKHOLE,
	}
	if err := netlink.RouteReplace(blackhole); err != nil {
		return fmt.Errorf("replace route in table %d: %w", resources.BlackholeTable, err)
	}

	for _, want := range desiredRules(p) {
		if err := ensureRule(want); err != nil {
			return err
		}
	}
	return nil
}

// ensureRule leaves want as the only ip rule at its priority: it deletes every rule there that
// ruleMatches rejects and adds want when none matched.
func ensureRule(want netlink.Rule) error {
	have, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list ip rules: %w", err)
	}

	found := false
	for _, r := range have {
		if r.Priority != want.Priority {
			continue
		}
		if ruleMatches(r, want) {
			found = true
			continue
		}
		if err := netlink.RuleDel(&r); err != nil {
			return fmt.Errorf("delete ip rule pref %d: %w", want.Priority, err)
		}
	}
	if found {
		return nil
	}
	if err := netlink.RuleAdd(&want); err != nil {
		return fmt.Errorf("add ip rule pref %d: %w", want.Priority, err)
	}
	return nil
}

// desiredRules returns the pref-90 rule (to p, lookup PeerTable) and the pref-102 rule (iif wg0,
// lookup BlackholeTable), both IPv4.
func desiredRules(p netip.Prefix) []netlink.Rule {
	peer := netlink.NewRule()
	peer.Family = netlink.FAMILY_V4
	peer.Priority = resources.PeerRulePref
	peer.Table = resources.PeerTable
	peer.Dst = &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}

	blackhole := netlink.NewRule()
	blackhole.Family = netlink.FAMILY_V4
	blackhole.Priority = resources.BlackholePref
	blackhole.Table = resources.BlackholeTable
	blackhole.IifName = resources.WgInterface

	return []netlink.Rule{*peer, *blackhole}
}

// ruleMatches reports whether have is want: same Priority and Table, the same Dst (both nil, or equal
// as strings), and the same IifName. Family is not compared: RuleList does not set it.
func ruleMatches(have, want netlink.Rule) bool {
	return have.Priority == want.Priority &&
		have.Table == want.Table &&
		dstString(have.Dst) == dstString(want.Dst) &&
		have.IifName == want.IifName
}

func dstString(n *net.IPNet) string {
	if n == nil {
		return ""
	}
	return n.String()
}
