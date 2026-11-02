//go:build linux

package datapath

import (
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestDesiredRules(t *testing.T) {
	got := desiredRules(netip.MustParsePrefix("10.8.0.0/24"))
	if len(got) != 2 {
		t.Fatalf("desiredRules returned %d rules, want 2", len(got))
	}

	peer, blackhole := got[0], got[1]
	if peer.Priority != 90 || peer.Table != 51821 || peer.Dst == nil || peer.Dst.String() != "10.8.0.0/24" || peer.Family != netlink.FAMILY_V4 {
		t.Errorf("pref-90 rule = %+v, want {Priority 90, Table 51821, Dst 10.8.0.0/24, Family V4}", peer)
	}
	if blackhole.Priority != 102 || blackhole.Table != 51822 || blackhole.IifName != "wg0" || blackhole.Family != netlink.FAMILY_V4 {
		t.Errorf("pref-102 rule = %+v, want {Priority 102, Table 51822, IifName wg0, Family V4}", blackhole)
	}
}

func TestRuleMatches(t *testing.T) {
	want := desiredRules(netip.MustParsePrefix("10.8.0.0/24"))

	otherDst := want[0]
	_, otherDst.Dst, _ = net.ParseCIDR("10.9.0.0/24")
	otherIif := want[1]
	otherIif.IifName = "eth0"
	otherTable := want[0]
	otherTable.Table = 51899

	tests := []struct {
		name string
		have netlink.Rule
		want netlink.Rule
		same bool
	}{
		{"pref 90 matches itself", want[0], want[0], true},
		{"pref 102 matches itself", want[1], want[1], true},
		{"pref 90 to another prefix", otherDst, want[0], false},
		{"pref 102 from another interface", otherIif, want[1], false},
		{"different table", otherTable, want[0], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ruleMatches(tt.have, tt.want); got != tt.same {
				t.Errorf("ruleMatches = %v, want %v", got, tt.same)
			}
		})
	}
}
