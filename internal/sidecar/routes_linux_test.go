//go:build linux

package sidecar

import (
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestToRoute(t *testing.T) {
	_, svc, err := net.ParseCIDR("10.96.0.0/12")
	if err != nil {
		t.Fatalf("parse CIDR: %v", err)
	}

	tests := []struct {
		name string
		in   netlink.Route
		want route
	}{
		{
			name: "default via a gateway",
			in: netlink.Route{
				Gw: net.ParseIP("10.244.0.1"), LinkIndex: 2, Priority: 100, Protocol: 4, Scope: netlink.SCOPE_UNIVERSE,
			},
			want: route{
				Dst: netip.MustParsePrefix("0.0.0.0/0"), Gw: netip.MustParseAddr("10.244.0.1"),
				LinkIndex: 2, Priority: 100, Protocol: 4, Scope: uint8(netlink.SCOPE_UNIVERSE),
			},
		},
		{
			name: "prefix without a gateway",
			in:   netlink.Route{Dst: svc, LinkIndex: 3, Protocol: routeProtocol, Scope: netlink.SCOPE_LINK},
			want: route{
				Dst: netip.MustParsePrefix("10.96.0.0/12"), LinkIndex: 3, Protocol: routeProtocol,
				Scope: uint8(netlink.SCOPE_LINK),
			},
		},
		{
			name: "malformed destination is not a default route",
			in:   netlink.Route{Dst: &net.IPNet{IP: net.IP{1, 2, 3}, Mask: net.CIDRMask(8, 32)}, LinkIndex: 3},
			want: route{LinkIndex: 3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toRoute(tt.in)
			if got != tt.want {
				t.Errorf("toRoute = %+v, want %+v", got, tt.want)
			}
		})
	}
}
