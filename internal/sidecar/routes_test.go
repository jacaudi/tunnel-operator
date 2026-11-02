package sidecar

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// scopeLink is rtnetlink's RT_SCOPE_LINK. netlink.SCOPE_LINK exists only on Linux, and this test runs everywhere.
const scopeLink = 253

func TestPlanRoutes(t *testing.T) {
	const (
		eth0 = 2
		wg0  = 5
	)
	gw := netip.MustParseAddr("10.244.0.1")
	def := netip.MustParsePrefix("0.0.0.0/0")
	pod := netip.MustParsePrefix("10.244.0.0/16")
	svc := netip.MustParsePrefix("10.96.0.0/12")
	local := []netip.Prefix{pod, svc}

	cniDefault := route{Dst: def, Gw: gw, LinkIndex: eth0}
	wgDefault := route{Dst: def, LinkIndex: wg0, Protocol: routeProtocol, Scope: scopeLink}
	podRoute := route{Dst: pod, Gw: gw, LinkIndex: eth0, Protocol: routeProtocol}
	svcRoute := route{Dst: svc, Gw: gw, LinkIndex: eth0, Protocol: routeProtocol}
	otherDefault := route{Dst: def, LinkIndex: 3, Scope: scopeLink}

	tests := []struct {
		name       string
		have       []route
		local      []netip.Prefix
		wantGw     netip.Addr
		wantGwLink int
		wantStale  []route
		wantErr    string
	}{
		{
			name: "first entry",
			have: []route{
				cniDefault,
				{Dst: netip.MustParsePrefix("10.244.0.0/24"), LinkIndex: eth0},
			},
			local:      local,
			wantGw:     gw,
			wantGwLink: eth0,
			wantStale:  []route{cniDefault},
		},
		{
			name:       "CNI default with a metric",
			have:       []route{{Dst: def, Gw: gw, LinkIndex: eth0, Priority: 100}},
			local:      local,
			wantGw:     gw,
			wantGwLink: eth0,
			wantStale:  []route{{Dst: def, Gw: gw, LinkIndex: eth0, Priority: 100}},
		},
		{
			name:       "re-entry",
			have:       []route{wgDefault, podRoute, svcRoute},
			local:      local,
			wantGw:     gw,
			wantGwLink: eth0,
		},
		{
			name:       "localCIDRs edit",
			have:       []route{wgDefault, podRoute, svcRoute},
			local:      []netip.Prefix{pod},
			wantGw:     gw,
			wantGwLink: eth0,
			wantStale:  []route{svcRoute},
		},
		{
			name: "CNI route outside local",
			have: []route{
				cniDefault,
				{Dst: netip.MustParsePrefix("192.168.5.0/24"), Gw: gw, LinkIndex: eth0, Protocol: 4},
			},
			local:      local,
			wantGw:     gw,
			wantGwLink: eth0,
			wantStale:  []route{cniDefault},
		},
		{
			name:       "contained, not equal",
			have:       []route{wgDefault, podRoute},
			local:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			wantGw:     gw,
			wantGwLink: eth0,
			wantStale:  []route{podRoute},
		},
		{
			name:       "gateway-less default elsewhere",
			have:       []route{wgDefault, podRoute, otherDefault},
			local:      []netip.Prefix{pod},
			wantGw:     gw,
			wantGwLink: eth0,
			wantStale:  []route{otherDefault},
		},
		{
			name:    "no gateway",
			have:    []route{{Dst: netip.MustParsePrefix("10.244.0.0/24"), LinkIndex: eth0}},
			local:   local,
			wantErr: "no CNI gateway",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := planRoutes(tt.have, wg0, tt.local)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("planRoutes error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("planRoutes: %v", err)
			}
			if got.Gw != tt.wantGw || got.GwLink != tt.wantGwLink {
				t.Errorf("gateway = %s on link %d, want %s on link %d", got.Gw, got.GwLink, tt.wantGw, tt.wantGwLink)
			}
			if !reflect.DeepEqual(got.Local, tt.local) {
				t.Errorf("Local = %v, want %v", got.Local, tt.local)
			}
			if !reflect.DeepEqual(got.Stale, tt.wantStale) {
				t.Errorf("Stale = %+v, want %+v", got.Stale, tt.wantStale)
			}
		})
	}
}
