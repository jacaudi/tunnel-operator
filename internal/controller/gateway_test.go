package controllers

import (
	"strings"
	"testing"

	"github.com/jacaudi/wireguard-operator/internal/resources"

	corev1 "k8s.io/api/core/v1"
)

func TestValidateLocalCIDRs(t *testing.T) {
	tests := []struct {
		name  string
		cidrs []string
		want  string // error text, or its prefix when wantPrefix; "" means nil
		// wantPrefix compares by prefix: the wrapped netip error text is not ours to pin.
		wantPrefix bool
	}{
		{name: "nil is valid", cidrs: nil},
		{name: "canonical IPv4 prefixes", cidrs: []string{"10.96.0.0/12", "10.244.0.0/16"}},
		{
			name:       "not a CIDR",
			cidrs:      []string{"10.0.0.0/24", "nope"},
			want:       `localCIDRs[1] "nope" is not a CIDR: `,
			wantPrefix: true,
		},
		{name: "IPv6", cidrs: []string{"fd00::/64"}, want: `localCIDRs[0] "fd00::/64" is not an IPv4 prefix`},
		{name: "host bits set", cidrs: []string{"10.1.0.1/16"}, want: `localCIDRs[0] "10.1.0.1/16" has host bits set; use 10.1.0.0/16`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errText(validateLocalCIDRs(tt.cidrs))
			if tt.wantPrefix {
				if got == "" || !strings.HasPrefix(got, tt.want) {
					t.Errorf("validateLocalCIDRs(%q) = %q, want prefix %q", tt.cidrs, got, tt.want)
				}
			} else if got != tt.want {
				t.Errorf("validateLocalCIDRs(%q) = %q, want %q", tt.cidrs, got, tt.want)
			}
		})
	}
}

func TestPeerCIDROverlap(t *testing.T) {
	tests := []struct {
		name       string
		peerCIDR   string
		localCIDRs []string
		want       string // "" means nil
	}{
		{name: "disjoint", peerCIDR: "10.8.0.0/24", localCIDRs: []string{"10.96.0.0/12"}},
		{
			name:       "local entry contains the peer range",
			peerCIDR:   "10.8.0.0/24",
			localCIDRs: []string{"10.96.0.0/12", "10.0.0.0/8"},
			want:       "peerCIDR 10.8.0.0/24 overlaps localCIDRs[1] 10.0.0.0/8; peer addresses must lie outside the cluster's networks",
		},
		{
			name:       "peer range contains the local entry",
			peerCIDR:   "10.8.0.0/24",
			localCIDRs: []string{"10.8.0.128/25"},
			want:       "peerCIDR 10.8.0.0/24 overlaps localCIDRs[0] 10.8.0.128/25; peer addresses must lie outside the cluster's networks",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errText(peerCIDROverlap(tt.peerCIDR, tt.localCIDRs)); got != tt.want {
				t.Errorf("peerCIDROverlap(%q, %q) = %q, want %q", tt.peerCIDR, tt.localCIDRs, got, tt.want)
			}
		})
	}
}

func TestClusterIPOutside(t *testing.T) {
	tests := []struct {
		name      string
		clusterIP string
		want      string // "" means nil
	}{
		{name: "inside", clusterIP: "10.96.0.10"},
		{
			name:      "outside",
			clusterIP: "10.0.0.5",
			want:      "Service vpn-svc has ClusterIP 10.0.0.5, which is in no localCIDRs entry; add the cluster's Service CIDR to localCIDRs",
		},
		{
			name:      "unset",
			clusterIP: "",
			want:      "Service vpn-svc has ClusterIP , which is in no localCIDRs entry; add the cluster's Service CIDR to localCIDRs",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errText(clusterIPOutside("vpn-svc", tt.clusterIP, []string{"10.96.0.0/12"})); got != tt.want {
				t.Errorf("clusterIPOutside(vpn-svc, %q) = %q, want %q", tt.clusterIP, got, tt.want)
			}
		})
	}
}

func TestReservedInEnv(t *testing.T) {
	tests := []struct {
		name string
		env  []corev1.EnvVar
		want string
	}{
		{name: "nil", env: nil, want: ""},
		{name: "a variable the operator does not render", env: []corev1.EnvVar{{Name: "VPN_SERVICE_PROVIDER"}}, want: ""},
		{name: "the first reserved name wins", env: []corev1.EnvVar{{Name: "A"}, {Name: "WIREGUARD_MTU"}, {Name: "VPN_TYPE"}}, want: "WIREGUARD_MTU"},
	}
	for _, reserved := range resources.ReservedGluetunEnv(nil) {
		tests = append(tests, struct {
			name string
			env  []corev1.EnvVar
			want string
		}{name: "reserved " + reserved.Name, env: []corev1.EnvVar{{Name: reserved.Name}}, want: reserved.Name})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reservedInEnv(tt.env); got != tt.want {
				t.Errorf("reservedInEnv(%v) = %q, want %q", tt.env, got, tt.want)
			}
		})
	}
}

func TestReservedInKeys(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		keys   []string
		want   string
	}{
		{name: "a key the operator does not render", keys: []string{"WIREGUARD_PRIVATE_KEY"}, want: ""},
		{name: "sorted order picks the first", keys: []string{"VPN_TYPE", "FIREWALL_INPUT_PORTS"}, want: "FIREWALL_INPUT_PORTS"},
		{name: "a prefix keeps an unrelated key clear", prefix: "X_", keys: []string{"VPN_TYPE"}, want: ""},
		{name: "a prefix completes a reserved name", prefix: "VPN_", keys: []string{"TYPE"}, want: "VPN_TYPE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reservedInKeys(tt.prefix, tt.keys); got != tt.want {
				t.Errorf("reservedInKeys(%q, %q) = %q, want %q", tt.prefix, tt.keys, got, tt.want)
			}
		})
	}
}

// errText returns err's text, or "" for nil.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
