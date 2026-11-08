package controllers

import (
	"strings"
	"testing"

	"github.com/jacaudi/tunnel-operator/internal/resources"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func TestProbeAddressInLocalCIDRs(t *testing.T) {
	const reserved = "contains 192.0.2.1, the address the gateway's readiness check routes through the tunnel; it is reserved for documentation (RFC 5737), so no cluster network should hold it"
	tests := []struct {
		name       string
		localCIDRs []string
		want       string // "" means nil
	}{
		{name: "cluster network", localCIDRs: []string{"10.96.0.0/12"}},
		{name: "second entry is the probe's documentation range", localCIDRs: []string{"10.0.0.0/24", "192.0.2.0/24"}, want: "localCIDRs[1] 192.0.2.0/24 " + reserved},
		{name: "a wider entry holds the probe", localCIDRs: []string{"192.0.0.0/8"}, want: "localCIDRs[0] 192.0.0.0/8 " + reserved},
		{name: "a neighbouring prefix does not", localCIDRs: []string{"192.0.2.2/31"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errText(probeAddressInLocalCIDRs(tt.localCIDRs)); got != tt.want {
				t.Errorf("probeAddressInLocalCIDRs(%q) = %q, want %q", tt.localCIDRs, got, tt.want)
			}
		})
	}
}

func TestProbeAddressInPeerCIDR(t *testing.T) {
	const reserved = "contains 192.0.2.1, the address the gateway's readiness check routes through the tunnel; it is reserved for documentation (RFC 5737), so choose a peer range that does not hold it"
	tests := []struct {
		name     string
		peerCIDR string
		want     string // "" means nil
	}{
		{name: "default peer range", peerCIDR: "10.8.0.0/24"},
		{name: "the probe's documentation range", peerCIDR: "192.0.2.0/24", want: "peerCIDR 192.0.2.0/24 " + reserved},
		{name: "a wider range holds the probe", peerCIDR: "192.0.0.0/22", want: "peerCIDR 192.0.0.0/22 " + reserved},
		{name: "a neighbouring prefix does not", peerCIDR: "192.0.2.4/30"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errText(probeAddressInPeerCIDR(tt.peerCIDR)); got != tt.want {
				t.Errorf("probeAddressInPeerCIDR(%q) = %q, want %q", tt.peerCIDR, got, tt.want)
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

// The four variables that lock gluetun's control server behind the agent's key. A user setting any of
// them, inline or through envFrom, would open the server or move it out from under the agent.
func TestIsReservedGluetunEnvCoversTheControlServer(t *testing.T) {
	for _, name := range []string{
		"HTTP_CONTROL_SERVER_ADDRESS",
		"HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH",
		"HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE",
		"VPN_PORT_FORWARDING_LISTENING_PORT",
	} {
		t.Run(name, func(t *testing.T) {
			if !isReservedGluetunEnv(name) {
				t.Errorf("isReservedGluetunEnv(%q) = false, want true", name)
			}
		})
	}
}

func TestSecretDiffers(t *testing.T) {
	want := map[string][]byte{"state.json": []byte("s"), "gluetun-api-key": []byte("k"), "gluetun-auth.toml": []byte("t")}
	tests := []struct {
		name string
		have map[string][]byte
		want bool
	}{
		{name: "identical", have: map[string][]byte{"state.json": []byte("s"), "gluetun-api-key": []byte("k"), "gluetun-auth.toml": []byte("t")}, want: false},
		{name: "a key the operator does not render is ignored", have: map[string][]byte{"state.json": []byte("s"), "gluetun-api-key": []byte("k"), "gluetun-auth.toml": []byte("t"), "extra": []byte("x")}, want: false},
		{name: "state differs", have: map[string][]byte{"state.json": []byte("old"), "gluetun-api-key": []byte("k"), "gluetun-auth.toml": []byte("t")}, want: true},
		{name: "the api key is missing", have: map[string][]byte{"state.json": []byte("s"), "gluetun-auth.toml": []byte("t")}, want: true},
		{name: "only the auth file differs", have: map[string][]byte{"state.json": []byte("s"), "gluetun-api-key": []byte("k"), "gluetun-auth.toml": []byte("old")}, want: true},
		{name: "no Secret data", have: nil, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := secretDiffers(tt.have, want); got != tt.want {
				t.Errorf("secretDiffers(%q, %q) = %v, want %v", tt.have, want, got, tt.want)
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

func TestRolloutProblem(t *testing.T) {
	one := int32(1)
	tests := []struct {
		name     string
		replicas *int32
		status   appsv1.DeploymentStatus
		want     string
	}{
		{
			name: "generation not observed", replicas: &one,
			status: appsv1.DeploymentStatus{ObservedGeneration: 1, UpdatedReplicas: 1, ReadyReplicas: 1},
			want:   "Deployment vpn-dep is not rolled out: generation 2 not yet observed",
		},
		{
			name: "not updated", replicas: &one,
			status: appsv1.DeploymentStatus{ObservedGeneration: 2, UpdatedReplicas: 0, ReadyReplicas: 1},
			want:   "Deployment vpn-dep is not rolled out: 1/1 ready, 0/1 updated",
		},
		{
			name: "not ready", replicas: &one,
			status: appsv1.DeploymentStatus{ObservedGeneration: 2, UpdatedReplicas: 1, ReadyReplicas: 0},
			want:   "Deployment vpn-dep is not rolled out: 0/1 ready, 1/1 updated",
		},
		{
			name: "rolled out", replicas: &one,
			status: appsv1.DeploymentStatus{ObservedGeneration: 2, UpdatedReplicas: 1, ReadyReplicas: 1},
		},
		{
			name: "observed generation ahead", replicas: &one,
			status: appsv1.DeploymentStatus{ObservedGeneration: 3, UpdatedReplicas: 1, ReadyReplicas: 1},
		},
		{
			name:   "unset replicas default to 1",
			status: appsv1.DeploymentStatus{ObservedGeneration: 2, UpdatedReplicas: 1, ReadyReplicas: 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "vpn-dep", Generation: 2},
				Spec:       appsv1.DeploymentSpec{Replicas: tt.replicas},
				Status:     tt.status,
			}
			if got := rolloutProblem(dep); got != tt.want {
				t.Errorf("rolloutProblem() = %q, want %q", got, tt.want)
			}
		})
	}
}
