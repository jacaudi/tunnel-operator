package resources

import (
	"regexp"
	"testing"
	"time"
)

func TestEgressConstants(t *testing.T) {
	tests := []struct {
		name      string
		got, want any
	}{
		{"EgressAPIPort", EgressAPIPort, 8081},
		{"GluetunControlAddress", GluetunControlAddress, "127.0.0.1:8000"},
		{"CycleDeadline", CycleDeadline, 150 * time.Second},
		{"CycleCooldown", CycleCooldown, 60 * time.Second},
		{"EgressPollInterval", EgressPollInterval, 30 * time.Second},
		{"EgressPollTimeout", EgressPollTimeout, 2 * time.Second},
		{"LabelCycle", LabelCycle, "tunnel-operator.io/cycle"},
		{"CycleAllowedValue", CycleAllowedValue, "allowed"},
		{"LabelForwardedPort", LabelForwardedPort, "tunnel-operator.io/forwarded-port"},
		{"ForwardedPortValue", ForwardedPortValue, "true"},
		{"AnnotationCycleRequestedAt", AnnotationCycleRequestedAt, "tunnel-operator.io/cycle-requested-at"},
		{"ChainPrerouting", ChainPrerouting, "TUNNEL-OP-PREROUTING"},
		{"ChainForward", ChainForward, "TUNNEL-OP-FORWARD"},
		{"ChainInput", ChainInput, "TUNNEL-OP-INPUT"},
		{"ChainOutput", ChainOutput, "TUNNEL-OP-OUTPUT"},
		{"GluetunAgentRole", GluetunAgentRole, "tunnel-operator-agent"},
		{"SecretKeyGluetunAPIKey", SecretKeyGluetunAPIKey, "gluetun-api-key"},
		{"SecretKeyGluetunAuth", SecretKeyGluetunAuth, "gluetun-auth.toml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestGluetunAuthTOML(t *testing.T) {
	got := string(GluetunAuthTOML("k"))
	// These are the only keys gluetun v3.41.3's DisallowUnknownFields decoder accepts for a role.
	want := `[[roles]]
name = "tunnel-operator-agent"
routes = ["GET /v1/publicip/ip", "GET /v1/portforward", "GET /v1/vpn/status", "PUT /v1/vpn/status"]
auth = "apikey"
apikey = "k"
`
	if got != want {
		t.Errorf("GluetunAuthTOML(k) = %q, want %q", got, want)
	}
}

func TestNewGluetunAPIKey(t *testing.T) {
	a, b := NewGluetunAPIKey(), NewGluetunAPIKey()
	// 32 random bytes in unpadded base64url.
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(a) {
		t.Errorf("NewGluetunAPIKey() = %q, want 43 base64url characters", a)
	}
	if a == b {
		t.Errorf("two keys are both %q, want distinct", a)
	}
}
