package resources

import (
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
