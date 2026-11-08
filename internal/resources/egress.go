package resources

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

const (
	// EgressAPIPort is the port the agent serves the egress API on, bound only to the server tunnel
	// address so it is reachable from inside the tunnel and nowhere else.
	EgressAPIPort = 8081
	// GluetunControlAddress is where gluetun's control server listens; only the agent reaches it.
	GluetunControlAddress = "127.0.0.1:8000"

	// LabelCycle marks a peer's pod as allowed to cycle the VPN; its value is CycleAllowedValue.
	LabelCycle = "tunnel-operator.io/cycle"
	// CycleAllowedValue is the value of LabelCycle that grants cycle permission.
	CycleAllowedValue = "allowed"
	// LabelForwardedPort marks a peer's pod as the holder of the forwarded port; its value is
	// ForwardedPortValue.
	LabelForwardedPort = "tunnel-operator.io/forwarded-port"
	// ForwardedPortValue is the value of LabelForwardedPort that requests the forwarded port.
	ForwardedPortValue = "true"
	// AnnotationCycleRequestedAt on a Wireguard requests a VPN cycle when its value changes.
	AnnotationCycleRequestedAt = "tunnel-operator.io/cycle-requested-at"

	// CycleDeadline is the single hard deadline of one VPN cycle.
	CycleDeadline = 150 * time.Second
	// CycleCooldown is the minimum gap between cycles, armed when gluetun is stopped.
	CycleCooldown = 60 * time.Second
	// EgressPollInterval is how often the operator requeues a Ready server to refresh status.egress.
	EgressPollInterval = 30 * time.Second
	// EgressPollTimeout bounds one operator request to the agent's /egress endpoint.
	EgressPollTimeout = 2 * time.Second

	// ChainPrerouting is the agent's nat chain holding the forwarded-port DNAT rules.
	ChainPrerouting = "TUNNEL-OP-PREROUTING"
	// ChainForward is the agent's filter chain accepting the forwarded-port traffic.
	ChainForward = "TUNNEL-OP-FORWARD"
	// ChainInput is the agent's filter chain accepting the egress API on wg0.
	ChainInput = "TUNNEL-OP-INPUT"
	// ChainOutput is the agent's filter chain accepting the egress API's replies on wg0.
	ChainOutput = "TUNNEL-OP-OUTPUT"

	// GluetunAgentRole is the gluetun control-server role the agent authenticates as.
	GluetunAgentRole = "tunnel-operator-agent"
	// SecretKeyGluetunAPIKey is the server Secret key holding the agent's gluetun API key.
	SecretKeyGluetunAPIKey = "gluetun-api-key" //nolint:gosec // G101: a Secret key name, not a credential
	// SecretKeyGluetunAuth is the server Secret key holding gluetun's auth config file.
	SecretKeyGluetunAuth = "gluetun-auth.toml" //nolint:gosec // G101: a Secret key name, not a credential
	// EnvGluetunAPIKey is the agent's environment variable carrying SecretKeyGluetunAPIKey.
	EnvGluetunAPIKey = "GLUETUN_API_KEY" //nolint:gosec // G101: an environment variable name, not a credential
)

// NewGluetunAPIKey returns a fresh API key for gluetun's control server: 32 random bytes in unpadded
// base64url, 43 characters. crypto/rand.Read never returns an error as of Go 1.24: it crashes the
// program if the system source fails, so there is nothing to handle.
func NewGluetunAPIKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// GluetunAuthTOML renders gluetun's roles file: one role, for the agent, limited to the routes the
// agent calls. gluetun v3.41.3 decodes a role with DisallowUnknownFields, so name, routes, auth and
// apikey are the only keys it may carry.
func GluetunAuthTOML(apiKey string) []byte {
	return fmt.Appendf(nil, `[[roles]]
name = %q
routes = ["GET /v1/publicip/ip", "GET /v1/portforward", "GET /v1/vpn/status", "PUT /v1/vpn/status"]
auth = "apikey"
apikey = %q
`, GluetunAgentRole, apiKey)
}
