package resources

import (
	"regexp"
	"testing"
)

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
