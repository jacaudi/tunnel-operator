package agent

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The hash GetDesiredState returns is compared against the previous hash to
// decide whether the desired state changed (see Run and the watcher loop). It is
// never persisted and never compared across process restarts, so the digest
// algorithm is free to change — but it must stay a stable, content-addressed
// value, which is what these tests pin.

func writeState(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

const validState = `{"ServerPrivateKey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=","Peers":[]}`

func TestGetDesiredStateHashIsSHA256(t *testing.T) {
	path := writeState(t, validState)

	_, hash, err := GetDesiredState(path)
	if err != nil {
		t.Fatalf("GetDesiredState: %v", err)
	}

	// SHA-256 is 32 bytes, so 64 hex characters. MD5 would be 32 — which is
	// what this asserted against before the algorithm was changed, and is the
	// reason the change is observable rather than cosmetic.
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64 (sha256); got %q", len(hash), hash)
	}
	if _, err := hex.DecodeString(hash); err != nil {
		t.Errorf("hash %q is not hex: %v", hash, err)
	}
}

func TestGetDesiredStateHashIsStable(t *testing.T) {
	path := writeState(t, validState)

	_, first, err := GetDesiredState(path)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	_, second, err := GetDesiredState(path)
	if err != nil {
		t.Fatalf("second read: %v", err)
	}

	if first != second {
		t.Errorf("hash is not stable across reads of identical content: %q != %q", first, second)
	}
}

func TestGetDesiredStateHashChangesWithContent(t *testing.T) {
	// Differs from validState only in the private key, so a hash that ignored
	// content would still collide here.
	const altered = `{"ServerPrivateKey":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=","Peers":[]}`

	_, a, err := GetDesiredState(writeState(t, validState))
	if err != nil {
		t.Fatalf("reading first fixture: %v", err)
	}
	_, b, err := GetDesiredState(writeState(t, altered))
	if err != nil {
		t.Fatalf("reading second fixture: %v", err)
	}

	if a == b {
		t.Errorf("different content produced the same hash %q — change detection would miss the update", a)
	}
}

func TestGetDesiredStateDecodesState(t *testing.T) {
	// Guards the fix for the digest change against silently breaking the parse:
	// the function returns both, and only the hash is changing.
	state, _, err := GetDesiredState(writeState(t, validState))
	if err != nil {
		t.Fatalf("GetDesiredState: %v", err)
	}
	if got := state.ServerPrivateKey; got != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=" {
		t.Errorf("ServerPrivateKey = %q, want the fixture's key", got)
	}
}

func TestIsStateValidNeedsNoServerAddressOrDNS(t *testing.T) {
	// A ClusterIP server has no external address and pushes no DNS, so a state whose
	// server status carries neither must still be applied.
	state := State{ServerPrivateKey: "PLA+byaz6a5jbnioieB4NEELG7sdq7Wk+3u9Kw0s6zk="}
	if err := IsStateValid(state); err != nil {
		t.Errorf("IsStateValid(state without address or DNS) = %v, want nil", err)
	}
}

func TestIsStateValidIgnoresFieldsTheAgentDoesNotRead(t *testing.T) {
	// During a rollout the new agent can read a state.json written by an operator that still
	// rendered fields the agent no longer reads. Unknown fields in state.json are ignored, not
	// rejected.
	const legacy = `{"Server":{"spec":{"mtu":"1380","serviceType":"LoadBalancer","dns":"1.1.1.1"},` +
		`"status":{"address":"203.0.113.10","dns":"10.0.0.10","port":"51820"}},` +
		`"ServerPrivateKey":"PLA+byaz6a5jbnioieB4NEELG7sdq7Wk+3u9Kw0s6zk=",` +
		`"Peers":[{"spec":{"publicKey":"v5Q+oRNBfxafhiAR9bXGEhRsRFfEFb7XsFV8DWGrykQ=",` +
		`"wireguardRef":"vpn","privateKeyRef":{"secretKeyRef":{"name":"p","key":"privateKey"}}},` +
		`"status":{"address":"10.8.0.2"}}]}`

	state, _, err := GetDesiredState(writeState(t, legacy))
	if err != nil {
		t.Fatalf("GetDesiredState(state with unknown fields): %v", err)
	}
	if err := IsStateValid(state); err != nil {
		t.Errorf("IsStateValid(state with unknown fields) = %v, want nil", err)
	}
	if len(state.Peers) != 1 || state.Peers[0].Status.Address != "10.8.0.2" {
		t.Errorf("peers = %+v, want the single peer of the state with unknown fields at 10.8.0.2", state.Peers)
	}
}

func TestIsStateValidRejectsAStateWithOnlySpecAddresses(t *testing.T) {
	// A state.json written by the M1 operator carries each peer's address in spec.address, which
	// this agent no longer reads. It must be rejected, not applied with an unaddressed peer.
	const m1 = `{"ServerPrivateKey":"PLA+byaz6a5jbnioieB4NEELG7sdq7Wk+3u9Kw0s6zk=",` +
		`"Peers":[{"spec":{"address":"10.8.0.2","publicKey":"v5Q+oRNBfxafhiAR9bXGEhRsRFfEFb7XsFV8DWGrykQ=",` +
		`"wireguardRef":"vpn"}}]}`

	state, _, err := GetDesiredState(writeState(t, m1))
	if err != nil {
		t.Fatalf("GetDesiredState(M1 state): %v", err)
	}
	err = IsStateValid(state)
	if err == nil || !strings.Contains(err.Error(), "does not have the address defined") {
		t.Errorf("IsStateValid(M1 state) = %v, want an error containing %q", err, "does not have the address defined")
	}
}

func TestGetDesiredStateReportsMissingFile(t *testing.T) {
	if _, _, err := GetDesiredState(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("expected an error for a missing state file, got nil")
	}
}

func TestPeerCIDR(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		want string
	}{
		{"empty falls back to the default", "", "10.8.0.0/24"},
		{"set is returned as is", "10.9.0.0/24", "10.9.0.0/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var state State
			state.Server.Spec.PeerCIDR = tt.cidr
			if got := PeerCIDR(state); got != tt.want {
				t.Errorf("PeerCIDR = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStateEgressRoundTrip(t *testing.T) {
	want := Egress{
		CycleAllowed:          []string{"10.8.0.2", "10.8.0.3"},
		ForwardedPortPeer:     "10.8.0.2",
		StaticPort:            51413,
		CycleRequestedAt:      "2026-11-08T10:00:00Z",
		LastHandledAnnotation: "2026-11-07T10:00:00Z",
	}
	b, err := json.Marshal(State{ServerPrivateKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=", Egress: want})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, _, err := GetDesiredState(writeState(t, string(b)))
	if err != nil {
		t.Fatalf("GetDesiredState: %v", err)
	}
	if !reflect.DeepEqual(got.Egress, want) {
		t.Errorf("Egress = %+v, want %+v", got.Egress, want)
	}

	// A state.json written before egress existed has no Egress key and still decodes.
	old, _, err := GetDesiredState(writeState(t, validState))
	if err != nil {
		t.Fatalf("GetDesiredState(state without Egress): %v", err)
	}
	if !reflect.DeepEqual(old.Egress, Egress{}) {
		t.Errorf("Egress = %+v, want the zero value when the key is absent", old.Egress)
	}
}
