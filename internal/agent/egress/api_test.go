package egress

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/agent"
)

const (
	cycler = "10.8.0.2" // a peer allowed to cycle
	holder = "10.8.0.3" // the peer holding the forwarded port
	other  = "10.8.0.4" // an attached peer with neither
)

func peerState() agent.State {
	var peers []v1alpha1.WireguardPeer
	for _, addr := range []string{cycler, holder, other} {
		peers = append(peers, v1alpha1.WireguardPeer{Status: v1alpha1.WireguardPeerStatus{Address: addr}})
	}
	return agent.State{
		Peers:  peers,
		Egress: agent.Egress{CycleAllowed: []string{cycler}, ForwardedPortPeer: holder},
	}
}

// call sends the request to h as if from remote (an IP) and returns the response.
func call(h http.Handler, method, path, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = net.JoinHostPort(remote, "40000")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// bodyMap decodes the JSON response body.
func bodyMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q is not JSON: %v", rec.Body.String(), err)
	}
	return m
}

func newPeerAPI(t *testing.T, f *fakeGluetun) (http.Handler, *Engine) {
	t.Helper()
	e, _ := newEngine(t, f)
	return PeerAPIHandler(e, peerState), e
}

func TestPeerAPIUnknownPeer403(t *testing.T) {
	h, _ := newPeerAPI(t, &fakeGluetun{status: "running", ip: "1.1.1.1"})
	for _, tt := range []struct{ method, path string }{
		{http.MethodGet, "/v1/egress"},
		{http.MethodPost, "/v1/cycle"},
	} {
		rec := call(h, tt.method, tt.path, "10.8.0.99")
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s status = %d, want 403", tt.method, tt.path, rec.Code)
		}
		if got := bodyMap(t, rec)["reason"]; got != "UnknownPeer" {
			t.Errorf("%s %s reason = %v, want UnknownPeer", tt.method, tt.path, got)
		}
	}
}

func TestPeerAPIEgressBody(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", port: 51413, newIP: "2.2.2.2"}
	h, e := newPeerAPI(t, f)
	e.Refresh(t.Context(), 0)

	tests := []struct {
		name       string
		remote     string
		wantHolder bool
	}{
		{"the holder", holder, true},
		{"another peer", other, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := call(h, http.MethodGet, "/v1/egress", tt.remote)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
			}
			got := bodyMap(t, rec)
			want := map[string]any{"exitIP": "1.1.1.1", "forwardedPort": 51413.0, "forwardedPortHolder": tt.wantHolder, "cycleInProgress": false}
			for k, v := range want {
				if got[k] != v {
					t.Errorf("%s = %v, want %v", k, got[k], v)
				}
			}
			for _, k := range []string{"lastCycle", "lastHandledAnnotation"} {
				if _, ok := got[k]; ok {
					t.Errorf("body has %q before any cycle or annotation: %v", k, got)
				}
			}
		})
	}
}

func TestPeerAPIEgressBodyAfterCycle(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", newIP: "2.2.2.2"}
	h, e := newPeerAPI(t, f)
	e.Refresh(t.Context(), 0)
	runCycle(t, e, "api:"+cycler)

	got := bodyMap(t, call(h, http.MethodGet, "/v1/egress", other))
	last, ok := got["lastCycle"].(map[string]any)
	if !ok {
		t.Fatalf("lastCycle = %v, want an object", got["lastCycle"])
	}
	want := map[string]any{"reason": "Succeeded", "oldExitIP": "1.1.1.1", "newExitIP": "2.2.2.2", "trigger": "api:" + cycler, "finishedAt": "2026-11-08T10:00:00Z"}
	for k, v := range want {
		if last[k] != v {
			t.Errorf("lastCycle.%s = %v, want %v", k, last[k], v)
		}
	}
}

func TestPeerAPICycleNotAllowed403(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", newIP: "2.2.2.2"}
	h, _ := newPeerAPI(t, f)

	rec := call(h, http.MethodPost, "/v1/cycle", other)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if got := bodyMap(t, rec)["reason"]; got != "CycleNotAllowed" {
		t.Errorf("reason = %v, want CycleNotAllowed", got)
	}
	if puts := f.putList(); len(puts) != 0 {
		t.Errorf("gluetun got PUTs %v, want none", puts)
	}
}

func TestPeerAPICycleAccepted202(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", newIP: "2.2.2.2"}
	h, e := newPeerAPI(t, f)
	e.Refresh(t.Context(), 0)

	rec := call(h, http.MethodPost, "/v1/cycle", cycler)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body)
	}
	if got := bodyMap(t, rec)["accepted"]; got != true {
		t.Errorf("accepted = %v, want true", got)
	}
	if c := lastCycle(t, waitIdle(t, e)); c.Trigger != "api:"+cycler || c.Reason != ReasonSucceeded {
		t.Errorf("LastCycle = %+v, want a Succeeded cycle triggered by api:%s", c, cycler)
	}
}

func TestPeerAPICycle409InProgressAndCooldown(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", newIP: "2.2.2.2"}
	f.holdPUT("stopped")
	h, e := newPeerAPI(t, f)
	e.Refresh(t.Context(), 0)

	if rec := call(h, http.MethodPost, "/v1/cycle", cycler); rec.Code != http.StatusAccepted {
		t.Fatalf("first cycle status = %d, want 202", rec.Code)
	}
	inProgress := call(h, http.MethodPost, "/v1/cycle", cycler)
	f.release("stopped")
	waitIdle(t, e)
	cooldown := call(h, http.MethodPost, "/v1/cycle", cycler)

	for _, tt := range []struct {
		name       string
		rec        *httptest.ResponseRecorder
		wantReason string
		wantRetry  float64
	}{
		{"while a cycle runs", inProgress, ReasonCycleInProgress, 10}, // the engine's 10 s deadline
		{"during the cooldown", cooldown, ReasonCooldownActive, 60},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409: %s", tt.rec.Code, tt.rec.Body)
			}
			got := bodyMap(t, tt.rec)
			if got["reason"] != tt.wantReason {
				t.Errorf("reason = %v, want %s", got["reason"], tt.wantReason)
			}
			if got["retryAfterSeconds"] != tt.wantRetry {
				t.Errorf("retryAfterSeconds = %v, want %v", got["retryAfterSeconds"], tt.wantRetry)
			}
			if got["message"] == "" || got["message"] == nil {
				t.Errorf("message = %v, want an explanation", got["message"])
			}
		})
	}
}

func TestPeerAPIRejectsNonPOSTCycle(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1"}
	h, _ := newPeerAPI(t, f)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if rec := call(h, method, "/v1/cycle", cycler); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /v1/cycle status = %d, want 405", method, rec.Code)
		}
	}
	if puts := f.putList(); len(puts) != 0 {
		t.Errorf("gluetun got PUTs %v, want none", puts)
	}
}

func TestStatusHandlerBody(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", port: 51413, newIP: "2.2.2.2"}
	e, _ := newEngine(t, f)
	e.Refresh(t.Context(), 0)
	e.HandleAnnotation("req-1", "")
	waitIdle(t, e)

	rec := call(StatusHandler(e), http.MethodGet, "/egress", "10.244.0.7")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	got := bodyMap(t, rec)
	want := map[string]any{"exitIP": "2.2.2.2", "forwardedPort": 51413.0, "cycleInProgress": false, "lastHandledAnnotation": "req-1"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if last, _ := got["lastCycle"].(map[string]any); last["trigger"] != "annotation:req-1" || last["reason"] != ReasonSucceeded {
		t.Errorf("lastCycle = %v, want a Succeeded cycle triggered by annotation:req-1", got["lastCycle"])
	}
	if _, ok := got["forwardedPortHolder"]; ok {
		t.Errorf("body has forwardedPortHolder, which is peer API only: %v", got)
	}
}

func TestPeerListenerBindsOnlyGivenAddress(t *testing.T) {
	l := &PeerListener{Handler: http.NotFoundHandler(), Port: 0}
	t.Cleanup(func() { closeListener(t, l) })

	if err := l.Ensure(netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	if !strings.HasPrefix(l.Addr(), "127.0.0.1:") {
		t.Fatalf("Addr() = %q, want it to start 127.0.0.1:", l.Addr())
	}
	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial %s: %v", l.Addr(), err)
	}
	_ = conn.Close()
}

func TestPeerListenerRejectsUnspecified(t *testing.T) {
	for _, addr := range []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified(), {}} {
		l := &PeerListener{Handler: http.NotFoundHandler(), Port: 0}
		if err := l.Ensure(addr); err == nil {
			closeListener(t, l)
			t.Errorf("Ensure(%v) = nil, want an error", addr)
		}
		if got := l.Addr(); got != "" {
			t.Errorf("Addr() after Ensure(%v) = %q, want it unbound", addr, got)
		}
	}
}

func TestPeerListenerEnsureIdempotent(t *testing.T) {
	l := &PeerListener{Handler: http.NotFoundHandler(), Port: 0}
	t.Cleanup(func() { closeListener(t, l) })
	addr := netip.MustParseAddr("127.0.0.1")

	if err := l.Ensure(addr); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	first := l.Addr()
	if err := l.Ensure(addr); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}

	if got := l.Addr(); got != first {
		t.Errorf("Addr() = %q after a second Ensure, want the unchanged %q", got, first)
	}
}

func TestPeerListenerRebindsOnAddressChange(t *testing.T) {
	// Linux binds all of 127.0.0.0/8; macOS only 127.0.0.1, so fall back to the IPv6 loopback.
	var second netip.Addr
	for _, c := range []string{"127.0.0.2", "::1"} {
		probe, err := net.Listen("tcp", net.JoinHostPort(c, "0"))
		if err != nil {
			continue
		}
		_ = probe.Close()
		second = netip.MustParseAddr(c)
		break
	}
	if !second.IsValid() {
		t.Skip("no second loopback address can be bound here")
	}

	l := &PeerListener{Handler: http.NotFoundHandler(), Port: 0}
	t.Cleanup(func() { closeListener(t, l) })
	if err := l.Ensure(netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Fatalf("Ensure 127.0.0.1: %v", err)
	}
	old := l.Addr()

	if err := l.Ensure(second); err != nil {
		t.Fatalf("Ensure %s: %v", second, err)
	}

	if host, _, _ := net.SplitHostPort(l.Addr()); host != second.String() {
		t.Errorf("Addr() = %q, want it on %s", l.Addr(), second)
	}
	if conn, err := net.Dial("tcp", old); err == nil {
		_ = conn.Close()
		t.Errorf("the old address %s still accepts connections", old)
	}
}

func TestPeerListenerBindErrorLeavesItUnbound(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1: never on a local interface.
	l := &PeerListener{Handler: http.NotFoundHandler(), Port: 0}

	if err := l.Ensure(netip.MustParseAddr("192.0.2.1")); err == nil {
		closeListener(t, l)
		t.Fatal("Ensure(192.0.2.1) = nil, want a bind error")
	}
	if got := l.Addr(); got != "" {
		t.Errorf("Addr() = %q, want it unbound", got)
	}
}

// closeListener shuts l down with a context that outlives t.Context(), which is already cancelled
// when cleanups run.
func closeListener(t *testing.T, l *PeerListener) {
	t.Helper()
	if err := l.Close(context.WithoutCancel(t.Context())); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// A server closed before its serve goroutine ran must still refuse connections: the listener is
// closed directly, not only through the server.
func TestPeerListenerCloseRefusesAtOnce(t *testing.T) {
	for range 200 {
		l := &PeerListener{Handler: http.NotFoundHandler(), Port: 0}
		if err := l.Ensure(netip.MustParseAddr("127.0.0.1")); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		addr := l.Addr()
		if err := l.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if conn, err := net.Dial("tcp", addr); err == nil {
			_ = conn.Close()
			t.Fatalf("%s still accepts connections after Close", addr)
		}
	}
}
