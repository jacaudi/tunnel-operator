package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/jacaudi/tunnel-operator/internal/agent"
)

// Reasons the peer API refuses a request with, alongside the engine's CycleInProgress and
// CooldownActive.
const (
	ReasonUnknownPeer     = "UnknownPeer"
	ReasonCycleNotAllowed = "CycleNotAllowed"
)

// NewServer returns an http.Server for addr with the agent's timeouts. They are not optional:
// without a ReadHeaderTimeout a client that opens a connection and dribbles header bytes holds a
// goroutine open indefinitely (Slowloris). On the health listener enough of those make the probe
// endpoint stop answering, which the kubelet reads as an unhealthy pod and restarts the tunnel.
func NewServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// body is the JSON of an egress snapshot. Unknown values are absent. ForwardedPortHolder is set
// only on the peer API and LastHandledAnnotation only on the pod-IP status endpoint.
type body struct {
	ExitIP                string `json:"exitIP,omitempty"`
	ForwardedPort         int32  `json:"forwardedPort,omitzero"`
	ForwardedPortHolder   *bool  `json:"forwardedPortHolder,omitempty"`
	LastCycle             *Cycle `json:"lastCycle,omitempty"`
	CycleInProgress       bool   `json:"cycleInProgress"`
	LastHandledAnnotation string `json:"lastHandledAnnotation,omitempty"`
}

func bodyOf(s Snapshot) body {
	return body{ExitIP: s.ExitIP, ForwardedPort: s.ForwardedPort, LastCycle: s.LastCycle, CycleInProgress: s.CycleInProgress}
}

// StatusHandler serves the egress snapshot for the operator's poll of the pod-IP listener
// (GET /egress, mounted by the caller). It reads the cache and never calls gluetun.
func StatusHandler(e *Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s := e.Snapshot()
		b := bodyOf(s)
		b.LastHandledAnnotation = s.LastHandledAnnotation
		writeJSON(w, http.StatusOK, b)
	})
}

// PeerAPIHandler serves the egress API to attached peers: GET /v1/egress and POST /v1/cycle. The
// caller is the request's source address, which is the peer's tunnel address; the per-peer /32s
// stop a peer from spoofing another's. state is read once per request.
func PeerAPIHandler(e *Engine, state func() agent.State) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/egress", func(w http.ResponseWriter, r *http.Request) {
		st, caller, ok := identify(w, r, state)
		if !ok {
			return
		}
		b := bodyOf(e.Snapshot())
		holder := caller == st.Egress.ForwardedPortPeer
		b.ForwardedPortHolder = &holder
		writeJSON(w, http.StatusOK, b)
	})
	mux.HandleFunc("POST /v1/cycle", func(w http.ResponseWriter, r *http.Request) {
		st, caller, ok := identify(w, r, state)
		if !ok {
			return
		}
		if !slices.Contains(st.Egress.CycleAllowed, caller) {
			writeError(w, http.StatusForbidden, ReasonCycleNotAllowed, "this peer is not allowed to cycle the VPN")
			return
		}
		accepted, reason, retryAfter := e.StartCycle("api:" + caller)
		if !accepted {
			writeJSON(w, http.StatusConflict, struct {
				Reason            string `json:"reason"`
				Message           string `json:"message"`
				RetryAfterSeconds int64  `json:"retryAfterSeconds"`
			}{reason, "the VPN cannot be cycled right now", int64(retryAfter / time.Second)})
			return
		}
		writeJSON(w, http.StatusAccepted, struct {
			Accepted bool `json:"accepted"`
		}{true})
	})
	return mux
}

// identify returns the state and the caller's tunnel address. A caller that is not among the
// state's peers gets a 403 and ok is false.
func identify(w http.ResponseWriter, r *http.Request, state func() agent.State) (agent.State, string, bool) {
	st := state()
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if a, err := netip.ParseAddr(host); err == nil {
			host = a.Unmap().String()
		}
		for _, p := range st.Peers {
			if p.Status.Address == host {
				return st, host, true
			}
		}
	}
	writeError(w, http.StatusForbidden, ReasonUnknownPeer, "the caller is not an attached peer")
	return st, "", false
}

func writeError(w http.ResponseWriter, code int, reason, message string) {
	writeJSON(w, code, struct {
		Reason  string `json:"reason"`
		Message string `json:"message"`
	}{reason, message})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("writing an egress API response failed", "error", err)
	}
}

// PeerListener serves Handler on one tunnel address and Port, and only there: gluetun accepts all
// pod-subnet input on eth0, so a wildcard bind would expose the API to the whole cluster. Use it
// through a pointer; Ensure and Close are safe to call concurrently.
type PeerListener struct {
	Handler http.Handler
	Port    int

	mu   sync.Mutex
	srv  *http.Server
	ln   net.Listener // nil when not bound
	addr netip.Addr   // what ln is bound to; the zero Addr when not bound
}

// Ensure binds addr:Port unless it already does. When addr changed it closes the old server first,
// so a bind error leaves the listener unbound; the caller retries on its next pass. An invalid or
// unspecified addr is refused and leaves any current binding alone.
func (l *PeerListener) Ensure(addr netip.Addr) error {
	if !addr.IsValid() || addr.IsUnspecified() {
		return fmt.Errorf("egress API: refusing to bind %q: not a specific address", addr)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln != nil && l.addr == addr {
		return nil
	}
	if l.srv != nil {
		l.stopLocked()
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(addr.String(), strconv.Itoa(l.Port)))
	if err != nil {
		return fmt.Errorf("egress API: %w", err)
	}
	srv := NewServer(ln.Addr().String(), l.Handler)
	l.srv, l.ln, l.addr = srv, ln, addr
	go func() { // ends when Close or a rebind closes srv
		if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			slog.Warn("the egress API server stopped", "addr", ln.Addr().String(), "error", err)
		}
	}()
	return nil
}

// stopLocked closes the server and its listener and leaves the listener unbound. The listener is
// closed directly because a server that has not reached Serve yet does not know it.
func (l *PeerListener) stopLocked() {
	_ = l.ln.Close()
	_ = l.srv.Close()
	l.srv, l.ln, l.addr = nil, nil, netip.Addr{}
}

// Addr returns the bound host:port, or "" when not bound.
func (l *PeerListener) Addr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln == nil {
		return ""
	}
	return l.ln.Addr().String()
}

// Close stops the server, waiting for in-flight requests until ctx ends. It is a no-op when not
// bound.
func (l *PeerListener) Close(ctx context.Context) error {
	l.mu.Lock()
	srv, ln := l.srv, l.ln
	l.srv, l.ln, l.addr = nil, nil, netip.Addr{}
	l.mu.Unlock()
	if srv == nil {
		return nil
	}
	err := srv.Shutdown(ctx)
	_ = ln.Close() // a server that has not reached Serve yet does not know ln
	if err != nil {
		_ = srv.Close()
		return fmt.Errorf("egress API: %w", err)
	}
	return nil
}
