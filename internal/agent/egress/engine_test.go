package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

// fakeGluetun is a stand-in for gluetun's control server. PUT stopped clears the public IP; PUT
// running brings it back as newIP, after ipLag empty reads.
type fakeGluetun struct {
	mu     sync.Mutex
	status string
	ip     string
	newIP  string
	port   int32
	ipLag  int
	lag    int
	noIP   bool                     // after a start the public IP never reappears
	stuck  bool                     // PUTs succeed but the status never changes
	getErr bool                     // every GET answers 500
	fail   map[string]int           // PUT status -> HTTP code to answer instead of 200
	hold   map[string]chan struct{} // PUT status -> blocks until the channel is closed
	puts   []string
}

func (f *fakeGluetun) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-Key") != apiKey {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet:
		f.get(w, r)
	case r.Method == http.MethodPut && r.URL.Path == "/v1/vpn/status":
		f.put(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeGluetun) get(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr {
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	}
	switch r.URL.Path {
	case "/v1/publicip/ip":
		ip := f.ip
		if f.lag > 0 {
			f.lag--
			ip = ""
		}
		_, _ = fmt.Fprintf(w, `{"public_ip":%q}`, ip)
	case "/v1/portforward":
		_, _ = fmt.Fprintf(w, `{"port":%d}`, f.port)
	case "/v1/vpn/status":
		_, _ = fmt.Fprintf(w, `{"status":%q}`, f.status)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeGluetun) put(w http.ResponseWriter, r *http.Request) {
	var body struct{ Status string }
	_ = json.NewDecoder(r.Body).Decode(&body)

	f.mu.Lock()
	f.puts = append(f.puts, body.Status)
	hold, code := f.hold[body.Status], f.fail[body.Status]
	f.mu.Unlock()

	if hold != nil {
		<-hold
	}
	if code != 0 {
		http.Error(w, "boom", code)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.stuck {
		f.status = body.Status
		switch body.Status {
		case "stopped":
			f.ip = ""
		case "running":
			f.ip, f.lag = f.newIP, f.ipLag
			if f.noIP {
				f.ip = ""
			}
		}
	}
	_, _ = fmt.Fprintf(w, `{"outcome":%q}`, body.Status)
}

func (f *fakeGluetun) putList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.puts)
}

func (f *fakeGluetun) setGetErr(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getErr = v
}

// holdPUT makes the next PUT of status block until release(status).
func (f *fakeGluetun) holdPUT(status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hold == nil {
		f.hold = map[string]chan struct{}{}
	}
	f.hold[status] = make(chan struct{})
}

func (f *fakeGluetun) release(status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ch := f.hold[status]; ch != nil {
		close(ch)
		delete(f.hold, status)
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// clockStart has a sub-second part so truncation is observable.
var clockStart = time.Date(2026, 11, 8, 10, 0, 0, 789_000_000, time.UTC)

// newEngine returns an Engine against f with generous limits and a fake clock; a test that wants a
// timeout to fire shrinks the relevant field before starting a cycle.
func newEngine(t *testing.T, f *fakeGluetun) (*Engine, *fakeClock) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	t.Cleanup(func() { // runs before srv.Close, so no handler is left blocked
		f.release("stopped")
		f.release("running")
	})
	clock := &fakeClock{t: clockStart}
	return &Engine{
		G:           &Gluetun{BaseURL: srv.URL, APIKey: apiKey, HTTP: srv.Client()},
		Now:         clock.Now,
		Poll:        time.Millisecond,
		Deadline:    10 * time.Second,
		Cooldown:    time.Minute,
		StepTimeout: 5 * time.Second,
		IPTimeout:   5 * time.Second,
	}, clock
}

// waitIdle blocks until no cycle is running and returns the snapshot taken then.
func waitIdle(t *testing.T, e *Engine) Snapshot {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		if s := e.Snapshot(); !s.CycleInProgress {
			return s
		}
	}
	t.Fatal("cycle still in progress after 10s")
	return Snapshot{}
}

// waitPuts blocks until the fake has recorded n PUTs.
func waitPuts(t *testing.T, f *fakeGluetun, n int) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		if len(f.putList()) >= n {
			return
		}
	}
	t.Fatalf("fewer than %d PUTs after 10s: %v", n, f.putList())
}

// runCycle starts a cycle, waits for it to finish and returns the snapshot.
func runCycle(t *testing.T, e *Engine, trigger string) Snapshot {
	t.Helper()
	if ok, reason, _ := e.StartCycle(trigger); !ok {
		t.Fatalf("StartCycle(%q) refused: %s", trigger, reason)
	}
	return waitIdle(t, e)
}

func lastCycle(t *testing.T, s Snapshot) Cycle {
	t.Helper()
	if s.LastCycle == nil {
		t.Fatal("LastCycle = nil, want a recorded cycle")
	}
	return *s.LastCycle
}

func TestCycleSucceeded(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", newIP: "2.2.2.2"}
	e, _ := newEngine(t, f)
	e.Refresh(t.Context(), 0)

	s := runCycle(t, e, "api:10.8.0.2")

	want := Cycle{Reason: "Succeeded", OldExitIP: "1.1.1.1", NewExitIP: "2.2.2.2", Trigger: "api:10.8.0.2", FinishedAt: clockStart.Truncate(time.Second)}
	if got := lastCycle(t, s); got != want {
		t.Errorf("LastCycle = %+v, want %+v", got, want)
	}
	if s.ExitIP != "2.2.2.2" {
		t.Errorf("ExitIP = %q, want the cache refreshed to 2.2.2.2", s.ExitIP)
	}
	if puts := f.putList(); len(puts) < 2 || puts[0] != "stopped" || puts[1] != "running" {
		t.Errorf("PUTs = %v, want stopped then running", puts)
	}
}

func TestCyclePollsUntilTheIPReturns(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", newIP: "2.2.2.2", ipLag: 5}
	e, _ := newEngine(t, f)
	e.Refresh(t.Context(), 0)

	s := runCycle(t, e, "api:10.8.0.2")

	if got := lastCycle(t, s); got.Reason != "Succeeded" || got.NewExitIP != "2.2.2.2" {
		t.Errorf("LastCycle = %+v, want Succeeded with 2.2.2.2 after the empty reads", got)
	}
}

func TestCycleIPUnchanged(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", newIP: "1.1.1.1"}
	e, _ := newEngine(t, f)
	e.Refresh(t.Context(), 0)

	s := runCycle(t, e, "api:10.8.0.2")

	got := lastCycle(t, s)
	if got.Reason != "IPUnchanged" || got.OldExitIP != "1.1.1.1" || got.NewExitIP != "1.1.1.1" {
		t.Errorf("LastCycle = %+v, want IPUnchanged with both IPs 1.1.1.1", got)
	}
}

func TestCycleEmptyIP(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", noIP: true}
	e, _ := newEngine(t, f)
	e.IPTimeout = 30 * time.Millisecond
	e.Refresh(t.Context(), 0)

	s := runCycle(t, e, "api:10.8.0.2")

	got := lastCycle(t, s)
	if got.Reason != "EmptyIP" || got.NewExitIP != "" || got.OldExitIP != "1.1.1.1" {
		t.Errorf("LastCycle = %+v, want EmptyIP with no new IP", got)
	}
}

func TestCycleTimeoutStopping(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", stuck: true}
	e, _ := newEngine(t, f)
	e.StepTimeout = 30 * time.Millisecond

	s := runCycle(t, e, "api:10.8.0.2")

	if got := lastCycle(t, s); got.Reason != "Timeout" {
		t.Errorf("Reason = %q, want Timeout when the status never reads stopped", got.Reason)
	}
}

func TestCycleTimeoutDeadline(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", stuck: true}
	e, _ := newEngine(t, f)
	e.Deadline = 30 * time.Millisecond // far below StepTimeout, so the deadline is what ends it

	s := runCycle(t, e, "api:10.8.0.2")

	if got := lastCycle(t, s); got.Reason != "Timeout" {
		t.Errorf("Reason = %q, want Timeout when the deadline is hit", got.Reason)
	}
}

func TestCycleGluetunError(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", fail: map[string]int{"stopped": http.StatusInternalServerError}}
	e, _ := newEngine(t, f)

	s := runCycle(t, e, "api:10.8.0.2")

	if got := lastCycle(t, s); got.Reason != "GluetunError" {
		t.Errorf("Reason = %q, want GluetunError", got.Reason)
	}
	if want := []string{"stopped", "running"}; !slices.Equal(f.putList(), want) {
		t.Errorf("PUTs = %v, want %v (the deferred restart)", f.putList(), want)
	}
	if ok, reason, _ := e.StartCycle("api:10.8.0.2"); ok || reason != "CooldownActive" {
		t.Errorf("StartCycle = %v, %q, want a refusal with CooldownActive (armed when PUT stopped was sent)", ok, reason)
	}
}

func TestCycleArmsCooldownOnTimeout(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", stuck: true}
	e, clock := newEngine(t, f)
	e.StepTimeout = 30 * time.Millisecond
	runCycle(t, e, "api:10.8.0.2")

	ok, reason, retryAfter := e.StartCycle("api:10.8.0.3")
	if ok || reason != "CooldownActive" || retryAfter != time.Minute {
		t.Errorf("StartCycle = %v, %q, %v, want a refusal with CooldownActive and the full minute", ok, reason, retryAfter)
	}

	clock.Advance(time.Minute - time.Second)
	if ok, reason, retryAfter := e.StartCycle("api:10.8.0.3"); ok || reason != "CooldownActive" || retryAfter != time.Second {
		t.Errorf("StartCycle = %v, %q, %v, want a refusal with one second left", ok, reason, retryAfter)
	}

	clock.Advance(time.Second)
	if ok, reason, _ := e.StartCycle("api:10.8.0.3"); !ok {
		t.Errorf("StartCycle refused with %q once the cooldown elapsed", reason)
	}
	waitIdle(t, e)
}

func TestCycleDefersRunningOnEveryFailure(t *testing.T) {
	tests := []struct {
		name       string
		fake       *fakeGluetun
		configure  func(*Engine)
		wantReason string
		wantPuts   []string
	}{
		{
			name:       "PUT stopped refused",
			fake:       &fakeGluetun{status: "running", fail: map[string]int{"stopped": http.StatusInternalServerError}},
			wantReason: "GluetunError",
			wantPuts:   []string{"stopped", "running"},
		},
		{
			name:       "status never reads stopped",
			fake:       &fakeGluetun{status: "running", stuck: true},
			configure:  func(e *Engine) { e.StepTimeout = 30 * time.Millisecond },
			wantReason: "Timeout",
			wantPuts:   []string{"stopped", "running"},
		},
		{
			name:       "deadline hit, so the restart runs on an expired context",
			fake:       &fakeGluetun{status: "running", stuck: true},
			configure:  func(e *Engine) { e.Deadline = 30 * time.Millisecond },
			wantReason: "Timeout",
			wantPuts:   []string{"stopped", "running"},
		},
		{
			name:       "PUT running refused",
			fake:       &fakeGluetun{status: "running", fail: map[string]int{"running": http.StatusInternalServerError}},
			wantReason: "GluetunError",
			wantPuts:   []string{"stopped", "running", "running"},
		},
		{
			name:       "IP never returns",
			fake:       &fakeGluetun{status: "running", noIP: true},
			configure:  func(e *Engine) { e.IPTimeout = 30 * time.Millisecond },
			wantReason: "EmptyIP",
			wantPuts:   []string{"stopped", "running", "running"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, _ := newEngine(t, tt.fake)
			if tt.configure != nil {
				tt.configure(e)
			}

			s := runCycle(t, e, "api:10.8.0.2")

			if got := lastCycle(t, s); got.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tt.wantReason)
			}
			if got := tt.fake.putList(); !slices.Equal(got, tt.wantPuts) {
				t.Errorf("PUTs = %v, want %v", got, tt.wantPuts)
			}
		})
	}
}

func TestStartCycleRejectsWhileRunning(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", newIP: "2.2.2.2"}
	e, _ := newEngine(t, f)
	f.holdPUT("stopped")
	if ok, reason, _ := e.StartCycle("api:10.8.0.2"); !ok {
		t.Fatalf("first StartCycle refused: %s", reason)
	}
	waitPuts(t, f, 1) // the cycle is now blocked inside PUT stopped

	ok, reason, retryAfter := e.StartCycle("api:10.8.0.3")

	if ok || reason != "CycleInProgress" || retryAfter != e.Deadline {
		t.Errorf("StartCycle = %v, %q, %v, want a refusal with CycleInProgress and the remaining deadline %v", ok, reason, retryAfter, e.Deadline)
	}
	if !e.Snapshot().CycleInProgress {
		t.Error("CycleInProgress = false while a cycle is running")
	}
	f.release("stopped")
	waitIdle(t, e)
}

func TestStartCycleRejectsWhileSelfHealing(t *testing.T) {
	f := &fakeGluetun{status: "stopped"}
	e, _ := newEngine(t, f)
	f.holdPUT("running")
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.SelfHeal(t.Context())
	}()
	waitPuts(t, f, 1) // the self-heal is blocked inside PUT running

	ok, reason, _ := e.StartCycle("api:10.8.0.2")

	if ok || reason != "CycleInProgress" {
		t.Errorf("StartCycle = %v, %q, want a refusal with CycleInProgress while gluetun is being restarted", ok, reason)
	}
	f.release("running")
	<-done
	if got := f.putList(); !slices.Equal(got, []string{"running"}) {
		t.Errorf("PUTs = %v, want only the self-heal's running", got)
	}
}

func TestSelfHealStartsStoppedGluetun(t *testing.T) {
	tests := []struct {
		status   string
		wantPuts []string
	}{
		{status: "stopped", wantPuts: []string{"running"}},
		{status: "running"},
		{status: "starting"},
		{status: "crashed"},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			f := &fakeGluetun{status: tt.status}
			e, _ := newEngine(t, f)

			e.SelfHeal(t.Context())

			if got := f.putList(); !slices.Equal(got, tt.wantPuts) {
				t.Errorf("PUTs = %v, want %v", got, tt.wantPuts)
			}
		})
	}
}

func TestSelfHealIdleWhileCycling(t *testing.T) {
	f := &fakeGluetun{status: "stopped", newIP: "2.2.2.2"} // a self-heal that ignored the cycle would PUT running
	e, _ := newEngine(t, f)
	f.holdPUT("stopped")
	if ok, reason, _ := e.StartCycle("api:10.8.0.2"); !ok {
		t.Fatalf("StartCycle refused: %s", reason)
	}
	waitPuts(t, f, 1)

	e.SelfHeal(t.Context())

	if got := f.putList(); !slices.Equal(got, []string{"stopped"}) {
		t.Errorf("PUTs = %v, want only the cycle's stopped", got)
	}
	f.release("stopped")
	waitIdle(t, e)
}

func TestRefreshStaticPortOverrides(t *testing.T) {
	tests := []struct {
		name       string
		staticPort int32
		want       int32
	}{
		{name: "gluetun's port", staticPort: 0, want: 5914},
		{name: "static port wins", staticPort: 60000, want: 60000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeGluetun{status: "running", ip: "1.1.1.1", port: 5914}
			e, _ := newEngine(t, f)

			e.Refresh(t.Context(), tt.staticPort)

			s := e.Snapshot()
			if s.ForwardedPort != tt.want || s.ExitIP != "1.1.1.1" {
				t.Errorf("Snapshot = %q:%d, want 1.1.1.1:%d", s.ExitIP, s.ForwardedPort, tt.want)
			}
		})
	}
}

func TestRefreshKeepsCacheOnError(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", port: 5914}
	e, _ := newEngine(t, f)
	e.Refresh(t.Context(), 0)
	f.setGetErr(true)

	e.Refresh(t.Context(), 0)

	if s := e.Snapshot(); s.ExitIP != "1.1.1.1" || s.ForwardedPort != 5914 {
		t.Errorf("Snapshot = %q:%d, want the cache kept at 1.1.1.1:5914 while gluetun errors", s.ExitIP, s.ForwardedPort)
	}
}

func TestHandleAnnotation(t *testing.T) {
	type step struct {
		requested, lastHandled string
		advance                time.Duration // moves the fake clock before the call
		wantCycles             int           // total cycles started once this call has settled
	}
	cooldown := time.Minute + time.Second
	tests := []struct {
		name        string
		steps       []step
		wantHandled string
		wantTrigger string
	}{
		{name: "empty requested", steps: []step{{requested: "", lastHandled: "", wantCycles: 0}}},
		{name: "equal to lastHandled", steps: []step{{requested: "V1", lastHandled: "V1", wantCycles: 0}}, wantHandled: "V1"},
		{name: "new value runs one cycle", steps: []step{{requested: "V1", wantCycles: 1}}, wantHandled: "V1", wantTrigger: "annotation:V1"},
		{name: "same new value again", steps: []step{{requested: "V1", wantCycles: 1}, {requested: "V1", wantCycles: 1}}, wantHandled: "V1"},
		{
			name: "new value during the cooldown runs after it, once",
			steps: []step{
				{requested: "V1", wantCycles: 1},
				{requested: "V2", lastHandled: "V1", wantCycles: 1},
				{requested: "V2", lastHandled: "V1", advance: cooldown, wantCycles: 2},
				{requested: "V2", lastHandled: "V1", wantCycles: 2},
			},
			wantHandled: "V2",
			wantTrigger: "annotation:V2",
		},
		{
			name: "stalled operator never writes the value back",
			steps: []step{
				{requested: "V2", lastHandled: "V1", wantCycles: 1},
				{requested: "V2", lastHandled: "V1", advance: cooldown, wantCycles: 1},
				{requested: "V2", lastHandled: "V1", advance: cooldown, wantCycles: 1},
				{requested: "V2", lastHandled: "V1", advance: cooldown, wantCycles: 1},
			},
			wantHandled: "V2",
		},
		{
			name:        "fresh engine is seeded from state",
			steps:       []step{{requested: "V1", lastHandled: "V1", wantCycles: 0}, {requested: "V1", lastHandled: "V1", advance: cooldown, wantCycles: 0}},
			wantHandled: "V1",
		},
		{
			name:        "seeding never overwrites",
			steps:       []step{{requested: "V1", lastHandled: "", wantCycles: 1}, {requested: "V1", lastHandled: "V0", advance: cooldown, wantCycles: 1}},
			wantHandled: "V1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeGluetun{status: "running", ip: "1.1.1.1", newIP: "2.2.2.2"}
			e, clock := newEngine(t, f)

			var s Snapshot
			for i, st := range tt.steps {
				clock.Advance(st.advance)
				e.HandleAnnotation(st.requested, st.lastHandled)
				s = waitIdle(t, e)
				got := 0
				for _, p := range f.putList() {
					if p == "stopped" {
						got++
					}
				}
				if got != st.wantCycles {
					t.Fatalf("step %d: cycles = %d, want %d (PUTs %v)", i, got, st.wantCycles, f.putList())
				}
			}

			if s.LastHandledAnnotation != tt.wantHandled {
				t.Errorf("LastHandledAnnotation = %q, want %q", s.LastHandledAnnotation, tt.wantHandled)
			}
			if tt.wantTrigger != "" {
				if got := lastCycle(t, s).Trigger; got != tt.wantTrigger {
					t.Errorf("Trigger = %q, want %q", got, tt.wantTrigger)
				}
			}
		})
	}
}

func TestCycleFinishedAtTruncatedToSecond(t *testing.T) {
	f := &fakeGluetun{status: "running", ip: "1.1.1.1", newIP: "2.2.2.2"}
	e, _ := newEngine(t, f)

	got := lastCycle(t, runCycle(t, e, "api:10.8.0.2")).FinishedAt

	if want := clockStart.Truncate(time.Second); !got.Equal(want) || got.Nanosecond() != 0 {
		t.Errorf("FinishedAt = %v, want %v (second precision)", got, want)
	}
}

func TestCycleJSONKeys(t *testing.T) {
	b, err := json.Marshal(Cycle{Reason: "Succeeded", OldExitIP: "1.1.1.1", NewExitIP: "2.2.2.2", Trigger: "api:10.8.0.2", FinishedAt: clockStart.Truncate(time.Second)})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	const want = `{"reason":"Succeeded","oldExitIP":"1.1.1.1","newExitIP":"2.2.2.2","trigger":"api:10.8.0.2","finishedAt":"2026-11-08T10:00:00Z"}`
	if got := string(b); got != want {
		t.Errorf("JSON = %s, want %s", got, want)
	}
}

// slowIP is a gluetunAPI whose PublicIP blocks until release is closed; the engine never calls
// anything else of it in these tests.
type slowIP struct {
	gluetunAPI
	release chan struct{}
}

func (s slowIP) PublicIP(ctx context.Context) (string, error) {
	select {
	case <-s.release:
		return "1.1.1.1", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func TestRefreshStaticPortDoesNotWaitForGluetun(t *testing.T) {
	g := slowIP{release: make(chan struct{})}
	e := &Engine{G: g, StepTimeout: 5 * time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Refresh(t.Context(), 60000)
	}()
	defer func() {
		close(g.release)
		<-done
	}()

	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		if e.Snapshot().ForwardedPort == 60000 {
			return
		}
	}
	t.Errorf("ForwardedPort = %d while gluetun's PublicIP hangs, want the static port 60000", e.Snapshot().ForwardedPort)
}
