package egress

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// The reasons a cycle ends with (Cycle.Reason) or is refused with (StartCycle).
const (
	ReasonSucceeded       = "Succeeded"
	ReasonIPUnchanged     = "IPUnchanged"
	ReasonEmptyIP         = "EmptyIP"
	ReasonTimeout         = "Timeout"
	ReasonGluetunError    = "GluetunError"
	ReasonCycleInProgress = "CycleInProgress"
	ReasonCooldownActive  = "CooldownActive"
)

const (
	statusStopped = "stopped"
	statusRunning = "running"

	// restoreTimeout bounds the deferred PUT running, which must outlive the cycle's own deadline.
	restoreTimeout = 30 * time.Second
)

// gluetunAPI is what the engine needs of gluetun's control server; *Gluetun implements it.
type gluetunAPI interface {
	PublicIP(ctx context.Context) (string, error)
	ForwardedPort(ctx context.Context) (int32, error)
	VPNStatus(ctx context.Context) (string, error)
	SetVPNStatus(ctx context.Context, status string) error
}

// Cycle is the outcome of one VPN cycle.
type Cycle struct {
	Reason     string    `json:"reason"`
	OldExitIP  string    `json:"oldExitIP"`
	NewExitIP  string    `json:"newExitIP"`
	Trigger    string    `json:"trigger"` // api:<peer address> or annotation:<value>
	FinishedAt time.Time `json:"finishedAt"`
}

// Snapshot is the engine's cached view; reading it never calls gluetun.
type Snapshot struct {
	ExitIP                string // "" while unknown
	ForwardedPort         int32  // 0 when none
	LastCycle             *Cycle // nil until a cycle has finished
	CycleInProgress       bool
	LastHandledAnnotation string
}

// Engine caches gluetun's exit IP and forwarded port and cycles the VPN on request. Use it through
// a pointer; it holds a mutex, which is never held across a call to gluetun.
type Engine struct {
	G        gluetunAPI
	Now      func() time.Time // defaults to time.Now
	Deadline time.Duration    // hard limit of one cycle; must be positive
	Cooldown time.Duration    // minimum gap between cycles, armed when gluetun is stopped
	// Poll is the gap between status and IP reads (default 1s). StepTimeout bounds each gluetun
	// request and each wait for a status (default 30s); IPTimeout bounds the wait for the new IP
	// (default 60s). All three are further bounded by Deadline.
	Poll        time.Duration
	StepTimeout time.Duration
	IPTimeout   time.Duration

	mu            sync.Mutex
	exitIP        string
	port          int32
	staticPort    int32
	last          *Cycle
	cycling       bool      // a cycle is running
	healing       bool      // a self-heal is restarting gluetun
	cycleEnds     time.Time // when the running cycle's deadline expires
	cooldownUntil time.Time
	handled       string // last annotation value whose cycle started
}

func (e *Engine) now() time.Time {
	if e.Now == nil {
		return time.Now()
	}
	return e.Now()
}

func (e *Engine) poll() time.Duration        { return cmp.Or(e.Poll, time.Second) }
func (e *Engine) stepTimeout() time.Duration { return cmp.Or(e.StepTimeout, 30*time.Second) }
func (e *Engine) ipTimeout() time.Duration   { return cmp.Or(e.IPTimeout, time.Minute) }

// Snapshot returns the cached state.
func (e *Engine) Snapshot() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := Snapshot{ExitIP: e.exitIP, ForwardedPort: e.port, CycleInProgress: e.cycling, LastHandledAnnotation: e.handled}
	if e.last != nil {
		c := *e.last
		s.LastCycle = &c
	}
	return s
}

// Refresh reads the exit IP and forwarded port from gluetun into the cache. A positive staticPort
// replaces gluetun's port. When gluetun errors the previous value is kept.
func (e *Engine) Refresh(ctx context.Context, staticPort int32) {
	ip, ipErr := bounded(ctx, e.stepTimeout(), e.G.PublicIP)
	port, portErr := staticPort, error(nil)
	if staticPort <= 0 {
		port, portErr = bounded(ctx, e.stepTimeout(), e.G.ForwardedPort)
	}

	e.mu.Lock()
	e.staticPort = staticPort
	if ipErr == nil {
		e.exitIP = ip
	}
	if portErr == nil {
		e.port = port
	}
	e.mu.Unlock()

	if err := errors.Join(ipErr, portErr); err != nil {
		slog.WarnContext(ctx, "refreshing the egress cache from gluetun failed; keeping the previous values", "error", err)
	}
}

// StartCycle starts a VPN cycle in its own goroutine, detached from the caller, unless one is
// already running (CycleInProgress) or the cooldown is active (CooldownActive). When it refuses,
// retryAfter is the wait in whole seconds, rounded up.
func (e *Engine) StartCycle(trigger string) (accepted bool, reason string, retryAfter time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.startLocked(trigger)
}

func (e *Engine) startLocked(trigger string) (bool, string, time.Duration) {
	now := e.now()
	switch {
	case e.healing: // a self-heal is restarting gluetun; a cycle must not interleave with it
		return false, ReasonCycleInProgress, time.Second
	case e.cycling:
		return false, ReasonCycleInProgress, wholeSeconds(e.cycleEnds.Sub(now))
	case now.Before(e.cooldownUntil):
		return false, ReasonCooldownActive, wholeSeconds(e.cooldownUntil.Sub(now))
	}
	e.cycling = true
	e.cycleEnds = now.Add(e.Deadline)
	go e.run(trigger, e.exitIP)
	return true, "", 0
}

// run executes one cycle and records its outcome. It is the cycle goroutine's whole life and ends
// at the latest when Deadline expires.
func (e *Engine) run(trigger, oldIP string) {
	ctx, cancel := context.WithTimeout(context.Background(), e.Deadline)
	defer cancel()

	reason, newIP, err := e.cycle(ctx, oldIP)
	if err != nil {
		slog.WarnContext(ctx, "VPN cycle failed", "trigger", trigger, "reason", reason, "error", err)
	}

	e.mu.Lock()
	staticPort := e.staticPort
	e.mu.Unlock()
	e.Refresh(context.WithoutCancel(ctx), staticPort)

	e.mu.Lock()
	defer e.mu.Unlock()
	e.last = &Cycle{Reason: reason, OldExitIP: oldIP, NewExitIP: newIP, Trigger: trigger, FinishedAt: e.now().Truncate(time.Second)}
	e.cycling = false
}

// cycle stops gluetun, starts it again and waits for the new exit IP. From the moment PUT stopped
// is sent the cooldown is armed and a PUT running is deferred, so every way out tries to leave
// gluetun running. err explains a Timeout or GluetunError.
func (e *Engine) cycle(ctx context.Context, oldIP string) (reason, newIP string, err error) {
	e.mu.Lock()
	e.cooldownUntil = e.now().Add(e.Cooldown)
	e.mu.Unlock()
	defer e.restart(ctx)

	if err := e.put(ctx, statusStopped); err != nil {
		return failure(err), "", err
	}
	if err := e.waitStatus(ctx, statusStopped); err != nil {
		return failure(err), "", err
	}
	if err := e.put(ctx, statusRunning); err != nil {
		return failure(err), "", err
	}
	if err := e.waitStatus(ctx, statusRunning); err != nil {
		return failure(err), "", err
	}

	ip, ok := e.waitIP(ctx)
	switch {
	case !ok && ctx.Err() != nil:
		return ReasonTimeout, "", ctx.Err()
	case !ok:
		return ReasonEmptyIP, "", nil
	case ip == oldIP:
		return ReasonIPUnchanged, ip, nil
	default:
		return ReasonSucceeded, ip, nil
	}
}

// restart is the deferred PUT running. It uses a context that outlives the cycle's deadline.
func (e *Engine) restart(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), restoreTimeout)
	defer cancel()
	if err := e.G.SetVPNStatus(ctx, statusRunning); err != nil {
		slog.WarnContext(ctx, "restarting gluetun after a VPN cycle failed", "error", err)
	}
}

func (e *Engine) put(ctx context.Context, status string) error {
	ctx, cancel := context.WithTimeout(ctx, e.stepTimeout())
	defer cancel()
	return e.G.SetVPNStatus(ctx, status)
}

// waitStatus polls until gluetun reports want. It returns the context error when StepTimeout or
// the deadline runs out, and gluetun's error when a read fails.
func (e *Engine) waitStatus(ctx context.Context, want string) error {
	ctx, cancel := context.WithTimeout(ctx, e.stepTimeout())
	defer cancel()
	for {
		got, err := e.G.VPNStatus(ctx)
		if err == nil && got == want {
			return nil
		}
		if err != nil && ctx.Err() == nil {
			return err
		}
		if err := sleep(ctx, e.poll()); err != nil {
			return err
		}
	}
}

// waitIP polls until gluetun reports a non-empty public IP, or IPTimeout or the deadline runs out.
// A failed read counts as not yet known.
func (e *Engine) waitIP(ctx context.Context) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, e.ipTimeout())
	defer cancel()
	for {
		if ip, err := bounded(ctx, e.stepTimeout(), e.G.PublicIP); err == nil && ip != "" {
			return ip, true
		}
		if sleep(ctx, e.poll()) != nil {
			return "", false
		}
	}
}

// SelfHeal sends PUT running when no cycle is running and gluetun reports stopped, for example
// after an interrupted cycle or a crashed restart.
func (e *Engine) SelfHeal(ctx context.Context) {
	e.mu.Lock()
	if e.cycling || e.healing {
		e.mu.Unlock()
		return
	}
	e.healing = true
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.healing = false
		e.mu.Unlock()
	}()

	status, err := bounded(ctx, e.stepTimeout(), e.G.VPNStatus)
	if err == nil && status == statusStopped {
		err = e.put(ctx, statusRunning)
	}
	if err != nil {
		slog.WarnContext(ctx, "self-healing gluetun failed", "error", err)
	}
}

// HandleAnnotation runs one cycle when requested is non-empty, differs from lastHandled (what the
// operator recorded) and differs from the last value this engine started a cycle for. That
// in-memory value is seeded from lastHandled only while empty, so a restarted agent does not
// repeat a handled request, and an operator that stops writing back never causes a repeat. A value
// refused by a running cycle or the cooldown is not marked handled and runs on a later call.
func (e *Engine) HandleAnnotation(requested, lastHandled string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handled == "" {
		e.handled = lastHandled
	}
	if requested == "" || requested == lastHandled || requested == e.handled {
		return
	}
	if accepted, _, _ := e.startLocked("annotation:" + requested); accepted {
		e.handled = requested
	}
}

// failure maps the error that ended steps 3 and 4 to a cycle reason.
func failure(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return ReasonTimeout
	}
	return ReasonGluetunError
}

// bounded calls f with ctx limited to d.
func bounded[T any](ctx context.Context, d time.Duration, f func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return f(ctx)
}

// sleep waits d, or returns ctx's error when it ends first.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// wholeSeconds rounds d up to whole seconds, at least one.
func wholeSeconds(d time.Duration) time.Duration {
	return max(time.Second, (d+time.Second-1)/time.Second*time.Second)
}
