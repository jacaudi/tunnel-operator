package controllers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/agent/egress"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestHTTPEgressReaderParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/egress" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"exitIP": "203.0.113.9",
			"forwardedPort": 51413,
			"lastCycle": {"reason": "Succeeded", "oldExitIP": "203.0.113.8", "newExitIP": "203.0.113.9", "trigger": "api:10.8.0.2", "finishedAt": "2026-11-08T12:00:00Z"},
			"cycleInProgress": true,
			"lastHandledAnnotation": "req-1"
		}`))
	}))
	t.Cleanup(srv.Close)

	got, err := HTTPEgressReader{Timeout: time.Second, baseURL: srv.URL}.Read(t.Context(), "192.0.2.1")
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	want := EgressReport{
		ExitIP:        "203.0.113.9",
		ForwardedPort: 51413,
		LastCycle: &v1alpha1.CycleResult{
			Reason: "Succeeded", OldExitIP: "203.0.113.8", NewExitIP: "203.0.113.9", Trigger: "api:10.8.0.2",
			FinishedAt: metav1.NewTime(time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)),
		},
		CycleInProgress:       true,
		LastHandledAnnotation: "req-1",
	}
	if !equality.Semantic.DeepEqual(got, want) {
		t.Errorf("Read() = %+v (lastCycle %+v), want %+v (lastCycle %+v)", got, got.LastCycle, want, want.LastCycle)
	}
}

func TestHTTPEgressReaderErrors(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"a non-200 status, whatever the body", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"exitIP": "203.0.113.9"}`))
		}},
		{"a body that is not JSON", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			t.Cleanup(srv.Close)

			if _, err := (HTTPEgressReader{Timeout: time.Second, baseURL: srv.URL}).Read(t.Context(), "192.0.2.1"); err == nil {
				t.Error("Read() error = nil, want an error")
			}
		})
	}
}

func TestHTTPEgressReaderTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs first, so no handler is left blocked when srv closes

	start := time.Now()
	_, err := HTTPEgressReader{Timeout: 50 * time.Millisecond, baseURL: srv.URL}.Read(t.Context(), "192.0.2.1")

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Read() error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Read() took %v, want it to give up near the 50ms timeout", elapsed)
	}
}

// stubGluetun is the engine's view of gluetun: PUT running swaps the exit IP, as a restart does.
type stubGluetun struct {
	mu     sync.Mutex
	status string
	ip     string
}

func (g *stubGluetun) PublicIP(context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ip, nil
}

func (g *stubGluetun) ForwardedPort(context.Context) (int32, error) { return 51413, nil }

func (g *stubGluetun) VPNStatus(context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.status, nil
}

func (g *stubGluetun) SetVPNStatus(_ context.Context, status string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.status = status
	if status == "running" {
		g.ip = "203.0.113.9"
	}
	return nil
}

// TestHTTPEgressReaderDecodesTheAgentHandler pins the decoder to the bytes the agent's real GET /egress
// handler writes, so a renamed JSON key on either side fails here instead of silently blanking a status.
func TestHTTPEgressReaderDecodesTheAgentHandler(t *testing.T) {
	engine := &egress.Engine{
		G:           &stubGluetun{status: "running", ip: "203.0.113.8"},
		Poll:        time.Millisecond,
		Deadline:    10 * time.Second,
		Cooldown:    time.Minute,
		StepTimeout: 5 * time.Second,
		IPTimeout:   5 * time.Second,
	}
	engine.Refresh(t.Context(), 0)
	engine.HandleAnnotation("req-1", "")
	deadline := time.Now().Add(5 * time.Second)
	for engine.Snapshot().LastCycle == nil {
		if time.Now().After(deadline) {
			t.Fatal("the engine's cycle did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	snap := engine.Snapshot()
	srv := httptest.NewServer(egress.StatusHandler(engine))
	t.Cleanup(srv.Close)

	got, err := HTTPEgressReader{Timeout: time.Second, baseURL: srv.URL}.Read(t.Context(), "192.0.2.1")
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	want := EgressReport{
		ExitIP:        "203.0.113.9",
		ForwardedPort: 51413,
		LastCycle: &v1alpha1.CycleResult{
			Reason: "Succeeded", OldExitIP: "203.0.113.8", NewExitIP: "203.0.113.9", Trigger: "annotation:req-1",
			FinishedAt: metav1.NewTime(snap.LastCycle.FinishedAt),
		},
		LastHandledAnnotation: "req-1",
	}
	if !equality.Semantic.DeepEqual(got, want) {
		t.Errorf("Read() = %+v (lastCycle %+v), want %+v (lastCycle %+v)", got, got.LastCycle, want, want.LastCycle)
	}
	if got.LastCycle.FinishedAt.IsZero() {
		t.Error("lastCycle.finishedAt did not decode")
	}
}

func TestGatewayPod(t *testing.T) {
	labels := map[string]string{"app": "wireguard", "instance": "vpn"}
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "vpn-dep", Namespace: "gw"},
		Spec:       appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: labels}},
	}
	pod := func(name string, ready, terminating bool) *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "gw", Labels: labels}}
		p.Status.PodIP = "10.1.0." + name
		if ready {
			p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		}
		if terminating {
			// A fake client drops a deleted pod unless a finalizer holds it.
			p.Finalizers = []string{"test/hold"}
		}
		return p
	}
	stranger := pod("9", true, false)
	stranger.Labels = map[string]string{"app": "other"}
	elsewhere := pod("8", true, false)
	elsewhere.Namespace = "other"

	tests := []struct {
		name string
		pods []*corev1.Pod
		want string // the chosen pod's name, "" for none
	}{
		{"one Ready pod", []*corev1.Pod{pod("1", true, false)}, "1"},
		{"no pods", nil, ""},
		{"two Ready pods, as during a rollout", []*corev1.Pod{pod("1", true, false), pod("2", true, false)}, ""},
		{"a terminating pod", []*corev1.Pod{pod("1", true, true)}, ""},
		{"a Ready pod beside a terminating one", []*corev1.Pod{pod("1", true, true), pod("2", true, false)}, "2"},
		{"a pod that is not Ready", []*corev1.Pod{pod("1", false, false)}, ""},
		{"pods the selector or the namespace excludes", []*corev1.Pod{pod("1", true, false), stranger, elsewhere}, "1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := fake.NewClientBuilder()
			for _, p := range tt.pods {
				b = b.WithObjects(p)
			}
			c := b.Build()
			for _, p := range tt.pods {
				if len(p.Finalizers) > 0 {
					if err := c.Delete(t.Context(), p); err != nil {
						t.Fatalf("delete pod %s: %v", p.Name, err)
					}
				}
			}

			got, ok, err := gatewayPod(t.Context(), c, dep)
			if err != nil {
				t.Fatalf("gatewayPod() error = %v", err)
			}
			if ok != (tt.want != "") {
				t.Fatalf("gatewayPod() ok = %v, want %v", ok, tt.want != "")
			}
			if ok && got.Name != tt.want {
				t.Errorf("gatewayPod() = %s, want %s", got.Name, tt.want)
			}
		})
	}

	t.Run("a failed list is an error", func(t *testing.T) {
		c := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errors.New("apiserver unreachable")
		}}).Build()
		if _, _, err := gatewayPod(t.Context(), c, dep); err == nil {
			t.Error("gatewayPod() error = nil, want the list failure")
		}
	})
}

func TestHTTPEgressReaderDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/egress", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) })
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, _ *http.Request) {
		followed.Add(1)
		_, _ = w.Write([]byte(`{"exitIP": "203.0.113.9"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if _, err := (HTTPEgressReader{Timeout: time.Second, baseURL: srv.URL}).Read(t.Context(), "192.0.2.1"); err == nil {
		t.Error("Read() error = nil, want a 302 rejected as a non-200")
	}
	if n := followed.Load(); n != 0 {
		t.Errorf("the redirect target was requested %d times, want 0", n)
	}
}
