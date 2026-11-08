package controllers

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/agent/egress"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestEgressAPIURL(t *testing.T) {
	tests := []struct {
		name     string
		peerCIDR string
		want     string
	}{
		{"the default peer CIDR", "", "http://10.8.0.1:8081"},
		{"a configured peer CIDR", "192.168.50.0/28", "http://192.168.50.1:8081"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := egressAPIURL(&v1alpha1.Wireguard{Spec: v1alpha1.WireguardSpec{PeerCIDR: tt.peerCIDR}})
			if err != nil {
				t.Fatalf("egressAPIURL() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("egressAPIURL() = %q, want %q", got, tt.want)
			}
		})
	}

	if _, err := egressAPIURL(&v1alpha1.Wireguard{Spec: v1alpha1.WireguardSpec{PeerCIDR: "fd00::/64"}}); err == nil {
		t.Error("egressAPIURL() error = nil for an IPv6 peer CIDR, want an error")
	}
}

func TestHeldPeer(t *testing.T) {
	tests := []struct {
		name    string
		reasons map[string]string
		want    string
	}{
		{"no candidates", nil, ""},
		{"the Held peer", map[string]string{"media/a": ReasonHeldByAnotherPeer, "media/b": ReasonHeld}, "media/b"},
		{"candidates and no holder", map[string]string{"media/a": ReasonHeldByAnotherPeer}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := heldPeer(tt.reasons); got != tt.want {
				t.Errorf("heldPeer() = %q, want %q", got, tt.want)
			}
		})
	}
}

// statusReconciler returns a reconciler over a fake apiserver holding a Wireguard with status, and a
// func returning the Wireguard it last sent through Status().Update, as sent: before the apiserver's
// JSON encoding could hide a sub-second timestamp.
func statusReconciler(t *testing.T, status v1alpha1.WireguardStatus) (*WireguardReconciler, *v1alpha1.Wireguard, func() *v1alpha1.Wireguard) {
	t.Helper()
	s := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add v1alpha1 to the scheme: %v", err)
	}
	wg := &v1alpha1.Wireguard{ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "gw", Generation: 3}, Status: status}
	var sent *v1alpha1.Wireguard
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(wg).WithStatusSubresource(&v1alpha1.Wireguard{}).
		WithInterceptorFuncs(interceptor.Funcs{SubResourceUpdate: func(ctx context.Context, cl client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			sent = obj.DeepCopyObject().(*v1alpha1.Wireguard)
			return cl.SubResource(sub).Update(ctx, obj, opts...)
		}}).Build()
	return &WireguardReconciler{Client: c}, wg, func() *v1alpha1.Wireguard { return sent }
}

func TestUpdateStatusEgress(t *testing.T) {
	finished := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	cycle := func(reason string, at time.Time) *v1alpha1.CycleResult {
		return &v1alpha1.CycleResult{Reason: reason, OldExitIP: "203.0.113.8", NewExitIP: "203.0.113.9", Trigger: "api:10.8.0.2", FinishedAt: metav1.NewTime(at)}
	}
	stored := &v1alpha1.EgressStatus{ExitIP: "198.51.100.1", ForwardedPort: 1111, ForwardedPortPeer: "media/old", LastHandledAnnotation: "old", LastCycle: cycle("Succeeded", finished.Add(-time.Hour))}
	const storedAPI = "http://10.8.0.1:8081"

	tests := []struct {
		name       string
		stored     *v1alpha1.EgressStatus
		egress     *egressUpdate
		want       *v1alpha1.EgressStatus
		wantAPI    string
		wantCycled string // "<status>/<reason>", "" when the condition is absent
	}{
		{
			name:    "a nil egress changes nothing under status.egress or status.egressAPI",
			stored:  stored,
			egress:  nil,
			want:    stored,
			wantAPI: storedAPI,
		},
		{
			name:       "no report writes the API URL and the holder and keeps every other field",
			stored:     stored,
			egress:     &egressUpdate{EgressAPI: "http://10.9.0.1:8081", ForwardedPortPeer: "media/new"},
			want:       &v1alpha1.EgressStatus{ExitIP: "198.51.100.1", ForwardedPort: 1111, ForwardedPortPeer: "media/new", LastHandledAnnotation: "old", LastCycle: stored.LastCycle},
			wantAPI:    "http://10.9.0.1:8081",
			wantCycled: "True/Succeeded",
		},
		{
			name:   "a report writes the exit IP, port and handled annotation and Cycled follows its cycle",
			stored: stored,
			egress: &egressUpdate{EgressAPI: storedAPI, ForwardedPortPeer: "media/old", Report: &EgressReport{
				ExitIP: "203.0.113.9", ForwardedPort: 51413, LastHandledAnnotation: "req-2", LastCycle: cycle("Succeeded", finished),
			}},
			want:       &v1alpha1.EgressStatus{ExitIP: "203.0.113.9", ForwardedPort: 51413, ForwardedPortPeer: "media/old", LastHandledAnnotation: "req-2", LastCycle: cycle("Succeeded", finished)},
			wantAPI:    storedAPI,
			wantCycled: "True/Succeeded",
		},
		{
			name:   "an IPUnchanged cycle is Cycled=False",
			stored: nil,
			egress: &egressUpdate{EgressAPI: storedAPI, Report: &EgressReport{ExitIP: "203.0.113.9", LastCycle: cycle("IPUnchanged", finished)}},
			want:   &v1alpha1.EgressStatus{ExitIP: "203.0.113.9", LastCycle: cycle("IPUnchanged", finished)}, wantAPI: storedAPI,
			wantCycled: "False/IPUnchanged",
		},
		{
			name:       "a report without a cycle keeps the stored one",
			stored:     stored,
			egress:     &egressUpdate{EgressAPI: storedAPI, ForwardedPortPeer: "media/old", Report: &EgressReport{ExitIP: "203.0.113.9"}},
			want:       &v1alpha1.EgressStatus{ExitIP: "203.0.113.9", ForwardedPortPeer: "media/old", LastCycle: stored.LastCycle},
			wantAPI:    storedAPI,
			wantCycled: "True/Succeeded",
		},
		{
			name:   "a cycle without finishedAt never reaches the apiserver",
			stored: stored,
			egress: &egressUpdate{EgressAPI: storedAPI, ForwardedPortPeer: "media/old", Report: &EgressReport{
				ExitIP: "203.0.113.9", LastCycle: &v1alpha1.CycleResult{Reason: "Succeeded", Trigger: "api:10.8.0.2"},
			}},
			want:       &v1alpha1.EgressStatus{ExitIP: "203.0.113.9", ForwardedPortPeer: "media/old", LastCycle: stored.LastCycle},
			wantAPI:    storedAPI,
			wantCycled: "True/Succeeded",
		},
		{
			name:   "finishedAt is stored with second precision",
			stored: nil,
			egress: &egressUpdate{EgressAPI: storedAPI, Report: &EgressReport{ExitIP: "203.0.113.9", LastCycle: cycle("Succeeded", finished.Add(500*time.Millisecond))}},
			want:   &v1alpha1.EgressStatus{ExitIP: "203.0.113.9", LastCycle: cycle("Succeeded", finished)}, wantAPI: storedAPI,
			wantCycled: "True/Succeeded",
		},
		{
			name:    "nothing known leaves status.egress absent",
			stored:  nil,
			egress:  &egressUpdate{EgressAPI: storedAPI},
			want:    nil,
			wantAPI: storedAPI,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, wg, sent := statusReconciler(t, v1alpha1.WireguardStatus{Egress: tt.stored.DeepCopy(), EgressAPI: storedAPI})
			ready := metav1.Condition{Type: ConditionReady, Status: metav1.ConditionTrue, Reason: "Active", Message: "VPN is active!"}

			if err := r.updateStatus(t.Context(), wg, ready, nil, tt.egress); err != nil {
				t.Fatalf("updateStatus() error = %v", err)
			}

			got := sent()
			if got == nil {
				t.Fatal("updateStatus() sent no status update")
			}
			if !equality.Semantic.DeepEqual(got.Status.Egress, tt.want) {
				t.Errorf("status.egress = %+v (lastCycle %+v), want %+v (lastCycle %+v)", got.Status.Egress, lastCycleOf(got.Status.Egress), tt.want, lastCycleOf(tt.want))
			}
			if got.Status.EgressAPI != tt.wantAPI {
				t.Errorf("status.egressAPI = %q, want %q", got.Status.EgressAPI, tt.wantAPI)
			}
			var gotCycled string
			if c := meta.FindStatusCondition(got.Status.Conditions, ConditionCycled); c != nil {
				gotCycled = string(c.Status) + "/" + c.Reason
			}
			if gotCycled != tt.wantCycled {
				t.Errorf("Cycled = %q, want %q", gotCycled, tt.wantCycled)
			}
			if got.Status.Status != v1alpha1.Ready {
				t.Errorf("status.status = %q, want Ready: the egress fields ride in the Ready write", got.Status.Status)
			}
		})
	}
}

func lastCycleOf(e *v1alpha1.EgressStatus) *v1alpha1.CycleResult {
	if e == nil {
		return nil
	}
	return e.LastCycle
}

// TestCycledConditionIsBounded pins what the agent can make the Cycled condition carry. The CRD rejects a
// condition whose reason is not an identifier or whose message exceeds 32768 characters, and a rejected
// status write fails every later pass, because the agent keeps reporting the same cycle. The trigger is
// "annotation:" plus a raw annotation value of up to 256 KiB.
func TestCycledConditionIsBounded(t *testing.T) {
	crdReason := regexp.MustCompile(`^[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?$`)
	finished := metav1.NewTime(time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC))
	tests := []struct {
		name       string
		cycle      v1alpha1.CycleResult
		wantStatus metav1.ConditionStatus
		wantReason string
	}{
		{"a known reason is kept", v1alpha1.CycleResult{Reason: egress.ReasonTimeout, Trigger: "api:10.8.0.2", FinishedAt: finished}, metav1.ConditionFalse, egress.ReasonTimeout},
		{"an unknown reason becomes Unknown", v1alpha1.CycleResult{Reason: "not a reason!", Trigger: "api:10.8.0.2", FinishedAt: finished}, metav1.ConditionFalse, "Unknown"},
		{"an empty reason becomes Unknown", v1alpha1.CycleResult{Trigger: "api:10.8.0.2", FinishedAt: finished}, metav1.ConditionFalse, "Unknown"},
		{"a 40 KB trigger stays within the message limit", v1alpha1.CycleResult{Reason: egress.ReasonSucceeded, Trigger: "annotation:" + strings.Repeat("x", 40<<10), FinishedAt: finished}, metav1.ConditionTrue, egress.ReasonSucceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var st v1alpha1.WireguardStatus

			applyEgress(&st, 1, &egressUpdate{Report: &EgressReport{LastCycle: &tt.cycle}})

			cond := meta.FindStatusCondition(st.Conditions, ConditionCycled)
			if cond == nil {
				t.Fatal("no Cycled condition")
			}
			if cond.Status != tt.wantStatus || cond.Reason != tt.wantReason {
				t.Errorf("Cycled = %s/%s, want %s/%s", cond.Status, cond.Reason, tt.wantStatus, tt.wantReason)
			}
			if !crdReason.MatchString(cond.Reason) {
				t.Errorf("Cycled reason %q does not match the CRD pattern", cond.Reason)
			}
			if n := len(cond.Message); n > 32768 {
				t.Errorf("Cycled message is %d characters, want at most 32768", n)
			}
			if got := st.Egress.LastCycle.Trigger; got != tt.cycle.Trigger {
				t.Errorf("status.egress.lastCycle.trigger was altered (%d characters, want %d): the CRD sets no limit on it", len(got), len(tt.cycle.Trigger))
			}
		})
	}
}
