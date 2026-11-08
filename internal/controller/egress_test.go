package controllers

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/agent"
	"github.com/jacaudi/tunnel-operator/internal/resources"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestElectHolder(t *testing.T) {
	t0 := metav1.NewTime(time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC))
	t1 := metav1.NewTime(t0.Add(time.Minute))
	cand := func(addr string, created metav1.Time, ns, name string) candidate {
		return candidate{address: addr, created: created, namespace: ns, name: name}
	}

	tests := []struct {
		name       string
		current    string
		candidates []candidate
		want       string
	}{
		{
			name:    "the current holder keeps the port while it is a candidate, though a peer is older",
			current: "10.8.0.3",
			candidates: []candidate{
				cand("10.8.0.2", t0, "ns", "old"),
				cand("10.8.0.3", t1, "ns", "young"),
			},
			want: "10.8.0.3",
		},
		{
			name:    "the oldest peer wins when the current holder is gone",
			current: "10.8.0.9",
			candidates: []candidate{
				cand("10.8.0.3", t1, "ns", "young"),
				cand("10.8.0.2", t0, "ns", "old"),
			},
			want: "10.8.0.2",
		},
		{
			name: "the oldest peer wins when there is no current holder",
			candidates: []candidate{
				cand("10.8.0.3", t1, "ns", "young"),
				cand("10.8.0.2", t0, "ns", "old"),
			},
			want: "10.8.0.2",
		},
		{
			name: "a tie on age is broken by the lower name",
			candidates: []candidate{
				cand("10.8.0.2", t0, "ns", "b"),
				cand("10.8.0.3", t0, "ns", "a"),
			},
			want: "10.8.0.3",
		},
		{
			name: "a tie on age and name is broken by the lower namespace",
			candidates: []candidate{
				cand("10.8.0.2", t0, "zeta", "app"),
				cand("10.8.0.3", t0, "alpha", "app"),
			},
			want: "10.8.0.3",
		},
		{
			name:    "no candidates leaves the port unheld, whoever held it",
			current: "10.8.0.2",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := electHolder(tt.current, tt.candidates); got != tt.want {
				t.Errorf("electHolder(%q, %v) = %q, want %q", tt.current, tt.candidates, got, tt.want)
			}
		})
	}
}

// podOwnedPeer is the peer ns/name whose controller is the Pod named ownerName with uid ownerUID.
func podOwnedPeer(ns, name, ownerName string, ownerUID types.UID) v1alpha1.WireguardPeer {
	return v1alpha1.WireguardPeer{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: ns,
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "v1", Kind: "Pod", Name: ownerName, UID: ownerUID, Controller: new(true),
		}},
	}}
}

func egressPod(ns, name string, uid types.UID, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: uid, Labels: labels}}
}

var bothLabels = map[string]string{
	resources.LabelCycle:         resources.CycleAllowedValue,
	resources.LabelForwardedPort: resources.ForwardedPortValue,
}

func TestOwnerOf(t *testing.T) {
	terminating := egressPod("ns", "app", "uid-1", bothLabels)
	terminating.DeletionTimestamp = new(metav1.Now())
	terminating.Finalizers = []string{"test/keep"}

	notAPod := podOwnedPeer("ns", "app", "app", "uid-1")
	notAPod.OwnerReferences[0].Kind = "ReplicaSet"
	notAController := podOwnedPeer("ns", "app", "app", "uid-1")
	notAController.OwnerReferences[0].Controller = nil

	tests := []struct {
		name string
		peer v1alpha1.WireguardPeer
		pod  *corev1.Pod // nil: the pod does not exist
		want ownerInfo
	}{
		{
			name: "name and UID match: verified, and both labels count",
			peer: podOwnedPeer("ns", "app", "app", "uid-1"),
			pod:  egressPod("ns", "app", "uid-1", bothLabels),
			want: ownerInfo{verified: true, cycle: true, forwardedPort: true},
		},
		{
			name: "verified with only the cycle label",
			peer: podOwnedPeer("ns", "app", "app", "uid-1"),
			pod:  egressPod("ns", "app", "uid-1", map[string]string{resources.LabelCycle: resources.CycleAllowedValue}),
			want: ownerInfo{verified: true, cycle: true},
		},
		{
			name: "verified with only the forwarded-port label",
			peer: podOwnedPeer("ns", "app", "app", "uid-1"),
			pod:  egressPod("ns", "app", "uid-1", map[string]string{resources.LabelForwardedPort: resources.ForwardedPortValue}),
			want: ownerInfo{verified: true, forwardedPort: true},
		},
		{
			name: "a label with any other value does not count",
			peer: podOwnedPeer("ns", "app", "app", "uid-1"),
			pod: egressPod("ns", "app", "uid-1", map[string]string{
				resources.LabelCycle: "denied", resources.LabelForwardedPort: "false",
			}),
			want: ownerInfo{verified: true},
		},
		{
			name: "a UID mismatch is not verified and the labels do not count",
			peer: podOwnedPeer("ns", "app", "app", "uid-forged"),
			pod:  egressPod("ns", "app", "uid-1", bothLabels),
			want: ownerInfo{},
		},
		{
			name: "a peer name other than the pod's is not verified, though the owner reference matches the pod",
			peer: podOwnedPeer("ns", "forged", "app", "uid-1"),
			pod:  egressPod("ns", "app", "uid-1", bothLabels),
			want: ownerInfo{},
		},
		{
			name: "a peer named for the pod whose controller names another pod is not verified",
			peer: podOwnedPeer("ns", "app", "other", "uid-1"),
			pod:  egressPod("ns", "app", "uid-1", bothLabels),
			want: ownerInfo{},
		},
		{
			name: "a controller that is not a Pod is not verified",
			peer: notAPod,
			pod:  egressPod("ns", "app", "uid-1", bothLabels),
			want: ownerInfo{},
		},
		{
			name: "an owner reference that is not the controller is not verified",
			peer: notAController,
			pod:  egressPod("ns", "app", "uid-1", bothLabels),
			want: ownerInfo{},
		},
		{
			name: "a peer with no owner is not verified",
			peer: v1alpha1.WireguardPeer{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"}},
			pod:  egressPod("ns", "app", "uid-1", bothLabels),
			want: ownerInfo{},
		},
		{
			name: "a terminating pod is not verified",
			peer: podOwnedPeer("ns", "app", "app", "uid-1"),
			pod:  terminating,
			want: ownerInfo{},
		},
		{
			name: "a missing pod is not verified, and is not an error",
			peer: podOwnedPeer("ns", "app", "app", "uid-1"),
			want: ownerInfo{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := fake.NewClientBuilder()
			if tt.pod != nil {
				b = b.WithObjects(tt.pod)
			}
			got, err := ownerOf(t.Context(), b.Build(), tt.peer)
			if err != nil {
				t.Fatalf("ownerOf() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ownerOf() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDesiredStateCarriesEgress(t *testing.T) {
	wg := &v1alpha1.Wireguard{ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "media"}}
	egress := agent.Egress{
		CycleAllowed:          []string{"10.8.0.2"},
		ForwardedPortPeer:     "10.8.0.3",
		StaticPort:            51413,
		CycleRequestedAt:      "2026-11-08T12:00:00Z",
		LastHandledAnnotation: "2026-11-07T12:00:00Z",
	}

	if got := desiredState(wg, "k", nil, egress).Egress; !reflect.DeepEqual(got, egress) {
		t.Errorf("desiredState().Egress = %+v, want %+v", got, egress)
	}
	if got := desiredState(wg, "k", nil, agent.Egress{}).Egress; !reflect.DeepEqual(got, agent.Egress{}) {
		t.Errorf("desiredState().Egress with no egress = %+v, want the zero value", got)
	}
}

func TestDesiredEgress(t *testing.T) {
	created := func(minutes int) metav1.Time {
		return metav1.NewTime(time.Date(2026, time.November, 8, 12, minutes, 0, 0, time.UTC))
	}
	// peer is an admitted peer, owned by the pod of its own name and uid, holding address.
	peer := func(name, address string, minutes int) v1alpha1.WireguardPeer {
		p := podOwnedPeer("media", name, name, types.UID("uid-"+name))
		p.CreationTimestamp = created(minutes)
		p.Status.Address = address
		return p
	}
	pod := func(name string, labels map[string]string) *corev1.Pod {
		return egressPod("media", name, types.UID("uid-"+name), labels)
	}
	cycle := map[string]string{resources.LabelCycle: resources.CycleAllowedValue}
	fwd := map[string]string{resources.LabelForwardedPort: resources.ForwardedPortValue}

	t.Run("cycle permission is the sorted addresses of the verified peers labelled for it", func(t *testing.T) {
		r := &WireguardReconciler{APIReader: fake.NewClientBuilder().WithObjects(
			pod("a", cycle), pod("b", cycle), pod("c", nil),
		).Build()}
		peers := []v1alpha1.WireguardPeer{peer("b", "10.8.0.10", 0), peer("a", "10.8.0.2", 0), peer("c", "10.8.0.4", 0)}
		got, conds, err := r.desiredEgress(t.Context(), &v1alpha1.Wireguard{}, peers, "")
		if err != nil {
			t.Fatalf("desiredEgress() error = %v", err)
		}
		if want := []string{"10.8.0.10", "10.8.0.2"}; !slices.Equal(got.CycleAllowed, want) {
			t.Errorf("CycleAllowed = %v, want %v", got.CycleAllowed, want)
		}
		// The agent matches a caller's host against status.address, so the entry must be that same bare address.
		for _, a := range got.CycleAllowed {
			if _, err := netip.ParseAddr(a); err != nil {
				t.Errorf("CycleAllowed entry %q is not a bare address: %v", a, err)
			}
		}
		if got.ForwardedPortPeer != "" || len(conds) != 0 {
			t.Errorf("no peer claims the port, got holder %q and conditions %v", got.ForwardedPortPeer, conds)
		}
	})

	t.Run("a forged peer gains no permission and is not a candidate for the port", func(t *testing.T) {
		r := &WireguardReconciler{APIReader: fake.NewClientBuilder().WithObjects(
			pod("victim", map[string]string{resources.LabelCycle: resources.CycleAllowedValue, resources.LabelForwardedPort: resources.ForwardedPortValue}),
		).Build()}
		forged := podOwnedPeer("media", "forged", "victim", "uid-victim")
		forged.Status.Address = "10.8.0.5"
		got, conds, err := r.desiredEgress(t.Context(), &v1alpha1.Wireguard{}, []v1alpha1.WireguardPeer{forged}, "")
		if err != nil {
			t.Fatalf("desiredEgress() error = %v", err)
		}
		if len(got.CycleAllowed) != 0 || got.ForwardedPortPeer != "" || len(conds) != 0 {
			t.Errorf("a forged peer gained egress: %+v, conditions %v", got, conds)
		}
	})

	t.Run("the older claimant holds the port and the other is HeldByAnotherPeer", func(t *testing.T) {
		r := &WireguardReconciler{APIReader: fake.NewClientBuilder().WithObjects(pod("old", fwd), pod("young", fwd)).Build()}
		peers := []v1alpha1.WireguardPeer{peer("young", "10.8.0.3", 5), peer("old", "10.8.0.2", 0)}
		got, conds, err := r.desiredEgress(t.Context(), &v1alpha1.Wireguard{}, peers, "")
		if err != nil {
			t.Fatalf("desiredEgress() error = %v", err)
		}
		if got.ForwardedPortPeer != "10.8.0.2" {
			t.Errorf("ForwardedPortPeer = %q, want 10.8.0.2", got.ForwardedPortPeer)
		}
		want := map[string]string{"media/old": ReasonHeld, "media/young": ReasonHeldByAnotherPeer}
		if !reflect.DeepEqual(conds, want) {
			t.Errorf("conditions = %v, want %v", conds, want)
		}
	})

	t.Run("the current holder keeps the port over an older claimant", func(t *testing.T) {
		r := &WireguardReconciler{APIReader: fake.NewClientBuilder().WithObjects(pod("old", fwd), pod("young", fwd)).Build()}
		peers := []v1alpha1.WireguardPeer{peer("young", "10.8.0.3", 5), peer("old", "10.8.0.2", 0)}
		got, _, err := r.desiredEgress(t.Context(), &v1alpha1.Wireguard{}, peers, "10.8.0.3")
		if err != nil {
			t.Fatalf("desiredEgress() error = %v", err)
		}
		if got.ForwardedPortPeer != "10.8.0.3" {
			t.Errorf("ForwardedPortPeer = %q, want the current holder 10.8.0.3", got.ForwardedPortPeer)
		}
	})

	t.Run("static port, annotation and last handled annotation come from the spec, annotation and status", func(t *testing.T) {
		r := &WireguardReconciler{APIReader: fake.NewClientBuilder().Build()}
		wg := &v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{resources.AnnotationCycleRequestedAt: "now"}},
			Spec:       v1alpha1.WireguardSpec{Gluetun: v1alpha1.GluetunSpec{PortForwarding: &v1alpha1.PortForwardingSpec{StaticPort: 51413}}},
			Status:     v1alpha1.WireguardStatus{Egress: &v1alpha1.EgressStatus{LastHandledAnnotation: "before"}},
		}
		got, _, err := r.desiredEgress(t.Context(), wg, nil, "")
		if err != nil {
			t.Fatalf("desiredEgress() error = %v", err)
		}
		want := agent.Egress{StaticPort: 51413, CycleRequestedAt: "now", LastHandledAnnotation: "before"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("desiredEgress() = %+v, want %+v", got, want)
		}
	})

	t.Run("a pod read that fails is an error, not an unverified peer", func(t *testing.T) {
		r := &WireguardReconciler{APIReader: newFakeClient(t, interceptor.Funcs{Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errors.New("apiserver unreachable")
		}})}
		if _, _, err := r.desiredEgress(t.Context(), &v1alpha1.Wireguard{}, []v1alpha1.WireguardPeer{peer("a", "10.8.0.2", 0)}, ""); err == nil {
			t.Error("desiredEgress() error = nil, want the read failure")
		}
	})
}

func TestSyncPortForwarding(t *testing.T) {
	mk := func(name string, conds ...metav1.Condition) v1alpha1.WireguardPeer {
		p := v1alpha1.WireguardPeer{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "media", Generation: 3}}
		p.Status.Conditions = conds
		return p
	}
	stale := metav1.Condition{Type: ConditionPortForwarding, Status: metav1.ConditionTrue, Reason: ReasonHeld, Message: "stale", ObservedGeneration: 3}
	ready := metav1.Condition{Type: ConditionReady, Status: metav1.ConditionTrue, Reason: "Active", ObservedGeneration: 3}
	holder, other, released := mk("holder", ready), mk("other", ready), mk("released", ready, stale)

	var writes []string
	c := newFakeClient(t, interceptor.Funcs{SubResourceUpdate: func(ctx context.Context, cl client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
		writes = append(writes, obj.GetName())
		return cl.SubResource(sub).Update(ctx, obj, opts...)
	}}, &holder, &other, &released)
	r := &WireguardReconciler{Client: c}

	peers := []v1alpha1.WireguardPeer{holder, other, released}
	conds := map[string]string{"media/holder": ReasonHeld, "media/other": ReasonHeldByAnotherPeer}
	if err := r.syncPortForwarding(t.Context(), peers, conds); err != nil {
		t.Fatalf("syncPortForwarding() error = %v", err)
	}

	got := func(name string) *metav1.Condition {
		p := &v1alpha1.WireguardPeer{}
		if err := c.Get(t.Context(), types.NamespacedName{Namespace: "media", Name: name}, p); err != nil {
			t.Fatalf("get %s: %v", name, err)
		}
		return meta.FindStatusCondition(p.Status.Conditions, ConditionPortForwarding)
	}
	if c := got("holder"); c == nil || c.Status != metav1.ConditionTrue || c.Reason != ReasonHeld || c.ObservedGeneration != 3 {
		t.Errorf("holder's PortForwarding = %+v, want True/Held at generation 3", c)
	}
	if c := got("other"); c == nil || c.Status != metav1.ConditionFalse || c.Reason != ReasonHeldByAnotherPeer || !strings.Contains(c.Message, "media/holder") {
		t.Errorf("other's PortForwarding = %+v, want False/HeldByAnotherPeer naming media/holder", c)
	}
	if c := got("released"); c != nil {
		t.Errorf("a peer no longer eligible keeps PortForwarding = %+v, want none", c)
	}
	if want := []string{"holder", "other", "released"}; !slices.Equal(writes, want) {
		t.Errorf("first pass wrote %v, want %v", writes, want)
	}

	// A second pass over the stored peers finds nothing to change and writes nothing.
	writes = nil
	stored := &v1alpha1.WireguardPeerList{}
	if err := c.List(t.Context(), stored); err != nil {
		t.Fatalf("list: %v", err)
	}
	if err := r.syncPortForwarding(t.Context(), stored.Items, conds); err != nil {
		t.Fatalf("syncPortForwarding() second pass error = %v", err)
	}
	if len(writes) != 0 {
		t.Errorf("an unchanged pass wrote %v, want no writes", writes)
	}
}
