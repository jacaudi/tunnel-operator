package sidecar

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
)

const testPublicKey = "gVKb6hS9AgvO7m3tTfnqE4qD8YHyQq5eVYfR3l2ePH0="

func testConfig() Config {
	return Config{Wireguard: "vpn", PodName: "app-1", PodNamespace: "media", PodUID: "uid-1"}
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add v1alpha1 to scheme: %v", err)
	}
	return s
}

// podOwner returns a Pod owner reference with the given controller flag.
func podOwner(uid types.UID, controller *bool) metav1.OwnerReference {
	return metav1.OwnerReference{APIVersion: "v1", Kind: "Pod", Name: "app-1", UID: uid, Controller: controller}
}

// peerWith returns desiredPeer's peer with mutate applied.
func peerWith(mutate func(*v1alpha1.WireguardPeer)) *v1alpha1.WireguardPeer {
	p := desiredPeer(testConfig(), testPublicKey)
	mutate(p)
	return p
}

// calls counts and records the writes a fake client receives.
type calls struct {
	creates int
	deletes int
	deleted []*ctrlclient.DeleteOptions
}

// newClient returns a fake client seeded with objs, whose Create and Delete are recorded in the
// returned calls and then delegated to the fake; a non-nil create may fail the Create first.
func newClient(t *testing.T, create func() error, objs ...ctrlclient.Object) (ctrlclient.Client, *calls) {
	t.Helper()
	c := &calls{}
	return fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, cl ctrlclient.WithWatch, obj ctrlclient.Object, opts ...ctrlclient.CreateOption) error {
			c.creates++
			if create != nil {
				if err := create(); err != nil {
					return err
				}
			}
			return cl.Create(ctx, obj, opts...)
		},
		Delete: func(ctx context.Context, cl ctrlclient.WithWatch, obj ctrlclient.Object, opts ...ctrlclient.DeleteOption) error {
			c.deletes++
			c.deleted = append(c.deleted, (&ctrlclient.DeleteOptions{}).ApplyOptions(opts))
			return cl.Delete(ctx, obj, opts...)
		},
	}).Build(), c
}

func getPeer(t *testing.T, c ctrlclient.Client) *v1alpha1.WireguardPeer {
	t.Helper()
	got := &v1alpha1.WireguardPeer{}
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "media", Name: "app-1"}, got); err != nil {
		t.Fatalf("get stored peer: %v", err)
	}
	return got
}

func TestDesiredPeer(t *testing.T) {
	got := desiredPeer(testConfig(), testPublicKey)

	if got.Name != "app-1" || got.Namespace != "media" {
		t.Errorf("peer is %s/%s, want media/app-1", got.Namespace, got.Name)
	}
	if want := (v1alpha1.WireguardPeerSpec{PublicKey: testPublicKey, WireguardRef: "vpn"}); got.Spec != want {
		t.Errorf("spec = %+v, want %+v", got.Spec, want)
	}
	if len(got.OwnerReferences) != 1 {
		t.Fatalf("owner references = %+v, want exactly one", got.OwnerReferences)
	}
	ref := got.OwnerReferences[0]
	if ref.APIVersion != "v1" || ref.Kind != "Pod" || ref.Name != "app-1" || ref.UID != "uid-1" {
		t.Errorf("owner reference = %+v, want v1 Pod app-1 uid-1", ref)
	}
	if ref.Controller == nil || !*ref.Controller {
		t.Errorf("owner reference Controller = %v, want true", ref.Controller)
	}
	if ref.BlockOwnerDeletion != nil {
		t.Errorf("owner reference BlockOwnerDeletion = %v, want nil", *ref.BlockOwnerDeletion)
	}
}

func TestDesiredPeerNamesTheGatewayNamespace(t *testing.T) {
	cfg := testConfig()
	cfg.WireguardNamespace = "network"

	got := desiredPeer(cfg, testPublicKey)

	if want := (v1alpha1.WireguardPeerSpec{PublicKey: testPublicKey, WireguardRef: "vpn", WireguardNamespace: "network"}); got.Spec != want {
		t.Errorf("spec = %+v, want %+v", got.Spec, want)
	}
	if got.Namespace != "media" {
		t.Errorf("peer namespace = %q, want the pod's own, media", got.Namespace)
	}
}

func TestDecidePeer(t *testing.T) {
	want := desiredPeer(testConfig(), testPublicKey)
	tests := []struct {
		name     string
		existing *v1alpha1.WireguardPeer
		want     peerAction
	}{
		{name: "none", existing: nil, want: actionCreate},
		{name: "this pod's", existing: want, want: actionKeep},
		{
			name: "controlled by another pod",
			existing: peerWith(func(p *v1alpha1.WireguardPeer) {
				p.OwnerReferences = []metav1.OwnerReference{podOwner("uid-old", new(true))}
			}),
			want: actionReplace,
		},
		{
			name:     "this pod, other publicKey",
			existing: peerWith(func(p *v1alpha1.WireguardPeer) { p.Spec.PublicKey = "other" }),
			want:     actionReplace,
		},
		{
			name:     "this pod, other wireguardRef",
			existing: peerWith(func(p *v1alpha1.WireguardPeer) { p.Spec.WireguardRef = "other" }),
			want:     actionReplace,
		},
		{
			name:     "this pod, other wireguardNamespace",
			existing: peerWith(func(p *v1alpha1.WireguardPeer) { p.Spec.WireguardNamespace = "network" }),
			want:     actionReplace,
		},
		{
			name:     "no owner references",
			existing: peerWith(func(p *v1alpha1.WireguardPeer) { p.OwnerReferences = nil }),
			want:     actionRefuse,
		},
		{
			name: "controlled by a ReplicaSet",
			existing: peerWith(func(p *v1alpha1.WireguardPeer) {
				p.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "app", UID: "uid-1", Controller: new(true)}}
			}),
			want: actionRefuse,
		},
		{
			name: "a Pod owner that is not the controller",
			existing: peerWith(func(p *v1alpha1.WireguardPeer) {
				p.OwnerReferences = []metav1.OwnerReference{podOwner("uid-1", nil)}
			}),
			want: actionRefuse,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decidePeer(tt.existing, want); got != tt.want {
				t.Errorf("decidePeer() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEnsurePeerCreates(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	publicKey := priv.PublicKey().String()
	c, _ := newClient(t, nil)

	got, err := ensurePeer(t.Context(), c, c, testConfig(), publicKey)
	if err != nil {
		t.Fatalf("ensurePeer() error = %v", err)
	}
	if got != nil {
		t.Errorf("ensurePeer() = %+v, want nil after a create", got)
	}
	stored, want := getPeer(t, c), desiredPeer(testConfig(), publicKey)
	if stored.Spec != want.Spec {
		t.Errorf("stored spec = %+v, want %+v", stored.Spec, want.Spec)
	}
	if !reflect.DeepEqual(stored.OwnerReferences, want.OwnerReferences) {
		t.Errorf("stored owner references = %+v, want %+v", stored.OwnerReferences, want.OwnerReferences)
	}
}

func TestEnsurePeerKeeps(t *testing.T) {
	c, n := newClient(t, nil, desiredPeer(testConfig(), testPublicKey))

	got, err := ensurePeer(t.Context(), c, c, testConfig(), testPublicKey)
	if err != nil {
		t.Fatalf("ensurePeer() error = %v", err)
	}
	if got == nil || got.Name != "app-1" {
		t.Errorf("ensurePeer() = %+v, want the existing peer", got)
	}
	if n.creates != 0 || n.deletes != 0 {
		t.Errorf("Create called %d times, Delete %d times, want neither", n.creates, n.deletes)
	}
}

func TestEnsurePeerReplacesStale(t *testing.T) {
	stale := peerWith(func(p *v1alpha1.WireguardPeer) {
		p.UID = "stale-uid"
		p.OwnerReferences = []metav1.OwnerReference{podOwner("uid-old", new(true))}
	})
	c, n := newClient(t, nil, stale)

	got, err := ensurePeer(t.Context(), c, c, testConfig(), testPublicKey)
	if err != nil {
		t.Fatalf("ensurePeer() error = %v", err)
	}
	if got != nil {
		t.Errorf("ensurePeer() = %+v, want nil after a replace", got)
	}
	if n.deletes != 1 {
		t.Fatalf("Delete called %d times, want 1", n.deletes)
	}
	if pre := n.deleted[0].Preconditions; pre == nil || pre.UID == nil || *pre.UID != "stale-uid" {
		t.Errorf("Delete preconditions = %+v, want UID stale-uid", pre)
	}
	if ctl := metav1.GetControllerOf(getPeer(t, c)); ctl == nil || ctl.UID != "uid-1" {
		t.Errorf("stored peer controller = %+v, want UID uid-1", ctl)
	}
}

func TestEnsurePeerRefuses(t *testing.T) {
	foreign := peerWith(func(p *v1alpha1.WireguardPeer) { p.OwnerReferences = nil })
	c, n := newClient(t, nil, foreign)

	_, err := ensurePeer(t.Context(), c, c, testConfig(), testPublicKey)
	if err == nil || !strings.Contains(err.Error(), "no Pod controls it") {
		t.Fatalf("ensurePeer() error = %v, want one containing %q", err, "no Pod controls it")
	}
	if n.deletes != 0 {
		t.Errorf("Delete called %d times, want 0", n.deletes)
	}
	if got := getPeer(t, c); !reflect.DeepEqual(got.Spec, foreign.Spec) || len(got.OwnerReferences) != 0 {
		t.Errorf("stored peer = %+v, want it unchanged", got)
	}
}

func TestEnsurePeerIgnoresAlreadyExists(t *testing.T) {
	exists := func() error {
		return apierrors.NewAlreadyExists(schema.GroupResource{Group: "vpn.tunnel-operator.io", Resource: "wireguardpeers"}, "app-1")
	}
	c, _ := newClient(t, exists)

	got, err := ensurePeer(t.Context(), c, c, testConfig(), testPublicKey)
	if err != nil || got != nil {
		t.Errorf("ensurePeer() = %+v, %v, want nil, nil", got, err)
	}
}
