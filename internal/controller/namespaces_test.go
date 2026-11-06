package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/agent"

	corev1 "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// peerIn returns a peer named name in namespace ns that references the Wireguard ref, in refNS
// when that is not empty.
func peerIn(ns, name, ref, refNS string) v1alpha1.WireguardPeer {
	return v1alpha1.WireguardPeer{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: ref, WireguardNamespace: refNS},
	}
}

func TestWireguardForPeerResolvesNamespace(t *testing.T) {
	peer := peerIn("media", "p", "vpn", "network")
	got := wireguardForPeer(t.Context(), &peer)
	want := []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: "network", Name: "vpn"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("wireguardForPeer() = %v, want %v", got, want)
	}
}

func TestNamespaceNotAllowed(t *testing.T) {
	gateway := func(allowed *v1alpha1.AllowedNamespaces) *v1alpha1.Wireguard {
		return &v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "network"},
			Spec:       v1alpha1.WireguardSpec{AllowedNamespaces: allowed},
		}
	}
	same := &v1alpha1.AllowedNamespaces{From: v1alpha1.FromSame}
	all := &v1alpha1.AllowedNamespaces{From: v1alpha1.FromAll}
	foreign, own := peerIn("media", "p", "vpn", "network"), peerIn("network", "p", "vpn", "")

	tests := []struct {
		name    string
		wg      *v1alpha1.Wireguard
		peer    v1alpha1.WireguardPeer
		refused bool
	}{
		{"no policy admits a foreign peer", gateway(nil), foreign, false},
		{"All admits a foreign peer", gateway(all), foreign, false},
		{"empty from admits a foreign peer", gateway(&v1alpha1.AllowedNamespaces{}), foreign, false},
		{"Same admits the gateway's own namespace", gateway(same), own, false},
		{"Same refuses a foreign peer", gateway(same), foreign, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nr, refused := namespaceNotAllowed(tt.wg, &tt.peer)
			if refused != tt.refused {
				t.Fatalf("namespaceNotAllowed() refused = %v, want %v", refused, tt.refused)
			}
			if refused && (nr.Reason != ReasonNamespaceNotAllowed || nr.Status != v1alpha1.Error) {
				t.Errorf("namespaceNotAllowed() = %+v, want reason %s and status %s", nr, ReasonNamespaceNotAllowed, v1alpha1.Error)
			}
		})
	}
}

func newFakeClient(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add v1alpha1 to the scheme: %v", err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add corev1 to the scheme: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).
		WithStatusSubresource(&v1alpha1.WireguardPeer{}).WithInterceptorFuncs(funcs).Build()
}

func TestGetWireguardPeersAcrossNamespaces(t *testing.T) {
	peers := []client.Object{
		new(peerIn("network", "own", "vpn", "")),
		new(peerIn("media", "app", "vpn", "network")),
		new(peerIn("media", "local", "vpn", "")),          // media/vpn, another gateway
		new(peerIn("media", "other", "other", "network")), // network/other
		new(peerIn("network", "elsewhere", "vpn", "media")),
	}
	r := &WireguardReconciler{Client: newFakeClient(t, interceptor.Funcs{}, peers...)}

	got, err := r.getWireguardPeers(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "network", Name: "vpn"}})
	if err != nil {
		t.Fatalf("getWireguardPeers() error = %v", err)
	}
	var names []string
	for _, p := range got.Items {
		names = append(names, p.Namespace+"/"+p.Name)
	}
	slices.Sort(names)
	if want := []string{"media/app", "network/own"}; !slices.Equal(names, want) {
		t.Errorf("getWireguardPeers() = %v, want %v", names, want)
	}
}

func TestDesiredStateOrdersPeersByNamespaceWithinAName(t *testing.T) {
	wg := &v1alpha1.Wireguard{ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "network"}}
	a, b := peerIn("alpha", "app", "vpn", "network"), peerIn("beta", "app", "vpn", "network")

	forward := desiredState(wg, "k", []v1alpha1.WireguardPeer{a, b})
	backward := desiredState(wg, "k", []v1alpha1.WireguardPeer{b, a})
	if !reflect.DeepEqual(forward, backward) {
		t.Errorf("desiredState() depends on input order:\n forward  %+v\n backward %+v", forward.Peers, backward.Peers)
	}
}

func TestDedupeAddressesBreaksATieByNamespace(t *testing.T) {
	created := metav1.NewTime(time.Date(2026, time.November, 5, 12, 0, 0, 0, time.UTC))
	mk := func(ns string) v1alpha1.WireguardPeer {
		p := peerIn(ns, "app", "vpn", "network")
		p.CreationTimestamp = created
		p.Status.Address = "10.8.0.2"
		return p
	}
	for _, order := range [][]string{{"alpha", "beta"}, {"beta", "alpha"}} {
		keep, losers := dedupeAddresses([]v1alpha1.WireguardPeer{mk(order[0]), mk(order[1])})
		if len(keep) != 1 || keep[0].Namespace != "alpha" || len(losers) != 1 || losers[0].Peer.Namespace != "beta" {
			t.Errorf("input order %v: keep = %v, losers = %v, want alpha to keep the address", order, keep, losers)
		}
	}
}

func TestSyncPeerIdentity(t *testing.T) {
	wg := &v1alpha1.Wireguard{
		ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "network"},
		Spec:       v1alpha1.WireguardSpec{LocalCIDRs: []string{"10.96.0.0/12", "10.244.0.0/16"}},
	}
	id := serverIdentity{Endpoint: "10.96.0.9:51820", PublicKey: "server-key"}
	synced := func(p v1alpha1.WireguardPeer) v1alpha1.WireguardPeer {
		p.Status.Endpoint, p.Status.ServerPublicKey, p.Status.LocalCIDRs = id.Endpoint, id.PublicKey, wg.Spec.LocalCIDRs
		return p
	}
	fresh := peerIn("media", "fresh", "vpn", "network")
	current := synced(peerIn("media", "current", "vpn", "network"))
	stale := synced(peerIn("media", "stale", "vpn", "network"))
	stale.Status.LocalCIDRs = []string{"10.96.0.0/12"}

	var wrote []string
	c := newFakeClient(t, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, cl client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			wrote = append(wrote, obj.GetName())
			return cl.SubResource(sub).Update(ctx, obj, opts...)
		},
	}, &fresh, &current, &stale)
	r := &WireguardReconciler{Client: c}

	// The peers as allocatePeers hands them back: read from the API, so with their resourceVersion.
	var peers []v1alpha1.WireguardPeer
	for _, name := range []string{"fresh", "current", "stale"} {
		p := v1alpha1.WireguardPeer{}
		if err := c.Get(t.Context(), types.NamespacedName{Namespace: "media", Name: name}, &p); err != nil {
			t.Fatalf("get %s: %v", name, err)
		}
		peers = append(peers, p)
	}

	if err := r.syncPeerIdentity(t.Context(), wg, id, peers); err != nil {
		t.Fatalf("syncPeerIdentity() error = %v", err)
	}
	if want := []string{"fresh", "stale"}; !slices.Equal(wrote, want) {
		t.Errorf("status writes = %v, want %v (a peer that already carries the identity is not rewritten)", wrote, want)
	}
	for _, name := range []string{"fresh", "stale"} {
		p := v1alpha1.WireguardPeer{}
		if err := c.Get(t.Context(), types.NamespacedName{Namespace: "media", Name: name}, &p); err != nil {
			t.Fatalf("get %s: %v", name, err)
		}
		if p.Status.Endpoint != id.Endpoint || p.Status.ServerPublicKey != id.PublicKey || !slices.Equal(p.Status.LocalCIDRs, wg.Spec.LocalCIDRs) {
			t.Errorf("%s status = %+v, want endpoint %s, key %s, localCIDRs %v", name, p.Status, id.Endpoint, id.PublicKey, wg.Spec.LocalCIDRs)
		}
	}
}

func TestAdmitPeersRefusesAForeignNamespaceUnderSame(t *testing.T) {
	wg := &v1alpha1.Wireguard{
		ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "network"},
		Spec:       v1alpha1.WireguardSpec{AllowedNamespaces: &v1alpha1.AllowedNamespaces{From: v1alpha1.FromSame}},
	}
	key := publicKeyForTest(t)
	own, foreign := peerIn("network", "own", "vpn", ""), peerIn("media", "app", "vpn", "network")
	own.Spec.PublicKey, foreign.Spec.PublicKey = key, key
	foreign.Status.Address = "10.8.0.2" // an address it held while the gateway still allowed it
	foreign.Status.Endpoint, foreign.Status.ServerPublicKey, foreign.Status.LocalCIDRs = "10.96.0.9:51820", "server-key", []string{"10.96.0.0/12"}
	c := newFakeClient(t, interceptor.Funcs{}, &own, &foreign)
	r := &WireguardReconciler{Client: c}

	admitted, err := r.admitPeers(t.Context(), wg, []v1alpha1.WireguardPeer{own, foreign})
	if err != nil {
		t.Fatalf("admitPeers() error = %v", err)
	}
	if len(admitted) != 1 || admitted[0].Name != "own" {
		t.Errorf("admitPeers() admitted %v, want only network/own", admitted)
	}
	got := v1alpha1.WireguardPeer{}
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "media", Name: "app"}, &got); err != nil {
		t.Fatalf("get the foreign peer: %v", err)
	}
	if got.Status.Address != "" || got.Status.Status != v1alpha1.Error {
		t.Errorf("foreign peer status = %+v, want its address released and status %s", got.Status, v1alpha1.Error)
	}
	if got.Status.Endpoint != "" || got.Status.ServerPublicKey != "" || len(got.Status.LocalCIDRs) != 0 {
		t.Errorf("foreign peer status = %+v, want its copy of the gateway identity cleared", got.Status)
	}
	if c := meta.FindStatusCondition(got.Status.Conditions, ConditionReady); c == nil || c.Reason != ReasonNamespaceNotAllowed {
		t.Errorf("foreign peer Ready condition = %+v, want reason %s", c, ReasonNamespaceNotAllowed)
	}
}

func TestPublicKeyConflict(t *testing.T) {
	want := notReady{
		Status:           v1alpha1.Pending,
		Message:          "Public key is held by peer media/app; waiting for it to be released",
		Reason:           ReasonPublicKeyConflict,
		ConditionMessage: "spec.publicKey is already held by peer media/app of this Wireguard, so this peer cannot be admitted",
	}
	if got := publicKeyConflict("media/app"); !reflect.DeepEqual(got, want) {
		t.Errorf("publicKeyConflict() = %+v, want %+v", got, want)
	}
}

func TestDedupePublicKeys(t *testing.T) {
	base := time.Date(2026, time.November, 5, 12, 0, 0, 0, time.UTC)
	old, young := metav1.NewTime(base), metav1.NewTime(base.Add(time.Second))
	peer := func(ns, name, key string, created metav1.Time) v1alpha1.WireguardPeer {
		p := peerIn(ns, name, "vpn", "network")
		p.Spec.PublicKey, p.CreationTimestamp = key, created
		return p
	}
	held := func(ns, name, key string) map[types.NamespacedName]string {
		return map[types.NamespacedName]string{{Namespace: ns, Name: name}: key}
	}
	type loser struct{ peer, winner string }
	tests := []struct {
		name       string
		peers      []v1alpha1.WireguardPeer
		current    map[types.NamespacedName]string
		wantKeep   []string
		wantLosers []loser
	}{
		{
			name:     "the key is the value compared",
			peers:    []v1alpha1.WireguardPeer{peer("a", "p", "k1", old), peer("b", "p", "k2", young)},
			wantKeep: []string{"a/p", "b/p"},
		},
		{
			name:       "the current holder keeps the key against an older peer with a smaller name",
			peers:      []v1alpha1.WireguardPeer{peer("ns", "aaa", "k1", old), peer("ns", "zzz", "k1", young)},
			current:    held("ns", "zzz", "k1"),
			wantKeep:   []string{"ns/zzz"},
			wantLosers: []loser{{"ns/aaa", "ns/zzz"}},
		},
		{
			name:       "a stale record of another key does not make a holder",
			peers:      []v1alpha1.WireguardPeer{peer("ns", "aaa", "k1", old), peer("ns", "zzz", "k1", young)},
			current:    held("ns", "zzz", "k0"),
			wantKeep:   []string{"ns/aaa"},
			wantLosers: []loser{{"ns/zzz", "ns/aaa"}},
		},
		{
			name:       "with no holder the older peer wins even with the larger name",
			peers:      []v1alpha1.WireguardPeer{peer("ns", "aaa", "k1", young), peer("ns", "zzz", "k1", old)},
			wantKeep:   []string{"ns/zzz"},
			wantLosers: []loser{{"ns/aaa", "ns/zzz"}},
		},
		{
			name:       "a tie goes to the smaller name before the smaller namespace",
			peers:      []v1alpha1.WireguardPeer{peer("a", "b", "k1", old), peer("b", "a", "k1", old)},
			wantKeep:   []string{"b/a"},
			wantLosers: []loser{{"a/b", "b/a"}},
		},
		{
			name:  "two holders fall back to the order",
			peers: []v1alpha1.WireguardPeer{peer("ns", "aaa", "k1", young), peer("ns", "zzz", "k1", old)},
			current: map[types.NamespacedName]string{
				{Namespace: "ns", Name: "aaa"}: "k1", {Namespace: "ns", Name: "zzz"}: "k1",
			},
			wantKeep:   []string{"ns/zzz"},
			wantLosers: []loser{{"ns/aaa", "ns/zzz"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keep, losers := dedupePublicKeys(tt.peers, tt.current)

			var gotKeep []string
			for _, p := range keep {
				gotKeep = append(gotKeep, p.Namespace+"/"+p.Name)
			}
			if !reflect.DeepEqual(gotKeep, tt.wantKeep) {
				t.Errorf("dedupePublicKeys() keep = %v, want %v", gotKeep, tt.wantKeep)
			}
			var gotLosers []loser
			for _, l := range losers {
				gotLosers = append(gotLosers, loser{l.Peer.Namespace + "/" + l.Peer.Name, l.Winner})
			}
			if !reflect.DeepEqual(gotLosers, tt.wantLosers) {
				t.Errorf("dedupePublicKeys() losers = %v, want %v", gotLosers, tt.wantLosers)
			}
		})
	}
}

func TestAdmittedKeys(t *testing.T) {
	wg := &v1alpha1.Wireguard{ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "network"}}
	state, err := json.Marshal(agent.State{Peers: []v1alpha1.WireguardPeer{
		{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "media"}, Spec: v1alpha1.WireguardPeerSpec{PublicKey: "k1"}},
	}})
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "network"},
		Data:       map[string][]byte{"state.json": state},
	}

	got, err := (&WireguardReconciler{Client: newFakeClient(t, interceptor.Funcs{}, secret)}).admittedKeys(t.Context(), wg)
	if err != nil {
		t.Fatalf("admittedKeys() error = %v", err)
	}
	if want := map[types.NamespacedName]string{{Namespace: "media", Name: "app"}: "k1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("admittedKeys() = %v, want %v", got, want)
	}

	got, err = (&WireguardReconciler{Client: newFakeClient(t, interceptor.Funcs{})}).admittedKeys(t.Context(), wg)
	if err != nil || len(got) != 0 {
		t.Errorf("admittedKeys() with no Secret = %v, %v, want none and no error", got, err)
	}
}

func TestReconcilePeersStopsBeforeAnyWriteWhenTheSecretCannotBeRead(t *testing.T) {
	boom := errors.New("secret unavailable")
	wg := &v1alpha1.Wireguard{ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "network"}}
	keyless := peerIn("media", "keyless", "vpn", "network") // admitPeers would write its status
	var writes []string
	c := newFakeClient(t, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				return boom
			}
			return cl.Get(ctx, key, obj, opts...)
		},
		SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, obj client.Object, _ ...client.SubResourceUpdateOption) error {
			writes = append(writes, obj.GetName())
			return nil
		},
	}, &keyless)
	r := &WireguardReconciler{Client: c}

	if _, err := r.admittedKeys(t.Context(), wg); !errors.Is(err, boom) {
		t.Errorf("admittedKeys() error = %v, want %v", err, boom)
	}
	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "network", Name: "vpn"}}
	if _, err := r.reconcilePeers(t.Context(), req, wg); !errors.Is(err, boom) {
		t.Errorf("reconcilePeers() error = %v, want %v", err, boom)
	}
	if len(writes) != 0 {
		t.Errorf("reconcilePeers() wrote the status of %v, want no writes", writes)
	}
}
