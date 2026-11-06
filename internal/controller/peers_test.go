package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/agent"

	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestWireguardForPeer(t *testing.T) {
	tests := []struct {
		name string
		obj  client.Object
		want []reconcile.Request
	}{
		{
			name: "peer maps to the Wireguard its wireguardRef names, in the peer's namespace",
			obj: &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "media"},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: "egress"},
			},
			want: []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: "media", Name: "egress"}}},
		},
		{
			name: "empty wireguardRef maps to nothing",
			obj:  &v1alpha1.WireguardPeer{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "media"}},
			want: nil,
		},
		{
			name: "another kind maps to nothing",
			obj:  &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "media"}},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wireguardForPeer(t.Context(), tt.obj)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("wireguardForPeer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWireguardNotFound(t *testing.T) {
	want := notReady{
		Status:           "pending",
		Message:          "Waiting for wireguard resource 'vpn' to be created",
		Reason:           "WireguardNotFound",
		ConditionMessage: "no Wireguard named vpn exists in namespace default",
	}
	if got := wireguardNotFound("vpn", "default"); !reflect.DeepEqual(got, want) {
		t.Errorf("wireguardNotFound() = %+v, want %+v", got, want)
	}
}

func TestPeerStatusMatches(t *testing.T) {
	// matching returns a peer that records publicKeyMissing at generation 2.
	matching := func() *v1alpha1.WireguardPeer {
		return &v1alpha1.WireguardPeer{
			ObjectMeta: metav1.ObjectMeta{Generation: 2},
			Status: v1alpha1.WireguardPeerStatus{
				Status:  publicKeyMissing.Status,
				Message: publicKeyMissing.Message,
				Conditions: []metav1.Condition{{
					Type:               ConditionReady,
					Status:             metav1.ConditionFalse,
					Reason:             ReasonPublicKeyMissing,
					Message:            publicKeyMissing.ConditionMessage,
					ObservedGeneration: 2,
				}},
			},
		}
	}

	tests := []struct {
		name   string
		mutate func(*v1alpha1.WireguardPeer)
		want   bool
	}{
		{name: "matches", mutate: func(*v1alpha1.WireguardPeer) {}, want: true},
		{name: "no condition", mutate: func(p *v1alpha1.WireguardPeer) { p.Status.Conditions = nil }, want: false},
		{
			name:   "stale observedGeneration",
			mutate: func(p *v1alpha1.WireguardPeer) { p.Status.Conditions[0].ObservedGeneration = 1 },
			want:   false,
		},
		{
			name:   "other reason",
			mutate: func(p *v1alpha1.WireguardPeer) { p.Status.Conditions[0].Reason = ReasonWireguardNotFound },
			want:   false,
		},
		{
			name:   "other summary status",
			mutate: func(p *v1alpha1.WireguardPeer) { p.Status.Status = v1alpha1.Ready },
			want:   false,
		},
		{
			name:   "address not yet released",
			mutate: func(p *v1alpha1.WireguardPeer) { p.Status.Address = "10.8.0.9" },
			want:   false,
		},
		{
			name:   "gateway identity not yet cleared",
			mutate: func(p *v1alpha1.WireguardPeer) { p.Status.Endpoint = "10.96.0.9:51820" },
			want:   false,
		},
		{
			name:   "server public key not yet cleared",
			mutate: func(p *v1alpha1.WireguardPeer) { p.Status.ServerPublicKey = "server-key" },
			want:   false,
		},
		{
			name:   "localCIDRs not yet cleared",
			mutate: func(p *v1alpha1.WireguardPeer) { p.Status.LocalCIDRs = []string{"10.96.0.0/12"} },
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer := matching()
			tt.mutate(peer)
			if got := peerStatusMatches(peer, publicKeyMissing); got != tt.want {
				t.Errorf("peerStatusMatches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSkipPeerWrite(t *testing.T) {
	gr := schema.GroupResource{Group: "vpn.tunnel-operator.io", Resource: "wireguardpeers"}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "conflict", err: apierrors.NewConflict(gr, "p", errors.New("stale")), want: true},
		{name: "not found", err: apierrors.NewNotFound(gr, "p"), want: true},
		{name: "bad request", err: apierrors.NewBadRequest("x"), want: false},
		{name: "nil", err: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := skipPeerWrite(tt.err); got != tt.want {
				t.Errorf("skipPeerWrite(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestDesiredStateIgnoresStatusAndMetadata(t *testing.T) {
	const privateKey = "PLA+byaz6a5jbnioieB4NEELG7sdq7Wk+3u9Kw0s6zk="

	wg := &v1alpha1.Wireguard{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "vpn",
			Namespace:       "media",
			ResourceVersion: "7",
			Annotations:     map[string]string{"probe.test/nudge": "a"},
		},
		Spec:   v1alpha1.WireguardSpec{PeerCIDR: "10.9.0.0/24"},
		Status: v1alpha1.WireguardStatus{Status: v1alpha1.Ready},
	}
	// peer returns a peer with every field the server must NOT render set, so the test can vary them.
	peer := func(name, publicKey, address, resourceVersion string) v1alpha1.WireguardPeer {
		return v1alpha1.WireguardPeer{
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				Namespace:       "media",
				ResourceVersion: resourceVersion,
				Labels:          map[string]string{"probe.test/nudge": resourceVersion},
				ManagedFields:   []metav1.ManagedFieldsEntry{{Manager: "manager", Operation: metav1.ManagedFieldsOperationUpdate}},
			},
			Spec: v1alpha1.WireguardPeerSpec{WireguardRef: "vpn", PublicKey: publicKey},
			Status: v1alpha1.WireguardPeerStatus{
				Address: address,
				Conditions: []metav1.Condition{{
					Type:   ConditionReady,
					Status: metav1.ConditionTrue,
					Reason: "Observed" + resourceVersion,
				}},
			},
		}
	}
	peers := []v1alpha1.WireguardPeer{
		peer("b", "keyB", "10.9.0.3", "11"),
		peer("a", "keyA", "10.9.0.2", "12"),
	}

	want := agent.State{
		Server: v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "media"},
			Spec:       v1alpha1.WireguardSpec{PeerCIDR: "10.9.0.0/24"},
		},
		ServerPrivateKey: privateKey,
		Peers: []v1alpha1.WireguardPeer{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "media"},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: "vpn", PublicKey: "keyA"},
				Status:     v1alpha1.WireguardPeerStatus{Address: "10.9.0.2"},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "media"},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: "vpn", PublicKey: "keyB"},
				Status:     v1alpha1.WireguardPeerStatus{Address: "10.9.0.3"},
			},
		},
	}

	got := desiredState(wg, privateKey, peers)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("desiredState() = %+v, want %+v", got, want)
	}
	if peers[0].Name != "b" || peers[1].Name != "a" {
		t.Errorf("desiredState() reordered its input: got %q then %q, want b then a", peers[0].Name, peers[1].Name)
	}

	// Changing every field the agent does not read must not change a byte of the rendered state.
	before, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wg.ResourceVersion = "8"
	wg.Annotations["probe.test/nudge"] = "b"
	wg.Status.Status = v1alpha1.Pending
	for i := range peers {
		peers[i].ResourceVersion += "9"
		peers[i].Labels["probe.test/nudge"] = "changed"
		peers[i].Status.Conditions[0].Reason = "Changed"
	}
	after, err := json.Marshal(desiredState(wg, privateKey, peers))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("state.json changed with fields the agent does not read:\n before %s\n after  %s", before, after)
	}
}

func TestAddressPoolExhausted(t *testing.T) {
	want := notReady{
		Status:           "pending",
		Message:          "No free address in 10.8.0.0/30",
		Reason:           "AddressPoolExhausted",
		ConditionMessage: "peerCIDR 10.8.0.0/30 has no free address for this peer",
	}
	if got := addressPoolExhausted("10.8.0.0/30"); !reflect.DeepEqual(got, want) {
		t.Errorf("addressPoolExhausted() = %+v, want %+v", got, want)
	}
}

// publicKeyForTest returns a freshly generated WireGuard public key in its canonical form.
func publicKeyForTest(t *testing.T) string {
	t.Helper()
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv.PublicKey().String()
}

func TestAdmissionProblem(t *testing.T) {
	good := publicKeyForTest(t)
	// ParseKey accepts a key whose last character carries non-zero padding bits, but the agent
	// matches peers by the canonical string, so it must not be admitted.
	nonCanonical := good[:42] + "B="
	if _, err := wgtypes.ParseKey(nonCanonical); err != nil {
		t.Fatalf("ParseKey(%q) = %v; the case needs a key ParseKey accepts", nonCanonical, err)
	}

	tests := []struct {
		name      string
		publicKey string
		want      notReady
		wantOK    bool
	}{
		{name: "empty key", publicKey: "", want: publicKeyMissing, wantOK: true},
		{name: "not base64 of 32 bytes", publicKey: "not-a-key", want: invalidPublicKey, wantOK: true},
		{name: "non-canonical padding bits", publicKey: nonCanonical, want: invalidPublicKey, wantOK: true},
		{name: "canonical key", publicKey: good, want: notReady{}, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer := &v1alpha1.WireguardPeer{Spec: v1alpha1.WireguardPeerSpec{WireguardRef: "vpn", PublicKey: tt.publicKey}}
			got, ok := admissionProblem(peer)
			if ok != tt.wantOK || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("admissionProblem(%q) = (%+v, %v), want (%+v, %v)", tt.publicKey, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// peerCIDRCases are the inputs shared by TestValidatePeerCIDR and the fuzz seed corpus.
var peerCIDRCases = []struct {
	cidr    string
	wantErr bool
}{
	{"10.8.0.0/24", false},
	{"10.9.0.0/16", false},
	{"192.168.4.0/30", false},
	{"10.8.0.5/24", true},
	{"10.8.0.0/31", true},
	{"10.8.0.0/32", true},
	{"fd00::/64", true},
	{"10.8.0.0", true},
	{"garbage", true},
	{"", true},
}

func TestValidatePeerCIDR(t *testing.T) {
	for _, tt := range peerCIDRCases {
		t.Run(tt.cidr, func(t *testing.T) {
			err := validatePeerCIDR(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePeerCIDR(%q) = %v, wantErr %v", tt.cidr, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePeerCIDRMessages(t *testing.T) {
	// parseErr is netip's own text for a string that is not a prefix, which the message embeds.
	parseErr := func(s string) string {
		_, err := netip.ParsePrefix(s)
		if err == nil {
			t.Fatalf("netip.ParsePrefix(%q) succeeded; the case needs a non-prefix", s)
		}
		return err.Error()
	}
	tests := []struct {
		cidr string
		want string
	}{
		{"10.8.0.5/24", `peerCIDR "10.8.0.5/24" has host bits set; use 10.8.0.0/24`},
		{"10.8.0.0/31", `peerCIDR "10.8.0.0/31" leaves no address for a peer; use /30 or shorter`},
		{"fd00::/64", `peerCIDR "fd00::/64" is not an IPv4 prefix`},
		{"10.8.0.0", `peerCIDR "10.8.0.0" is not a CIDR: ` + parseErr("10.8.0.0")},
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			err := validatePeerCIDR(tt.cidr)
			if err == nil || err.Error() != tt.want {
				t.Errorf("validatePeerCIDR(%q) = %v, want %q", tt.cidr, err, tt.want)
			}
		})
	}
}

func FuzzValidatePeerCIDR(f *testing.F) {
	for _, tt := range peerCIDRCases {
		f.Add(tt.cidr)
	}
	f.Fuzz(func(t *testing.T, cidr string) {
		err := validatePeerCIDR(cidr)
		p, parseErr := netip.ParsePrefix(cidr)
		if err != nil {
			// Reverse direction: every canonical IPv4 prefix of /30 or shorter is accepted.
			if parseErr == nil && p.Addr().Is4() && p.Bits() <= 30 && p == p.Masked() {
				t.Errorf("validatePeerCIDR(%q) = %v for the valid IPv4 prefix %v", cidr, err, p)
			}
			return
		}
		if parseErr != nil {
			t.Fatalf("validatePeerCIDR(%q) = nil, but netip.ParsePrefix fails: %v", cidr, parseErr)
		}
		if !p.Addr().Is4() || p.Bits() > 30 || p != p.Masked() {
			t.Errorf("validatePeerCIDR(%q) = nil for %v: want an IPv4 prefix of /30 or shorter with no host bits", cidr, p)
		}
	})
}

func TestAddressConflict(t *testing.T) {
	want := notReady{
		Status:           "pending",
		Message:          "Address 10.8.0.2 is held by peer a; waiting for a new address",
		Reason:           "AddressConflict",
		ConditionMessage: "Address 10.8.0.2 is held by peer a; waiting for a new address",
	}
	if got := addressConflict("10.8.0.2", "a"); !reflect.DeepEqual(got, want) {
		t.Errorf("addressConflict() = %+v, want %+v", got, want)
	}
}

func TestDedupeAddresses(t *testing.T) {
	base := time.Date(2026, time.October, 31, 12, 0, 0, 0, time.UTC)
	t0, t1, t2 := metav1.NewTime(base), metav1.NewTime(base.Add(time.Second)), metav1.NewTime(base.Add(2*time.Second))
	peer := func(name, address string, created metav1.Time) v1alpha1.WireguardPeer {
		return v1alpha1.WireguardPeer{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", CreationTimestamp: created},
			Status:     v1alpha1.WireguardPeerStatus{Address: address},
		}
	}
	type loser struct{ peer, winner string }

	tests := []struct {
		name       string
		peers      []v1alpha1.WireguardPeer
		wantKeep   []string
		wantLosers []loser
	}{
		{
			name:     "no duplicates",
			peers:    []v1alpha1.WireguardPeer{peer("a", "10.8.0.2", t0), peer("b", "10.8.0.3", t1)},
			wantKeep: []string{"a", "b"},
		},
		{
			name:       "older wins",
			peers:      []v1alpha1.WireguardPeer{peer("young", "10.8.0.2", t1), peer("old", "10.8.0.2", t0)},
			wantKeep:   []string{"old"},
			wantLosers: []loser{{"young", "ns/old"}},
		},
		{
			name:       "older wins even with the larger name",
			peers:      []v1alpha1.WireguardPeer{peer("a", "10.8.0.2", t1), peer("b", "10.8.0.2", t0)},
			wantKeep:   []string{"b"},
			wantLosers: []loser{{"a", "ns/b"}},
		},
		{
			name:       "tie goes to smaller name",
			peers:      []v1alpha1.WireguardPeer{peer("b", "10.8.0.2", t0), peer("a", "10.8.0.2", t0)},
			wantKeep:   []string{"a"},
			wantLosers: []loser{{"b", "ns/a"}},
		},
		{
			name:       "three holders",
			peers:      []v1alpha1.WireguardPeer{peer("c", "10.8.0.2", t2), peer("a", "10.8.0.2", t0), peer("b", "10.8.0.2", t1)},
			wantKeep:   []string{"a"},
			wantLosers: []loser{{"c", "ns/a"}, {"b", "ns/a"}},
		},
		{
			name:     "unaddressed kept",
			peers:    []v1alpha1.WireguardPeer{peer("x", "", t0), peer("y", "10.8.0.2", t1)},
			wantKeep: []string{"x", "y"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keep, losers := dedupeAddresses(tt.peers)

			var gotKeep []string
			for _, p := range keep {
				gotKeep = append(gotKeep, p.Name)
			}
			if !reflect.DeepEqual(gotKeep, tt.wantKeep) {
				t.Errorf("dedupeAddresses() keep = %v, want %v", gotKeep, tt.wantKeep)
			}
			var gotLosers []loser
			for _, l := range losers {
				gotLosers = append(gotLosers, loser{l.Peer.Name, l.Winner})
			}
			if !reflect.DeepEqual(gotLosers, tt.wantLosers) {
				t.Errorf("dedupeAddresses() losers = %v, want %v", gotLosers, tt.wantLosers)
			}
		})
	}
}

func TestAddressUsable(t *testing.T) {
	const cidr = "10.8.0.0/24"
	tests := []struct {
		addr string
		want bool
	}{
		{"10.8.0.2", true},
		{"10.8.0.254", true},
		{"10.8.0.255", true}, // the allocator hands the broadcast address out too
		{"10.8.0.0", false},  // network
		{"10.8.0.1", false},  // gateway
		{"10.9.0.2", false},  // outside the prefix
		{"", false},
		{"garbage", false},
		{"fd00::2", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := addressUsable(tt.addr, cidr); got != tt.want {
				t.Errorf("addressUsable(%q, %q) = %v, want %v", tt.addr, cidr, got, tt.want)
			}
		})
	}
}

// failingStatusClient is a client whose every status write returns err and, when wrote is set,
// records the name of each peer written. List returns peers. Any other call panics on the nil
// embedded client, which the test must not reach.
type failingStatusClient struct {
	client.Client
	err   error
	peers []v1alpha1.WireguardPeer
	wrote *[]string
}

func (c failingStatusClient) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	list.(*v1alpha1.WireguardPeerList).Items = c.peers
	return nil
}

func (c failingStatusClient) Status() client.SubResourceWriter {
	return failingStatusWriter{err: c.err, wrote: c.wrote}
}

type failingStatusWriter struct {
	client.SubResourceWriter
	err   error
	wrote *[]string
}

func (w failingStatusWriter) Update(_ context.Context, obj client.Object, _ ...client.SubResourceUpdateOption) error {
	if w.wrote != nil {
		*w.wrote = append(*w.wrote, obj.GetName())
	}
	return w.err
}

func TestAdmitPeersStatusWriteErrors(t *testing.T) {
	gr := schema.GroupResource{Group: "vpn.tunnel-operator.io", Resource: "wireguardpeers"}
	keyless := v1alpha1.WireguardPeer{ObjectMeta: metav1.ObjectMeta{Name: "keyless", Namespace: "default"}}
	keyed := v1alpha1.WireguardPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "keyed", Namespace: "default"},
		Spec:       v1alpha1.WireguardPeerSpec{PublicKey: publicKeyForTest(t)},
	}
	tests := []struct {
		name      string
		writeErr  error
		wantNames []string
		wantErr   bool
	}{
		{"invalid object is skipped", apierrors.NewInvalid(schema.GroupKind{Group: gr.Group, Kind: "WireguardPeer"}, "keyless", nil), []string{"keyed"}, false},
		{"conflict is skipped", apierrors.NewConflict(gr, "keyless", errors.New("stale")), []string{"keyed"}, false},
		{"other errors are returned", apierrors.NewInternalError(errors.New("boom")), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &WireguardReconciler{Client: failingStatusClient{err: tt.writeErr}}

			admitted, err := r.admitPeers(t.Context(), &v1alpha1.Wireguard{}, []v1alpha1.WireguardPeer{keyless, keyed})
			if (err != nil) != tt.wantErr {
				t.Fatalf("admitPeers() error = %v, wantErr %v", err, tt.wantErr)
			}
			var got []string
			for _, p := range admitted {
				got = append(got, p.Name)
			}
			if !reflect.DeepEqual(got, tt.wantNames) {
				t.Errorf("admitPeers() admitted %v, want %v", got, tt.wantNames)
			}
		})
	}
}

func TestMarkPeersWireguardNotFoundStatusWriteErrors(t *testing.T) {
	gr := schema.GroupResource{Group: "vpn.tunnel-operator.io", Resource: "wireguardpeers"}
	peers := []v1alpha1.WireguardPeer{
		{ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: "default"}, Spec: v1alpha1.WireguardPeerSpec{WireguardRef: "vpn"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: "default"}, Spec: v1alpha1.WireguardPeerSpec{WireguardRef: "vpn"}},
	}
	tests := []struct {
		name      string
		writeErr  error
		wantWrote []string
		wantErr   bool
	}{
		{"invalid object is skipped", apierrors.NewInvalid(schema.GroupKind{Group: gr.Group, Kind: "WireguardPeer"}, "first", nil), []string{"first", "second"}, false},
		{"conflict is skipped", apierrors.NewConflict(gr, "first", errors.New("stale")), []string{"first", "second"}, false},
		{"other errors are returned", apierrors.NewInternalError(errors.New("boom")), []string{"first"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wrote []string
			r := &WireguardReconciler{Client: failingStatusClient{err: tt.writeErr, peers: peers, wrote: &wrote}}

			err := r.markPeersWireguardNotFound(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "vpn"}})
			if (err != nil) != tt.wantErr {
				t.Fatalf("markPeersWireguardNotFound() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(wrote, tt.wantWrote) {
				t.Errorf("markPeersWireguardNotFound() wrote status of %v, want %v", wrote, tt.wantWrote)
			}
		})
	}
}

func TestDesiredStateDropsGluetun(t *testing.T) {
	wg := &v1alpha1.Wireguard{
		ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "media"},
		Spec: v1alpha1.WireguardSpec{
			LocalCIDRs: []string{"10.96.0.0/12"},
			Gluetun: v1alpha1.GluetunSpec{
				Env: []corev1.EnvVar{{Name: "A", Value: "b"}},
				EnvFrom: []corev1.EnvFromSource{{
					SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "s"}},
				}},
			},
		},
	}

	got := desiredState(wg, "k", nil).Server.Spec
	want := v1alpha1.WireguardSpec{LocalCIDRs: []string{"10.96.0.0/12"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("desiredState().Server.Spec = %+v, want %+v", got, want)
	}
	if len(wg.Spec.Gluetun.Env) != 1 {
		t.Errorf("desiredState() zeroed its input: len(wg.Spec.Gluetun.Env) = %d, want 1", len(wg.Spec.Gluetun.Env))
	}
}
