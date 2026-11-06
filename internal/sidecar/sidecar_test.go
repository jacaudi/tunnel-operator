package sidecar

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
)

// applyCall is one Apply the fake datapath received.
type applyCall struct {
	key wgtypes.Key
	tun Tunnel
}

// fakeDatapath records each Apply and returns err. When applied is non-nil it also signals each Apply
// on it, without blocking.
type fakeDatapath struct {
	calls   []applyCall
	err     error
	applied chan struct{}
}

func (f *fakeDatapath) Apply(key wgtypes.Key, t Tunnel) error {
	f.calls = append(f.calls, applyCall{key: key, tun: t})
	if f.applied != nil {
		select {
		case f.applied <- struct{}{}:
		default:
		}
	}
	return f.err
}

// stepFixture returns a runner over a fake client seeded with objs, the client and the fake datapath.
func stepFixture(t *testing.T, objs ...ctrlclient.Object) (*runner, ctrlclient.Client, *fakeDatapath) {
	t.Helper()
	c, _ := newClient(t, nil, objs...)
	dp := &fakeDatapath{}
	return &runner{r: c, w: c, dp: dp, cfg: testConfig(), key: newPrivateKey(t)}, c, dp
}

// addressedPeer returns the peer rn registers, with status.address address.
func addressedPeer(rn *runner, address string) *v1alpha1.WireguardPeer {
	p := desiredPeer(rn.cfg, rn.key.PublicKey().String())
	p.Status.Address = address
	return p
}

// publishedPeer returns the peer rn registers, with the status the operator publishes once the gateway
// admits it, and the gateway's public key.
func publishedPeer(t *testing.T, rn *runner) (*v1alpha1.WireguardPeer, wgtypes.Key) {
	t.Helper()
	fixture, serverKey := tunnelFixture(t)
	p := desiredPeer(rn.cfg, rn.key.PublicKey().String())
	p.Status = fixture.Status
	return p, serverKey
}

func TestStepRegistersAndWaits(t *testing.T) {
	rn, c, dp := stepFixture(t)

	err := rn.step(t.Context())
	if !errors.Is(err, errWaiting) || !strings.Contains(err.Error(), "registered") {
		t.Fatalf("step = %v, want errWaiting containing %q", err, "registered")
	}
	got := getPeer(t, c)
	if got.Name != "app-1" || got.Spec.PublicKey != rn.key.PublicKey().String() {
		t.Errorf("peer = %s with key %q, want app-1 with the runner's public key", got.Name, got.Spec.PublicKey)
	}
	if len(dp.calls) != 0 {
		t.Errorf("datapath received %d calls, want 0", len(dp.calls))
	}
}

func TestStepWaitsForAddress(t *testing.T) {
	rn, _, dp := stepFixture(t)
	if err := rn.w.Create(t.Context(), addressedPeer(rn, "")); err != nil {
		t.Fatalf("seed peer: %v", err)
	}

	err := rn.step(t.Context())
	if !errors.Is(err, errWaiting) || !strings.Contains(err.Error(), "has no status.address") {
		t.Fatalf("step = %v, want errWaiting containing %q", err, "has no status.address")
	}
	if len(dp.calls) != 0 {
		t.Errorf("datapath received %d calls, want 0", len(dp.calls))
	}
}

func TestStepWaitsForGatewayStatus(t *testing.T) {
	rn, _, dp := stepFixture(t)
	if err := rn.w.Create(t.Context(), addressedPeer(rn, "10.8.0.7")); err != nil {
		t.Fatalf("seed peer: %v", err)
	}

	err := rn.step(t.Context())
	if !errors.Is(err, errWaiting) || !strings.Contains(err.Error(), "has no status.endpoint") {
		t.Fatalf("step = %v, want errWaiting containing %q", err, "has no status.endpoint")
	}
	if len(dp.calls) != 0 {
		t.Errorf("datapath received %d calls, want 0", len(dp.calls))
	}
}

func TestStepApplies(t *testing.T) {
	rn, _, dp := stepFixture(t)
	peer, serverKey := publishedPeer(t, rn)
	if err := rn.w.Create(t.Context(), peer); err != nil {
		t.Fatalf("seed peer: %v", err)
	}

	if err := rn.step(t.Context()); err != nil {
		t.Fatalf("step: %v", err)
	}
	want := applyCall{key: rn.key, tun: Tunnel{
		Address:   netip.MustParsePrefix("10.8.0.7/32"),
		ServerKey: serverKey,
		Endpoint:  netip.MustParseAddrPort("10.96.0.20:51820"),
		LocalCIDRs: []netip.Prefix{
			netip.MustParsePrefix("10.244.0.0/16"),
			netip.MustParsePrefix("10.96.0.0/12"),
		},
	}}
	if len(dp.calls) != 1 || !reflect.DeepEqual(dp.calls[0], want) {
		t.Errorf("datapath calls = %+v, want exactly [%+v]", dp.calls, want)
	}
}

func TestStepRecreatesDeletedPeer(t *testing.T) {
	rn, c, dp := stepFixture(t)
	peer, _ := publishedPeer(t, rn)
	if err := c.Create(t.Context(), peer); err != nil {
		t.Fatalf("seed peer: %v", err)
	}
	if err := rn.step(t.Context()); err != nil {
		t.Fatalf("first step: %v", err)
	}
	if err := c.Delete(t.Context(), peer); err != nil {
		t.Fatalf("delete peer: %v", err)
	}

	err := rn.step(t.Context())
	if !errors.Is(err, errWaiting) || !strings.Contains(err.Error(), "registered") {
		t.Fatalf("second step = %v, want errWaiting containing %q", err, "registered")
	}
	got := getPeer(t, c)
	if got.Spec.PublicKey != rn.key.PublicKey().String() {
		t.Errorf("peer = %+v, want one registered with the runner's public key", got)
	}
	if len(dp.calls) != 1 {
		t.Errorf("datapath received %d calls, want 1 (from the first pass only)", len(dp.calls))
	}
}

func TestStepReturnsApplyError(t *testing.T) {
	rn, _, dp := stepFixture(t)
	dp.err = errors.New("boom")
	peer, _ := publishedPeer(t, rn)
	if err := rn.w.Create(t.Context(), peer); err != nil {
		t.Fatalf("seed peer: %v", err)
	}

	err := rn.step(t.Context())
	if !errors.Is(err, dp.err) || errors.Is(err, errWaiting) {
		t.Errorf("step = %v, want the datapath's error and not errWaiting", err)
	}
}

// seededRunner returns a runner whose pass reaches the datapath.
func seededRunner(t *testing.T) (*runner, *fakeDatapath) {
	t.Helper()
	rn, _, dp := stepFixture(t)
	peer, _ := publishedPeer(t, rn)
	if err := rn.w.Create(t.Context(), peer); err != nil {
		t.Fatalf("seed peer: %v", err)
	}
	return rn, dp
}

func TestLoopMakesNoPassWhenDone(t *testing.T) {
	rn, dp := seededRunner(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	loop(ctx, rn, make(chan struct{}), logr.Discard())

	if len(dp.calls) != 0 {
		t.Errorf("datapath received %d calls, want 0", len(dp.calls))
	}
}

func TestLoopPassesAtOnceAndOnKick(t *testing.T) {
	rn, dp := seededRunner(t)
	dp.applied = make(chan struct{}, 1)
	kick := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		loop(ctx, rn, kick, logr.Discard())
	}()

	wait := func(what string) {
		t.Helper()
		select {
		case <-dp.applied:
		case <-time.After(5 * time.Second):
			t.Fatalf("no pass %s", what)
		}
	}
	wait("at start")
	kick <- struct{}{}
	wait("after a kick")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not return after its context was done")
	}
}
