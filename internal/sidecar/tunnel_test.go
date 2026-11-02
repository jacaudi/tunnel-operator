package sidecar

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jacaudi/wireguard-operator/api/v1alpha1"
	"github.com/jacaudi/wireguard-operator/internal/resources"
)

func newPrivateKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

// tunnelFixture returns the peer app-1 and the Wireguard vpn, both complete, and the server's public key.
func tunnelFixture(t *testing.T) (*v1alpha1.WireguardPeer, *v1alpha1.Wireguard, wgtypes.Key) {
	t.Helper()
	serverKey := newPrivateKey(t).PublicKey()
	peer := &v1alpha1.WireguardPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "app-1"},
		Status:     v1alpha1.WireguardPeerStatus{Address: "10.8.0.7"},
	}
	wg := &v1alpha1.Wireguard{
		ObjectMeta: metav1.ObjectMeta{Name: "vpn"},
		Spec:       v1alpha1.WireguardSpec{LocalCIDRs: []string{"10.244.0.0/16", "10.96.0.0/12"}},
		Status:     v1alpha1.WireguardStatus{Endpoint: "10.96.0.20:51820", PublicKey: serverKey.String()},
	}
	return peer, wg, serverKey
}

func TestDesiredTunnel(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*v1alpha1.WireguardPeer, *v1alpha1.Wireguard)
		wantCIDRs   []string
		wantWaiting bool
		wantErr     string
	}{
		{name: "complete", wantCIDRs: []string{"10.244.0.0/16", "10.96.0.0/12"}},
		{
			name:        "no address",
			mutate:      func(p *v1alpha1.WireguardPeer, _ *v1alpha1.Wireguard) { p.Status.Address = "" },
			wantWaiting: true,
			wantErr:     "has no status.address",
		},
		{
			name:        "no endpoint",
			mutate:      func(_ *v1alpha1.WireguardPeer, w *v1alpha1.Wireguard) { w.Status.Endpoint = "" },
			wantWaiting: true,
			wantErr:     "has no status.endpoint",
		},
		{
			name:        "no public key",
			mutate:      func(_ *v1alpha1.WireguardPeer, w *v1alpha1.Wireguard) { w.Status.PublicKey = "" },
			wantWaiting: true,
			wantErr:     "has no status.publicKey",
		},
		{
			name:    "IPv6 address",
			mutate:  func(p *v1alpha1.WireguardPeer, _ *v1alpha1.Wireguard) { p.Status.Address = "fd00::7" },
			wantErr: "is not IPv4",
		},
		{
			name:    "endpoint without a port",
			mutate:  func(_ *v1alpha1.WireguardPeer, w *v1alpha1.Wireguard) { w.Status.Endpoint = "10.96.0.20" },
			wantErr: "parse status.endpoint",
		},
		{
			name:    "no localCIDRs",
			mutate:  func(_ *v1alpha1.WireguardPeer, w *v1alpha1.Wireguard) { w.Spec.LocalCIDRs = nil },
			wantErr: "has no spec.localCIDRs",
		},
		{
			name: "entry with host bits is masked",
			mutate: func(_ *v1alpha1.WireguardPeer, w *v1alpha1.Wireguard) {
				w.Spec.LocalCIDRs = []string{"10.244.0.5/16", "10.96.0.0/12"}
			},
			wantCIDRs: []string{"10.244.0.0/16", "10.96.0.0/12"},
		},
		{
			name:    "entry covering every address",
			mutate:  func(_ *v1alpha1.WireguardPeer, w *v1alpha1.Wireguard) { w.Spec.LocalCIDRs = []string{"0.0.0.0/0"} },
			wantErr: "covers every address",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			peer, wg, serverKey := tunnelFixture(t)
			if tc.mutate != nil {
				tc.mutate(peer, wg)
			}

			got, err := desiredTunnel(peer, wg)

			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("desiredTunnel error = %v, want one containing %q", err, tc.wantErr)
				}
				if waiting := errors.Is(err, errWaiting); waiting != tc.wantWaiting {
					t.Errorf("errors.Is(err, errWaiting) = %v, want %v (%v)", waiting, tc.wantWaiting, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("desiredTunnel: %v", err)
			}
			want := Tunnel{
				Address:   netip.MustParsePrefix("10.8.0.7/32"),
				ServerKey: serverKey,
				Endpoint:  netip.MustParseAddrPort("10.96.0.20:51820"),
			}
			for _, c := range tc.wantCIDRs {
				want.LocalCIDRs = append(want.LocalCIDRs, netip.MustParsePrefix(c))
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("desiredTunnel = %+v, want %+v", got, want)
			}
		})
	}
}

func testTunnel(t *testing.T) Tunnel {
	t.Helper()
	peer, wg, _ := tunnelFixture(t)
	tun, err := desiredTunnel(peer, wg)
	if err != nil {
		t.Fatalf("desiredTunnel: %v", err)
	}
	return tun
}

// matchingDevice returns the device deviceConfig leaves untouched for key and tun.
func matchingDevice(tun Tunnel, key wgtypes.Key) *wgtypes.Device {
	return &wgtypes.Device{
		Name:       resources.WgInterface,
		PrivateKey: key,
		Peers: []wgtypes.Peer{{
			PublicKey:                   tun.ServerKey,
			Endpoint:                    net.UDPAddrFromAddrPort(tun.Endpoint),
			PersistentKeepaliveInterval: resources.Keepalive,
			AllowedIPs:                  []net.IPNet{{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}},
		}},
	}
}

func TestDeviceConfig(t *testing.T) {
	key := newPrivateKey(t)
	tun := testTunnel(t)

	t.Run("no device state", func(t *testing.T) {
		got, change := deviceConfig(nil, key, tun)

		if !change {
			t.Fatal("deviceConfig(nil) change = false, want true")
		}
		if got.PrivateKey == nil || *got.PrivateKey != key {
			t.Errorf("PrivateKey = %v, want %v", got.PrivateKey, key)
		}
		if !got.ReplacePeers {
			t.Error("ReplacePeers = false, want true")
		}
		if got.ListenPort != nil {
			t.Errorf("ListenPort = %d, want nil", *got.ListenPort)
		}
		if len(got.Peers) != 1 {
			t.Fatalf("len(Peers) = %d, want 1", len(got.Peers))
		}
		p := got.Peers[0]
		if p.PublicKey != tun.ServerKey {
			t.Errorf("peer PublicKey = %v, want %v", p.PublicKey, tun.ServerKey)
		}
		if p.Endpoint == nil || p.Endpoint.String() != "10.96.0.20:51820" {
			t.Errorf("peer Endpoint = %v, want 10.96.0.20:51820", p.Endpoint)
		}
		if p.PersistentKeepaliveInterval == nil || *p.PersistentKeepaliveInterval != resources.Keepalive {
			t.Errorf("peer PersistentKeepaliveInterval = %v, want %s", p.PersistentKeepaliveInterval, resources.Keepalive)
		}
		if !p.ReplaceAllowedIPs {
			t.Error("peer ReplaceAllowedIPs = false, want true")
		}
		if len(p.AllowedIPs) != 1 || p.AllowedIPs[0].String() != "0.0.0.0/0" {
			t.Errorf("peer AllowedIPs = %v, want [0.0.0.0/0]", p.AllowedIPs)
		}
	})

	tests := []struct {
		name       string
		mutate     func(*wgtypes.Device)
		wantChange bool
	}{
		{name: "matching device", mutate: func(*wgtypes.Device) {}},
		{name: "another endpoint port", mutate: func(d *wgtypes.Device) { d.Peers[0].Endpoint.Port = 51821 }, wantChange: true},
		{name: "no endpoint", mutate: func(d *wgtypes.Device) { d.Peers[0].Endpoint = nil }, wantChange: true},
		{name: "another server key", mutate: func(d *wgtypes.Device) { d.Peers[0].PublicKey = newPrivateKey(t).PublicKey() }, wantChange: true},
		{name: "a second peer", mutate: func(d *wgtypes.Device) { d.Peers = append(d.Peers, d.Peers[0]) }, wantChange: true},
		{name: "no peer", mutate: func(d *wgtypes.Device) { d.Peers = nil }, wantChange: true},
		{name: "another private key", mutate: func(d *wgtypes.Device) { d.PrivateKey = newPrivateKey(t) }, wantChange: true},
		{name: "keepalive off", mutate: func(d *wgtypes.Device) { d.Peers[0].PersistentKeepaliveInterval = 0 }, wantChange: true},
		{
			name: "another allowed IP",
			mutate: func(d *wgtypes.Device) {
				d.Peers[0].AllowedIPs = []net.IPNet{{IP: net.ParseIP("10.8.0.1").To4(), Mask: net.CIDRMask(32, 32)}}
			},
			wantChange: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dev := matchingDevice(tun, key)
			tc.mutate(dev)

			_, change := deviceConfig(dev, key, tun)

			if change != tc.wantChange {
				t.Errorf("deviceConfig change = %v, want %v", change, tc.wantChange)
			}
		})
	}
}

func TestCheckDevice(t *testing.T) {
	now := time.Date(2026, time.November, 2, 12, 0, 0, 0, time.UTC)
	peer := func(handshake time.Time) wgtypes.Peer { return wgtypes.Peer{LastHandshakeTime: handshake} }
	tests := []struct {
		name    string
		peers   []wgtypes.Peer
		wantErr string
	}{
		{name: "no peer", wantErr: "has 0 peers, want 1"},
		{name: "two peers", peers: []wgtypes.Peer{peer(now), peer(now)}, wantErr: "has 2 peers, want 1"},
		{name: "no handshake", peers: []wgtypes.Peer{peer(time.Time{})}, wantErr: "has not completed a handshake"},
		{name: "stale handshake", peers: []wgtypes.Peer{peer(now.Add(-200 * time.Second))}, wantErr: "more than 3m0s"},
		{name: "fresh handshake", peers: []wgtypes.Peer{peer(now.Add(-10 * time.Second))}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkDevice(&wgtypes.Device{Name: resources.WgInterface, Peers: tc.peers}, now)

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkDevice: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("checkDevice error = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}
