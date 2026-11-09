package datapath

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPeerProbeSource(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr string // exact text; empty means any error when want is also empty
	}{
		{in: "10.8.0.0/24", want: "10.8.0.2"},
		{in: "10.8.0.0/30", want: "10.8.0.2"},
		{in: "172.16.4.0/22", want: "172.16.4.2"},
		{in: "10.8.0.5/24", want: "10.8.0.2"},
		{in: "10.8.0.0/31", wantErr: `peerCIDR 10.8.0.0/31 has no second host for the peer-path probe: server address: prefix "10.8.0.0/31" has fewer than 4 addresses`},
		{in: "10.8.0.1/32"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := peerProbeSource(netip.MustParsePrefix(tt.in))
			if tt.want == "" {
				if err == nil {
					t.Fatalf("peerProbeSource(%s) = %s, want an error", tt.in, got)
				}
				if tt.wantErr != "" && err.Error() != tt.wantErr {
					t.Fatalf("error = %q, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("peerProbeSource(%s) error: %v", tt.in, err)
			}
			if got.String() != tt.want {
				t.Fatalf("peerProbeSource(%s) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}

func TestJudgePeerPath(t *testing.T) {
	probe := netip.MustParseAddr("192.0.2.1")
	src := netip.MustParseAddr("10.8.0.2")
	tests := []struct {
		name    string
		dev     string
		err     error
		wantErr string // exact text, or a prefix when wantIs is set
		wantIs  error
	}{
		{name: "tunnel", dev: "tun0"},
		{
			name:    "blackhole",
			err:     fmt.Errorf("wrap: %w", unix.EINVAL),
			wantErr: "peer path: 192.0.2.1 from 10.8.0.2 arriving on wg0 is blackholed (no tunnel route)",
		},
		{
			name:    "wrong device",
			dev:     "eth0",
			wantErr: "peer path: 192.0.2.1 from 10.8.0.2 arriving on wg0 routes via eth0, not tun0",
		},
		{
			name:    "other lookup failure",
			err:     unix.ENETUNREACH,
			wantErr: "peer path: look up 192.0.2.1 from 10.8.0.2 arriving on wg0: ",
			wantIs:  unix.ENETUNREACH,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := judgePeerPath(probe, src, tt.dev, tt.err)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("judgePeerPath = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("judgePeerPath = nil, want %q", tt.wantErr)
			}
			if tt.wantIs != nil {
				if !strings.HasPrefix(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want prefix %q", err, tt.wantErr)
				}
				if !errors.Is(err, tt.wantIs) {
					t.Fatalf("error %v does not match %v", err, tt.wantIs)
				}
				return
			}
			if err.Error() != tt.wantErr {
				t.Fatalf("error = %q, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestCheckPeerPathRejectsBadPeerCIDR(t *testing.T) {
	err := CheckPeerPath("nope")
	if err == nil {
		t.Fatal("CheckPeerPath(\"nope\") = nil, want an error")
	}
	if want := `parse peerCIDR "nope": `; !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("error = %q, want prefix %q", err, want)
	}
}
