package ipam

import (
	"net/netip"
	"testing"
)

func TestServerAddress(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		want    string
		wantErr bool
	}{
		{name: "masked /24", prefix: "10.8.0.0/24", want: "10.8.0.1"},
		{name: "unmasked /24", prefix: "10.8.0.5/24", want: "10.8.0.1"},
		{name: "smallest usable /30", prefix: "192.168.0.0/30", want: "192.168.0.1"},
		{name: "too small /31", prefix: "10.8.0.0/31", wantErr: true},
		{name: "ipv6", prefix: "fd00::/64", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ServerAddress(netip.MustParsePrefix(tt.prefix))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ServerAddress(%s) error = %v, wantErr %v", tt.prefix, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.String() != tt.want {
				t.Errorf("ServerAddress(%s) = %s, want %s", tt.prefix, got, tt.want)
			}
		})
	}
}
