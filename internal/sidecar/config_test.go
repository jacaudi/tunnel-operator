package sidecar

import (
	"maps"
	"strings"
	"testing"
)

func TestConfigFromEnv(t *testing.T) {
	full := map[string]string{
		"POD_NAME":      "app-1",
		"POD_NAMESPACE": "media",
		"POD_UID":       "uid-1",
		"POD_IP":        "10.244.0.7",
		"HOST_IP":       "172.18.0.2",
	}
	without := func(keys ...string) map[string]string {
		env := maps.Clone(full)
		for _, k := range keys {
			delete(env, k)
		}
		return env
	}
	hostNetwork := without()
	hostNetwork["POD_IP"] = "172.18.0.2"

	tests := []struct {
		name      string
		wireguard string
		env       map[string]string
		want      Config
		wantErr   string // exact text, or a prefix when prefix is set
		prefix    bool
	}{
		{
			name:      "gateway in another namespace",
			wireguard: "network/vpn",
			env:       full,
			want: Config{
				Wireguard:          "vpn",
				WireguardNamespace: "network",
				KeyPath:            DefaultKeyPath,
				PodName:            "app-1",
				PodNamespace:       "media",
				PodUID:             "uid-1",
			},
		},
		{
			name:      "full environment",
			wireguard: "vpn",
			env:       full,
			want: Config{
				Wireguard:    "vpn",
				KeyPath:      DefaultKeyPath,
				PodName:      "app-1",
				PodNamespace: "media",
				PodUID:       "uid-1",
			},
		},
		{
			name:      "namespace without a name",
			wireguard: "network/",
			env:       full,
			wantErr:   `--wireguard "network/" must be a name or namespace/name`,
		},
		{
			name:      "name without a namespace",
			wireguard: "/vpn",
			env:       full,
			wantErr:   `--wireguard "/vpn" must be a name or namespace/name`,
		},
		{
			name:      "too many parts",
			wireguard: "a/b/c",
			env:       full,
			wantErr:   `--wireguard "a/b/c" must be a name or namespace/name`,
		},
		{
			name:    "no wireguard",
			env:     full,
			wantErr: "--wireguard is required",
		},
		{
			name:      "names every missing variable in order",
			wireguard: "vpn",
			env:       without("HOST_IP", "POD_UID"),
			wantErr:   "missing environment: POD_UID, HOST_IP",
		},
		{
			name:      "host network",
			wireguard: "vpn",
			env:       hostNetwork,
			wantErr:   "refusing to start: POD_IP 172.18.0.2 equals HOST_IP",
			prefix:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConfigFromEnv(tt.wireguard, DefaultKeyPath, func(k string) string { return tt.env[k] })
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ConfigFromEnv() = %+v, want error %q", got, tt.wantErr)
				}
				if tt.prefix && !strings.HasPrefix(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want prefix %q", err, tt.wantErr)
				}
				if !tt.prefix && err.Error() != tt.wantErr {
					t.Errorf("error = %q, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ConfigFromEnv() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ConfigFromEnv() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
