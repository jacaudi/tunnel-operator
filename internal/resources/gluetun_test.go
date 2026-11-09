package resources

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestReservedGluetunEnv(t *testing.T) {
	got := ReservedGluetunEnv([]string{"10.96.0.0/12", "10.244.0.0/16"})
	want := []corev1.EnvVar{
		{Name: "VPN_TYPE", Value: "wireguard"},
		{Name: "VPN_INTERFACE", Value: "tun0"},
		{Name: "FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT", Value: "on"},
		{Name: "FIREWALL_INPUT_PORTS", Value: "51820,8080"},
		{Name: "FIREWALL_OUTBOUND_SUBNETS", Value: "10.96.0.0/12,10.244.0.0/16"},
		{Name: "HEALTH_SERVER_ADDRESS", Value: "127.0.0.1:9999"},
		{Name: "WIREGUARD_MTU", Value: "1320"},
		{Name: "HTTP_CONTROL_SERVER_ADDRESS", Value: "127.0.0.1:8000"},
		{Name: "HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH", Value: "/gluetun/auth/config.toml"},
		{Name: "HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE", Value: "{}"},
		{Name: "VPN_PORT_FORWARDING_LISTENING_PORT", Value: ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReservedGluetunEnv = %v, want %v", got, want)
	}
}
