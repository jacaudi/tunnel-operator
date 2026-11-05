// Package sidecar is the WireGuard client that runs in an application pod: it registers the pod as a WireguardPeer, configures wg0 from the server's status and routes the pod's internet traffic through it.
package sidecar

import (
	"errors"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/types"
)

// DefaultKeyPath is where the client keeps its private key: a file in the memory-backed volume
// mounted at /var/run/wireguard, so a container restart reuses the key and it never reaches disk.
const DefaultKeyPath = "/var/run/wireguard/key"

// Config is the client's configuration: its flags and the pod identity the downward API provides.
type Config struct {
	Wireguard          string    // the name of the Wireguard to attach to (--wireguard)
	WireguardNamespace string    // its namespace (--wireguard namespace/name); empty means the pod's own
	KeyPath            string    // the private key file: DefaultKeyPath in the pod, a temporary file in tests
	PodName            string    // POD_NAME
	PodNamespace       string    // POD_NAMESPACE
	PodUID             types.UID // POD_UID
}

// ConfigFromEnv returns the Config for wireguard, a name or namespace/name, and keyPath, reading the pod
// identity through getenv. It fails when wireguard is empty or malformed, when any of POD_NAME,
// POD_NAMESPACE, POD_UID, POD_IP or HOST_IP is unset (naming every missing one), and when POD_IP
// equals HOST_IP: a pod in the host network namespace would have the node's default route replaced.
func ConfigFromEnv(wireguard, keyPath string, getenv func(string) string) (Config, error) {
	if wireguard == "" {
		return Config{}, errors.New("--wireguard is required")
	}
	name, namespace := wireguard, ""
	if ns, n, ok := strings.Cut(wireguard, "/"); ok {
		if ns == "" || n == "" || strings.Contains(n, "/") {
			return Config{}, fmt.Errorf("--wireguard %q must be a name or namespace/name", wireguard)
		}
		name, namespace = n, ns
	}
	var missing []string
	for _, name := range []string{"POD_NAME", "POD_NAMESPACE", "POD_UID", "POD_IP", "HOST_IP"} {
		if getenv(name) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing environment: %s", strings.Join(missing, ", "))
	}
	if podIP := getenv("POD_IP"); podIP == getenv("HOST_IP") {
		return Config{}, fmt.Errorf("refusing to start: POD_IP %s equals HOST_IP, so the pod shares the node's network namespace and replacing its default route would cut the node off", podIP)
	}
	return Config{
		Wireguard:          name,
		WireguardNamespace: namespace,
		KeyPath:            keyPath,
		PodName:            getenv("POD_NAME"),
		PodNamespace:       getenv("POD_NAMESPACE"),
		PodUID:             types.UID(getenv("POD_UID")),
	}, nil
}
