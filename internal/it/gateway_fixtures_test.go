//go:build e2e

package it

import (
	"fmt"
	"strings"
)

// Test-only WireGuard keys: they exist only for this suite and protect nothing.
const (
	exitPrivateKey     = "KJhsh78nyP8dtJ87MdLg+0JO145XEECk9tfWI6vnRn0="
	exitPublicKey      = "AYNRJn0s26gSGnHymNxYenvpLT2xTbnGMD/tcplNOAs="
	gluetunPrivateKey  = "cHJnm6zzjcI0NdODUiV//ucNIJDtzU1Dw6htwW7WNlM="
	gluetunPublicKey   = "b5uYV5xkLlRwTcTcMeQMTsH5nUprO6/G2G5my9Ozg0I="
	testPeerPrivateKey = "8P7aWcSyobr1TmkcGVQq/QUBZEqor2qEqaecOfwK0mg="
	testPeerPublicKey  = "4qsgD4XEJr/mtQz9hFK1UNYa23NEEFvsMaAAbPDN0Xo="
)

const (
	// exitAddress lives on the exit node's loopback, so a request for it only succeeds by travelling
	// through the tunnel.
	exitAddress          = "203.0.113.10"
	gluetunTunnelAddress = "10.64.0.2/32"
	exitTunnelAddress    = "10.64.0.1/24"
	httpEchoImage        = "hashicorp/http-echo:1.0.0"
	// exitHTTPPort is http-echo's default port; the image runs as non-root and cannot bind :80.
	exitHTTPPort = 5678
	curlImage    = "curlimages/curl:8.17.0"
	// kindLocalCIDRs is a YAML flow list covering kind's node, pod and Service ranges (and GitHub
	// runners' Docker network), overlapping neither the peer CIDR 10.8.0.0/24 nor the exit tunnel.
	kindLocalCIDRs = "[10.244.0.0/16, 10.96.0.0/12, 172.16.0.0/12]"
)

// exitNodeManifests returns the exit node: a Secret exit-key holding exitPrivateKey, a Deployment exit
// whose pod runs a privileged sysctl init (ip_forward=1), a wg container (agentImage) that brings up
// wg0 at exitTunnelAddress with gluetun as its only peer, masquerades -o eth0 and adds exitAddress to
// lo, and an echo container (httpEchoImage, args -text=exit, listening on exitHTTPPort); and a ClusterIP Service exit on
// UDP 51820.
func exitNodeManifests() string {
	return fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata: {name: exit-key}
stringData: {private: %[1]s}
---
apiVersion: v1
kind: Service
metadata: {name: exit}
spec:
  selector: {app: exit}
  ports: [{name: wg, protocol: UDP, port: 51820, targetPort: 51820}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: exit}
spec:
  replicas: 1
  selector: {matchLabels: {app: exit}}
  template:
    metadata: {labels: {app: exit}}
    spec:
      initContainers:
      - name: sysctl
        image: %[2]s
        command: [sh, -c, "echo 1 > /proc/sys/net/ipv4/ip_forward"]
        securityContext: {privileged: true}
      containers:
      - name: wg
        image: %[2]s
        command:
        - sh
        - -c
        - |
          set -ex
          ip link add wg0 type wireguard
          wg set wg0 private-key /keys/private listen-port 51820 peer %[3]s allowed-ips %[4]s
          ip addr add %[5]s dev wg0
          ip link set wg0 up
          iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
          ip addr add %[6]s/32 dev lo
          exec sleep infinity
        securityContext: {capabilities: {add: [NET_ADMIN]}}
        volumeMounts: [{name: keys, mountPath: /keys, readOnly: true}]
      - name: echo
        image: %[7]s
        args: ["-text=exit"]
      volumes: [{name: keys, secret: {secretName: exit-key}}]
`, exitPrivateKey, agentImage, gluetunPublicKey, gluetunTunnelAddress, exitTunnelAddress, exitAddress, httpEchoImage)
}

// gatewayManifests returns a Secret gluetun-key holding WIREGUARD_PRIVATE_KEY=gluetunPrivateKey and the
// Wireguard vpn: localCIDRs kindLocalCIDRs; gluetun env VPN_SERVICE_PROVIDER=custom,
// WIREGUARD_ENDPOINT_IP=exitIP, WIREGUARD_ENDPOINT_PORT=51820, WIREGUARD_PUBLIC_KEY=exitPublicKey,
// WIREGUARD_ADDRESSES=gluetunTunnelAddress, HEALTH_TARGET_ADDRESSES=<exitAddress>:<exitHTTPPort> and
// HEALTH_ICMP_TARGET_IPS=exitAddress; envFrom the gluetun-key Secret.
func gatewayManifests(exitIP string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata: {name: gluetun-key}
stringData: {WIREGUARD_PRIVATE_KEY: %s}
---
apiVersion: vpn.tunnel-operator.io/v1alpha1
kind: Wireguard
metadata: {name: vpn}
spec:
  localCIDRs: %s
  gluetun:
    env:
    - {name: VPN_SERVICE_PROVIDER, value: custom}
    - {name: WIREGUARD_ENDPOINT_IP, value: "%s"}
    - {name: WIREGUARD_ENDPOINT_PORT, value: "51820"}
    - {name: WIREGUARD_PUBLIC_KEY, value: "%s"}
    - {name: WIREGUARD_ADDRESSES, value: "%s"}
    - {name: HEALTH_TARGET_ADDRESSES, value: "%s:%d"}
    - {name: HEALTH_ICMP_TARGET_IPS, value: "%s"}
    envFrom:
    - secretRef: {name: gluetun-key}
`, gluetunPrivateKey, kindLocalCIDRs, exitIP, exitPublicKey, gluetunTunnelAddress, exitAddress, exitHTTPPort, exitAddress)
}

// testPeerManifests returns the WireguardPeer peer20 (wireguardRef vpn, publicKey testPeerPublicKey).
func testPeerManifests() string {
	return fmt.Sprintf(`apiVersion: vpn.tunnel-operator.io/v1alpha1
kind: WireguardPeer
metadata: {name: peer20}
spec:
  wireguardRef: vpn
  publicKey: "%s"
`, testPeerPublicKey)
}

// testPeerPod returns the Pod tpeer: a wg container (agentImage, NET_ADMIN) that brings up wg0 at
// address/32 with the server as its only peer (endpoint, AllowedIPs exitAddress/32, keepalive 25,
// MTU 1320) and routes exitAddress/32 via wg0; and a curl container (curlImage, sleep).
func testPeerPod(address, serverPublicKey, endpoint string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata: {name: tpeer}
spec:
  containers:
  - name: wg
    image: %[1]s
    env: [{name: WG_PRIVATE_KEY, value: "%[2]s"}]
    command:
    - sh
    - -c
    - |
      set -ex
      printf '%%s' "$WG_PRIVATE_KEY" > /tmp/wg.key
      ip link add wg0 type wireguard
      wg set wg0 private-key /tmp/wg.key peer %[3]s endpoint %[4]s allowed-ips %[5]s/32 persistent-keepalive 25
      ip addr add %[6]s/32 dev wg0
      ip link set wg0 mtu 1320 up
      ip route add %[5]s/32 dev wg0
      exec sleep infinity
    securityContext: {capabilities: {add: [NET_ADMIN]}}
  - name: curl
    image: %[7]s
    command: [sleep, infinity]
`, agentImage, testPeerPrivateKey, serverPublicKey, endpoint, exitAddress, address, curlImage)
}

// leakCounterLine returns the line of an `iptables-save -c` dump holding the leak counter rule (peer
// traffic leaving on eth0), or "" when there is none.
func leakCounterLine(save string) string {
	for line := range strings.SplitSeq(save, "\n") {
		if strings.Contains(line, "-A POSTROUTING -s 10.8.0.0/24 -o eth0") {
			return line
		}
	}
	return ""
}
