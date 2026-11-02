//go:build e2e
// +build e2e

package it

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("wireguard controller", func() {
	It("egresses a peer's traffic through gluetun and leaks nothing on eth0", func() {
		// The fake exit node: a WireGuard peer for gluetun with a test address on its loopback behind http-echo.
		output, err := KubectlApply(exitNodeManifests(), TestNamespace)
		Expect(err).NotTo(HaveOccurred(), "apply the exit node: %s", output)
		waitForDeploymentTobeReady("exit", TestNamespace, GatewayTimeout)

		exitIP, err := KubectlGet("service/exit", TestNamespace, "{.spec.clusterIP}")
		Expect(err).NotTo(HaveOccurred(), "kubectl get service/exit: %s", exitIP)
		Expect(exitIP).NotTo(BeEmpty())

		output, err = KubectlApply(gatewayManifests(exitIP), TestNamespace)
		Expect(err).NotTo(HaveOccurred(), "apply the gateway: %s", output)
		output, err = KubectlApply(testPeerManifests(), TestNamespace)
		Expect(err).NotTo(HaveOccurred(), "apply the peer: %s", output)

		// Ready now includes gluetun being healthy through its tunnel to the exit node.
		WaitForWireguardToBeReady("vpn", TestNamespace, GatewayTimeout)
		WaitForPeerToBeReady("peer20", TestNamespace)

		// The controller allocated the peer an address from the server's peerCIDR.
		Eventually(func(g Gomega) {
			address, err := KubectlGet("wireguardpeer/peer20", TestNamespace, "{.status.address}")
			g.Expect(err).NotTo(HaveOccurred(), "kubectl get wireguardpeer/peer20: %s", address)
			g.Expect(address).To(Equal("10.8.0.2"))
		}, Timeout, Interval).Should(Succeed())

		// The server published the address a client dials: the Service's ClusterIP and WireGuard port.
		Eventually(func(g Gomega) {
			endpoint, err := KubectlGet("wireguard/vpn", TestNamespace, "{.status.endpoint}")
			g.Expect(err).NotTo(HaveOccurred(), "kubectl get wireguard/vpn: %s", endpoint)
			clusterIP, err := KubectlGet("service/vpn-svc", TestNamespace, "{.spec.clusterIP}")
			g.Expect(err).NotTo(HaveOccurred(), "kubectl get service/vpn-svc: %s", clusterIP)
			g.Expect(endpoint).To(Equal(clusterIP + ":51820"))
		}, Timeout, Interval).Should(Succeed())

		// The agent's wg0 admitted the peer, so the controller's state reached the agent.
		Eventually(func(g Gomega) {
			peers, err := KubectlExec("deploy/vpn-dep", "agent", TestNamespace, "wg", "show", "wg0", "peers")
			g.Expect(err).NotTo(HaveOccurred(), "wg show wg0 peers in vpn-dep: %s", peers)
			g.Expect(peers).To(ContainSubstring(testPeerPublicKey))
		}, Timeout, Interval).Should(Succeed())

		// The agent installed the fail-closed datapath: both ip rules, both one-route tables, and the
		// forwarding, masquerade and MSS rules.
		inAgent := func(g Gomega, command ...string) string {
			out, err := KubectlExec("deploy/vpn-dep", "agent", TestNamespace, command...)
			g.Expect(err).NotTo(HaveOccurred(), "%v in vpn-dep: %s", command, out)
			return out
		}
		Eventually(func(g Gomega) {
			rules := inAgent(g, "ip", "rule", "show")
			g.Expect(rules).To(MatchRegexp(`(?m)^90:\s+from all to 10\.8\.0\.0/24 lookup 51821$`))
			g.Expect(rules).To(MatchRegexp(`(?m)^102:\s+from all iif wg0 lookup 51822$`))
		}, Timeout, Interval).Should(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(inAgent(g, "ip", "route", "show", "table", "51821")).To(ContainSubstring("10.8.0.0/24 dev wg0"))
		}, Timeout, Interval).Should(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(inAgent(g, "ip", "route", "show", "table", "51822")).To(ContainSubstring("blackhole default"))
		}, Timeout, Interval).Should(Succeed())
		Eventually(func(g Gomega) {
			forward := inAgent(g, "iptables", "-S", "FORWARD")
			g.Expect(forward).To(ContainSubstring("-P FORWARD DROP"))
			g.Expect(forward).To(ContainSubstring("-A FORWARD -s 10.8.0.0/24 -i wg0 -o tun0 -j ACCEPT"))
			g.Expect(forward).To(ContainSubstring("-A FORWARD -i tun0 -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"))
		}, Timeout, Interval).Should(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(inAgent(g, "iptables", "-t", "nat", "-S", "POSTROUTING")).To(ContainSubstring("-A POSTROUTING -s 10.8.0.0/24 -o tun0 -j MASQUERADE"))
		}, Timeout, Interval).Should(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(inAgent(g, "iptables", "-t", "mangle", "-S", "FORWARD")).To(ContainSubstring("-A FORWARD -o tun0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"))
		}, Timeout, Interval).Should(Succeed())

		// The leak counter: a rule that matches peer traffic leaving on eth0 and does nothing else.
		// A fail-closed gateway never lets a packet reach it.
		out, err := KubectlExec("deploy/vpn-dep", "agent", TestNamespace, "iptables", "-t", "mangle", "-A", "POSTROUTING", "-o", "eth0", "-s", "10.8.0.0/24")
		Expect(err).NotTo(HaveOccurred(), "add the leak counter: %s", out)

		// A hand-configured peer with the address the controller allocated to peer20.
		publicKey, err := KubectlGet("wireguard/vpn", TestNamespace, "{.status.publicKey}")
		Expect(err).NotTo(HaveOccurred(), "kubectl get wireguard/vpn: %s", publicKey)
		endpoint, err := KubectlGet("wireguard/vpn", TestNamespace, "{.status.endpoint}")
		Expect(err).NotTo(HaveOccurred(), "kubectl get wireguard/vpn: %s", endpoint)
		output, err = KubectlApply(testPeerPod("10.8.0.2", publicKey, endpoint), TestNamespace)
		Expect(err).NotTo(HaveOccurred(), "apply the test peer pod: %s", output)
		Eventually(func(g Gomega) {
			phase, err := KubectlGet("pod/tpeer", TestNamespace, "{.status.phase}")
			g.Expect(err).NotTo(HaveOccurred(), "kubectl get pod/tpeer: %s", phase)
			g.Expect(phase).To(Equal("Running"))
		}, Timeout, Interval).Should(Succeed())

		// The peer reaches the exit node's test address through the gateway and gluetun's tunnel. The
		// first fetch waits out the peer's handshake and the container start.
		fetch := func() (string, error) {
			return KubectlExec("pod/tpeer", "curl", TestNamespace, "curl", "-sS", "--max-time", "5", fmt.Sprintf("http://%s:%d/", exitAddress, exitHTTPPort))
		}
		Eventually(func(g Gomega) {
			body, err := fetch()
			g.Expect(err).NotTo(HaveOccurred(), "curl %s:%d from tpeer: %s", exitAddress, exitHTTPPort, body)
			g.Expect(body).To(Equal("exit"))
		}, GatewayTimeout, Interval).Should(Succeed())
		for range 5 {
			body, err := fetch()
			Expect(err).NotTo(HaveOccurred(), "curl %s:%d from tpeer: %s", exitAddress, exitHTTPPort, body)
			Expect(body).To(Equal("exit"))
		}

		// None of that traffic left the gateway on eth0.
		save, err := KubectlExec("deploy/vpn-dep", "agent", TestNamespace, "iptables-save", "-c", "-t", "mangle")
		Expect(err).NotTo(HaveOccurred(), "iptables-save in vpn-dep: %s", save)
		line := leakCounterLine(save)
		Expect(line).To(HavePrefix("[0:0] "), "leak counter: %q", line)

		// The blackhole rule is what stops peer traffic when gluetun's tunnel rule (pref 101) is gone: with
		// it removed, a wg0 packet falls through to the agent's pref-102 rule and the blackhole default.
		routeGet := func() (string, error) {
			return KubectlExec("deploy/vpn-dep", "agent", TestNamespace, "ip", "route", "get", exitAddress, "from", "10.8.0.2", "iif", "wg0")
		}
		restoreRule := func() (string, error) {
			return KubectlExec("deploy/vpn-dep", "agent", TestNamespace, "ip", "rule", "add", "not", "fwmark", "51820", "lookup", "51820", "pref", "101")
		}

		// Positive control: with gluetun's rule in place the peer's packet routes into tun0.
		route, err := routeGet()
		Expect(err).NotTo(HaveOccurred(), "ip route get before deleting rule 101: %s", route)
		Expect(route).To(ContainSubstring("dev tun0"))

		// Restore rule 101 even when an assertion below fails. Ginkgo's Fail panics, so the deferred call
		// runs; "File exists" means gluetun or the explicit restore below already put it back.
		defer func() {
			if restored, restoreErr := restoreRule(); restoreErr != nil && !strings.Contains(restored, "File exists") {
				fmt.Fprintf(GinkgoWriter, "restore ip rule 101: %v: %s\n", restoreErr, restored)
			}
		}()
		out, err = KubectlExec("deploy/vpn-dep", "agent", TestNamespace, "ip", "rule", "del", "pref", "101")
		Expect(err).NotTo(HaveOccurred(), "delete gluetun's ip rule 101: %s", out)

		// The kernel returns -EINVAL for a FIB result of RTN_BLACKHOLE, so ip prints "Invalid argument"
		// and never the word "blackhole".
		route, err = routeGet()
		Expect(err).To(HaveOccurred(), "ip route get without rule 101 returned a route: %s", route)
		Expect(route).To(ContainSubstring("Invalid argument"))
		Expect(route).NotTo(ContainSubstring("dev eth0"))

		// The packet itself is dropped, not rerouted.
		body, err := fetch()
		Expect(err).To(HaveOccurred(), "curl %s:%d from tpeer without rule 101 succeeded: %s", exitAddress, exitHTTPPort, body)
		save, err = KubectlExec("deploy/vpn-dep", "agent", TestNamespace, "iptables-save", "-c", "-t", "mangle")
		Expect(err).NotTo(HaveOccurred(), "iptables-save in vpn-dep: %s", save)
		line = leakCounterLine(save)
		Expect(line).To(HavePrefix("[0:0] "), "leak counter after deleting rule 101: %q", line)

		// Restoring the rule restores the path.
		out, err = restoreRule()
		if err != nil {
			Expect(out).To(ContainSubstring("File exists"), "restore ip rule 101")
		}
		Eventually(func(g Gomega) {
			body, err := fetch()
			g.Expect(err).NotTo(HaveOccurred(), "curl %s:%d from tpeer after restoring rule 101: %s", exitAddress, exitHTTPPort, body)
			g.Expect(body).To(Equal("exit"))
		}, GatewayTimeout, Interval).Should(Succeed())
		route, err = routeGet()
		Expect(err).NotTo(HaveOccurred(), "ip route get after restoring rule 101: %s", route)
		Expect(route).To(ContainSubstring("dev tun0"))
	})

	It("exposes controller manager metrics", func() {
		// Ensure the controller-manager Deployment is ready (BeforeSuite already waits for it)

		controllerMetricsCheckPod := `
apiVersion: v1
kind: Pod
metadata:
  name: controller-metrics-check
  namespace: wireguard-system
spec:
  restartPolicy: Never
  serviceAccountName: wireguard-metrics-reader
  containers:
  - name: curl
    image: curlimages/curl:8.17.0
    command: ["sh","-c"]
    args:
    - >
      TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token);
      curl -sS -H "Authorization: Bearer $TOKEN" http://wireguard-controller-manager-metrics-service.wireguard-system.svc.cluster.local:8080/metrics |
      grep -E 'controller_runtime_reconcile_total|process_cpu_seconds_total'
`
		output, err := KubectlApply(controllerMetricsCheckPod, "wireguard-system")
		Expect(err).NotTo(HaveOccurred())
		Expect(output).To(Equal("pod/controller-metrics-check created"))

		WaitForPodSucceeded("controller-metrics-check", "wireguard-system")

		logs, err := KubectlLogs("controller-metrics-check", "wireguard-system")
		Expect(err).NotTo(HaveOccurred())
		Expect(logs).To(ContainSubstring("controller_runtime_reconcile_total"))
	})
})
