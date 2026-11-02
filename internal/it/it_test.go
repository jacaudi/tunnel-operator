//go:build e2e
// +build e2e

package it

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jacaudi/wireguard-operator/internal/resources"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/labels"
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

	It("routes a client pod through the gateway and fails closed", func() {
		fetchURL := fmt.Sprintf("http://%s:%d/", exitAddress, exitHTTPPort)
		// get reads one jsonpath field of a resource, failing the enclosing Eventually or the spec.
		get := func(g Gomega, resource, jsonpath string) string {
			out, err := KubectlGet(resource, TestNamespace, jsonpath)
			g.Expect(err).NotTo(HaveOccurred(), "kubectl get %s %s: %s", resource, jsonpath, out)
			return out
		}
		// vpnAgent runs a command in the gateway's agent container.
		vpnAgent := func(g Gomega, command ...string) string {
			out, err := KubectlExec("deploy/vpn-dep", "agent", TestNamespace, command...)
			g.Expect(err).NotTo(HaveOccurred(), "%v in vpn-dep: %s", command, out)
			return out
		}
		// sidecar runs a command in the wg-client container of target (deploy/app or pod/<name>).
		sidecar := func(g Gomega, target string, command ...string) string {
			out, err := KubectlExec(target, "wg-client", TestNamespace, command...)
			g.Expect(err).NotTo(HaveOccurred(), "%v in wg-client of %s: %s", command, target, out)
			return out
		}
		canaryLog := func() (string, error) {
			return kubectl("", "logs", "-n", TestNamespace, "canary", "-c", "echo")
		}
		leakCounter := func() {
			Eventually(func(g Gomega) { ensureLeakCounter(g) }, Timeout, Interval).Should(Succeed())
		}
		appFetchesExit := func(timeout time.Duration) {
			Eventually(func(g Gomega) {
				body, err := appFetch()
				g.Expect(err).NotTo(HaveOccurred(), "curl %s from app: %s", fetchURL, body)
				g.Expect(body).To(Equal("exit"))
			}, timeout, Interval).Should(Succeed())
		}

		By("setting up the exit node, the gateway, the neighbour and the node canary")
		output, err := KubectlApply(exitNodeManifests(), TestNamespace)
		Expect(err).NotTo(HaveOccurred(), "apply the exit node: %s", output)
		waitForDeploymentTobeReady("exit", TestNamespace, GatewayTimeout)

		exitIP := get(Default, "service/exit", "{.spec.clusterIP}")
		Expect(exitIP).NotTo(BeEmpty())
		output, err = KubectlApply(gatewayManifests(exitIP), TestNamespace)
		Expect(err).NotTo(HaveOccurred(), "apply the gateway: %s", output)
		WaitForWireguardToBeReady("vpn", TestNamespace, GatewayTimeout)

		for _, fixture := range []struct{ name, manifests string }{
			{"neighbour", neighbourManifests()},
			{"canary", canaryManifests()},
			{"canary-client", canaryClientManifests()},
		} {
			output, err = KubectlApply(fixture.manifests, TestNamespace)
			Expect(err).NotTo(HaveOccurred(), "apply %s: %s", fixture.name, output)
		}
		waitForDeploymentTobeReady("neighbour", TestNamespace, Timeout)
		neighbourIP, err := kubectl("", "get", "pods", "-n", TestNamespace, "-l", "app=neighbour", "-o", "jsonpath={.items[0].status.podIP}")
		Expect(err).NotTo(HaveOccurred(), "neighbour pod IP: %s", neighbourIP)
		Expect(neighbourIP).NotTo(BeEmpty())
		inCluster := func() {
			Eventually(func(g Gomega) { expectInCluster(g, neighbourIP) }, Timeout, Interval).Should(Succeed())
		}

		// The canary's positive control: a pod with no tunnel reaches the canary, and the canary logs it. That
		// proves a leak would be seen, and that the log check below can fire.
		Eventually(func(g Gomega) {
			body, err := KubectlExec("pod/canary-client", "curl", TestNamespace, "curl", "-sS", "--max-time", "2", fetchURL)
			g.Expect(err).NotTo(HaveOccurred(), "curl %s from canary-client: %s", fetchURL, body)
			g.Expect(body).To(Equal("node"))
		}, Timeout, Interval).Should(Succeed())
		canaryClientIP := get(Default, "pod/canary-client", "{.status.podIP}")
		Expect(canaryClientIP).NotTo(BeEmpty())
		Eventually(func(g Gomega) {
			logs, err := canaryLog()
			g.Expect(err).NotTo(HaveOccurred(), "canary logs: %s", logs)
			g.Expect(logs).To(ContainSubstring(" " + canaryClientIP + ":"))
		}, Timeout, Interval).Should(Succeed())
		leakCounter()

		// The kube-apiserver runs OwnerReferencesPermissionEnforcement, so the client's RBAC proof (no pods/finalizers needed)
		// is real: the peer's controller owner reference would be refused without it.
		apiserverArgs, err := kubectl("", "get", "pods", "-n", "kube-system", "-l", "component=kube-apiserver", "-o", "jsonpath={.items[0].spec.containers[0].command}")
		Expect(err).NotTo(HaveOccurred(), "kube-apiserver command: %s", apiserverArgs)
		Expect(apiserverArgs).To(ContainSubstring("OwnerReferencesPermissionEnforcement"))

		By("applying examples/client.yaml and waiting for the client to register")
		output, err = KubectlApply(clientManifests(agentImage), TestNamespace)
		Expect(err).NotTo(HaveOccurred(), "apply the client: %s", output)
		waitForDeploymentTobeReady("app", TestNamespace, GatewayTimeout)

		clientPod, err := kubectl("", "get", "pods", "-n", TestNamespace, "-l", "app=app", "-o", "jsonpath={.items[0].metadata.name}")
		Expect(err).NotTo(HaveOccurred(), "client pod name: %s", clientPod)
		Expect(clientPod).NotTo(BeEmpty())
		clientUID := get(Default, "pod/"+clientPod, "{.metadata.uid}")
		peer := func(g Gomega, jsonpath string) string { return get(g, "wireguardpeer/"+clientPod, jsonpath) }

		Expect(peer(Default, "{.metadata.ownerReferences[0].kind}")).To(Equal("Pod"))
		Expect(peer(Default, "{.metadata.ownerReferences[0].uid}")).To(Equal(clientUID))
		Expect(peer(Default, "{.metadata.ownerReferences[0].controller}")).To(Equal("true"))
		clientAddress := peer(Default, "{.status.address}")
		Expect(clientAddress).NotTo(BeEmpty())

		clientKey := peer(Default, "{.spec.publicKey}")
		Eventually(func(g Gomega) {
			g.Expect(vpnAgent(g, "wg", "show", "wg0", "peers")).To(ContainSubstring(clientKey))
		}, GatewayTimeout, Interval).Should(Succeed())

		// Later steps compare restarts against these, never against literal counts: a startup-probe expiry
		// during the first rollout on a slow runner is not a defect of the recovery under test.
		const (
			sidecarRestartsPath = `{.status.initContainerStatuses[?(@.name=="wg-client")].restartCount}`
			appRestartsPath     = `{.status.containerStatuses[?(@.name=="app")].restartCount}`
			sidecarStartedPath  = `{.status.initContainerStatuses[?(@.name=="wg-client")].started}`
		)
		restarts := func(g Gomega, jsonpath string) int {
			out := get(g, "pod/"+clientPod, jsonpath)
			n, err := strconv.Atoi(out)
			g.Expect(err).NotTo(HaveOccurred(), "restart count %q at %s", out, jsonpath)
			return n
		}
		sidecarRestarts := restarts(Default, sidecarRestartsPath)
		appRestarts := restarts(Default, appRestartsPath)

		By("scenario (a): the tunnel is up")
		// The startup probe held the app until the tunnel was up, so the first request already goes through it.
		for range 5 {
			body, err := appFetch()
			Expect(err).NotTo(HaveOccurred(), "curl %s from app: %s", fetchURL, body)
			Expect(body).To(Equal("exit"))
		}
		routes := sidecar(Default, "deploy/app", "ip", "-4", "route", "show")
		Expect(routes).To(MatchRegexp(`(?m)^default dev wg0 proto 151 scope link`))
		Expect(routeLines(routes, "default")).To(HaveLen(1), "ip -4 route show:\n%s", routes)
		Expect(routes).To(MatchRegexp(`(?m)^10\.96\.0\.0/12 via \S+ dev eth0 proto 151`))
		Expect(sidecar(Default, "deploy/app", "ip", "-6", "route", "show", "default")).To(BeEmpty())
		Expect(sidecar(Default, "deploy/app", "ip", "route", "get", "1.1.1.1")).To(ContainSubstring("dev wg0"))
		Expect(sidecar(Default, "deploy/app", "ip", "link", "show", "wg0")).To(ContainSubstring("mtu 1320"))
		inCluster()
		expectNoLeak(Default)

		By("scenario (b): the exit node is gone")
		output, err = KubectlPatch("deployment/exit", TestNamespace, "merge", `{"spec":{"replicas":0}}`)
		Expect(err).NotTo(HaveOccurred(), "scale the exit node down: %s", output)
		Eventually(func(g Gomega) {
			g.Expect(get(g, "wireguard/vpn", `{.status.conditions[?(@.type=="Ready")].status}`)).To(Equal("False"))
			g.Expect(get(g, "wireguard/vpn", `{.status.conditions[?(@.type=="Ready")].reason}`)).To(Equal("DeploymentNotReady"))
		}, GatewayTimeout, Interval).Should(Succeed())
		for range 5 {
			body, err := appFetch()
			Expect(err).To(HaveOccurred(), "curl %s from app with the exit node gone returned %q", fetchURL, body)
			expectNeverNode(Default, body, err)
		}
		inCluster()
		expectNoLeak(Default)
		output, err = KubectlPatch("deployment/exit", TestNamespace, "merge", `{"spec":{"replicas":1}}`)
		Expect(err).NotTo(HaveOccurred(), "scale the exit node up: %s", output)
		waitForDeploymentTobeReady("exit", TestNamespace, GatewayTimeout)
		WaitForWireguardToBeReady("vpn", TestNamespace, GatewayTimeout)
		appFetchesExit(GatewayTimeout)

		By("scenario (c): gluetun's firewall is rolled back and its tunnel rule is gone")
		// gluetun's disable() IPv4 commands, plus the tunnel rule. Scenario (d) restores both.
		vpnAgent(Default, "sh", "-c", "iptables -F && iptables -X && iptables -P INPUT ACCEPT && iptables -P OUTPUT ACCEPT && iptables -P FORWARD ACCEPT && ip rule del pref 101")
		route, err := KubectlExec("deploy/vpn-dep", "agent", TestNamespace, "ip", "route", "get", exitAddress, "from", clientAddress, "iif", "wg0")
		Expect(err).To(HaveOccurred(), "ip route get without rule 101 returned a route: %s", route)
		Expect(route).To(ContainSubstring("Invalid argument"))
		for range 10 {
			body, err := appFetch()
			expectNeverNode(Default, body, err)
		}
		expectNoLeak(Default)
		inCluster()

		By("scenario (d): the gateway pod is replaced")
		vpnSelector := labels.SelectorFromSet(resources.LabelsForWireguard("vpn")).String()
		vpnPods := func(jsonpath string) (string, error) {
			return kubectl("", "get", "pods", "-n", TestNamespace, "-l", vpnSelector, "-o", "jsonpath="+jsonpath)
		}
		vpnPod, err := vpnPods("{.items[0].metadata.name}")
		Expect(err).NotTo(HaveOccurred(), "gateway pod name: %s", vpnPod)
		Expect(vpnPod).NotTo(BeEmpty())
		output, err = kubectl("", "delete", "pod", vpnPod, "-n", TestNamespace, "--wait=false")
		Expect(err).NotTo(HaveOccurred(), "delete the gateway pod: %s", output)
		Eventually(func(g Gomega) {
			names, err := vpnPods("{.items[*].metadata.name}")
			g.Expect(err).NotTo(HaveOccurred(), "gateway pod names: %s", names)
			g.Expect(names).NotTo(ContainSubstring(vpnPod))
		}, GatewayTimeout, Interval).Should(Succeed())
		WaitForWireguardToBeReady("vpn", TestNamespace, GatewayTimeout)
		leakCounter()
		appFetchesExit(GatewayTimeout)
		expectNoLeak(Default)
		inCluster()
		Expect(restarts(Default, sidecarRestartsPath)).To(Equal(sidecarRestarts), "the sidecar restarted when the gateway pod was replaced")
		Expect(restarts(Default, appRestartsPath)).To(Equal(appRestarts), "the app restarted when the gateway pod was replaced")

		By("scenario (f): the sidecar restarts")
		peerUID := peer(Default, "{.metadata.uid}")
		// The command's own exit may report an error because the container stops.
		_, _ = KubectlExec("pod/"+clientPod, "wg-client", TestNamespace, "sh", "-c", "kill 1")
		Eventually(func(g Gomega) {
			g.Expect(restarts(g, sidecarRestartsPath)).To(Equal(sidecarRestarts + 1))
			g.Expect(get(g, "pod/"+clientPod, sidecarStartedPath)).To(Equal("true"))
		}, GatewayTimeout, Interval).Should(Succeed())
		Expect(peer(Default, "{.spec.publicKey}")).To(Equal(clientKey), "the restarted sidecar did not reuse its key")
		Expect(peer(Default, "{.metadata.uid}")).To(Equal(peerUID), "the restarted sidecar replaced its peer")
		time.Sleep(2 * resources.ReassertInterval)
		sidecarLogs, err := kubectl("", "logs", "-n", TestNamespace, clientPod, "-c", "wg-client")
		Expect(err).NotTo(HaveOccurred(), "wg-client logs: %s", sidecarLogs)
		Expect(sidecarLogs).NotTo(ContainSubstring("client pass failed"))
		check, err := KubectlExec("pod/"+clientPod, "wg-client", TestNamespace, "agent", "client", "--check")
		Expect(err).NotTo(HaveOccurred(), "agent client --check after the restart: %s", check)
		body, err := appFetch()
		Expect(err).NotTo(HaveOccurred(), "curl %s from app: %s", fetchURL, body)
		Expect(body).To(Equal("exit"))
		inCluster()

		By("scenario (g): wg0 vanishes under the app, and stray default routes are removed")
		// One exec, so the sidecar's next pass cannot restore wg0 in between.
		left := sidecar(Default, "pod/"+clientPod, "sh", "-c", "ip link del wg0 && ip -4 route show default")
		Expect(left).To(BeEmpty(), "a default route survived deleting wg0")
		for range 3 {
			body, err := appFetch()
			expectNeverNode(Default, body, err)
		}
		expectInCluster(Default, neighbourIP)
		appFetchesExit(GatewayTimeout)

		// A CNI-style stray IPv4 default (a metric RouteReplace does not replace) and an IPv6 default.
		viaRoute := regexp.MustCompile(`via (\S+) dev eth0`).FindStringSubmatch(sidecar(Default, "pod/"+clientPod, "ip", "-4", "route", "show", "10.96.0.0/12"))
		Expect(viaRoute).To(HaveLen(2), "no `via <gateway> dev eth0` in the Service route")
		ipv6Flag, ipv6Err := KubectlExec("pod/"+clientPod, "wg-client", TestNamespace, "cat", "/proc/sys/net/ipv6/conf/eth0/disable_ipv6")
		ipv6 := ipv6Err == nil && ipv6Flag == "0"
		if ipv6 {
			By("scenario (g): removing an IPv6 stray default")
		} else {
			By(fmt.Sprintf("scenario (g): IPv6 disabled on eth0 (err=%v), skipping the IPv6 stray-default check", ipv6Err))
		}
		install := "ip route add default via " + viaRoute[1] + " dev eth0 metric 100"
		if ipv6 {
			install += " && ip -6 route add default via fe80::1 dev eth0"
		}
		install += " && ip -4 route show default"
		if ipv6 {
			install += " && ip -6 route show default"
		}
		installed := sidecar(Default, "pod/"+clientPod, "sh", "-c", install)
		defaults := routeLines(installed, "default")
		ipv6Defaults := routeLines(installed, "default via fe80::1")
		Expect(defaults).To(HaveLen(2+len(ipv6Defaults)), "the strays were not installed:\n%s", installed)
		if ipv6 {
			Expect(ipv6Defaults).To(HaveLen(1), "the IPv6 stray was not installed:\n%s", installed)
		}
		Eventually(func(g Gomega) {
			v4 := sidecar(g, "pod/"+clientPod, "ip", "-4", "route", "show")
			g.Expect(routeLines(v4, "default")).To(HaveLen(1), "ip -4 route show:\n%s", v4)
			g.Expect(v4).To(MatchRegexp(`(?m)^default dev wg0 proto 151 scope link`))
			if ipv6 {
				g.Expect(sidecar(g, "pod/"+clientPod, "ip", "-6", "route", "show", "default")).To(BeEmpty())
			}
		}, Timeout, Interval).Should(Succeed())
		body, err = appFetch()
		Expect(err).NotTo(HaveOccurred(), "curl %s from app: %s", fetchURL, body)
		Expect(body).To(Equal("exit"))
		inCluster()

		By("the canary never heard from the client")
		clientPodIP := get(Default, "pod/"+clientPod, "{.status.podIP}")
		Expect(clientPodIP).NotTo(BeEmpty())
		logs, err := canaryLog()
		Expect(err).NotTo(HaveOccurred(), "canary logs: %s", logs)
		Expect(logs).NotTo(ContainSubstring(" "+clientPodIP+":"), "the client's request reached the node canary")

		By("scenario (e): five replicas, five addresses")
		output, err = KubectlPatch("deployment/app", TestNamespace, "merge", `{"spec":{"replicas":5}}`)
		Expect(err).NotTo(HaveOccurred(), "scale the client up: %s", output)
		waitForDeploymentTobeReady("app", TestNamespace, GatewayTimeout)
		podNames, err := kubectl("", "get", "pods", "-n", TestNamespace, "-l", "app=app", "-o", "jsonpath={.items[*].metadata.name}")
		Expect(err).NotTo(HaveOccurred(), "client pod names: %s", podNames)
		Expect(strings.Fields(podNames)).To(HaveLen(5))
		addresses := map[string]struct{}{}
		for name := range strings.FieldsSeq(podNames) {
			var address string
			Eventually(func(g Gomega) {
				address = get(g, "wireguardpeer/"+name, "{.status.address}")
				g.Expect(address).NotTo(BeEmpty())
			}, Timeout, Interval).Should(Succeed())
			addresses[address] = struct{}{}
		}
		Expect(addresses).To(HaveLen(5), "addresses: %v", addresses)

		By("scenario (e): a deleted pod's peer goes away")
		output, err = kubectl("", "delete", "pod", clientPod, "-n", TestNamespace, "--wait=false")
		Expect(err).NotTo(HaveOccurred(), "delete the client pod: %s", output)
		Eventually(func(g Gomega) {
			out, err := KubectlGet("wireguardpeer/"+clientPod, TestNamespace, "{.metadata.name}")
			g.Expect(err).To(HaveOccurred(), "wireguardpeer/%s still exists: %s", clientPod, out)
			g.Expect(out).To(Or(ContainSubstring("NotFound"), ContainSubstring("not found")))
		}, Timeout, Interval).Should(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(vpnAgent(g, "wg", "show", "wg0", "peers")).NotTo(ContainSubstring(clientKey))
		}, GatewayTimeout, Interval).Should(Succeed())
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
