//go:build e2e

package it

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jacaudi/tunnel-operator/internal/resources"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	// egressNamespace holds this spec's whole world (exit node, gateway, clients), so nothing collides with
	// the other top-level specs, which Ginkgo v1 may run in any order.
	egressNamespace = "egress-e2e"
	// egressForwardedPort is the staticPort the gateway forwards and the holder listens on, TCP and UDP.
	egressForwardedPort = 51413
	// holderScript listens on egressForwardedPort over TCP and UDP and answers each connection or datagram.
	holderScript = "nc -lk -p 51413 -e echo tcp-ok & while true; do nc -u -l -p 51413 -e echo udp-ok; done"
	readyPath    = `{.status.conditions[?(@.type=="Ready")].status}`
)

// outsiderManifest is a busybox Pod with no tunnel, so it is outside the gateway's peer network.
var outsiderManifest = fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata: {name: outsider}
spec:
  containers:
  - {name: sh, image: %s, command: [sleep, infinity]}
`, busyboxImage)

var _ = Describe("egress API", func() {
	It("serves the egress API to attached pods, cycles on request and routes the forwarded port to its holder", func() {
		ns := egressNamespace
		get := func(g Gomega, resource, jsonpath string) string {
			out, err := KubectlGet(resource, ns, jsonpath)
			g.Expect(err).NotTo(HaveOccurred(), "kubectl get %s: %s", resource, out)
			return out
		}
		exec := func(g Gomega, target, container string, command ...string) string {
			out, err := KubectlExec(target, container, ns, command...)
			g.Expect(err).NotTo(HaveOccurred(), "%v in %s of %s: %s", command, container, target, out)
			return out
		}
		vpnAgent := func(g Gomega, command ...string) string {
			return exec(g, "deploy/vpn-dep", "agent", command...)
		}
		podOf := func(name string) string {
			out, err := kubectl("", "get", "pods", "-n", ns, "-l", "app="+name, "-o", "jsonpath={.items[0].metadata.name}")
			Expect(err).NotTo(HaveOccurred(), "pod of %s: %s", name, out)
			Expect(out).NotTo(BeEmpty())
			return out
		}
		// applyClient applies the client Deployment name and waits until its pod is up, which the sidecar's
		// startup probe holds until the tunnel is up, and its peer is Ready; it returns the pod's name.
		applyClient := func(name string, podLabels map[string]string, script string) string {
			output, err := KubectlApply(egressClientManifest(name, podLabels, []string{script}), ns)
			Expect(err).NotTo(HaveOccurred(), "apply client %s: %s", name, output)
			waitForDeploymentTobeReady(name, ns, GatewayTimeout)
			pod := podOf(name)
			WaitForPeerToBeReady(pod, ns)
			return pod
		}
		peerCondition := func(g Gomega, peer, field string) string {
			return get(g, "wireguardpeer/"+peer, fmt.Sprintf(`{.status.conditions[?(@.type=="PortForwarding")].%s}`, field))
		}
		wireguard := func(g Gomega, jsonpath string) string { return get(g, "wireguard/vpn", jsonpath) }

		By("setting up namespace " + ns + " with an exit node and a gateway forwarding staticPort 51413")
		output, err := kubectl("", "create", "namespace", ns)
		Expect(err).NotTo(HaveOccurred(), "create namespace %s: %s", ns, output)
		defer func() { _, _ = kubectl("", "delete", "namespace", ns, "--wait") }()

		output, err = KubectlApply(exitNodeManifests(), ns)
		Expect(err).NotTo(HaveOccurred(), "apply the exit node: %s", output)
		waitForDeploymentTobeReady("exit", ns, GatewayTimeout)
		exitIP := get(Default, "service/exit", "{.spec.clusterIP}")
		Expect(exitIP).NotTo(BeEmpty())
		output, err = KubectlApply(gatewayManifests(exitIP, egressForwardedPort), ns)
		Expect(err).NotTo(HaveOccurred(), "apply the gateway: %s", output)
		output, err = KubectlApply(clientRBACManifests(), ns)
		Expect(err).NotTo(HaveOccurred(), "apply the client RBAC: %s", output)
		WaitForWireguardToBeReady("vpn", ns, GatewayTimeout)

		By("1: gluetun's control server refuses a request without the API key")
		output, err = KubectlExec("deploy/vpn-dep", "gluetun", ns, "wget", "-q", "-O-", "-S", "http://127.0.0.1:8000/v1/publicip/ip")
		Expect(err).To(HaveOccurred(), "an unauthenticated request to gluetun's control server succeeded: %s", output)
		Expect(output).To(ContainSubstring("401"))

		By("2: the labelled holder reads the egress API, which reports the forwarded port and that it holds it")
		holderPod := applyClient("holder", map[string]string{
			resources.LabelForwardedPort: resources.ForwardedPortValue,
			resources.LabelCycle:         resources.CycleAllowedValue,
		}, holderScript)
		var egressAPI string
		Eventually(func(g Gomega) {
			egressAPI = wireguard(g, "{.status.egressAPI}")
			g.Expect(egressAPI).NotTo(BeEmpty())
		}, Timeout, Interval).Should(Succeed())
		Eventually(func(g Gomega) {
			body := exec(g, "deploy/holder", "app", "wget", "-q", "-O-", egressAPI+"/v1/egress")
			var snapshot struct {
				ForwardedPort       int32 `json:"forwardedPort"`
				ForwardedPortHolder bool  `json:"forwardedPortHolder"`
			}
			g.Expect(json.Unmarshal([]byte(body), &snapshot)).To(Succeed(), "GET /v1/egress body: %s", body)
			g.Expect(snapshot.ForwardedPort).To(Equal(int32(egressForwardedPort)), "GET /v1/egress body: %s", body)
			g.Expect(snapshot.ForwardedPortHolder).To(BeTrue(), "GET /v1/egress body: %s", body)
		}, GatewayTimeout, Interval).Should(Succeed())

		By("3: a pod outside the tunnel is refused at the egress API port")
		output, err = KubectlApply(outsiderManifest, ns)
		Expect(err).NotTo(HaveOccurred(), "apply the outsider: %s", output)
		output, err = kubectl("", "wait", "--for=condition=Ready", "pod/outsider", "-n", ns, "--timeout=2m")
		Expect(err).NotTo(HaveOccurred(), "wait for the outsider: %s", output)
		gatewayIP, err := kubectl("", "get", "pods", "-n", ns, "-l", labels.SelectorFromSet(resources.LabelsForWireguard("vpn")).String(), "-o", "jsonpath={.items[0].status.podIP}")
		Expect(err).NotTo(HaveOccurred(), "gateway pod IP: %s", gatewayIP)
		Expect(gatewayIP).NotTo(BeEmpty())
		output, err = KubectlExec("pod/outsider", "sh", ns, "nc", "-w", "3", gatewayIP, fmt.Sprint(resources.EgressAPIPort))
		Expect(err).To(HaveOccurred(), "the egress API answered a pod outside the tunnel: %s", output)
		// busybox nc prints nothing on a refused connection and exits 1; a missing binary or exec failure would not exit 1.
		Expect(output).To(ContainSubstring("exit code 1"))

		By("4: an attached client without the cycle label is refused a cycle")
		applyClient("plain", nil, "sleep infinity")
		output, err = KubectlExec("deploy/plain", "app", ns, "wget", "-q", "-O-", "-S", "--post-data=", egressAPI+"/v1/cycle")
		Expect(err).To(HaveOccurred(), "POST /v1/cycle from an unlabelled client succeeded: %s", output)
		Expect(output).To(ContainSubstring("403"))

		By("5: the labelled holder cycles the VPN and the gateway stays Ready and leak-free")
		Eventually(func(g Gomega) { ensureLeakCounter(g, ns) }, Timeout, Interval).Should(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(exec(g, "deploy/holder", "app", "wget", "-q", "-O-", "--post-data=", egressAPI+"/v1/cycle")).To(Equal(`{"accepted":true}`))
		}, Timeout, Interval).Should(Succeed())
		Eventually(func(g Gomega) {
			// The gateway must hold Ready=True through the cycle, so this is a hard failure rather than a retry.
			Expect(wireguard(g, readyPath)).To(Equal("True"), "the gateway left Ready during the cycle")
			g.Expect(wireguard(g, "{.status.egress.lastCycle.reason}")).To(Or(Equal("IPUnchanged"), Equal("EmptyIP")))
		}, 4*time.Minute, 5*time.Second).Should(Succeed())
		expectNoLeak(Default, ns)

		By("6: the cycle-requested-at annotation produces exactly one more cycle")
		before := wireguard(Default, "{.status.egress.lastCycle.finishedAt}")
		requestedAt := time.Now().UTC().Format(time.RFC3339)
		output, err = kubectl("", "annotate", "wireguard/vpn", "-n", ns, resources.AnnotationCycleRequestedAt+"="+requestedAt, "--overwrite")
		Expect(err).NotTo(HaveOccurred(), "annotate the gateway: %s", output)
		Eventually(func(g Gomega) {
			g.Expect(wireguard(g, "{.status.egress.lastCycle.trigger}")).To(Equal("annotation:" + requestedAt))
			g.Expect(wireguard(g, "{.status.egress.lastHandledAnnotation}")).To(Equal(requestedAt))
		}, 4*time.Minute, 5*time.Second).Should(Succeed())
		finishedAt := wireguard(Default, "{.status.egress.lastCycle.finishedAt}")
		Expect(finishedAt).NotTo(Equal(before), "the annotation's cycle did not replace the previous one")
		// Once the cooldown has passed a handled annotation must not start a second cycle.
		time.Sleep(resources.CycleCooldown)
		Consistently(func(g Gomega) {
			g.Expect(wireguard(g, "{.status.egress.lastCycle.finishedAt}")).To(Equal(finishedAt))
		}, 20*time.Second, 5*time.Second).Should(Succeed())

		By("7: the exit node reaches the holder's listener through gluetun's forwarded port, over TCP and UDP")
		gluetunTunnelIP := strings.TrimSuffix(gluetunTunnelAddress, "/32")
		Eventually(func(g Gomega) {
			g.Expect(exec(g, "deploy/exit", "send", "sh", "-c", fmt.Sprintf("echo hi | nc -w 3 %s %d", gluetunTunnelIP, egressForwardedPort))).To(Equal("tcp-ok"))
			g.Expect(exec(g, "deploy/exit", "send", "sh", "-c", fmt.Sprintf("echo hi | nc -u -w 3 %s %d", gluetunTunnelIP, egressForwardedPort))).To(Equal("udp-ok"))
		}, time.Minute, Interval).Should(Succeed())

		By("8: a second labelled pod is told another peer holds the port, and takes it over when the holder goes")
		holderAddress := get(Default, "wireguardpeer/"+holderPod, "{.status.address}")
		Expect(holderAddress).NotTo(BeEmpty())
		secondPod := applyClient("second", map[string]string{resources.LabelForwardedPort: resources.ForwardedPortValue}, "sleep infinity")
		Eventually(func(g Gomega) {
			g.Expect(peerCondition(g, secondPod, "status")).To(Equal("False"))
			g.Expect(peerCondition(g, secondPod, "reason")).To(Equal("HeldByAnotherPeer"))
		}, Timeout, Interval).Should(Succeed())
		output, err = kubectl("", "delete", "deployment/holder", "-n", ns, "--wait")
		Expect(err).NotTo(HaveOccurred(), "delete the holder: %s", output)
		Eventually(func(g Gomega) {
			g.Expect(peerCondition(g, secondPod, "status")).To(Equal("True"))
			g.Expect(peerCondition(g, secondPod, "reason")).To(Equal("Held"))
		}, time.Minute, Interval).Should(Succeed())
		secondAddress := get(Default, "wireguardpeer/"+secondPod, "{.status.address}")
		Expect(secondAddress).NotTo(BeEmpty())
		// The agent reads the new holder from the state Secret the kubelet syncs into its pod, which can take a minute or two.
		Eventually(func(g Gomega) {
			nat := vpnAgent(g, "iptables-save", "-t", "nat")
			g.Expect(nat).NotTo(ContainSubstring("--to-destination "+holderAddress), "the old holder's DNAT rule is still installed")
			g.Expect(nat).To(ContainSubstring(fmt.Sprintf("--to-destination %s:%d", secondAddress, egressForwardedPort)))
		}, 3*time.Minute, Interval).Should(Succeed())

		By("9: a filter flush in the agent is repaired, with the new holder's ACCEPT rules back")
		vpnAgent(Default, "iptables", "-F")
		Eventually(func(g Gomega) {
			for _, c := range []struct{ builtin, chain string }{
				{"FORWARD", resources.ChainForward}, {"INPUT", resources.ChainInput}, {"OUTPUT", resources.ChainOutput},
			} {
				vpnAgent(g, "iptables", "-C", c.builtin, "-j", c.chain)
			}
			rules := vpnAgent(g, "iptables", "-S", resources.ChainForward)
			for _, proto := range []string{"tcp", "udp"} {
				g.Expect(rules).To(MatchRegexp(fmt.Sprintf(`(?m)^-A %s .*-d %s/32 .*-p %s .*--dport %d -j ACCEPT$`,
					resources.ChainForward, regexp.QuoteMeta(secondAddress), proto, egressForwardedPort)))
			}
		}, 15*time.Second, Interval).Should(Succeed())
	})
})
