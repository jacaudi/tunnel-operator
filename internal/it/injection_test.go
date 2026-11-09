//go:build e2e

package it

import (
	"fmt"
	"strings"

	"github.com/jacaudi/tunnel-operator/internal/resources"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	// operatorNamespace is where the chart installs the operator, and so the only namespace whose
	// default-gateway annotation the operator honours.
	operatorNamespace = "tunnel-system"
	// appsNamespace holds the labelled workloads that attach to the gateway across a namespace boundary.
	appsNamespace = "inject-apps"

	// notInjectedMessage is part of the static backstop's refusal (config/admission).
	notInjectedMessage = "but was not injected with the WireGuard sidecar"

	// injectPolicy is the MutatingAdmissionPolicy the operator writes, addressed by the beta version this
	// cluster serves.
	injectPolicy = "mutatingadmissionpolicies.v1beta1.admissionregistration.k8s.io/tunnel-operator-inject"
)

// labelledDeployment returns a plain Deployment named name with no sidecar block, whose pods opt in to
// injection by label alone. With noToken its pods set automountServiceAccountToken: false, so only the
// token the injected sidecar projects for itself can reach the apiserver.
func labelledDeployment(name string, noToken bool) string {
	automount := ""
	if noToken {
		automount = "automountServiceAccountToken: false"
	}
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata: {name: %[1]s}
spec:
  replicas: 1
  selector: {matchLabels: {app: %[1]s}}
  template:
    metadata:
      labels: {app: %[1]s, "%[2]s": "true"}
    spec:
      %[3]s
      containers:
      - name: app
        image: %[4]s
        command: [sleep, infinity]
`, name, resources.LabelEnabled, automount, curlImage)
}

// labelledPod returns a bare Pod named name, labelled for injection.
func labelledPod(name string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  labels: {"%s": "true"}
spec:
  containers:
  - name: app
    image: %s
    command: [sleep, infinity]
`, name, resources.LabelEnabled, curlImage)
}

var _ = Describe("label-driven sidecar injection", func() {
	It("injects labelled workloads through the default gateway and fails closed without one", func() {
		fetchURL := fmt.Sprintf("http://%s:%d/", exitAddress, exitHTTPPort)
		get := func(g Gomega, resource, namespace, jsonpath string) string {
			out, err := KubectlGet(resource, namespace, jsonpath)
			g.Expect(err).NotTo(HaveOccurred(), "kubectl get %s -n %s %s: %s", resource, namespace, jsonpath, out)
			return out
		}
		// dryRun asks the apiserver to admit manifests without creating them, so a probe leaves nothing behind.
		dryRun := func(manifests, namespace string) (string, error) {
			return kubectl(manifests, "apply", "--dry-run=server", "-n", namespace, "-f", "-")
		}
		// injectionLive blocks until the apiserver injects: policies take effect a moment after the operator writes them.
		injectionLive := func() {
			Eventually(func() error {
				out, err := dryRun(labelledPod("probe"), appsNamespace)
				if err != nil {
					return fmt.Errorf("%s: %w", out, err)
				}
				return nil
			}, Timeout, Interval).Should(Succeed())
		}
		// refusesLabelledPods blocks until a labelled pod is refused with the backstop's message.
		refusesLabelledPods := func() {
			Eventually(func(g Gomega) {
				out, err := dryRun(labelledPod("refused"), appsNamespace)
				g.Expect(err).To(HaveOccurred(), "a labelled pod was admitted: %s", out)
				g.Expect(out).To(ContainSubstring(notInjectedMessage))
			}, Timeout, Interval).Should(Succeed())
		}
		// podOf returns the name of the one pod of the Deployment name in namespace.
		podOf := func(g Gomega, name, namespace string) string {
			out, err := kubectl("", "get", "pods", "-n", namespace, "-l", "app="+name, "-o", "jsonpath={.items[0].metadata.name}")
			g.Expect(err).NotTo(HaveOccurred(), "pod of %s: %s", name, out)
			g.Expect(out).NotTo(BeEmpty())
			return out
		}
		canaryLog := func() (string, error) {
			return kubectl("", "logs", "-n", TestNamespace, "canary", "-c", "echo")
		}

		By("the node canary and a positive control, so a leak to the node would be seen")
		for _, fixture := range []struct{ name, manifests string }{
			{"canary", canaryManifests()},
			{"canary-client", canaryClientManifests()},
		} {
			output, err := KubectlApply(fixture.manifests, TestNamespace)
			Expect(err).NotTo(HaveOccurred(), "apply %s: %s", fixture.name, output)
		}
		Eventually(func(g Gomega) {
			body, err := KubectlExec("pod/canary-client", "curl", TestNamespace, "curl", "-sS", "--max-time", "2", fetchURL)
			g.Expect(err).NotTo(HaveOccurred(), "curl %s from canary-client: %s", fetchURL, body)
			g.Expect(body).To(Equal("node"))
		}, Timeout, Interval).Should(Succeed())

		By("an exit node and a gateway in the operator's namespace, with a second namespace for the workloads")
		// The existing specs' gateway lives in the default namespace, which the operator does not honour a
		// default annotation in. This is a second, complete one in the operator's own namespace.
		output, err := KubectlApply(exitNodeManifests(), operatorNamespace)
		Expect(err).NotTo(HaveOccurred(), "apply the exit node: %s", output)
		waitForDeploymentTobeReady("exit", operatorNamespace, GatewayTimeout)
		exitIP := get(Default, "service/exit", operatorNamespace, "{.spec.clusterIP}")
		Expect(exitIP).NotTo(BeEmpty())
		output, err = KubectlApply(gatewayManifests(exitIP, 0), operatorNamespace)
		Expect(err).NotTo(HaveOccurred(), "apply the gateway: %s", output)
		WaitForWireguardToBeReady("vpn", operatorNamespace, GatewayTimeout)

		output, err = kubectl("", "create", "namespace", appsNamespace)
		Expect(err).NotTo(HaveOccurred(), "create namespace %s: %s", appsNamespace, output)
		defer func() { _, _ = kubectl("", "delete", "namespace", appsNamespace, "--wait=false") }()

		By("with no default gateway yet, a labelled pod is refused with the backstop's message")
		refusesLabelledPods()
		// The static backstop ships in the release, so this holds from install, before any policy exists.
		output, err = kubectl("", "get", injectPolicy)
		Expect(err).To(HaveOccurred(), "the mutating policy exists before any default gateway: %s", output)

		By("annotating the gateway as the default turns injection on")
		output, err = kubectl("", "annotate", "wireguard/vpn", "-n", operatorNamespace, resources.AnnotationDefault+"=true", "--overwrite")
		Expect(err).NotTo(HaveOccurred(), "annotate the gateway: %s", output)
		injectionLive()

		// reachesExit waits for a labelled Deployment's pod to be injected, registered and tunnelled, then
		// asserts its traffic reached the exit node and never the node canary.
		reachesExit := func(name, namespace string) {
			waitForDeploymentTobeReady(name, namespace, GatewayTimeout)
			var pod, podIP string
			Eventually(func(g Gomega) {
				pod = podOf(g, name, namespace)
				podIP = get(g, "pod/"+pod, namespace, "{.status.podIP}")
				g.Expect(podIP).NotTo(BeEmpty())
			}, Timeout, Interval).Should(Succeed())

			Expect(get(Default, "pod/"+pod, namespace, "{.spec.initContainers[0].name}")).To(Equal(resources.SidecarContainer),
				"the sidecar must be the first init container")
			Expect(get(Default, "pod/"+pod, namespace, "{.spec.initContainers[0].image}")).To(Equal(agentImage),
				"the sidecar runs the operator's own agent image")
			Expect(get(Default, "pod/"+pod, namespace, "{.spec.initContainers[0].args}")).To(ContainSubstring(operatorNamespace + "/vpn"))
			WaitForPeerToBeReady(pod, namespace)

			Eventually(func(g Gomega) {
				body, err := KubectlExec("pod/"+pod, "app", namespace, "curl", "-sS", "--max-time", "2", fetchURL)
				g.Expect(err).NotTo(HaveOccurred(), "curl %s from %s/%s: %s", fetchURL, namespace, pod, body)
				expectNeverNode(g, body, err)
				g.Expect(body).To(Equal("exit"))
			}, GatewayTimeout, Interval).Should(Succeed())

			logs, err := canaryLog()
			Expect(err).NotTo(HaveOccurred(), "canary logs: %s", logs)
			Expect(logs).NotTo(ContainSubstring(" "+podIP+":"), "%s/%s leaked to the node canary", namespace, pod)
		}

		By("scenario 1: a plain labelled Deployment in another namespace reaches the exit and gets the RoleBinding")
		output, err = KubectlApply(labelledDeployment("injected", false), appsNamespace)
		Expect(err).NotTo(HaveOccurred(), "apply the labelled Deployment: %s", output)
		reachesExit("injected", appsNamespace)
		Expect(get(Default, "rolebinding/"+resources.ClientRoleName, appsNamespace, `{.metadata.labels.app\.kubernetes\.io/managed-by}`)).
			To(Equal(resources.ManagedByValue))

		By("scenario 2: a pod that mounts no ServiceAccount token is injected, registers and reaches the exit")
		output, err = KubectlApply(labelledDeployment("injected-notoken", true), appsNamespace)
		Expect(err).NotTo(HaveOccurred(), "apply the no-token Deployment: %s", output)
		reachesExit("injected-notoken", appsNamespace)

		By("scenario 3: a labelled pod in the gateway's own namespace is injected and reaches the exit")
		output, err = KubectlApply(labelledDeployment("injected-local", false), operatorNamespace)
		Expect(err).NotTo(HaveOccurred(), "apply the labelled Deployment in %s: %s", operatorNamespace, output)
		defer func() {
			_, _ = kubectl("", "delete", "deployment/injected-local", "-n", operatorNamespace, "--wait=false")
		}()
		reachesExit("injected-local", operatorNamespace)

		By("scenario 4: with the default annotation removed, a new labelled pod is refused; restored, it is injected again")
		output, err = kubectl("", "annotate", "wireguard/vpn", "-n", operatorNamespace, resources.AnnotationDefault+"-")
		Expect(err).NotTo(HaveOccurred(), "remove the default annotation: %s", output)
		// Restore it even when an assertion below fails.
		defer func() {
			_, _ = kubectl("", "annotate", "wireguard/vpn", "-n", operatorNamespace, resources.AnnotationDefault+"=true", "--overwrite")
		}()
		Eventually(func() string {
			out, _ := kubectl("", "get", injectPolicy)
			return out
		}, Timeout, Interval).Should(ContainSubstring("NotFound"), "the operator must remove its policy")
		refusesLabelledPods()

		output, err = kubectl("", "annotate", "wireguard/vpn", "-n", operatorNamespace, resources.AnnotationDefault+"=true", "--overwrite")
		Expect(err).NotTo(HaveOccurred(), "restore the default annotation: %s", output)
		injectionLive()
		output, err = KubectlApply(labelledPod("reinjected"), appsNamespace)
		Expect(err).NotTo(HaveOccurred(), "apply a labelled pod once injection is back: %s", output)
		Expect(get(Default, "pod/reinjected", appsNamespace, "{.spec.initContainers[0].name}")).To(Equal(resources.SidecarContainer))

		By("scenario 5: once the labelled workloads are gone, the namespace's RoleBinding goes")
		output, err = kubectl("", "delete", "deployment/injected", "deployment/injected-notoken", "pod/reinjected", "-n", appsNamespace, "--wait=true")
		Expect(err).NotTo(HaveOccurred(), "delete the labelled workloads: %s", output)
		Eventually(func() string {
			out, _ := KubectlGet("rolebinding/"+resources.ClientRoleName, appsNamespace, "{.metadata.name}")
			return strings.TrimSpace(out)
		}, Timeout, Interval).ShouldNot(Equal(resources.ClientRoleName), "no labelled pod remains, so the RoleBinding must be deleted")
	})
})
