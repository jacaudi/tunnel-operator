//go:build e2e

package it

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"strings"

	. "github.com/onsi/gomega"
)

// clientExample is the shipped example the suite applies, so the example is what the suite proves.
const clientExample = "../../examples/client.yaml"

// clientImagePlaceholder is the image reference examples/client.yaml carries for users to replace.
const clientImagePlaceholder = "ghcr.io/jacaudi/tunnel-operator/agent:vX.Y.Z"

// clientManifests returns examples/client.yaml with its image placeholder replaced by image. It fails
// the spec unless the placeholder occurs exactly once.
func clientManifests(image string) string {
	content, err := os.ReadFile(clientExample)
	Expect(err).NotTo(HaveOccurred(), "read %s", clientExample)
	Expect(strings.Count(string(content), clientImagePlaceholder)).To(Equal(1), "%s must carry %s exactly once", clientExample, clientImagePlaceholder)
	return strings.ReplaceAll(string(content), clientImagePlaceholder, image)
}

// neighbourManifests returns a Deployment and a ClusterIP Service, both named neighbour (port
// exitHTTPPort), whose pod (label app: neighbour, the Deployment's selector and the Service's)
// runs httpEchoImage with -text=neighbour.
func neighbourManifests() string {
	return fmt.Sprintf(`apiVersion: v1
kind: Service
metadata: {name: neighbour}
spec:
  selector: {app: neighbour}
  ports: [{port: %[1]d, targetPort: %[1]d}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: neighbour}
spec:
  replicas: 1
  selector: {matchLabels: {app: neighbour}}
  template:
    metadata: {labels: {app: neighbour}}
    spec:
      containers:
      - name: echo
        image: %[2]s
        args: ["-text=neighbour"]
`, exitHTTPPort, httpEchoImage)
}

// canaryManifests returns the Pod canary: hostNetwork, with a container lo (agentImage, NET_ADMIN)
// that runs `ip addr replace 203.0.113.10/32 dev lo` then sleeps, and a container echo
// (httpEchoImage, -text=node), which listens on the node's exitHTTPPort. A client whose traffic
// escaped through eth0 would get node instead of exit.
func canaryManifests() string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata: {name: canary}
spec:
  hostNetwork: true
  containers:
  - name: lo
    image: %[1]s
    command: ["sh", "-c", "ip addr replace %[2]s/32 dev lo && exec sleep infinity"]
    securityContext: {capabilities: {add: [NET_ADMIN]}}
  - name: echo
    image: %[3]s
    args: ["-text=node"]
`, agentImage, exitAddress, httpEchoImage)
}

// canaryClientManifests returns the Pod canary-client: one container curl (curlImage, sleep
// infinity) with no tunnel. Its requests to exitAddress leave through eth0, so it must get node: the
// positive control that proves the canary can catch a leak.
func canaryClientManifests() string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata: {name: canary-client}
spec:
  containers:
  - name: curl
    image: %s
    command: [sleep, infinity]
`, curlImage)
}

// appFetch runs curl in the app container of deploy/app against exitAddress:exitHTTPPort with a
// 2 s timeout and returns the body, or the error output and the error.
func appFetch() (string, error) {
	return KubectlExec("deploy/app", "app", TestNamespace, "curl", "-sS", "--max-time", "2", fmt.Sprintf("http://%s:%d/", exitAddress, exitHTTPPort))
}

// expectNeverNode asserts that the app's request reached the exit node or got no answer: body is exit
// when err is nil, and never node.
func expectNeverNode(g Gomega, body string, err error) {
	g.Expect(body).NotTo(Equal("node"), "the request leaked to the node canary")
	if err == nil {
		g.Expect(body).To(Equal("exit"))
	}
}

// expectInCluster asserts criterion 3 from the app container: getent hosts kubernetes.default
// succeeds, http://neighbour:<exitHTTPPort>/ (the Service) returns neighbour, and
// http://<neighbourIP>:<exitHTTPPort>/ (the neighbour pod directly) returns neighbour.
func expectInCluster(g Gomega, neighbourIP string) {
	out, err := KubectlExec("deploy/app", "app", TestNamespace, "getent", "hosts", "kubernetes.default")
	g.Expect(err).NotTo(HaveOccurred(), "getent hosts kubernetes.default in app: %s", out)
	for _, host := range []string{"neighbour", neighbourIP} {
		url := fmt.Sprintf("http://%s:%d/", host, exitHTTPPort)
		body, err := KubectlExec("deploy/app", "app", TestNamespace, "curl", "-sS", "--max-time", "2", url)
		g.Expect(err).NotTo(HaveOccurred(), "curl %s in app: %s", url, body)
		g.Expect(body).To(Equal("neighbour"), "curl %s in app", url)
	}
}

// routeLines returns the lines of an `ip route` listing that start with prefix.
func routeLines(routes, prefix string) []string {
	var lines []string
	for line := range strings.SplitSeq(routes, "\n") {
		if strings.HasPrefix(line, prefix) {
			lines = append(lines, line)
		}
	}
	return lines
}

// leakCounterRule is the leak counter's match: peer traffic leaving the gateway on eth0.
var leakCounterRule = []string{"POSTROUTING", "-o", "eth0", "-s", "10.8.0.0/24"}

// ensureLeakCounter adds the leak counter rule to the agent container of deploy/vpn-dep in namespace
// unless it is already there (iptables -C, then -A).
func ensureLeakCounter(g Gomega, namespace string) {
	if _, err := KubectlExec("deploy/vpn-dep", "agent", namespace, append([]string{"iptables", "-t", "mangle", "-C"}, leakCounterRule...)...); err == nil {
		return
	}
	out, err := KubectlExec("deploy/vpn-dep", "agent", namespace, append([]string{"iptables", "-t", "mangle", "-A"}, leakCounterRule...)...)
	g.Expect(err).NotTo(HaveOccurred(), "add the leak counter: %s", out)
}

// expectNoLeak asserts that the leak counter on deploy/vpn-dep in namespace reads [0:0].
func expectNoLeak(g Gomega, namespace string) {
	save, err := KubectlExec("deploy/vpn-dep", "agent", namespace, "iptables-save", "-c", "-t", "mangle")
	g.Expect(err).NotTo(HaveOccurred(), "iptables-save in vpn-dep: %s", save)
	line := leakCounterLine(save)
	g.Expect(line).To(HavePrefix("[0:0] "), "leak counter: %q", line)
}

// clientRBACManifests returns the ServiceAccount vpn-client and the RoleBinding to ClusterRole
// tunnel-operator-client: the part of examples/client.yaml before its Deployment.
func clientRBACManifests() string {
	rbac, _, found := strings.Cut(clientManifests(agentImage), "apiVersion: apps/v1")
	Expect(found).To(BeTrue(), "%s must carry its Deployment after the RBAC", clientExample)
	return rbac
}

// egressClientManifest returns one Deployment name whose pod carries labels plus app: name, the
// examples/client.yaml pod spec up to its app container (volumes and the wg-client sidecar, image set to
// agentImage), serviceAccountName vpn-client, and one app container running busyboxImage with command
// sh -c and args appArgs. The sidecar block is cut from the example, so the example is what runs.
func egressClientManifest(name string, labels map[string]string, appArgs []string) string {
	example := clientManifests(agentImage)
	start := strings.Index(example, "      volumes:\n")
	end := strings.Index(example, "      containers:\n")
	Expect(start).To(BeNumerically(">", 0), "%s must carry the pod's volumes", clientExample)
	Expect(end).To(BeNumerically(">", start), "%s must carry the app containers after its volumes and init containers", clientExample)

	podLabels := map[string]string{"app": name}
	maps.Copy(podLabels, labels)
	labelsJSON, err := json.Marshal(podLabels)
	Expect(err).NotTo(HaveOccurred())
	argsJSON, err := json.Marshal(appArgs)
	Expect(err).NotTo(HaveOccurred())

	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata: {name: %[1]s, labels: {app: %[1]s}}
spec:
  replicas: 1
  selector: {matchLabels: {app: %[1]s}}
  template:
    metadata: {labels: %[2]s}
    spec:
      serviceAccountName: vpn-client
%[3]s      containers:
      - name: app
        image: %[4]s
        command: ["sh", "-c"]
        args: %[5]s
`, name, labelsJSON, example[start:end], busyboxImage, argsJSON)
}

// crossNamespaceClientManifests returns examples/client.yaml with its image placeholder replaced by
// image and its `--wireguard vpn` argument replaced by `--wireguard <gatewayNamespace>/vpn`, so the
// client attaches to the gateway in another namespace. It fails the spec unless the argument occurs
// exactly once.
func crossNamespaceClientManifests(image, gatewayNamespace string) string {
	const arg = `"--wireguard", "vpn"`
	manifests := clientManifests(image)
	Expect(strings.Count(manifests, arg)).To(Equal(1), "%s must carry %s exactly once", clientExample, arg)
	return strings.ReplaceAll(manifests, arg, fmt.Sprintf(`"--wireguard", "%s/vpn"`, gatewayNamespace))
}
