//go:build e2e
// +build e2e

package it

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/wireguard-operator/api/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v12 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	kind "sigs.k8s.io/kind/pkg/cluster"
	kindcmd "sigs.k8s.io/kind/pkg/cmd"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var k8sClient client.Client
var releasePath string
var agentImage string
var managerImage string
var kindBinary string
var kubeConfigPath string

var testProvider = kind.NewProvider(
	kind.ProviderWithDocker())

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t,
		"Controller Suite")
}

const (
	Timeout = time.Second * 120
	// GatewayTimeout bounds waits that include gluetun becoming healthy through the fake exit node (about 1 s once
	// both pods run with images cached, measured on kind; the rest of the budget is image pulls on a cold node).
	GatewayTimeout      = 5 * time.Minute
	Interval            = time.Second * 1
	testClusterName     = "wg-kind-test"
	testKindContextName = "kind-" + testClusterName
	TestNamespace       = "default"
)

func waitForDeploymentTobeReady(name string, namespace string, timeout time.Duration) {
	// Wait for the rollout to complete: observed generation matches the spec
	// generation AND ready replicas equals the desired replicas. This prevents
	// false positives during rolling updates where the old pod is still ready
	// while the new pod is crash-looping.
	Eventually(func() bool {
		deploymentKey := types.NamespacedName{
			Namespace: namespace,
			Name:      name,
		}

		deployment := &v12.Deployment{}
		if err := k8sClient.Get(context.Background(), deploymentKey, deployment); err != nil {
			return false
		}
		desired := int32(1)
		if deployment.Spec.Replicas != nil {
			desired = *deployment.Spec.Replicas
		}
		return deployment.Status.ObservedGeneration >= deployment.Generation &&
			deployment.Status.ReadyReplicas == desired &&
			deployment.Status.UpdatedReplicas == desired
	}, timeout, Interval).Should(BeTrue())

}

// WaitForWireguardToBeReady waits until the controller has processed the Wireguard's current spec
// (#45), then until its Deployment has rolled out.
//
// The CR's Ready condition is the only signal that the controller has seen a spec: the condition
// records the generation of the object the reconcile rendered, so Ready=True with an
// observedGeneration that has caught up with metadata.generation means the controller acted on this
// spec. The Deployment's own generation cannot show that; it does not move until the controller
// applies the change.
//
// The controller stamps the generation of the object it rendered, so the barrier is exact.
//
// The condition type is the literal "Ready": this suite is an external client of the CRD's
// condition contract and does not import internal/controller.
func WaitForWireguardToBeReady(name string, namespace string, timeout time.Duration) {
	Eventually(func(g Gomega) {
		wgKey := types.NamespacedName{
			Namespace: namespace,
			Name:      name,
		}
		wg := &v1alpha1.Wireguard{}
		g.Expect(k8sClient.Get(context.Background(), wgKey, wg)).To(Succeed())
		ready := meta.FindStatusCondition(wg.Status.Conditions, "Ready")
		g.Expect(ready).NotTo(BeNil(), "Wireguard %s/%s has no Ready condition; conditions: %+v", namespace, name, wg.Status.Conditions)
		g.Expect(ready.Status).To(Equal(metav1.ConditionTrue), "Ready=%s reason=%s: %s", ready.Status, ready.Reason, ready.Message)
		g.Expect(ready.ObservedGeneration).To(BeNumerically(">=", wg.Generation), "Ready observedGeneration %d is behind generation %d", ready.ObservedGeneration, wg.Generation)
	}, timeout, Interval).Should(Succeed())

	waitForDeploymentTobeReady(name+"-dep", namespace, timeout)
}
func WaitForPeerToBeReady(name string, namespace string) {
	Eventually(func() string {
		wgKey := types.NamespacedName{
			Namespace: namespace,
			Name:      name,
		}
		wg := &v1alpha1.WireguardPeer{}
		k8sClient.Get(context.Background(), wgKey, wg)
		return wg.Status.Status
	}, Timeout, Interval).Should(Equal(v1alpha1.Ready))

}

func WaitForPodSucceeded(name string, namespace string) {
	Eventually(func() string {
		out, _ := exec.Command("kubectl", "--context", testKindContextName, "-n", namespace, "get", "pod", name, "-o", "jsonpath={.status.phase}").Output()
		return strings.TrimSpace(string(out))
	}, Timeout, Interval).Should(Equal("Succeeded"))
}

// kubectl runs kubectl against the test kind context with stdin (none when empty) and returns its
// trimmed stdout, or its trimmed stderr and the error when it fails.
func kubectl(stdin string, args ...string) (string, error) {
	cmd := exec.Command("kubectl", append([]string{"--context", testKindContextName}, args...)...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(stderr.String()), err
	}
	return strings.TrimSpace(stdout.String()), nil
}

func KubectlLogs(pod string, namespace string) (string, error) {
	return kubectl("", "logs", "-n", namespace, pod)
}

// KubectlExec runs a command in a container of target (deploy/<name> or pod/<name>) and returns its
// trimmed stdout, or stderr on failure.
func KubectlExec(target, container, namespace string, command ...string) (string, error) {
	return kubectl("", append([]string{"exec", "-n", namespace, target, "-c", container, "--"}, command...)...)
}

// KubectlApply applies a YAML resource to the given namespace using the test kind context.
func KubectlApply(resource string, namespace string) (string, error) {
	return kubectl(resource, "apply", "-n", namespace, "-f", "-")
}

// KubectlGet runs kubectl get with a jsonpath and returns the trimmed output.
func KubectlGet(resource string, namespace string, jsonpath string) (string, error) {
	return kubectl("", "get", "-n", namespace, resource, "-o", "jsonpath="+jsonpath)
}

// KubectlPatch patches a resource using a strategic merge patch.
func KubectlPatch(resource string, namespace string, patchType string, patch string) (string, error) {
	return kubectl("", "patch", "-n", namespace, resource, "--type", patchType, "-p", patch)
}

// exitStderr returns the trimmed stderr of a failed exec.Cmd, or "" when err is not an *exec.ExitError.
func exitStderr(err error) string {
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return strings.TrimSpace(string(exitErr.Stderr))
	}
	return ""
}

// clusterCreated is true once this run has created the kind cluster, so AfterSuite deletes only a
// cluster the run owns.
var clusterCreated bool

var _ = BeforeSuite(func() {
	envs := []struct {
		name string
		dest *string
	}{
		{"WIREGUARD_OPERATOR_RELEASE_PATH", &releasePath},
		{"AGENT_IMAGE", &agentImage},
		{"MANAGER_IMAGE", &managerImage},
		{"KIND_BIN", &kindBinary},
		{"KUBE_CONFIG", &kubeConfigPath},
	}
	var missing []string
	for _, e := range envs {
		if *e.dest = os.Getenv(e.name); *e.dest == "" {
			missing = append(missing, e.name)
		}
	}
	if len(missing) > 0 {
		Fail(fmt.Sprintf("e2e suite needs %s; run it through make run-e2e", strings.Join(missing, ", ")))
	}

	config := v1alpha4.Cluster{
		Nodes: []v1alpha4.Node{
			{
				Role: v1alpha4.ControlPlaneRole,
				ExtraPortMappings: []v1alpha4.PortMapping{
					{
						HostPort:      31820,
						ContainerPort: 31820,
						Protocol:      v1alpha4.PortMappingProtocolUDP,
					},
				},
			},
		},
	}

	By("bootstrapping test environment")

	provider := kind.NewProvider(
		kind.ProviderWithLogger(kindcmd.NewLogger()))

	err := provider.Create(testClusterName, kind.CreateWithV1Alpha4Config(&config))
	Expect(err).NotTo(HaveOccurred(), "kind create cluster %s", testClusterName)
	clusterCreated = true

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeConfigPath},
		&clientcmd.ConfigOverrides{
			CurrentContext: testKindContextName,
		})

	c, err := clientConfig.ClientConfig()
	Expect(err).NotTo(HaveOccurred(), "build the kind client config")

	// load locally built images
	for _, image := range []string{managerImage, agentImage} {
		_, err := exec.
			Command(kindBinary, "load", "docker-image", image, "--name", testClusterName).
			Output()
		Expect(err).NotTo(HaveOccurred(), "kind load docker-image %s: %s", image, exitStderr(err))
	}

	// simulate what users exactly do in real life.
	b, err := exec.
		Command("kubectl", "apply", "-f", releasePath, "--context", testKindContextName).
		Output()
	Expect(err).NotTo(HaveOccurred(), "kubectl apply -f %s: %s", releasePath, exitStderr(err))

	expectedResources := []string{
		"namespace/wireguard-system",
		"customresourcedefinition.apiextensions.k8s.io/wireguardpeers.vpn.wireguard-operator.io",
		"customresourcedefinition.apiextensions.k8s.io/wireguards.vpn.wireguard-operator.io",
		"serviceaccount/wireguard-controller-manager",
		"serviceaccount/wireguard-metrics-reader",
		"role.rbac.authorization.k8s.io/wireguard-leader-election-role",
		"clusterrole.rbac.authorization.k8s.io/wireguard-manager-role",
		"clusterrole.rbac.authorization.k8s.io/wireguard-metrics-reader",
		"rolebinding.rbac.authorization.k8s.io/wireguard-leader-election-rolebinding",
		"clusterrolebinding.rbac.authorization.k8s.io/wireguard-manager-rolebinding",
		"clusterrolebinding.rbac.authorization.k8s.io/wireguard-metrics-reader",
		"service/wireguard-controller-manager-metrics-service",
		"deployment.apps/wireguard-controller-manager",
	}

	Expect(strings.Split(strings.Trim(strings.ReplaceAll(string(b), " created", ""), "\n"), "\n")).To(BeEquivalentTo(expectedResources))

	err = v1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred(), "add the v1alpha1 scheme")

	k8sClient, err = client.New(c, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred(), "build the controller-runtime client")

	// wait until operator is ready
	Eventually(func() int {
		deploymentKey := types.NamespacedName{
			Namespace: "wireguard-system",
			Name:      "wireguard-controller-manager",
		}

		deployment := &v12.Deployment{}
		k8sClient.Get(context.Background(), deploymentKey, deployment)
		return int(deployment.Status.ReadyReplicas)
	}, Timeout, Interval).Should(Equal(1))
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	if !clusterCreated {
		return
	}
	cleanup := os.Getenv("SKIP_CLEANUP")
	if cleanup == "1" || strings.EqualFold(cleanup, "true") {
		return
	}
	err := testProvider.Delete(testClusterName, kubeConfigPath)
	Expect(err).NotTo(HaveOccurred())
})
