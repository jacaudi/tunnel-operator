//go:build integration

package controllers

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jacaudi/tunnel-operator/internal/resources"
)

// notInjectedMessage and hostNetworkMessage are the static backstop's two denials
// (config/admission/require_injection_policy.yaml).
const (
	notInjectedMessage = "but was not injected with the WireGuard sidecar"
	hostNetworkMessage = "hostNetwork pods cannot be tunnelled"
)

// labelledPod returns a pod opted in to injection, in namespace ns, that has not been injected.
// mutate adjusts it before the caller creates it.
func labelledPod(ns string, mutate ...func(*corev1.Pod)) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "labelled-",
			Namespace:    ns,
			Labels:       map[string]string{resources.LabelEnabled: "true"},
		},
		Spec: corev1.PodSpec{
			// A real apiserver's ServiceAccount admission plugin defaults this before validation, and a
			// projected token is invalid without it. envtest runs that plugin disabled, so the pod says it.
			ServiceAccountName: "default",
			Containers:         []corev1.Container{{Name: "app", Image: "busybox"}},
		},
	}
	for _, m := range mutate {
		m(pod)
	}
	return pod
}

// The static backstop must refuse a labelled pod that was not injected. These specs hold with no
// default gateway, so nothing injects: every labelled pod below arrives as written.
var _ = Describe("require-injection backstop", func() {
	// A policy left by another spec would inject these pods instead of leaving them as written.
	BeforeEach(waitForNoInjectPolicy)

	var created []*corev1.Pod
	create := func(pod *corev1.Pod) error {
		err := k8sClient.Create(context.Background(), pod)
		if err == nil {
			created = append(created, pod)
		}
		return err
	}
	AfterEach(func() {
		for _, pod := range created {
			_ = k8sClient.Delete(context.Background(), pod, client.GracePeriodSeconds(0))
		}
		created = nil
	})

	It("rejects a labelled pod that was not injected, naming the cause", func() {
		err := create(labelledPod("default"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(notInjectedMessage))
		Expect(err.Error()).To(ContainSubstring("annotated wireguard-operator.io/default=true"))
	})

	It("rejects a labelled hostNetwork pod with the hostNetwork message", func() {
		err := create(labelledPod("default", func(p *corev1.Pod) { p.Spec.HostNetwork = true }))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(hostNetworkMessage))
	})

	It("admits an unlabelled pod", func() {
		pod := labelledPod("default", func(p *corev1.Pod) { p.Labels = nil })
		Expect(create(pod)).To(Succeed())
	})

	It("admits a labelled pod that is the operator's own component", func() {
		pod := labelledPod("default", func(p *corev1.Pod) { p.Labels[resources.LabelComponent] = resources.ComponentGateway })
		Expect(create(pod)).To(Succeed())
	})

	It("admits a labelled pod in kube-system", func() {
		Expect(create(labelledPod("kube-system"))).To(Succeed())
	})

	It("admits a labelled pod that already carries wg-client first, as a native sidecar", func() {
		pod := labelledPod("default", func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{
				Name:          resources.SidecarContainer,
				Image:         "busybox",
				RestartPolicy: new(corev1.ContainerRestartPolicyAlways),
			}}
		})
		Expect(create(pod)).To(Succeed())
	})

	It("rejects a labelled pod whose wg-client is not a native sidecar", func() {
		err := create(labelledPod("default", func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: resources.SidecarContainer, Image: "busybox"}}
		}))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(notInjectedMessage))
	})

	It("rejects a labelled pod whose wg-client is not the first init container", func() {
		err := create(labelledPod("default", func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{
				{Name: "first", Image: "busybox"},
				{Name: resources.SidecarContainer, Image: "busybox", RestartPolicy: new(corev1.ContainerRestartPolicyAlways)},
			}
		}))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(notInjectedMessage))
	})
})

// waitForBackstop blocks until the apiserver enforces the static backstop. A policy and binding take
// effect asynchronously after they are created, so the suite probes with a labelled pod, which is
// refused once the policy is live, and creates nothing.
func waitForBackstop() {
	Eventually(func() error {
		pod := labelledPod("default")
		err := k8sClient.Create(context.Background(), pod)
		if err == nil {
			_ = k8sClient.Delete(context.Background(), pod, client.GracePeriodSeconds(0))
			return fmt.Errorf("a labelled pod was admitted: the backstop is not enforced yet")
		}
		if !strings.Contains(err.Error(), notInjectedMessage) {
			return fmt.Errorf("the labelled probe pod was refused for another reason: %w", err)
		}
		return nil
	}, 30*time.Second, 250*time.Millisecond).Should(Succeed())
}

// installAdmissionBackstop creates the policy and binding the release ships, from the same files in
// config/admission, so the suite proves the shipped manifests rather than a copy of them. The names
// are the unprefixed ones: only kustomize adds the namePrefix.
func installAdmissionBackstop() {
	files, err := filepath.Glob(filepath.Join("..", "..", "config", "admission", "require_injection_*.yaml"))
	Expect(err).NotTo(HaveOccurred())
	Expect(files).To(HaveLen(2), "config/admission must hold the policy and its binding")

	for _, file := range files {
		raw, err := os.ReadFile(file)
		Expect(err).NotTo(HaveOccurred())
		obj := &unstructured.Unstructured{}
		Expect(yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096).Decode(&obj.Object)).To(Succeed(), file)
		Expect(k8sClient.Create(context.Background(), obj)).To(Succeed(), file)
	}
}
