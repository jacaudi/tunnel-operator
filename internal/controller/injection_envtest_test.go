//go:build integration

package controllers

import (
	"context"
	"slices"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/resources"
)

// testOperatorNamespace is the namespace the suite's InjectionPolicyReconciler treats as the operator's.
const testOperatorNamespace = "wg-system"

// The envtest apiserver serves the MutatingAdmissionPolicy beta, not v1 (see floor_test.go).
var injectPolicyGVK = schema.GroupVersionKind{Group: admissionGroup, Version: "v1beta1", Kind: "MutatingAdmissionPolicy"}

// injectPolicyExists reports whether the operator-written policy is in the cluster.
func injectPolicyExists() (bool, error) {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(injectPolicyGVK)
	err := k8sClient.Get(context.Background(), types.NamespacedName{Name: injectPolicyName}, u)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

// waitForNoInjectPolicy blocks until the operator has removed its policy and left it removed, and the
// apiserver has stopped enforcing it: the backstop alone then decides every labelled pod.
//
// Absent once is not enough. The reconciler reads Wireguards from a cache, so a pass triggered by one
// deletion can still see the other and briefly write the policy for it, until the next event removes it
// again. So absent is retried until it holds for a full second: a policy that reappears inside the window
// restarts the wait rather than failing it.
func waitForNoInjectPolicy() {
	Eventually(func(g Gomega) {
		g.Consistently(injectPolicyExists, time.Second, 100*time.Millisecond).Should(BeFalse())
	}, 30*time.Second, 250*time.Millisecond).Should(Succeed())
	// A deleted policy takes effect asynchronously: probe with a labelled pod that is refused once it has.
	waitForBackstop()
}

var _ = Describe("sidecar injection policy", func() {
	var (
		wgs     []*v1alpha1.Wireguard
		created []*corev1.Pod
	)

	newWireguard := func(ns, name string, annotated bool) *v1alpha1.Wireguard {
		wg := &v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
		}
		if annotated {
			wg.Annotations = map[string]string{resources.AnnotationDefault: "true"}
		}
		Expect(k8sClient.Create(context.Background(), wg)).To(Succeed())
		wgs = append(wgs, wg)
		return wg
	}

	// admit creates pod once the apiserver admits it: the policy and its binding take effect
	// asynchronously, and until they do the backstop refuses the pod.
	admit := func(pod *corev1.Pod) *corev1.Pod {
		Eventually(func() error { return k8sClient.Create(context.Background(), pod) }, 30*time.Second, 250*time.Millisecond).Should(Succeed())
		created = append(created, pod)
		return pod
	}

	BeforeEach(func() {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testOperatorNamespace}}
		Expect(client.IgnoreAlreadyExists(k8sClient.Create(context.Background(), ns))).To(Succeed())
		waitForNoInjectPolicy()
	})

	AfterEach(func() {
		removeTouchPolicy()
		for _, pod := range created {
			_ = k8sClient.Delete(context.Background(), pod, client.GracePeriodSeconds(0))
		}
		for _, wg := range wgs {
			_ = k8sClient.Delete(context.Background(), wg)
		}
		// Deletion is asynchronous. While two defaults are being deleted one at a time, the reconciler sees
		// the first go and briefly writes the policy for the other, which would inject the next spec's pods.
		// Wait until the Wireguards are gone, then until the policy is.
		for _, wg := range wgs {
			Eventually(func() bool {
				err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(wg), &v1alpha1.Wireguard{})
				return apierrors.IsNotFound(err)
			}, 30*time.Second, 250*time.Millisecond).Should(BeTrue(), "Wireguard %s must be gone", client.ObjectKeyFromObject(wg))
		}
		created, wgs = nil, nil
		waitForNoInjectPolicy()
	})

	It("inserts the sidecar first, with its volumes, and mounts the token only in the sidecar", func() {
		newWireguard(testOperatorNamespace, "vpn", true)

		pod := admit(labelledPod("default"))

		inits := pod.Spec.InitContainers
		Expect(inits).To(HaveLen(1))
		Expect(inits[0].Name).To(Equal(resources.SidecarContainer))
		Expect(inits[0].Image).To(Equal(wgTestImage))
		Expect(inits[0].Args).To(Equal([]string{"client", "--wireguard", testOperatorNamespace + "/vpn"}))
		Expect(inits[0].RestartPolicy).To(Equal(new(corev1.ContainerRestartPolicyAlways)))

		var names []string
		for _, v := range pod.Spec.Volumes {
			names = append(names, v.Name)
		}
		Expect(names).To(ContainElements(resources.VolumeKey, resources.VolumeToken))

		mounts := func(c corev1.Container) []string {
			var out []string
			for _, m := range c.VolumeMounts {
				out = append(out, m.Name)
			}
			return out
		}
		Expect(mounts(inits[0])).To(ContainElement(resources.VolumeToken))
		for _, c := range pod.Spec.Containers {
			Expect(mounts(c)).NotTo(ContainElement(resources.VolumeToken), "the application must not see the sidecar's token")
		}
	})

	It("keeps the pod's own init containers and volumes after the sidecar", func() {
		newWireguard(testOperatorNamespace, "vpn", true)

		pod := admit(labelledPod("default", func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: "setup", Image: "busybox"}}
			p.Spec.Volumes = []corev1.Volume{{Name: "mine", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
		}))

		var inits, vols []string
		for _, c := range pod.Spec.InitContainers {
			inits = append(inits, c.Name)
		}
		for _, v := range pod.Spec.Volumes {
			vols = append(vols, v.Name)
		}
		Expect(inits).To(Equal([]string{resources.SidecarContainer, "setup"}))
		Expect(vols).To(ConsistOf("mine", resources.VolumeKey, resources.VolumeToken))
	})

	It("injects a pod that opts out of mounting a ServiceAccount token, giving the sidecar its own", func() {
		newWireguard(testOperatorNamespace, "vpn", true)

		pod := admit(labelledPod("default", func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = new(false) }))

		Expect(pod.Spec.InitContainers).To(HaveLen(1))
		Expect(slices.IndexFunc(pod.Spec.Volumes, func(v corev1.Volume) bool { return v.Name == resources.VolumeToken })).To(BeNumerically(">=", 0))
	})

	It("does not inject a pod that already carries wg-client", func() {
		newWireguard(testOperatorNamespace, "vpn", true)
		// Wait for the policy to be live, with a probe pod that proves it injects.
		admit(labelledPod("default"))

		pod := admit(labelledPod("default", func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{
				Name: resources.SidecarContainer, Image: "hand-written", RestartPolicy: new(corev1.ContainerRestartPolicyAlways),
			}}
		}))

		Expect(pod.Spec.InitContainers).To(HaveLen(1))
		Expect(pod.Spec.InitContainers[0].Image).To(Equal("hand-written"))
		Expect(pod.Spec.Volumes).To(BeEmpty())
	})

	It("does not inject twice when another mutation makes the apiserver reinvoke the policy", func() {
		newWireguard(testOperatorNamespace, "vpn", true)
		installTouchPolicy()

		// Both policies take effect asynchronously: create pods until one carries the second policy'"'"'s mark.
		// Without it, reinvocation was never exercised.
		Eventually(func() (map[string]string, error) {
			pod := labelledPod("default")
			if err := k8sClient.Create(context.Background(), pod); err != nil {
				return nil, err
			}
			created = append(created, pod)
			return pod.Annotations, nil
		}, 30*time.Second, 250*time.Millisecond).Should(HaveKeyWithValue("test.tunnel-operator.io/touched", "true"))
		pod := created[len(created)-1]
		Expect(pod.Spec.InitContainers).To(HaveLen(1), "reinvocation must not inject a second sidecar")
	})

	It("leaves an unlabelled pod untouched", func() {
		newWireguard(testOperatorNamespace, "vpn", true)
		admit(labelledPod("default")) // the policy is live

		pod := admit(labelledPod("default", func(p *corev1.Pod) { p.Labels = nil }))

		Expect(pod.Spec.InitContainers).To(BeEmpty())
		Expect(pod.Spec.Volumes).To(BeEmpty())
	})

	It("leaves a pod carrying the component label untouched, whatever its value", func() {
		newWireguard(testOperatorNamespace, "vpn", true)
		admit(labelledPod("default")) // the policy is live

		pod := admit(labelledPod("default", func(p *corev1.Pod) { p.Labels[resources.LabelComponent] = resources.ComponentOperator }))

		Expect(pod.Spec.InitContainers).To(BeEmpty())
	})

	It("injects a labelled pod in the operator's own namespace", func() {
		newWireguard(testOperatorNamespace, "vpn", true)

		pod := admit(labelledPod(testOperatorNamespace))

		Expect(pod.Spec.InitContainers).To(HaveLen(1))
	})

	It("stops injecting, and refuses labelled pods, when the default annotation is removed; and resumes when it returns", func() {
		wg := newWireguard(testOperatorNamespace, "vpn", true)
		admit(labelledPod("default")) // the policy is live

		Eventually(func() error {
			live := &v1alpha1.Wireguard{}
			if err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(wg), live); err != nil {
				return err
			}
			delete(live.Annotations, resources.AnnotationDefault)
			return k8sClient.Update(context.Background(), live)
		}, 10*time.Second, 250*time.Millisecond).Should(Succeed())
		waitForNoInjectPolicy()

		err := k8sClient.Create(context.Background(), labelledPod("default"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(notInjectedMessage))

		Eventually(func() error {
			live := &v1alpha1.Wireguard{}
			if err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(wg), live); err != nil {
				return err
			}
			live.Annotations = map[string]string{resources.AnnotationDefault: "true"}
			return k8sClient.Update(context.Background(), live)
		}, 10*time.Second, 250*time.Millisecond).Should(Succeed())
		Expect(admit(labelledPod("default")).Spec.InitContainers).To(HaveLen(1))
	})

	It("refuses labelled pods while two Wireguards in the operator's namespace are defaults", func() {
		newWireguard(testOperatorNamespace, "vpn-a", true)
		admit(labelledPod("default")) // the policy is live
		newWireguard(testOperatorNamespace, "vpn-b", true)
		waitForNoInjectPolicy()

		err := k8sClient.Create(context.Background(), labelledPod("default"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(notInjectedMessage))
	})

	It("ignores a default annotation outside the operator's namespace", func() {
		newWireguard("default", "tenant-vpn", true)
		// Nothing creates the policy, so give the reconciler time to wrongly do so.
		Consistently(injectPolicyExists, 3*time.Second, 250*time.Millisecond).Should(BeFalse())

		err := k8sClient.Create(context.Background(), labelledPod("default"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(notInjectedMessage))
	})
})

// touchPolicy is a second MutatingAdmissionPolicy, named to sort after the operator's, that mutates every
// labelled pod. The apiserver reinvokes a policy declared reinvocationPolicy: IfNeeded when a later
// mutation changed the object, which is the case the operator's matchCondition must survive.
func touchPolicy(kind string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: admissionGroup, Version: "v1beta1", Kind: kind})
	u.SetName("zzz-test-touch")
	return u
}

func installTouchPolicy() {
	policy := touchPolicy("MutatingAdmissionPolicy")
	policy.Object["spec"] = map[string]any{
		"failurePolicy":      "Fail",
		"reinvocationPolicy": "Never",
		"matchConstraints": map[string]any{"resourceRules": []any{map[string]any{
			"apiGroups": []any{""}, "apiVersions": []any{"v1"}, "operations": []any{"CREATE"}, "resources": []any{"pods"},
		}}},
		"mutations": []any{map[string]any{
			"patchType": "JSONPatch",
			"jsonPatch": map[string]any{"expression": `[JSONPatch{op: "add",
  path: (has(object.metadata.annotations) ? "/metadata/annotations/" + jsonpatch.escapeKey("test.tunnel-operator.io/touched") : "/metadata/annotations"),
  value: (has(object.metadata.annotations) ? dyn("true") : dyn({"test.tunnel-operator.io/touched": "true"}))}]`},
		}},
	}
	binding := touchPolicy("MutatingAdmissionPolicyBinding")
	match, err := injectMatchResources()
	Expect(err).NotTo(HaveOccurred())
	binding.Object["spec"] = map[string]any{"policyName": "zzz-test-touch", "matchResources": match}
	Expect(k8sClient.Create(context.Background(), policy)).To(Succeed())
	Expect(k8sClient.Create(context.Background(), binding)).To(Succeed())
}

func removeTouchPolicy() {
	_ = k8sClient.Delete(context.Background(), touchPolicy("MutatingAdmissionPolicyBinding"))
	_ = k8sClient.Delete(context.Background(), touchPolicy("MutatingAdmissionPolicy"))
}
