//go:build integration

package controllers

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jacaudi/wireguard-operator/internal/resources"
)

var _ = Describe("client RoleBinding", func() {
	const (
		timeout  = 20 * time.Second
		interval = 250 * time.Millisecond
	)

	var ns string

	// bindingKey is the operator's RoleBinding in ns.
	bindingKey := func() types.NamespacedName {
		return types.NamespacedName{Namespace: ns, Name: resources.ClientRoleName}
	}
	getBinding := func() (*rbacv1.RoleBinding, error) {
		rb := &rbacv1.RoleBinding{}
		err := k8sClient.Get(context.Background(), bindingKey(), rb)
		return rb, err
	}
	// injectedPod creates a labelled pod that already carries wg-client, which the backstop admits
	// without the mutating policy: these specs are about RBAC, not injection.
	injectedPod := func() *corev1.Pod {
		pod := labelledPod(ns, func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{
				Name: resources.SidecarContainer, Image: "busybox", RestartPolicy: new(corev1.ContainerRestartPolicyAlways),
			}}
		})
		Eventually(func() error { return k8sClient.Create(context.Background(), pod) }, timeout, interval).Should(Succeed())
		return pod
	}
	deletePod := func(pod *corev1.Pod) {
		Expect(client.IgnoreNotFound(k8sClient.Delete(context.Background(), pod, client.GracePeriodSeconds(0)))).To(Succeed())
	}

	BeforeEach(func() {
		ns = "rb-" + rand.String(6)
		Expect(k8sClient.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})).To(Succeed())
	})

	It("is created for the first labelled pod, kept for the second, and deleted after the last", func() {
		first := injectedPod()
		Eventually(func() error { _, err := getBinding(); return err }, timeout, interval).Should(Succeed())

		rb, _ := getBinding()
		Expect(rb.Labels).To(HaveKeyWithValue(resources.LabelManagedBy, resources.ManagedByValue))
		Expect(rb.RoleRef).To(Equal(rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: resources.ClientRoleName}))
		Expect(rb.Subjects).To(ConsistOf(rbacv1.Subject{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: "system:serviceaccounts:" + ns}))

		second := injectedPod()
		deletePod(first)
		Consistently(func() error { _, err := getBinding(); return err }, 3*time.Second, interval).Should(Succeed(),
			"a labelled pod remains, so the binding must stay")

		deletePod(second)
		Eventually(func() bool { _, err := getBinding(); return apierrors.IsNotFound(err) }, timeout, interval).Should(BeTrue(),
			"the last labelled pod is gone, so the binding must go")
	})

	It("is not created for a pod that injection does not apply to", func() {
		pod := labelledPod(ns, func(p *corev1.Pod) { p.Labels[resources.LabelComponent] = resources.ComponentGateway })
		Expect(k8sClient.Create(context.Background(), pod)).To(Succeed())
		defer deletePod(pod)

		Consistently(func() bool { _, err := getBinding(); return apierrors.IsNotFound(err) }, 3*time.Second, interval).Should(BeTrue())
	})

	It("never touches a RoleBinding of that name it did not create", func() {
		foreign := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: resources.ClientRoleName, Labels: map[string]string{"owner": "a-human"}},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
			Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: "someone"}},
		}
		Expect(k8sClient.Create(context.Background(), foreign)).To(Succeed())
		before, err := getBinding()
		Expect(err).NotTo(HaveOccurred())

		pod := injectedPod()
		// Give the reconciler time to wrongly overwrite it.
		Consistently(func() (string, error) {
			rb, err := getBinding()
			return rb.ResourceVersion, err
		}, 3*time.Second, interval).Should(Equal(before.ResourceVersion), "the foreign RoleBinding must be left unchanged")

		deletePod(pod)
		Consistently(func() (string, error) {
			rb, err := getBinding()
			return rb.ResourceVersion, err
		}, 3*time.Second, interval).Should(Equal(before.ResourceVersion), "and must survive the last pod's deletion")
	})
})
