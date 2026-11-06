//go:build integration

package controllers

import (
	"context"
	stderrors "errors"
	"time"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("applyOwned", func() {
	// Timeout and Interval in wireguard_controller_test.go are declared inside its Describe
	// closure and are not visible here. Declare our own.
	const (
		applyNS       = "default"
		applyTimeout  = time.Second * 10
		applyInterval = time.Millisecond * 250
	)

	// newTestReconciler builds a reconciler wired to the direct test client. Its builders are
	// normally initialised by SetupWithManager, which we do not call here, so nothing in this
	// spec may touch r.deploymentBuilder and friends.
	newTestReconciler := func() *WireguardReconciler {
		return &WireguardReconciler{
			Client:               k8sClient,
			Scheme:               scheme.Scheme,
			AgentImage:           wgTestImage,
			AgentImagePullPolicy: corev1.PullIfNotPresent,
		}
	}

	// A minimal Deployment that does not collide with the operator-managed "vpn-dep".
	desired := func() *appsv1.Deployment {
		labels := map[string]string{"app": "apply-seam-probe"}
		replicas := int32(1)
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "apply-seam-probe", Namespace: applyNS},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{MatchLabels: labels},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: labels},
					Spec: corev1.PodSpec{Containers: []corev1.Container{{
						Name: "probe", Image: "registry.invalid/probe:v1",
					}}},
				},
			},
		}
	}

	key := types.NamespacedName{Name: "apply-seam-probe", Namespace: applyNS}

	AfterEach(func() {
		dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}}
		_ = k8sClient.Delete(context.Background(), dep)
	})

	It("creates the object, derives the GVK, and owns it under FieldManager", func() {
		r := newTestReconciler()
		obj := desired()

		Expect(r.applyOwned(context.Background(), obj)).Should(Succeed())

		// The GVK must have been stamped on -- SSA rejects a body without apiVersion/kind.
		Expect(obj.GroupVersionKind().Kind).Should(Equal("Deployment"))
		Expect(obj.GroupVersionKind().GroupVersion().String()).Should(Equal("apps/v1"))

		// The apply response is decoded back into obj, so it carries server state.
		Expect(obj.UID).ShouldNot(BeEmpty())
		Expect(obj.ResourceVersion).ShouldNot(BeEmpty())

		live := &appsv1.Deployment{}
		Expect(k8sClient.Get(context.Background(), key, live)).Should(Succeed())
		Expect(obj.ResourceVersion).Should(Equal(live.ResourceVersion))

		var managers []string
		for _, mf := range live.ManagedFields {
			managers = append(managers, mf.Manager)
		}
		Expect(managers).Should(ContainElement(FieldManager))
	})

	It("does not churn resourceVersion when applied repeatedly with identical content", func() {
		r := newTestReconciler()
		Expect(r.applyOwned(context.Background(), desired())).Should(Succeed())

		first := &appsv1.Deployment{}
		Expect(k8sClient.Get(context.Background(), key, first)).Should(Succeed())

		for i := range 4 {
			Expect(r.applyOwned(context.Background(), desired())).Should(Succeed())
			now := &appsv1.Deployment{}
			Expect(k8sClient.Get(context.Background(), key, now)).Should(Succeed())
			Expect(now.ResourceVersion).Should(Equal(first.ResourceVersion),
				"apply %d persisted a write when nothing changed", i+1)
			Expect(now.Generation).Should(Equal(first.Generation))
		}
	})

	It("converges a field changed by another writer", func() {
		r := newTestReconciler()
		Expect(r.applyOwned(context.Background(), desired())).Should(Succeed())

		tampered := &appsv1.Deployment{}
		Expect(k8sClient.Get(context.Background(), key, tampered)).Should(Succeed())
		tampered.Spec.Template.Spec.Containers[0].Image = "registry.invalid/tampered:latest"
		Expect(k8sClient.Update(context.Background(), tampered, client.FieldOwner("someone-else"))).Should(Succeed())

		Expect(r.applyOwned(context.Background(), desired())).Should(Succeed())

		live := &appsv1.Deployment{}
		Expect(k8sClient.Get(context.Background(), key, live)).Should(Succeed())
		Expect(live.Spec.Template.Spec.Containers[0].Image).Should(Equal("registry.invalid/probe:v1"))
	})

	It("migrates a legacy Update-owned object so a field it stops rendering is removed", func() {
		ctx := context.Background()

		// withSidecar renders the probe plus a second container. Seeded under "manager" -- the
		// production binary's field manager before this change; the literal pins that on-cluster
		// contract -- it is the pre-SSA shape: an object written by Create, owned by an Update entry.
		withSidecar := func() *appsv1.Deployment {
			dep := desired()
			dep.Spec.Template.Spec.Containers = append(dep.Spec.Template.Spec.Containers,
				corev1.Container{Name: "legacy-sidecar", Image: "registry.invalid/sidecar:v1"})
			return dep
		}
		Expect(k8sClient.Create(ctx, withSidecar(), client.FieldOwner("manager"))).Should(Succeed())
		seeded := &appsv1.Deployment{}
		Expect(k8sClient.Get(ctx, key, seeded)).Should(Succeed())

		// Adopt with identical content. The migration rewrites ownership only: the stored spec
		// is untouched, and no Update entry is left behind -- not "manager", and not one for the
		// client that sent the migration patch.
		r := newTestReconciler()
		Expect(r.applyOwned(ctx, withSidecar())).Should(Succeed())

		adopted := &appsv1.Deployment{}
		Expect(k8sClient.Get(ctx, key, adopted)).Should(Succeed())
		Expect(adopted.Generation).Should(Equal(seeded.Generation), "adoption must not change the spec")
		var managers []string
		for _, mf := range adopted.ManagedFields {
			managers = append(managers, mf.Manager)
		}
		Expect(managers).Should(ConsistOf(FieldManager))

		// Stop rendering the sidecar. Only an exclusive owner can prune it.
		Expect(r.applyOwned(ctx, desired())).Should(Succeed())

		live := &appsv1.Deployment{}
		Expect(k8sClient.Get(ctx, key, live)).Should(Succeed())
		var containers []string
		for _, c := range live.Spec.Template.Spec.Containers {
			containers = append(containers, c.Name)
		}
		Expect(containers).Should(Equal([]string{"probe"}),
			"a container the legacy manager co-owned must be pruned once ownership migrates")

		// The migration is one write, once: re-applying identical content persists nothing.
		Expect(r.applyOwned(ctx, desired())).Should(Succeed())
		again := &appsv1.Deployment{}
		Expect(k8sClient.Get(ctx, key, again)).Should(Succeed())
		Expect(again.ResourceVersion).Should(Equal(live.ResourceVersion))
	})

	It("wraps its errors with the object's identity and keeps the API status inspectable", func() {
		ctx := context.Background()

		unregistered := newTestReconciler()
		unregistered.Scheme = runtime.NewScheme()
		Expect(unregistered.applyOwned(ctx, desired())).Should(
			MatchError(ContainSubstring("resolve GVK for *v1.Deployment")))

		invalid := desired()
		invalid.Spec.Template.Spec.Containers = nil
		err := newTestReconciler().applyOwned(ctx, invalid)
		Expect(err).Should(MatchError(ContainSubstring("apply Deployment default/apply-seam-probe")))
		Expect(apierrors.IsInvalid(err)).Should(BeTrue(), "the apiserver's status must survive wrapping: %v", err)
	})

	It("records a Degraded condition when failDegraded is called", func() {
		r := newTestReconciler()

		nn := types.NamespacedName{Name: "apply-degraded", Namespace: applyNS}
		wg := &v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{Name: nn.Name, Namespace: nn.Namespace},
			Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
		}
		Expect(k8sClient.Create(context.Background(), wg)).Should(Succeed())
		defer func() {
			// The manager reconciles this object, so it also creates children. Clean them up:
			// BeforeEach in wireguard_controller_test.go does not delete Deployments, and
			// envtest runs no garbage collector, so anything left here leaks for the whole run.
			_ = k8sClient.Delete(context.Background(), wg)
			_ = k8sClient.Delete(context.Background(), &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: nn.Name + "-dep", Namespace: applyNS}})
			_ = k8sClient.Delete(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: nn.Name + "-svc", Namespace: applyNS}})
		}()

		fetched := &v1alpha1.Wireguard{}
		Expect(k8sClient.Get(context.Background(), nn, fetched)).Should(Succeed())

		_, err := r.failDegraded(context.Background(),
			fetched, errProbe, "ProbeFailed", "probe failed")
		Expect(err).Should(MatchError(errProbe))

		// Assert on the CONDITION, not on Status.Status.
		//
		// The manager's reconciler is watching this object and writes its own conditions
		// concurrently. updateStatus derives the summary field from whichever condition it just
		// wrote, so Status.Status flips to "pending" the moment the manager reconciles -- there
		// is no name the manager will not pick up, and asserting the summary field is a race.
		// Conditions are merged by type, so the Degraded condition survives alongside the
		// manager's Progressing one.
		//
		// The write is re-issued on every poll: updateStatus swallows conflicts and lets the
		// next reconcile retry (wireguard_controller.go, IsConflict branch), so a single call
		// can be lost to the manager's concurrent status write. Re-issuing is exactly what the
		// requeue does in production.
		Eventually(func() bool {
			_, _ = r.failDegraded(context.Background(),
				fetched, errProbe, "ProbeFailed", "probe failed")

			live := &v1alpha1.Wireguard{}
			if err := k8sClient.Get(context.Background(), nn, live); err != nil {
				return false
			}
			for _, c := range live.Status.Conditions {
				if c.Type == ConditionDegraded && c.Reason == "ProbeFailed" &&
					c.Status == metav1.ConditionTrue {
					return true
				}
			}
			return false
		}, applyTimeout, applyInterval).Should(BeTrue(),
			"expected a Degraded condition with reason ProbeFailed")
	})
})

var errProbe = stderrors.New("probe error")
