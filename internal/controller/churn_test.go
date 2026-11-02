//go:build integration

package controllers

import (
	"context"
	"sync"
	"time"

	"github.com/jacaudi/wireguard-operator/api/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// countingClient records writes the reconciler issues, keyed by namespace/name.
//
// Issue #2's stated acceptance criterion -- watch resourceVersion over several reconciles --
// cannot distinguish a good implementation from a bad one: the apiserver discards a write whose
// defaulted result is byte-identical to what is stored, so an implementation issuing a full PUT
// every reconcile still holds resourceVersion and generation constant.
//
// This counter measures requests ISSUED, which is a different thing from writes PERSISTED. It
// therefore cannot tell Server-Side Apply from a read-modify-write -- both issue one request per
// object per reconcile. What it can tell, precisely, is how many times a SINGLE object is written
// within one reconcile. That is the defect this change removes: four drift checks all comparing
// against one stale read, issuing up to four Deployment writes in a single pass.
type countingClient struct {
	client.Client

	mu     sync.Mutex
	writes map[string]int
	// migrations counts the subset of writes that are applyOwned's legacy field-manager migration
	// (the only JSON patch the reconciler sends). Never cleared by reset: it is counted from birth.
	migrations map[string]int
}

func newCountingClient(c client.Client) *countingClient {
	return &countingClient{Client: c, writes: map[string]int{}, migrations: map[string]int{}}
}

func (c *countingClient) record(obj client.Object, migration bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := obj.GetNamespace() + "/" + obj.GetName()
	c.writes[key]++
	if migration {
		c.migrations[key]++
	}
}

// writesTo returns the total writes issued to the named objects in a namespace.
func (c *countingClient) writesTo(ns string, names ...string) int {
	return c.count(false, ns, names)
}

// migrationsTo returns the legacy field-manager migrations issued to the named objects, ever.
func (c *countingClient) migrationsTo(ns string, names ...string) int {
	return c.count(true, ns, names)
}

func (c *countingClient) count(migrationsOnly bool, ns string, names []string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.writes
	if migrationsOnly {
		m = c.migrations
	}
	total := 0
	for _, n := range names {
		total += m[ns+"/"+n]
	}
	return total
}

func (c *countingClient) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = map[string]int{}
}

func (c *countingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.record(obj, false)
	return c.Client.Update(ctx, obj, opts...)
}

func (c *countingClient) Patch(ctx context.Context, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
	c.record(obj, p.Type() == types.JSONPatchType)
	return c.Client.Patch(ctx, obj, p, opts...)
}

func (c *countingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	c.record(obj, false)
	return c.Client.Create(ctx, obj, opts...)
}

var _ = Describe("no update churn", func() {
	// Timeout and Interval in wireguard_controller_test.go are declared INSIDE its Describe
	// closure, so they are not visible here. Declare our own.
	const (
		churnNS       = "churn-probe"
		churnName     = "churn"
		churnTimeout  = time.Second * 10
		churnInterval = time.Millisecond * 250
	)

	It("applies each owned object at most once per reconcile and persists nothing", func() {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: churnNS}}
		if err := k8sClient.Create(context.Background(), ns); err != nil {
			Expect(client.IgnoreAlreadyExists(err)).Should(Succeed())
		}

		wg := &v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{Name: churnName, Namespace: churnNS},
			Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
		}
		Expect(k8sClient.Create(context.Background(), wg)).Should(Succeed())
		defer func() {
			_ = k8sClient.Delete(context.Background(), wg)
			_ = k8sClient.Delete(context.Background(), &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: churnName + "-dep", Namespace: churnNS}})
		}()

		depKey := types.NamespacedName{Name: churnName + "-dep", Namespace: churnNS}
		Eventually(func() error {
			return k8sClient.Get(context.Background(), depKey, &appsv1.Deployment{})
		}, churnTimeout, churnInterval).Should(Succeed())

		wgKey := types.NamespacedName{Name: churnName, Namespace: churnNS}
		svcName := churnName + "-svc"

		// awaitQuiet returns once no reconcile is in flight: the Service is the first object a
		// reconcile applies, so two seconds without a Service write means the cascade has finished.
		awaitQuiet := func() {
			n := writeCounter.writesTo(churnNS, svcName)
			Consistently(func() int { return writeCounter.writesTo(churnNS, svcName) },
				"2s", churnInterval).Should(Equal(n), "a reconcile was still in flight")
		}

		// Let the create cascade finish. Ready=True is written only by a reconcile that applied all
		// two objects, and the status write it causes triggers one more reconcile; wait that out
		// too, so reset() cannot land between a reconcile's Service apply and its Deployment apply.
		Eventually(func() bool {
			live := &v1alpha1.Wireguard{}
			if err := k8sClient.Get(context.Background(), wgKey, live); err != nil {
				return false
			}
			for _, c := range live.Status.Conditions {
				if c.Type == ConditionReady && c.Status == metav1.ConditionTrue {
					return true
				}
			}
			return false
		}, churnTimeout, churnInterval).Should(BeTrue(), "the churn Wireguard should reach Ready before measuring")
		awaitQuiet()

		// Now the snapshot really is settled.
		var settled appsv1.Deployment
		Expect(k8sClient.Get(context.Background(), depKey, &settled)).Should(Succeed())

		writeCounter.reset()

		// Nudge the reconciler by annotating the Wireguard.
		//
		// The annotation does not reach state.json, which carries only the Wireguard's name, namespace and
		// spec. The assertions below still name the Deployment and Service explicitly: the Secret is not this
		// spec's subject.
		for i := range 3 {
			Eventually(func() error {
				live := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(),
					types.NamespacedName{Name: churnName, Namespace: churnNS}, live); err != nil {
					return err
				}
				if live.Annotations == nil {
					live.Annotations = map[string]string{}
				}
				live.Annotations["probe.test/nudge"] = string(rune('a' + i))
				return k8sClient.Update(context.Background(), live)
			}, churnTimeout, churnInterval).Should(Succeed())
		}

		// Nothing the Deployment renders changed, so no write may be persisted.
		Consistently(func() string {
			live := &appsv1.Deployment{}
			if err := k8sClient.Get(context.Background(), depKey, live); err != nil {
				return "get-failed"
			}
			return live.ResourceVersion
		}, "3s", churnInterval).Should(Equal(settled.ResourceVersion),
			"the Deployment must not be rewritten when nothing it renders has changed")

		// The Service is applied exactly once per reconcile: one call site, no branches. It is
		// therefore a reconcile counter. The Deployment must match it one-for-one -- the
		// pre-change code could write the Deployment up to four times in a single reconcile.
		awaitQuiet()
		svcWrites := writeCounter.writesTo(churnNS, svcName)
		depWrites := writeCounter.writesTo(churnNS, churnName+"-dep")

		Expect(svcWrites).Should(BeNumerically(">", 0), "sanity: the reconciler should have run")
		Expect(depWrites).Should(Equal(svcWrites),
			"the Deployment must be applied exactly once per reconcile")

		// SSA-born objects carry no legacy entry, so applyOwned must never send them a migration
		// patch -- counted from creation, not from reset().
		Expect(writeCounter.migrationsTo(churnNS, churnName+"-dep", svcName)).
			Should(BeZero(), "an object the operator created by apply must never be migrated")
	})
})
