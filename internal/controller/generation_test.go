//go:build integration

package controllers

import (
	"context"
	"sync"
	"time"

	"github.com/jacaudi/wireguard-operator/api/v1alpha1"
	"github.com/jacaudi/wireguard-operator/internal/ipam"
	"github.com/jacaudi/wireguard-operator/internal/resources"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// genHookClient wraps the test client for one reconcile. On the first Get of key it records the
// returned generation in fetched and then bumps the stored Wireguard's spec, so the stored
// generation moves past the one the reconcile renders. It records the Ready condition of every
// Wireguard status write sent through Status().Update.
type genHookClient struct {
	client.Client
	key     types.NamespacedName
	once    sync.Once
	fetched int64
	mu      sync.Mutex
	ready   []metav1.Condition
}

func (c *genHookClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := c.Client.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if wg, ok := obj.(*v1alpha1.Wireguard); ok && key == c.key {
		var bumpErr error
		c.once.Do(func() {
			c.fetched = wg.Generation
			bumpErr = retry.RetryOnConflict(retry.DefaultRetry, func() error {
				live := &v1alpha1.Wireguard{}
				if err := c.Client.Get(ctx, key, live); err != nil {
					return err
				}
				live.Spec.NodeSelector = map[string]string{"gen-stamp": "bumped"}
				return c.Update(ctx, live)
			})
		})
		return bumpErr
	}
	return nil
}

func (c *genHookClient) Status() client.SubResourceWriter {
	return genHookStatusWriter{SubResourceWriter: c.Client.Status(), hook: c}
}

// genHookStatusWriter records the Ready condition of each Wireguard status update before delegating.
type genHookStatusWriter struct {
	client.SubResourceWriter
	hook *genHookClient
}

func (w genHookStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if wg, ok := obj.(*v1alpha1.Wireguard); ok {
		if cond := meta.FindStatusCondition(wg.Status.Conditions, ConditionReady); cond != nil {
			w.hook.mu.Lock()
			w.hook.ready = append(w.hook.ready, *cond)
			w.hook.mu.Unlock()
		}
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

var _ = Describe("status generation stamp", func() {
	const (
		genNS       = "default"
		genTimeout  = time.Second * 10
		genInterval = time.Millisecond * 250
	)

	key := types.NamespacedName{Name: "gen-stamp", Namespace: genNS}

	AfterEach(func() {
		err := k8sClient.Delete(context.Background(), &v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}})
		if err != nil && !errors.IsNotFound(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	It("stamps the generation the reconcile rendered, not the one it re-read", func() {
		ctx := context.Background()
		Expect(k8sClient.Create(ctx, &v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}})).To(Succeed())

		// The manager's controller has fully reconciled it once.
		Eventually(func() string {
			live := &v1alpha1.Wireguard{}
			if err := k8sClient.Get(ctx, key, live); err != nil {
				return ""
			}
			return live.Status.Status
		}, genTimeout, genInterval).Should(Equal(v1alpha1.Ready))

		// Wrap the direct apiserver client, never the manager's cached one, so updateStatus's
		// re-read deterministically sees the bumped generation.
		hook := &genHookClient{Client: k8sClient, key: key}
		r := &WireguardReconciler{
			Client:               hook,
			Scheme:               scheme.Scheme,
			AgentImage:           wgTestImage,
			AgentImagePullPolicy: corev1.PullIfNotPresent,
		}
		r.secretBuilder = resources.NewSecretBuilder(scheme.Scheme)
		r.serviceBuilder = resources.NewServiceBuilder(scheme.Scheme)
		r.deploymentBuilder = resources.NewDeploymentBuilder(scheme.Scheme, wgTestImage, corev1.PullIfNotPresent)
		r.ipAllocator = ipam.NewAllocator()

		_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())

		stored := &v1alpha1.Wireguard{}
		Expect(k8sClient.Get(ctx, key, stored)).To(Succeed())
		Expect(stored.Generation).To(Equal(hook.fetched+1), "the hook must have bumped the spec once")

		hook.mu.Lock()
		defer hook.mu.Unlock()
		Expect(hook.ready).NotTo(BeEmpty())
		for _, c := range hook.ready {
			Expect(c.ObservedGeneration).To(Equal(hook.fetched), "Ready %s/%s", c.Status, c.Reason)
		}
	})
})
