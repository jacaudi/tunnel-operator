//go:build integration

package controllers

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/jacaudi/wireguard-operator/api/v1alpha1"
	"github.com/jacaudi/wireguard-operator/internal/agent"
	"github.com/jacaudi/wireguard-operator/internal/resources"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("wireguard controller", func() {

	// Define utility constants for object names and testing timeouts/durations and intervals.
	const (
		wgName      = "vpn"
		wgNamespace = "default"
		Timeout     = time.Second * 10
		Interval    = time.Millisecond * 250
	)

	wgKey := types.NamespacedName{
		Name:      wgName,
		Namespace: wgNamespace,
	}

	BeforeEach(func() {
		var listOpts []client.ListOption

		// delete all wg resources
		wgList := &v1alpha1.WireguardList{}
		Expect(k8sClient.List(context.Background(), wgList, listOpts...)).Should(Succeed())
		for _, wg := range wgList.Items {
			Expect(k8sClient.Delete(context.Background(), &wg)).Should(Succeed())
		}
		// delete all wg-peer resources
		peerList := &v1alpha1.WireguardPeerList{}
		Expect(k8sClient.List(context.Background(), peerList, listOpts...)).Should(Succeed())
		for _, peer := range peerList.Items {
			Expect(k8sClient.Delete(context.Background(), &peer)).Should(Succeed())
		}

		// delete all wg-peer services
		svcList := &corev1.ServiceList{}
		Expect(k8sClient.List(context.Background(), svcList, listOpts...)).Should(Succeed())
		for _, svc := range svcList.Items {
			Expect(k8sClient.Delete(context.Background(), &svc)).Should(Succeed())
		}

		// delete all nodes
		nodeList := &corev1.NodeList{}
		Expect(k8sClient.List(context.Background(), nodeList, listOpts...)).Should(Succeed())
		for _, node := range nodeList.Items {
			Expect(k8sClient.Delete(context.Background(), &node)).Should(Succeed())
		}

		// delete all secrets
		secretList := &corev1.SecretList{}
		Expect(k8sClient.List(context.Background(), secretList, listOpts...)).Should(Succeed())
		for _, secret := range secretList.Items {
			Expect(k8sClient.Delete(context.Background(), &secret)).Should(Succeed())
		}
	})
	Context("Wireguard", func() {
		It("rejects a Wireguard without localCIDRs", func() {
			err := k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: "no-local", Namespace: wgNamespace},
				Spec:       v1alpha1.WireguardSpec{},
			})
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "a nil localCIDRs is rejected, got %v", err)

			err = k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: "no-local", Namespace: wgNamespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: []string{}},
			})
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "an empty localCIDRs is rejected, got %v", err)
			Expect(err.Error()).To(ContainSubstring("spec.localCIDRs"))
		})

		It("keeps spec.gluetun out of the server's state.json", func() {
			key := types.NamespacedName{Name: "vpn-gluetun-strip", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
				Spec: v1alpha1.WireguardSpec{
					LocalCIDRs: testLocalCIDRs,
					Gluetun: v1alpha1.GluetunSpec{
						Env: []corev1.EnvVar{{Name: "WIREGUARD_PRIVATE_KEY", Value: "inline-secret-value"}},
					},
				},
			})).Should(Succeed())

			Eventually(serverState(key), Timeout, Interval).Should(ContainSubstring("10.0.0.0/24"))
			Consistently(serverState(key), "2s", Interval).ShouldNot(ContainSubstring("inline-secret-value"))
		})

		It("allocates an address to a publicKey peer and writes no client config", func() {
			wgServer := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			}
			Expect(k8sClient.Create(context.Background(), wgServer)).Should(Succeed())

			key, err := wgtypes.GeneratePrivateKey()
			Expect(err).ShouldNot(HaveOccurred())
			publicKey := key.PublicKey().String()

			peerKey := types.NamespacedName{Name: wgName + "-pod-peer", Namespace: wgNamespace}
			peer := &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: peerKey.Name, Namespace: peerKey.Namespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgName, PublicKey: publicKey},
			}
			Expect(k8sClient.Create(context.Background(), peer)).Should(Succeed())

			Eventually(func() string {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), peerKey, got); err != nil {
					return ""
				}
				return got.Status.Address
			}, Timeout, Interval).Should(Equal("10.8.0.2"))

			// A peer without a publicKey is never minted a key, never allocated an address and
			// never handed to the server: it reports Ready=False with reason PublicKeyMissing.
			keylessKey := types.NamespacedName{Name: wgName + "-keyless-peer", Namespace: wgNamespace}
			keyless := &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: keylessKey.Name, Namespace: keylessKey.Namespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgName},
			}
			Expect(k8sClient.Create(context.Background(), keyless)).Should(Succeed())
			Eventually(func() string {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), keylessKey, got); err != nil {
					return ""
				}
				c := meta.FindStatusCondition(got.Status.Conditions, ConditionReady)
				if c == nil || c.Status != metav1.ConditionFalse {
					return "no-ready-false-condition"
				}
				return c.Reason
			}, Timeout, Interval).Should(Equal("PublicKeyMissing"))
			Consistently(func() string {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), keylessKey, got); err != nil {
					return "get-failed"
				}
				return got.Status.Address + "|" + got.Status.Status
			}, "2s", Interval).Should(Equal("|"+v1alpha1.Pending), "a keyless peer gets no address and is never Ready")

			// The server Secret's state.json carries the keyed peer: that is all the agent needs.
			stateJSON := func() string {
				secret := &corev1.Secret{}
				if err := k8sClient.Get(context.Background(), wgKey, secret); err != nil {
					return ""
				}
				return string(secret.Data["state.json"])
			}
			Eventually(stateJSON, Timeout, Interval).Should(ContainSubstring(publicKey))
			Consistently(stateJSON, "2s", Interval).ShouldNot(ContainSubstring(keylessKey.Name),
				"a peer without a publicKey must not reach the server")

			// No client configuration and no peer key material is ever written.
			Consistently(func() bool {
				err := k8sClient.Get(context.Background(),
					types.NamespacedName{Name: wgName + "-peer-configs", Namespace: wgNamespace}, &corev1.Secret{})
				return apierrors.IsNotFound(err)
			}, "2s", Interval).Should(BeTrue(), "no aggregated peer-config Secret may exist")
			for _, name := range []string{peerKey.Name, keylessKey.Name} {
				err = k8sClient.Get(context.Background(),
					types.NamespacedName{Name: name + "-peer", Namespace: wgNamespace}, &corev1.Secret{})
				Expect(apierrors.IsNotFound(err)).Should(BeTrue(), "no per-peer key Secret may exist for %s", name)
			}

			// Once the keyless peer supplies a key it is admitted: it gets an address, becomes
			// Ready, and the PublicKeyMissing condition is cleared rather than left behind.
			Eventually(func() error {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), keylessKey, got); err != nil {
					return err
				}
				got.Spec.PublicKey = newPublicKey()
				return k8sClient.Update(context.Background(), got)
			}, Timeout, Interval).Should(Succeed())
			Eventually(func() string {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), keylessKey, got); err != nil {
					return "get-failed"
				}
				if c := meta.FindStatusCondition(got.Status.Conditions, ConditionReady); c != nil {
					return "condition Ready=" + string(c.Status) + "/" + c.Reason
				}
				if got.Status.Address == "" {
					return "no-address"
				}
				return got.Status.Status
			}, Timeout, Interval).Should(Equal(v1alpha1.Ready), "a peer that gains a key is admitted and its PublicKeyMissing condition cleared")
		})

		It("Should create a WG with a ClusterIP Service and WG peer successfully", func() {
			wgKey := types.NamespacedName{
				Name:      wgName,
				Namespace: wgNamespace,
			}
			created := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wgKey.Name,
					Namespace: wgKey.Namespace,
				},
				Spec: v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			}
			expectedLabels := map[string]string{"app": "wireguard", "instance": wgKey.Name}

			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			// service created
			serviceName := wgKey.Name + "-svc"
			serviceKey := types.NamespacedName{
				Namespace: wgKey.Namespace,
				Name:      serviceName,
			}

			// match labels
			Eventually(func() map[string]string {
				svc := &corev1.Service{}
				k8sClient.Get(context.Background(), serviceKey, svc)
				return svc.Spec.Selector
			}, Timeout, Interval).Should(BeEquivalentTo(expectedLabels))

			// match service type
			Eventually(func() corev1.ServiceType {
				svc := &corev1.Service{}
				k8sClient.Get(context.Background(), serviceKey, svc)
				return svc.Spec.Type
			}, Timeout, Interval).Should(Equal(corev1.ServiceTypeClusterIP))

			Eventually(func() v1alpha1.WireguardStatus {
				wg := &v1alpha1.Wireguard{}
				err := k8sClient.Get(context.Background(), wgKey, wg)
				if err != nil {
					return v1alpha1.WireguardStatus{}
				}
				return wg.Status
			}, Timeout, Interval).Should(SatisfyAny(
				WithTransform(func(s v1alpha1.WireguardStatus) string { return s.Status }, Equal("pending")),
				WithTransform(func(s v1alpha1.WireguardStatus) string { return s.Status }, Equal("ready")),
			))

			// check that wireguard resource got the right summary fields after the service is ready
			wg := &v1alpha1.Wireguard{}
			Eventually(func() []string {
				err := k8sClient.Get(context.Background(), wgKey, wg)
				if err != nil {
					return []string{"", ""}
				}
				return []string{wg.Status.Status, wg.Status.Message}
			}, Timeout, Interval).Should(Equal([]string{"ready", "VPN is active!"}))

			Eventually(func() string {
				deploymentKey := types.NamespacedName{
					Name:      wgName + "-dep",
					Namespace: wgNamespace,
				}
				deployment := &appsv1.Deployment{}
				Expect(k8sClient.Get(context.Background(), deploymentKey, deployment)).Should(Succeed())
				Expect(len(deployment.Spec.Template.Spec.Containers)).Should(Equal(2))
				for _, c := range deployment.Spec.Template.Spec.Containers {
					if c.Name == "agent" {
						return c.Image
					}
				}
				return "no agent container"
			}, Timeout, Interval).Should(Equal(wgTestImage))

			// create peer
			peerKey := types.NamespacedName{
				Name:      wgKey.Name + "peer",
				Namespace: wgKey.Namespace,
			}
			peer := &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      peerKey.Name,
					Namespace: peerKey.Namespace,
				},
				Spec: v1alpha1.WireguardPeerSpec{
					WireguardRef: wgKey.Name,
					PublicKey:    newPublicKey(),
				},
			}
			Expect(k8sClient.Create(context.Background(), peer)).Should(Succeed())

			// get peer secret
			wgSecretKeyName := types.NamespacedName{
				Name:      wgKey.Name,
				Namespace: wgKey.Namespace,
			}
			wgSecret := &corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(context.Background(), wgSecretKeyName, wgSecret)
			}, Timeout, Interval).Should(Succeed())
			_ = wgSecret.Data["publicKey"]

			Eventually(func() string {
				Expect(k8sClient.Get(context.Background(), peerKey, peer)).Should(Succeed())
				print(peer.Status.Message)
				return peer.Status.Address
			}, Timeout, Interval).Should(Equal("10.8.0.2"))

			Eventually(func() v1alpha1.WireguardPeerStatus {
				err := k8sClient.Get(context.Background(), peerKey, peer)
				if err != nil {
					return v1alpha1.WireguardPeerStatus{}
				}
				return peer.Status
			}, Timeout, Interval).Should(Equal(v1alpha1.WireguardPeerStatus{
				Status:  "ready",
				Message: "Peer configured",
				Address: "10.8.0.2",
			}))

			Eventually(func() error {
				return k8sClient.Get(context.Background(), wgSecretKeyName, wgSecret)
			}, Timeout, Interval).Should(Succeed())

		})

		It("switches a server Deployment left on RollingUpdate to Recreate", func() {
			const name = "vpn-rollover"
			key := types.NamespacedName{Name: name, Namespace: wgNamespace}
			depKey := types.NamespacedName{Name: name + "-dep", Namespace: wgNamespace}
			ls := resources.LabelsForWireguard(name)

			// Seed the Deployment an earlier operator left behind BEFORE the Wireguard exists. It has
			// no strategy, so the apiserver defaults RollingUpdate and its rollingUpdate block.
			legacy := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: depKey.Name, Namespace: depKey.Namespace},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{MatchLabels: ls},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{Labels: ls},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: "agent", Image: wgTestImage}},
						},
					},
				},
			}
			Expect(k8sClient.Create(context.Background(), legacy)).Should(Succeed())
			defer func() {
				Expect(client.IgnoreNotFound(k8sClient.Delete(context.Background(), legacy))).Should(Succeed())
			}()
			Expect(legacy.Spec.Strategy.RollingUpdate).ShouldNot(BeNil(),
				"precondition: the apiserver defaults a RollingUpdate block")

			wg := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			}
			Expect(k8sClient.Create(context.Background(), wg)).Should(Succeed())
			defer func() {
				Expect(client.IgnoreNotFound(k8sClient.Delete(context.Background(), wg))).Should(Succeed())
			}()

			dep := &appsv1.Deployment{}
			Eventually(func() string {
				if err := k8sClient.Get(context.Background(), depKey, dep); err != nil {
					return "get-failed"
				}
				return string(dep.Spec.Strategy.Type)
			}, Timeout, Interval).Should(Equal("Recreate"))
			Expect(dep.Spec.Strategy.RollingUpdate).Should(BeNil())
			Expect(dep.Spec.Template.Spec.Containers).Should(HaveLen(2))

			Consistently(func() bool {
				got := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), key, got); err != nil {
					return true
				}
				return meta.IsStatusConditionTrue(got.Status.Conditions, ConditionDegraded)
			}, "2s", Interval).Should(BeFalse(), "the strategy migration must not leave the Wireguard Degraded")
		})

		It("reports DeploymentNotReady until the Deployment rolls out, then Ready", func() {
			const name = "held"
			key := types.NamespacedName{Name: name, Namespace: wgNamespace}
			depKey := types.NamespacedName{Name: name + "-dep", Namespace: wgNamespace}

			wg := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			}
			Expect(k8sClient.Create(context.Background(), wg)).Should(Succeed())
			// Ginkgo v1 allows no AfterEach inside an It.
			defer func() {
				Expect(client.IgnoreNotFound(k8sClient.Delete(context.Background(), wg))).Should(Succeed())
				Expect(client.IgnoreNotFound(k8sClient.Delete(context.Background(), &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: depKey.Name, Namespace: depKey.Namespace},
				}))).Should(Succeed())
			}()

			ready := func(g Gomega) (cond *metav1.Condition, got *v1alpha1.Wireguard) {
				got = &v1alpha1.Wireguard{}
				g.Expect(k8sClient.Get(context.Background(), key, got)).Should(Succeed())
				return meta.FindStatusCondition(got.Status.Conditions, ConditionReady), got
			}

			Eventually(func(g Gomega) {
				cond, got := ready(g)
				g.Expect(cond).ShouldNot(BeNil())
				g.Expect(cond.Status).Should(Equal(metav1.ConditionFalse))
				g.Expect(cond.Reason).Should(Equal(ReasonDeploymentNotReady))
				g.Expect(cond.Message).Should(Equal("Deployment held-dep is not rolled out: generation 1 not yet observed"))
				g.Expect(got.Status.Status).Should(Equal(v1alpha1.Pending))
				g.Expect(got.Status.Endpoint).Should(HaveSuffix(":51820"))
				g.Expect(got.Status.PublicKey).ShouldNot(BeEmpty())
				degraded := meta.FindStatusCondition(got.Status.Conditions, ConditionDegraded)
				g.Expect(degraded).ShouldNot(BeNil())
				g.Expect(degraded.Status).Should(Equal(metav1.ConditionFalse))
				g.Expect(degraded.Reason).Should(Equal("Reconciled"))
			}, Timeout, Interval).Should(Succeed())

			setStatus := func(mutate func(dep *appsv1.Deployment)) {
				Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
					dep := &appsv1.Deployment{}
					if err := k8sClient.Get(context.Background(), depKey, dep); err != nil {
						return err
					}
					mutate(dep)
					return k8sClient.Status().Update(context.Background(), dep)
				})).Should(Succeed())
			}

			setStatus(func(dep *appsv1.Deployment) {
				dep.Status.ObservedGeneration = dep.Generation
				dep.Status.Replicas = 1
				dep.Status.UpdatedReplicas = 1
				dep.Status.ReadyReplicas = 0
			})
			Eventually(func(g Gomega) string {
				cond, _ := ready(g)
				g.Expect(cond).ShouldNot(BeNil())
				return cond.Message
			}, Timeout, Interval).Should(Equal("Deployment held-dep is not rolled out: 0/1 ready, 1/1 updated"))

			setStatus(func(dep *appsv1.Deployment) {
				dep.Status.ReadyReplicas = 1
				dep.Status.AvailableReplicas = 1
			})
			Eventually(func(g Gomega) {
				cond, got := ready(g)
				g.Expect(cond).ShouldNot(BeNil())
				g.Expect(cond.Status).Should(Equal(metav1.ConditionTrue))
				g.Expect(cond.Reason).Should(Equal("Active"))
				g.Expect(got.Status.Status).Should(Equal(v1alpha1.Ready))
			}, Timeout, Interval).Should(Succeed())
		})

		It("allocates peer addresses from a custom PeerCIDR", func() {
			wgKey := types.NamespacedName{
				Name:      wgName,
				Namespace: wgNamespace,
			}

			const customCIDR = "10.9.0.0/24"

			created := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wgKey.Name,
					Namespace: wgKey.Namespace,
				},
				Spec: v1alpha1.WireguardSpec{
					PeerCIDR:   customCIDR,
					LocalCIDRs: testLocalCIDRs,
				},
			}
			expectedLabels := map[string]string{"app": "wireguard", "instance": wgKey.Name}

			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			// service created
			serviceName := wgKey.Name + "-svc"
			serviceKey := types.NamespacedName{
				Namespace: wgKey.Namespace,
				Name:      serviceName,
			}

			// match labels
			Eventually(func() map[string]string {
				svc := &corev1.Service{}
				k8sClient.Get(context.Background(), serviceKey, svc)
				return svc.Spec.Selector
			}, Timeout, Interval).Should(BeEquivalentTo(expectedLabels))

			// match service type
			Eventually(func() corev1.ServiceType {
				svc := &corev1.Service{}
				k8sClient.Get(context.Background(), serviceKey, svc)
				return svc.Spec.Type
			}, Timeout, Interval).Should(Equal(corev1.ServiceTypeClusterIP))

			// create peer
			peerKey := types.NamespacedName{
				Name:      wgKey.Name + "peer-v4only",
				Namespace: wgKey.Namespace,
			}
			peer := &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      peerKey.Name,
					Namespace: peerKey.Namespace,
				},
				Spec: v1alpha1.WireguardPeerSpec{
					WireguardRef: wgKey.Name,
					PublicKey:    newPublicKey(),
				},
			}
			Expect(k8sClient.Create(context.Background(), peer)).Should(Succeed())

			// first usable IP in 10.9.0.0/24 after network (.0) and gateway (.1) is .2
			Eventually(func() string {
				Expect(k8sClient.Get(context.Background(), peerKey, peer)).Should(Succeed())
				return peer.Status.Address
			}, Timeout, Interval).Should(Equal("10.9.0.2"))
		})

		It("reconciles deployment tolerations when spec changes", func() {
			expectedTolerations := []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/control-plane",
					Operator: corev1.TolerationOpExists,
					Effect:   corev1.TaintEffectNoSchedule,
				},
			}

			wgServer := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wgKey.Name,
					Namespace: wgKey.Namespace,
				},
				Spec: v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			}
			Expect(k8sClient.Create(context.Background(), wgServer)).Should(Succeed())

			serviceKey := types.NamespacedName{
				Namespace: wgKey.Namespace,
				Name:      wgKey.Name + "-svc",
			}
			Eventually(func() error {
				svc := &corev1.Service{}
				return k8sClient.Get(context.Background(), serviceKey, svc)
			}, Timeout, Interval).Should(Succeed())

			depKey := types.NamespacedName{
				Namespace: wgKey.Namespace,
				Name:      wgKey.Name + "-dep",
			}

			Eventually(func() []corev1.Toleration {
				dep := &appsv1.Deployment{}
				err := k8sClient.Get(context.Background(), depKey, dep)
				if err != nil {
					return nil
				}
				return dep.Spec.Template.Spec.Tolerations
			}, Timeout, Interval).Should(BeEmpty())

			Eventually(func() error {
				wg := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), wgKey, wg); err != nil {
					return err
				}
				wg.Spec.Tolerations = expectedTolerations
				return k8sClient.Update(context.Background(), wg)
			}, Timeout, Interval).Should(Succeed())

			Eventually(func() []corev1.Toleration {
				dep := &appsv1.Deployment{}
				err := k8sClient.Get(context.Background(), depKey, dep)
				if err != nil {
					return nil
				}
				return dep.Spec.Template.Spec.Tolerations
			}, Timeout, Interval).Should(Equal(expectedTolerations))

			Eventually(func() error {
				wg := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), wgKey, wg); err != nil {
					return err
				}
				wg.Spec.Tolerations = nil
				return k8sClient.Update(context.Background(), wg)
			}, Timeout, Interval).Should(Succeed())

			Eventually(func() []corev1.Toleration {
				dep := &appsv1.Deployment{}
				err := k8sClient.Get(context.Background(), depKey, dep)
				if err != nil {
					return nil
				}
				return dep.Spec.Template.Spec.Tolerations
			}, Timeout, Interval).Should(BeEmpty())
		})

		It("converges a spec field that never had a bespoke drift check", func() {
			created := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			}
			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			serviceKey := types.NamespacedName{Name: wgName + "-svc", Namespace: wgNamespace}
			Eventually(func() error {
				return k8sClient.Get(context.Background(), serviceKey, &corev1.Service{})
			}, Timeout, Interval).Should(Succeed())

			deploymentKey := types.NamespacedName{Name: wgName + "-dep", Namespace: wgNamespace}
			Eventually(func() error {
				dep := &appsv1.Deployment{}
				return k8sClient.Get(context.Background(), deploymentKey, dep)
			}, Timeout, Interval).Should(Succeed())

			// Set a field with no drift check in the pre-change controller.
			Eventually(func() error {
				wg := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), wgKey, wg); err != nil {
					return err
				}
				wg.Spec.Agent.Resources = corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse("123Mi"),
					},
				}
				return k8sClient.Update(context.Background(), wg)
			}, Timeout, Interval).Should(Succeed())

			Eventually(func() string {
				dep := &appsv1.Deployment{}
				if err := k8sClient.Get(context.Background(), deploymentKey, dep); err != nil {
					return "get-failed"
				}
				for _, c := range dep.Spec.Template.Spec.Containers {
					if c.Name == "agent" {
						if q, ok := c.Resources.Requests[corev1.ResourceMemory]; ok {
							return q.String()
						}
						return "unset"
					}
				}
				return "no-agent-container"
			}, Timeout, Interval).Should(Equal("123Mi"))
		})

		It("reconciles a new peer through the peer watch and never owns it", func() {
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			})).Should(Succeed())
			Eventually(func() string {
				wg := &v1alpha1.Wireguard{}
				_ = k8sClient.Get(context.Background(), wgKey, wg)
				return wg.Status.Status
			}, Timeout, Interval).Should(Equal("ready"))

			publicKey := newPublicKey()
			peerKey := types.NamespacedName{Name: wgName + "-watched-peer", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: peerKey.Name, Namespace: peerKey.Namespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgName, PublicKey: publicKey},
			})).Should(Succeed())

			Eventually(func() string {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), peerKey, got); err != nil {
					return ""
				}
				return got.Status.Address
			}, Timeout, Interval).Should(Equal("10.8.0.2"))
			Eventually(serverState(wgKey), Timeout, Interval).Should(ContainSubstring(publicKey))

			Consistently(func() int {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), peerKey, got); err != nil {
					return -1
				}
				return len(got.OwnerReferences)
			}, "2s", Interval).Should(BeZero(), "the Wireguard watches its peers; it must not own them")
		})

		It("reports WireguardNotFound until the peer's Wireguard exists", func() {
			peerKey := types.NamespacedName{Name: wgName + "-early-peer", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: peerKey.Name, Namespace: peerKey.Namespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgName, PublicKey: newPublicKey()},
			})).Should(Succeed())

			// notFound summarises the peer's WireguardNotFound state, or says what it found instead.
			notFound := func() string {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), peerKey, got); err != nil {
					return "get-failed"
				}
				c := meta.FindStatusCondition(got.Status.Conditions, ConditionReady)
				if c == nil || c.Status != metav1.ConditionFalse {
					return "no-ready-false-condition"
				}
				return c.Reason + "|" + got.Status.Status + "|" + got.Status.Message
			}
			const want = "WireguardNotFound|pending|Waiting for wireguard resource 'vpn' to be created"
			Eventually(notFound, Timeout, Interval).Should(Equal(want))

			wg := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			}
			Expect(k8sClient.Create(context.Background(), wg)).Should(Succeed())
			Eventually(func() string {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), peerKey, got); err != nil {
					return "get-failed"
				}
				if c := meta.FindStatusCondition(got.Status.Conditions, ConditionReady); c != nil {
					return "condition Ready=" + string(c.Status) + "/" + c.Reason
				}
				return got.Status.Status + "|" + got.Status.Address
			}, Timeout, Interval).Should(Equal(v1alpha1.Ready+"|10.8.0.2"), "once the server exists the peer is admitted and the condition cleared")

			Expect(k8sClient.Delete(context.Background(), wg)).Should(Succeed())
			Eventually(func() bool {
				return apierrors.IsNotFound(k8sClient.Get(context.Background(), wgKey, &v1alpha1.Wireguard{}))
			}, Timeout, Interval).Should(BeTrue())
			Eventually(notFound, Timeout, Interval).Should(Equal(want), "deleting the Wireguard must report its peers WireguardNotFound again")

			// The same write that reports WireguardNotFound releases the peer's address.
			gone := &v1alpha1.WireguardPeer{}
			Expect(k8sClient.Get(context.Background(), peerKey, gone)).Should(Succeed())
			Expect(gone.Status.Address).Should(BeEmpty(), "a peer whose Wireguard is gone holds no address")
		})

		It("releases a peer's address when its publicKey is removed", func() {
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			})).Should(Succeed())

			releasedKey := types.NamespacedName{Name: wgName + "-released-peer", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: releasedKey.Name, Namespace: releasedKey.Namespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgName, PublicKey: newPublicKey()},
			})).Should(Succeed())
			Eventually(peerAddress(releasedKey), Timeout, Interval).Should(Equal("10.8.0.2"))

			Eventually(func() error {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), releasedKey, got); err != nil {
					return err
				}
				got.Spec.PublicKey = ""
				return k8sClient.Update(context.Background(), got)
			}, Timeout, Interval).Should(Succeed())
			Eventually(func() string {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), releasedKey, got); err != nil {
					return "get-failed"
				}
				c := meta.FindStatusCondition(got.Status.Conditions, ConditionReady)
				if c == nil || c.Status != metav1.ConditionFalse {
					return "no-ready-false-condition"
				}
				return c.Reason + "|" + got.Status.Address
			}, Timeout, Interval).Should(Equal("PublicKeyMissing|"), "a peer that loses its publicKey is released")

			// The released address is reusable: a new peer takes it.
			reuseKey := types.NamespacedName{Name: wgName + "-reuse-peer", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: reuseKey.Name, Namespace: reuseKey.Namespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgName, PublicKey: newPublicKey()},
			})).Should(Succeed())
			Eventually(peerAddress(reuseKey), Timeout, Interval).Should(Equal("10.8.0.2"))
		})

		It("moves a peer to the server its wireguardRef names", func() {
			wg2Key := types.NamespacedName{Name: wgName + "2", Namespace: wgNamespace}
			for _, key := range []types.NamespacedName{wgKey, wg2Key} {
				Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
					ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
					Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
				})).Should(Succeed())
			}
			for _, key := range []types.NamespacedName{wgKey, wg2Key} {
				Eventually(func() string {
					wg := &v1alpha1.Wireguard{}
					_ = k8sClient.Get(context.Background(), key, wg)
					return wg.Status.Status
				}, Timeout, Interval).Should(Equal("ready"))
			}

			publicKey := newPublicKey()
			peerKey := types.NamespacedName{Name: wgName + "-moving-peer", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: peerKey.Name, Namespace: peerKey.Namespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgName, PublicKey: publicKey},
			})).Should(Succeed())
			Eventually(serverState(wgKey), Timeout, Interval).Should(ContainSubstring(publicKey))

			Eventually(func() error {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), peerKey, got); err != nil {
					return err
				}
				got.Spec.WireguardRef = wg2Key.Name
				return k8sClient.Update(context.Background(), got)
			}, Timeout, Interval).Should(Succeed())

			Eventually(serverState(wgKey), Timeout, Interval).ShouldNot(ContainSubstring(publicKey), "the old server drops the peer")
			Eventually(serverState(wg2Key), Timeout, Interval).Should(ContainSubstring(publicKey), "the new server admits the peer")
		})

		It("does not rewrite the server Secret for a peer edit the agent does not read", func() {
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			})).Should(Succeed())

			publicKey := newPublicKey()
			peerKey := types.NamespacedName{Name: wgName + "-quiet-peer", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: peerKey.Name, Namespace: peerKey.Namespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgName, PublicKey: publicKey},
			})).Should(Succeed())

			Eventually(func() string {
				wg := &v1alpha1.Wireguard{}
				_ = k8sClient.Get(context.Background(), wgKey, wg)
				return wg.Status.Status
			}, Timeout, Interval).Should(Equal("ready"))
			Eventually(serverState(wgKey), Timeout, Interval).Should(ContainSubstring(publicKey))

			// Settle: let the cascade of reconciles the creates caused finish before counting.
			Eventually(func() bool {
				before := writeCounter.writesTo(wgNamespace, wgName)
				time.Sleep(2 * time.Second)
				return writeCounter.writesTo(wgNamespace, wgName) == before
			}, "20s", Interval).Should(BeTrue())
			n := writeCounter.writesTo(wgNamespace, wgName)

			for _, label := range []string{"a", "b", "c"} {
				Eventually(func() error {
					got := &v1alpha1.WireguardPeer{}
					if err := k8sClient.Get(context.Background(), peerKey, got); err != nil {
						return err
					}
					if got.Labels == nil {
						got.Labels = map[string]string{}
					}
					got.Labels["probe.test/nudge"] = label
					return k8sClient.Update(context.Background(), got)
				}, Timeout, Interval).Should(Succeed())
			}

			// The Secret is the only object named vpn that the operator writes through the client;
			// status writes do not pass through countingClient.
			Consistently(func() int { return writeCounter.writesTo(wgNamespace, wgName) },
				"3s", Interval).Should(Equal(n), "a peer edit the agent does not read must not rewrite the server Secret")
		})

		It("reports AddressPoolExhausted and keeps serving the other peers when the pool is full", func() {
			// A /30 has two allocatable addresses: .0 is the network and .1 the gateway.
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{PeerCIDR: "10.8.0.0/30", LocalCIDRs: testLocalCIDRs},
			})).Should(Succeed())

			pool1Key := types.NamespacedName{Name: wgName + "-pool-1", Namespace: wgNamespace}
			pool2Key := types.NamespacedName{Name: wgName + "-pool-2", Namespace: wgNamespace}
			pool3Key := types.NamespacedName{Name: wgName + "-pool-3", Namespace: wgNamespace}
			pool2PublicKey := newPublicKey()

			Expect(k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: pool1Key.Name, Namespace: pool1Key.Namespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgName, PublicKey: newPublicKey()},
			})).Should(Succeed())
			Eventually(peerAddress(pool1Key), Timeout, Interval).Should(Equal("10.8.0.2"))
			Expect(k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: pool2Key.Name, Namespace: pool2Key.Namespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgName, PublicKey: pool2PublicKey},
			})).Should(Succeed())
			Eventually(peerAddress(pool2Key), Timeout, Interval).Should(Equal("10.8.0.3"))

			Expect(k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: pool3Key.Name, Namespace: pool3Key.Namespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgName, PublicKey: newPublicKey()},
			})).Should(Succeed())
			Eventually(func() string {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), pool3Key, got); err != nil {
					return "get-failed"
				}
				c := meta.FindStatusCondition(got.Status.Conditions, ConditionReady)
				if c == nil || c.Status != metav1.ConditionFalse {
					return "no-ready-false-condition"
				}
				return c.Reason + "|" + got.Status.Status + "|" + got.Status.Address
			}, Timeout, Interval).Should(Equal("AddressPoolExhausted|pending|"), "a peer the pool cannot serve is pending, not an error")

			// The full pool must not stop the pass: an edit to a peer that holds an address still
			// reaches state.json.
			rotated := newPublicKey()
			Eventually(func() error {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), pool1Key, got); err != nil {
					return err
				}
				got.Spec.PublicKey = rotated
				return k8sClient.Update(context.Background(), got)
			}, Timeout, Interval).Should(Succeed())
			Eventually(serverState(wgKey), Timeout, Interval).Should(SatisfyAll(
				ContainSubstring(rotated), ContainSubstring(pool2PublicKey)))

			Consistently(func() string {
				wg := &v1alpha1.Wireguard{}
				_ = k8sClient.Get(context.Background(), wgKey, wg)
				return wg.Status.Status
			}, "2s", Interval).Should(Equal("ready"), "a full pool must not degrade the server")
		})

		It("keeps the oldest peer's address when two peers share one", func() {
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			})).Should(Succeed())

			peerAKey := types.NamespacedName{Name: wgName + "-peer-a", Namespace: wgNamespace}
			peerBKey := types.NamespacedName{Name: wgName + "-peer-b", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: peerAKey.Name, Namespace: peerAKey.Namespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgName, PublicKey: newPublicKey()},
			})).Should(Succeed())
			Eventually(peerAddress(peerAKey), Timeout, Interval).Should(Equal("10.8.0.2"))
			Expect(k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: peerBKey.Name, Namespace: peerBKey.Namespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgName, PublicKey: newPublicKey()},
			})).Should(Succeed())
			Eventually(peerAddress(peerBKey), Timeout, Interval).Should(Equal("10.8.0.3"))

			// Simulate a stale-cache double allocation: the one allowed write to an operator-owned
			// field, because the operator changes it back.
			Eventually(func() error {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), peerBKey, got); err != nil {
					return err
				}
				got.Status.Address = "10.8.0.2"
				return k8sClient.Status().Update(context.Background(), got)
			}, Timeout, Interval).Should(Succeed())

			Eventually(func() bool {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), peerBKey, got); err != nil {
					return false
				}
				return got.Status.Address != "" && got.Status.Address != "10.8.0.2" && got.Status.Status == v1alpha1.Ready
			}, Timeout, Interval).Should(BeTrue(), "the younger holder of a shared address is re-allocated and ready")
			Consistently(peerAddress(peerAKey), "2s", Interval).Should(Equal("10.8.0.2"), "the oldest holder keeps its address")

			Eventually(func() []string {
				secret := &corev1.Secret{}
				if err := k8sClient.Get(context.Background(), wgKey, secret); err != nil {
					return nil
				}
				var state agent.State
				if err := json.Unmarshal(secret.Data["state.json"], &state); err != nil || len(state.Peers) != 2 {
					return nil
				}
				var addresses []string
				for _, p := range state.Peers {
					addresses = append(addresses, p.Status.Address)
				}
				slices.Sort(addresses)
				return slices.Compact(addresses)
			}, Timeout, Interval).Should(HaveLen(2), "state.json lists two peers with distinct addresses")
		})

		It("re-allocates a peer whose address is outside its server's peerCIDR", func() {
			wg2Key := types.NamespacedName{Name: wgName + "2", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			})).Should(Succeed())
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wg2Key.Name, Namespace: wg2Key.Namespace},
				Spec:       v1alpha1.WireguardSpec{PeerCIDR: "10.9.0.0/24", LocalCIDRs: testLocalCIDRs},
			})).Should(Succeed())
			for _, key := range []types.NamespacedName{wgKey, wg2Key} {
				Eventually(func() string {
					wg := &v1alpha1.Wireguard{}
					_ = k8sClient.Get(context.Background(), key, wg)
					return wg.Status.Status
				}, Timeout, Interval).Should(Equal("ready"))
			}

			publicKey := newPublicKey()
			peerKey := types.NamespacedName{Name: wgName + "-cidr-peer", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: peerKey.Name, Namespace: peerKey.Namespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgName, PublicKey: publicKey},
			})).Should(Succeed())
			Eventually(peerAddress(peerKey), Timeout, Interval).Should(Equal("10.8.0.2"))

			Eventually(func() error {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), peerKey, got); err != nil {
					return err
				}
				got.Spec.WireguardRef = wg2Key.Name
				return k8sClient.Update(context.Background(), got)
			}, Timeout, Interval).Should(Succeed())

			Eventually(func() string {
				got := &v1alpha1.WireguardPeer{}
				if err := k8sClient.Get(context.Background(), peerKey, got); err != nil {
					return "get-failed"
				}
				return got.Status.Address + "|" + got.Status.Status
			}, Timeout, Interval).Should(Equal("10.9.0.2|"+v1alpha1.Ready), "a peer moved to a server with another peerCIDR is re-allocated inside it")
			Eventually(serverState(wg2Key), Timeout, Interval).Should(ContainSubstring(publicKey), "the new server admits the peer")
		})

		It("reverts a Deployment field changed outside the operator", func() {
			created := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			}
			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			serviceKey := types.NamespacedName{Name: wgName + "-svc", Namespace: wgNamespace}
			Eventually(func() error {
				return k8sClient.Get(context.Background(), serviceKey, &corev1.Service{})
			}, Timeout, Interval).Should(Succeed())

			deploymentKey := types.NamespacedName{Name: wgName + "-dep", Namespace: wgNamespace}
			Eventually(func() error {
				return k8sClient.Get(context.Background(), deploymentKey, &appsv1.Deployment{})
			}, Timeout, Interval).Should(Succeed())

			Eventually(func() error {
				dep := &appsv1.Deployment{}
				if err := k8sClient.Get(context.Background(), deploymentKey, dep); err != nil {
					return err
				}
				dep.Spec.Template.Spec.Containers[0].Image = "registry.invalid/tampered:latest"
				return k8sClient.Update(context.Background(), dep, client.FieldOwner("kubectl-edit"))
			}, Timeout, Interval).Should(Succeed())

			Eventually(func() string {
				dep := &appsv1.Deployment{}
				if err := k8sClient.Get(context.Background(), deploymentKey, dep); err != nil {
					return "get-failed"
				}
				for _, c := range dep.Spec.Template.Spec.Containers {
					if c.Name == "agent" {
						return c.Image
					}
				}
				return "no-agent"
			}, Timeout, Interval).Should(Equal(wgTestImage))
		})

		It("preserves the apiserver's clusterIP allocation across reconciles", func() {
			created := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			}
			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			serviceKey := types.NamespacedName{Name: wgName + "-svc", Namespace: wgNamespace}
			Eventually(func() bool {
				svc := &corev1.Service{}
				if err := k8sClient.Get(context.Background(), serviceKey, svc); err != nil {
					return false
				}
				return svc.Spec.ClusterIP != ""
			}, Timeout, Interval).Should(BeTrue(), "apiserver should have allocated a clusterIP")

			first := &corev1.Service{}
			Expect(k8sClient.Get(context.Background(), serviceKey, first)).Should(Succeed())

			// Nudge the reconciler; the allocations must not move.
			for i := range 3 {
				Eventually(func() error {
					wg := &v1alpha1.Wireguard{}
					if err := k8sClient.Get(context.Background(), wgKey, wg); err != nil {
						return err
					}
					if wg.Annotations == nil {
						wg.Annotations = map[string]string{}
					}
					wg.Annotations["probe.test/nudge"] = string(rune('a' + i))
					return k8sClient.Update(context.Background(), wg)
				}, Timeout, Interval).Should(Succeed())
			}

			Consistently(func() bool {
				svc := &corev1.Service{}
				if err := k8sClient.Get(context.Background(), serviceKey, svc); err != nil {
					return false
				}
				return svc.Spec.ClusterIP == first.Spec.ClusterIP
			}, "3s", Interval).Should(BeTrue(), "the server-assigned clusterIP must survive apply")
		})

		It("publishes the server's endpoint and public key in status", func() {
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			})).Should(Succeed())

			serviceKey := types.NamespacedName{Name: wgName + "-svc", Namespace: wgNamespace}
			svc := &corev1.Service{}
			Eventually(func() string {
				if err := k8sClient.Get(context.Background(), serviceKey, svc); err != nil {
					return ""
				}
				return svc.Spec.ClusterIP
			}, Timeout, Interval).ShouldNot(BeEmpty(), "the apiserver should have allocated a clusterIP")

			secret := &corev1.Secret{}
			Eventually(func() string {
				if err := k8sClient.Get(context.Background(), wgKey, secret); err != nil {
					return ""
				}
				return string(secret.Data["publicKey"])
			}, Timeout, Interval).ShouldNot(BeEmpty(), "the server Secret should carry a public key")

			Eventually(func() string {
				wg := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), wgKey, wg); err != nil {
					return ""
				}
				return wg.Status.Endpoint
			}, Timeout, Interval).Should(Equal(svc.Spec.ClusterIP + ":51820"))
			Eventually(func() string {
				wg := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), wgKey, wg); err != nil {
					return ""
				}
				return wg.Status.PublicKey
			}, Timeout, Interval).Should(Equal(string(secret.Data["publicKey"])))
		})

		It("adopts a Deployment written before Server-Side Apply, so a later removal converges", func() {
			deploymentKey := types.NamespacedName{Name: wgName + "-dep", Namespace: wgNamespace}

			// The suite leaks Deployments between specs; start from a clean slate.
			stale := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: deploymentKey.Name, Namespace: deploymentKey.Namespace},
			}
			_ = k8sClient.Delete(context.Background(), stale)
			Eventually(func() bool {
				err := k8sClient.Get(context.Background(), deploymentKey, &appsv1.Deployment{})
				return err != nil
			}, Timeout, Interval).Should(BeTrue(), "leftover Deployment should be gone")

			// Seed the legacy object BEFORE the Wireguard exists -- otherwise the operator creates
			// the Deployment by apply first and this spec tests nothing. The real builder renders
			// exactly what the pre-change operator wrote, a toleration included; its owner
			// reference is dropped because the Wireguard has no UID yet (the operator's apply adds
			// one). "manager" is the field manager the production binary recorded before this change.
			// One of the two legacy seeds in the suite (see the Service variant below); design §7.3.
			owner := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			}
			owner.Spec.Tolerations = []corev1.Toleration{{
				Key:      "probe.test/legacy",
				Operator: corev1.TolerationOpExists,
				Effect:   corev1.TaintEffectNoSchedule,
			}}
			legacy, err := resources.NewDeploymentBuilder(k8sClient.Scheme(), wgTestImage, corev1.PullIfNotPresent).
				ForWireguard(owner)
			Expect(err).ShouldNot(HaveOccurred())
			legacy.OwnerReferences = nil
			Expect(k8sClient.Create(context.Background(), legacy, client.FieldOwner("manager"))).Should(Succeed())
			seededGeneration := legacy.Generation

			Expect(k8sClient.Create(context.Background(), owner)).Should(Succeed())

			serviceKey := types.NamespacedName{Name: wgName + "-svc", Namespace: wgNamespace}
			Eventually(func() error {
				return k8sClient.Get(context.Background(), serviceKey, &corev1.Service{})
			}, Timeout, Interval).Should(Succeed())

			// Adopted: the owner reference proves the operator's apply ran (the migration patch
			// alone adds none).
			Eventually(func() bool {
				dep := &appsv1.Deployment{}
				if err := k8sClient.Get(context.Background(), deploymentKey, dep); err != nil {
					return false
				}
				var managers []string
				for _, mf := range dep.ManagedFields {
					managers = append(managers, mf.Manager)
				}
				return len(dep.OwnerReferences) > 0 && slices.Contains(managers, FieldManager)
			}, Timeout, Interval).Should(BeTrue(), "the operator should have applied over the legacy Deployment")

			adopted := &appsv1.Deployment{}
			Expect(k8sClient.Get(context.Background(), deploymentKey, adopted)).Should(Succeed())
			Expect(adopted.Generation).Should(Equal(seededGeneration),
				"adopting identical content must not change the stored spec or trigger a rollout")

			Eventually(func() error {
				wg := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), wgKey, wg); err != nil {
					return err
				}
				wg.Spec.Tolerations = nil
				return k8sClient.Update(context.Background(), wg)
			}, Timeout, Interval).Should(Succeed())

			// The proof that adoption is complete. Without the legacy-manager migration in
			// applyOwned, "manager" still co-owns the toleration and the apiserver never prunes it.
			Eventually(func() []corev1.Toleration {
				dep := &appsv1.Deployment{}
				if err := k8sClient.Get(context.Background(), deploymentKey, dep); err != nil {
					return []corev1.Toleration{{Key: "get-failed"}}
				}
				return dep.Spec.Template.Spec.Tolerations
			}, Timeout, Interval).Should(BeEmpty(), "the legacy-owned toleration must be removed")

			removed := &appsv1.Deployment{}
			Expect(k8sClient.Get(context.Background(), deploymentKey, removed)).Should(Succeed())
			var managers []string
			for _, mf := range removed.ManagedFields {
				managers = append(managers, mf.Manager)
			}
			Expect(managers).ShouldNot(ContainElement("manager"), "the legacy Update entry must be gone")
		})

		It("adopts a legacy Service without moving its clusterIP allocation", func() {
			// Spec 6's Service variant (design §10.2 item 10): if the legacy entry owned an
			// allocated field, migration would hand it to the operator, whose next apply
			// relinquishes it. The assertions below pin that it does not own clusterIP, and
			// that the allocation survives adoption.
			// Same seeding rules as above; BeforeEach already deletes Services.
			serviceKey := types.NamespacedName{Name: wgName + "-svc", Namespace: wgNamespace}
			owner := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			}
			legacy, err := resources.NewServiceBuilder(k8sClient.Scheme()).ForWireguard(owner)
			Expect(err).ShouldNot(HaveOccurred())
			legacy.OwnerReferences = nil
			Expect(k8sClient.Create(context.Background(), legacy, client.FieldOwner("manager"))).Should(Succeed())

			seeded := &corev1.Service{}
			Expect(k8sClient.Get(context.Background(), serviceKey, seeded)).Should(Succeed())
			Expect(seeded.Spec.ClusterIP).ShouldNot(BeEmpty())

			// The apiserver allocated clusterIP itself, so the legacy Update entry must not own
			// it: there is nothing allocated for the migration to hand over.
			var legacyFields string
			for _, mf := range seeded.ManagedFields {
				if mf.Manager == "manager" && mf.Operation == metav1.ManagedFieldsOperationUpdate && mf.FieldsV1 != nil {
					legacyFields = string(mf.FieldsV1.Raw)
				}
			}
			Expect(legacyFields).ShouldNot(BeEmpty(), "the seed must carry an Update entry for manager")
			Expect(legacyFields).ShouldNot(ContainSubstring(`"f:clusterIP"`), "the legacy entry must not own clusterIP")

			Expect(k8sClient.Create(context.Background(), owner)).Should(Succeed())

			adopted := &corev1.Service{}
			Eventually(func() bool {
				if err := k8sClient.Get(context.Background(), serviceKey, adopted); err != nil {
					return false
				}
				var managers []string
				for _, mf := range adopted.ManagedFields {
					managers = append(managers, mf.Manager)
				}
				return len(adopted.OwnerReferences) > 0 &&
					slices.Contains(managers, FieldManager) && !slices.Contains(managers, "manager")
			}, Timeout, Interval).Should(BeTrue(), "the operator should adopt the legacy Service")

			Expect(adopted.Spec.ClusterIP).Should(Equal(seeded.Spec.ClusterIP))
		})

		It("converts a Service left as LoadBalancer by an earlier operator to ClusterIP", func() {
			// A cluster that ran the operator before the trim can still hold <name>-svc as a
			// LoadBalancer written by the "manager" field manager. It must converge, not wedge.
			serviceKey := types.NamespacedName{Name: wgName + "-svc", Namespace: wgNamespace}
			labels := resources.LabelsForWireguard(wgName)
			legacy := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceKey.Name, Namespace: serviceKey.Namespace, Labels: labels},
				Spec: corev1.ServiceSpec{
					Type:     corev1.ServiceTypeLoadBalancer,
					Selector: labels,
					Ports: []corev1.ServicePort{{
						Name: "wireguard", Protocol: corev1.ProtocolUDP, Port: resources.WireguardPort,
					}},
				},
			}
			Expect(k8sClient.Create(context.Background(), legacy, client.FieldOwner("manager"))).Should(Succeed())

			created := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			}
			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			Eventually(func() corev1.ServiceType {
				svc := &corev1.Service{}
				if err := k8sClient.Get(context.Background(), serviceKey, svc); err != nil {
					return ""
				}
				return svc.Spec.Type
			}, Timeout, Interval).Should(Equal(corev1.ServiceTypeClusterIP))

			Eventually(func() string {
				wg := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), wgKey, wg); err != nil {
					return ""
				}
				return wg.Status.Status
			}, Timeout, Interval).Should(Equal(v1alpha1.Ready))
		})

		It("reports Degraded while an apply can never succeed, and clears it once one does", func() {
			// A memory request above its limit is rejected by the apiserver, permanently.
			created := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			}
			created.Spec.Agent.Resources = corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
				Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("128Mi")},
			}
			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			Eventually(func() string {
				wg := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), wgKey, wg); err != nil {
					return "get-failed"
				}
				for _, c := range wg.Status.Conditions {
					if c.Type == ConditionDegraded && c.Status == metav1.ConditionTrue {
						return c.Reason
					}
				}
				return "no-degraded-condition"
			}, Timeout, Interval).Should(Equal("DeploymentApplyFailed"))

			// Remove the cause. The next reconcile applies every object, so Ready must be True and
			// Degraded must be False -- not left True beside it from the earlier failure.
			Eventually(func() error {
				wg := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), wgKey, wg); err != nil {
					return err
				}
				wg.Spec.Agent.Resources = corev1.ResourceRequirements{}
				return k8sClient.Update(context.Background(), wg)
			}, Timeout, Interval).Should(Succeed())

			Eventually(func() map[string]metav1.ConditionStatus {
				wg := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), wgKey, wg); err != nil {
					return nil
				}
				got := map[string]metav1.ConditionStatus{}
				for _, c := range wg.Status.Conditions {
					got[c.Type] = c.Status
				}
				return got
			}, Timeout, Interval).Should(SatisfyAll(
				HaveKeyWithValue(ConditionReady, metav1.ConditionTrue),
				HaveKeyWithValue(ConditionDegraded, metav1.ConditionFalse),
			), "a successful reconcile must clear Degraded")
		})

		It("rejects a peer whose publicKey is not a WireGuard key at admission", func() {
			peer := &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "vpn-badkey-peer", Namespace: wgNamespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: "vpn", PublicKey: "not-a-key"},
			}
			err := k8sClient.Create(context.Background(), peer)
			Expect(err).Should(HaveOccurred())
			Expect(apierrors.IsInvalid(err)).Should(BeTrue(), "got %v", err)
			Expect(err.Error()).Should(ContainSubstring("spec.publicKey"))
		})

		It("reports Degraded for an invalid peerCIDR and applies nothing until it is fixed", func() {
			// Its own name: a still-running reconcile of an earlier spec's "vpn" could re-create
			// vpn-svc or Secret vpn after BeforeEach deleted them.
			badKey := types.NamespacedName{Name: "vpn-badcidr", Namespace: wgNamespace}
			bad := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: badKey.Name, Namespace: badKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{PeerCIDR: "10.8.0.5/24", LocalCIDRs: testLocalCIDRs},
			}
			Expect(k8sClient.Create(context.Background(), bad)).Should(Succeed())

			Eventually(func() string {
				wg := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), badKey, wg); err != nil {
					return "get-failed"
				}
				for _, c := range wg.Status.Conditions {
					if c.Type == ConditionDegraded && c.Status == metav1.ConditionTrue {
						return c.Reason
					}
				}
				return "no-degraded-condition"
			}, Timeout, Interval).Should(Equal("InvalidPeerCIDR"))

			// The validation returns before the Service apply, so nothing is written.
			Consistently(func() []bool {
				svcErr := k8sClient.Get(context.Background(), types.NamespacedName{Name: badKey.Name + "-svc", Namespace: badKey.Namespace}, &corev1.Service{})
				secretErr := k8sClient.Get(context.Background(), badKey, &corev1.Secret{})
				return []bool{apierrors.IsNotFound(svcErr), apierrors.IsNotFound(secretErr)}
			}, "2s", Interval).Should(Equal([]bool{true, true}), "an invalid peerCIDR must apply no Service and no Secret")

			Eventually(func() error {
				wg := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), badKey, wg); err != nil {
					return err
				}
				wg.Spec.PeerCIDR = "10.8.0.0/24"
				return k8sClient.Update(context.Background(), wg)
			}, Timeout, Interval).Should(Succeed())

			Eventually(func() map[string]metav1.ConditionStatus {
				wg := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), badKey, wg); err != nil {
					return nil
				}
				got := map[string]metav1.ConditionStatus{}
				for _, c := range wg.Status.Conditions {
					got[c.Type] = c.Status
				}
				return got
			}, Timeout, Interval).Should(SatisfyAll(
				HaveKeyWithValue(ConditionReady, metav1.ConditionTrue),
				HaveKeyWithValue(ConditionDegraded, metav1.ConditionFalse),
			), "fixing the peerCIDR must clear Degraded")
		})

		It("nudges only server pods in the Wireguard's namespace", func() {
			const otherNS = "nudge-other"
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: otherNS}}
			if err := k8sClient.Create(context.Background(), ns); err != nil {
				Expect(client.IgnoreAlreadyExists(err)).Should(Succeed())
			}
			// A pod that shares the server's labels but lives in another namespace.
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "other-server",
					Namespace: otherNS,
					Labels:    map[string]string{"app": "wireguard", "instance": wgName},
				},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox"}}},
			}
			Expect(k8sClient.Create(context.Background(), pod)).Should(Succeed())
			defer func() {
				_ = k8sClient.Delete(context.Background(), pod)
				_ = k8sClient.Delete(context.Background(), ns)
			}()

			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: wgKey.Name, Namespace: wgKey.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
			})).Should(Succeed())
			// The nudge runs only once the server Secret exists, so wait for it to settle.
			Eventually(serverState(wgKey), Timeout, Interval).ShouldNot(BeEmpty())

			// A keyed peer changes state.json, which nudges the pods that serve this Wireguard.
			publicKey := newPublicKey()
			Expect(k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: wgName + "-nudge-peer", Namespace: wgNamespace},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgName, PublicKey: publicKey},
			})).Should(Succeed())
			Eventually(serverState(wgKey), Timeout, Interval).Should(ContainSubstring(publicKey))

			podKey := types.NamespacedName{Name: pod.Name, Namespace: otherNS}
			Consistently(func() string {
				got := &corev1.Pod{}
				if err := k8sClient.Get(context.Background(), podKey, got); err != nil {
					return "get-failed"
				}
				return got.Annotations["wgConfigLastUpdated"]
			}, "3s", Interval).Should(BeEmpty(), "a pod in another namespace must not be nudged")
		})

		// expectDegradedWithoutDeployment waits for the Degraded condition want on the Wireguard key
		// names, then asserts its Deployment is never rendered.
		expectDegradedWithoutDeployment := func(key types.NamespacedName, want string) {
			Eventually(degraded(key), Timeout, Interval).Should(Equal(want))
			Consistently(func() bool {
				err := k8sClient.Get(context.Background(), types.NamespacedName{Name: key.Name + "-dep", Namespace: key.Namespace}, &appsv1.Deployment{})
				return apierrors.IsNotFound(err)
			}, "2s", Interval).Should(BeTrue(), "a spec the operator cannot render must render no Deployment")
		}

		It("reports InvalidLocalCIDRs and renders no Deployment", func() {
			key := types.NamespacedName{Name: "vpn-badlocal", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: []string{"10.0.0.0/24", "10.1.0.1/16"}},
			})).Should(Succeed())

			expectDegradedWithoutDeployment(key, `InvalidLocalCIDRs|localCIDRs[1] "10.1.0.1/16" has host bits set; use 10.1.0.0/16`)
		})

		It("reports PeerCIDROverlapsLocalCIDRs and renders no Deployment", func() {
			key := types.NamespacedName{Name: "vpn-overlap", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: []string{"10.0.0.0/24", "10.8.0.0/16"}},
			})).Should(Succeed())

			expectDegradedWithoutDeployment(key, "PeerCIDROverlapsLocalCIDRs|peerCIDR 10.8.0.0/24 overlaps localCIDRs[1] 10.8.0.0/16; peer addresses must lie outside the cluster's networks")
		})

		It("reports ProbeAddressInLocalCIDRs and renders no Deployment", func() {
			key := types.NamespacedName{Name: "vpn-probe", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: []string{"10.0.0.0/24", "192.0.2.0/24"}},
			})).Should(Succeed())

			expectDegradedWithoutDeployment(key, "ProbeAddressInLocalCIDRs|localCIDRs[1] 192.0.2.0/24 contains 192.0.2.1, the address the gateway's readiness check routes through the tunnel; it is reserved for documentation (RFC 5737), so no cluster network should hold it")
		})

		It("reports ProbeAddressInPeerCIDR and renders no Deployment", func() {
			key := types.NamespacedName{Name: "vpn-probe-peer", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
				Spec:       v1alpha1.WireguardSpec{PeerCIDR: "192.0.2.0/24", LocalCIDRs: []string{"10.0.0.0/24"}},
			})).Should(Succeed())

			expectDegradedWithoutDeployment(key, "ProbeAddressInPeerCIDR|peerCIDR 192.0.2.0/24 contains 192.0.2.1, the address the gateway's readiness check routes through the tunnel; it is reserved for documentation (RFC 5737), so choose a peer range that does not hold it")
		})

		It("reports ClusterIPOutsideLocalCIDRs and renders no Deployment", func() {
			key := types.NamespacedName{Name: "vpn-cip", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
				Spec:       v1alpha1.WireguardSpec{LocalCIDRs: []string{"192.168.0.0/16"}},
			})).Should(Succeed())

			svcKey := types.NamespacedName{Name: key.Name + "-svc", Namespace: key.Namespace}
			clusterIP := func() string {
				svc := &corev1.Service{}
				if err := k8sClient.Get(context.Background(), svcKey, svc); err != nil {
					return ""
				}
				return svc.Spec.ClusterIP
			}
			var ip string
			Eventually(func() string { ip = clusterIP(); return ip }, Timeout, Interval).ShouldNot(BeEmpty())

			expectDegradedWithoutDeployment(key, "ClusterIPOutsideLocalCIDRs|Service vpn-cip-svc has ClusterIP "+ip+", which is in no localCIDRs entry; add the cluster's Service CIDR to localCIDRs")
		})

		It("reports ReservedGluetunEnv for an env entry, and clears it once the entry is gone", func() {
			key := types.NamespacedName{Name: "vpn-resenv", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
				Spec: v1alpha1.WireguardSpec{
					LocalCIDRs: testLocalCIDRs,
					Gluetun: v1alpha1.GluetunSpec{Env: []corev1.EnvVar{
						{Name: "VPN_SERVICE_PROVIDER", Value: "custom"},
						{Name: "VPN_INTERFACE", Value: "wg0"},
					}},
				},
			})).Should(Succeed())

			expectDegradedWithoutDeployment(key, "ReservedGluetunEnv|spec.gluetun.env sets VPN_INTERFACE, which the operator renders")

			Eventually(func() error {
				wg := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), key, wg); err != nil {
					return err
				}
				wg.Spec.Gluetun.Env = []corev1.EnvVar{{Name: "VPN_SERVICE_PROVIDER", Value: "custom"}}
				return k8sClient.Update(context.Background(), wg)
			}, Timeout, Interval).Should(Succeed())

			Eventually(func() error {
				return k8sClient.Get(context.Background(), types.NamespacedName{Name: key.Name + "-dep", Namespace: key.Namespace}, &appsv1.Deployment{})
			}, Timeout, Interval).Should(Succeed())
			Eventually(func() string {
				wg := &v1alpha1.Wireguard{}
				if err := k8sClient.Get(context.Background(), key, wg); err != nil {
					return "get-failed"
				}
				c := meta.FindStatusCondition(wg.Status.Conditions, ConditionDegraded)
				if c == nil || c.Status != metav1.ConditionFalse {
					return "not-cleared"
				}
				return c.Reason
			}, Timeout, Interval).Should(Equal("Reconciled"))
		})

		It("reports ReservedGluetunEnv for a key of a referenced Secret", func() {
			Expect(k8sClient.Create(context.Background(), &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "gluetun-creds", Namespace: wgNamespace},
				Data:       map[string][]byte{"WIREGUARD_PRIVATE_KEY": []byte("x"), "VPN_TYPE": []byte("openvpn")},
			})).Should(Succeed())

			key := types.NamespacedName{Name: "vpn-ressecret", Namespace: wgNamespace}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
				Spec: v1alpha1.WireguardSpec{
					LocalCIDRs: testLocalCIDRs,
					Gluetun: v1alpha1.GluetunSpec{EnvFrom: []corev1.EnvFromSource{{
						SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "gluetun-creds"}},
					}}},
				},
			})).Should(Succeed())

			expectDegradedWithoutDeployment(key, "ReservedGluetunEnv|Secret gluetun-creds, referenced by spec.gluetun.envFrom[0], sets VPN_TYPE, which the operator renders")
		})
	})

})

// degraded returns a poller for the Degraded condition of the Wireguard named by key: its reason and
// message joined by "|" while the condition is True, else "".
func degraded(key types.NamespacedName) func() string {
	return func() string {
		wg := &v1alpha1.Wireguard{}
		if err := k8sClient.Get(context.Background(), key, wg); err != nil {
			return ""
		}
		c := meta.FindStatusCondition(wg.Status.Conditions, ConditionDegraded)
		if c == nil || c.Status != metav1.ConditionTrue {
			return ""
		}
		return c.Reason + "|" + c.Message
	}
}

// newPublicKey returns a fresh WireGuard public key. The operator no longer mints peer keys, so
// every peer a spec expects to be configured must carry one.
func newPublicKey() string {
	key, err := wgtypes.GeneratePrivateKey()
	Expect(err).ShouldNot(HaveOccurred())
	return key.PublicKey().String()
}

// serverState returns a poller for the state.json the Wireguard named by key hands its agent, or
// "" while the Secret does not exist.
func serverState(key types.NamespacedName) func() string {
	return func() string {
		secret := &corev1.Secret{}
		if err := k8sClient.Get(context.Background(), key, secret); err != nil {
			return ""
		}
		return string(secret.Data["state.json"])
	}
}

// peerAddress returns a poller for the status.address of the peer named by key, or "get-failed"
// while it cannot be read.
func peerAddress(key types.NamespacedName) func() string {
	return func() string {
		got := &v1alpha1.WireguardPeer{}
		if err := k8sClient.Get(context.Background(), key, got); err != nil {
			return "get-failed"
		}
		return got.Status.Address
	}
}
