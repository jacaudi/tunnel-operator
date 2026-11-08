//go:build integration

package controllers

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/agent"
	"github.com/jacaudi/tunnel-operator/internal/resources"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The specs below read the egress permissions the operator renders into state.json from the labels on a
// peer's own pod. Nothing watches Pods and the 30 s requeue exceeds the 10 s timeout, so a spec that
// changes a pod's labels nudges the Wireguard (its annotation) to trigger the reconcile that reads them.
var _ = Describe("egress permissions from verified pod labels", func() {
	const (
		egressNS       = "egress-t6"
		egressTimeout  = time.Second * 10
		egressInterval = time.Millisecond * 250
	)
	ctx := context.Background()

	var created []client.Object
	BeforeEach(func() {
		err := k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: egressNS}})
		Expect(client.IgnoreAlreadyExists(err)).Should(Succeed())
	})
	AfterEach(func() {
		for _, obj := range created {
			_ = k8sClient.Delete(ctx, obj)
		}
		created = nil
	})

	// gateway creates a Wireguard named name, mutated by mutate, and waits until it is Ready.
	gateway := func(name string, mutate ...func(*v1alpha1.Wireguard)) types.NamespacedName {
		wg := &v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: egressNS},
			Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs},
		}
		for _, m := range mutate {
			m(wg)
		}
		Expect(k8sClient.Create(ctx, wg)).Should(Succeed())
		created = append(created, wg)
		key := client.ObjectKeyFromObject(wg)
		Eventually(func() string {
			live := &v1alpha1.Wireguard{}
			_ = k8sClient.Get(ctx, key, live)
			return live.Status.Status
		}, egressTimeout, egressInterval).Should(Equal(v1alpha1.Ready))
		return key
	}

	// attachPeer creates the peer name, owned as the controller by the Pod ownerName with ownerUID.
	attachPeer := func(gw types.NamespacedName, name, ownerName string, ownerUID types.UID) types.NamespacedName {
		peer := &v1alpha1.WireguardPeer{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: egressNS,
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "v1", Kind: "Pod", Name: ownerName, UID: ownerUID, Controller: new(true),
				}},
			},
			Spec: v1alpha1.WireguardPeerSpec{WireguardRef: gw.Name, PublicKey: newPublicKey()},
		}
		Expect(k8sClient.Create(ctx, peer)).Should(Succeed())
		created = append(created, peer)
		return client.ObjectKeyFromObject(peer)
	}

	// attach creates the pod name with labels, then the peer of that name for gw, owned by the pod as
	// the sidecar would create it, and returns the peer's key.
	attach := func(gw types.NamespacedName, name string, labels map[string]string) types.NamespacedName {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: egressNS, Labels: labels},
			Spec: corev1.PodSpec{
				ServiceAccountName: "default",
				Containers:         []corev1.Container{{Name: "app", Image: "busybox"}},
			},
		}
		Expect(k8sClient.Create(ctx, pod)).Should(Succeed())
		created = append(created, pod)
		return attachPeer(gw, name, name, pod.UID)
	}

	address := func(peer types.NamespacedName) func() string {
		return func() string {
			p := &v1alpha1.WireguardPeer{}
			_ = k8sClient.Get(ctx, peer, p)
			return p.Status.Address
		}
	}

	// egressOf polls the Egress of the state.json the gateway hands its agent, and the addresses of the
	// peers it lists.
	egressOf := func(gw types.NamespacedName) func() agent.State {
		return func() agent.State {
			secret := &corev1.Secret{}
			var state agent.State
			if err := k8sClient.Get(ctx, gw, secret); err == nil {
				_ = json.Unmarshal(secret.Data["state.json"], &state)
			}
			return state
		}
	}

	portForwarding := func(peer types.NamespacedName) func() *metav1.Condition {
		return func() *metav1.Condition {
			p := &v1alpha1.WireguardPeer{}
			_ = k8sClient.Get(ctx, peer, p)
			return meta.FindStatusCondition(p.Status.Conditions, "PortForwarding")
		}
	}

	nudge := func(gw types.NamespacedName, n string) {
		Eventually(func() error {
			live := &v1alpha1.Wireguard{}
			if err := k8sClient.Get(ctx, gw, live); err != nil {
				return err
			}
			if live.Annotations == nil {
				live.Annotations = map[string]string{}
			}
			live.Annotations["probe.test/nudge"] = n
			return k8sClient.Update(ctx, live)
		}, egressTimeout, egressInterval).Should(Succeed())
	}

	cycle := map[string]string{resources.LabelCycle: resources.CycleAllowedValue}
	fwd := map[string]string{resources.LabelForwardedPort: resources.ForwardedPortValue}

	It("a labelled verified pod's peer appears in state.json CycleAllowed", func() {
		gw := gateway("cycle")
		peer := attach(gw, "app", cycle)
		attach(gw, "bystander", nil)

		Eventually(address(peer), egressTimeout, egressInterval).ShouldNot(BeEmpty())
		addr := address(peer)()
		// The agent matches a caller's host against status.address, so CycleAllowed holds that same bare address.
		_, err := netip.ParseAddr(addr)
		Expect(err).ShouldNot(HaveOccurred(), "status.address is a bare address, as CycleAllowed must be")
		Eventually(func() []string { return egressOf(gw)().Egress.CycleAllowed }, egressTimeout, egressInterval).
			Should(Equal([]string{addr}), "only the labelled pod's peer may cycle")
	})

	It("a forged peer naming a labelled pod gains nothing", func() {
		gw := gateway("forged")
		victim := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "victim", Namespace: egressNS,
				Labels: map[string]string{
					resources.LabelCycle:         resources.CycleAllowedValue,
					resources.LabelForwardedPort: resources.ForwardedPortValue,
				},
			},
			Spec: corev1.PodSpec{ServiceAccountName: "default", Containers: []corev1.Container{{Name: "app", Image: "busybox"}}},
		}
		Expect(k8sClient.Create(ctx, victim)).Should(Succeed())
		created = append(created, victim)

		// One peer points at the victim under another name, one is named for it under another UID.
		pointing := attachPeer(gw, "pointing-at-victim", "victim", victim.UID)
		wrongUID := attachPeer(gw, "victim", "victim", types.UID("00000000-0000-0000-0000-000000000000"))

		Eventually(address(pointing), egressTimeout, egressInterval).ShouldNot(BeEmpty())
		Eventually(address(wrongUID), egressTimeout, egressInterval).ShouldNot(BeEmpty())
		Eventually(func() int { return len(egressOf(gw)().Peers) }, egressTimeout, egressInterval).Should(Equal(2),
			"both forged peers are admitted, so a reconcile has evaluated them")
		nudge(gw, "a")
		Consistently(egressOf(gw), "3s", egressInterval).Should(WithTransform(func(s agent.State) agent.Egress { return s.Egress }, Equal(agent.Egress{})),
			"neither forged peer may cycle or hold the port")
		Expect(portForwarding(pointing)()).Should(BeNil())
		Expect(portForwarding(wrongUID)()).Should(BeNil())
	})

	// twoClaimants attaches an older and a younger pod, both labelled for the forwarded port, and waits for
	// the older to hold it.
	twoClaimants := func(gw types.NamespacedName) (older, younger types.NamespacedName, olderPod *corev1.Pod) {
		older = attach(gw, "older", fwd)
		Eventually(address(older), egressTimeout, egressInterval).ShouldNot(BeEmpty())
		// creationTimestamp has one-second resolution: the younger peer must be created a full second later.
		time.Sleep(1100 * time.Millisecond)
		younger = attach(gw, "younger", fwd)
		Eventually(address(younger), egressTimeout, egressInterval).ShouldNot(BeEmpty())
		olderPod = &corev1.Pod{}
		Expect(k8sClient.Get(ctx, older, olderPod)).Should(Succeed())
		return older, younger, olderPod
	}

	It("two forwarded-port pods: the older holds, the other gets PortForwarding=False/HeldByAnotherPeer", func() {
		gw := gateway("election")
		older, younger, _ := twoClaimants(gw)

		Eventually(func() string { return egressOf(gw)().Egress.ForwardedPortPeer }, egressTimeout, egressInterval).
			Should(Equal(address(older)()), "the older claimant holds the port")
		Eventually(func() string {
			if c := portForwarding(older)(); c != nil {
				return string(c.Status) + "/" + c.Reason
			}
			return ""
		}, egressTimeout, egressInterval).Should(Equal("True/Held"))
		Eventually(func() string {
			if c := portForwarding(younger)(); c != nil {
				return string(c.Status) + "/" + c.Reason
			}
			return ""
		}, egressTimeout, egressInterval).Should(Equal("False/HeldByAnotherPeer"))
		Consistently(func() string { return egressOf(gw)().Egress.ForwardedPortPeer }, "2s", egressInterval).
			Should(Equal(address(older)()), "the holder keeps the port")
	})

	It("removing the holder's label releases the port to the other", func() {
		gw := gateway("release")
		older, younger, olderPod := twoClaimants(gw)
		Eventually(func() string { return egressOf(gw)().Egress.ForwardedPortPeer }, egressTimeout, egressInterval).
			Should(Equal(address(older)()))

		olderPod.Labels = nil
		Expect(k8sClient.Update(ctx, olderPod)).Should(Succeed())
		nudge(gw, "b")

		Eventually(func() string { return egressOf(gw)().Egress.ForwardedPortPeer }, egressTimeout, egressInterval).
			Should(Equal(address(younger)()), "the port goes to the other claimant")
		Eventually(func() string {
			if c := portForwarding(younger)(); c != nil {
				return string(c.Status) + "/" + c.Reason
			}
			return ""
		}, egressTimeout, egressInterval).Should(Equal("True/Held"))
		Eventually(portForwarding(older), egressTimeout, egressInterval).Should(BeNil(),
			"a peer that is no longer a claimant carries no PortForwarding condition")
	})

	It("staticPort and the cycle annotation reach state.json", func() {
		gw := gateway("static", func(wg *v1alpha1.Wireguard) {
			wg.Spec.Gluetun.PortForwarding = &v1alpha1.PortForwardingSpec{StaticPort: 51413}
			wg.Annotations = map[string]string{resources.AnnotationCycleRequestedAt: "request-1"}
		})

		Eventually(func() agent.Egress { return egressOf(gw)().Egress }, egressTimeout, egressInterval).
			Should(Equal(agent.Egress{StaticPort: 51413, CycleRequestedAt: "request-1"}))

		Eventually(func() error {
			live := &v1alpha1.Wireguard{}
			if err := k8sClient.Get(ctx, gw, live); err != nil {
				return err
			}
			live.Annotations[resources.AnnotationCycleRequestedAt] = "request-2"
			return k8sClient.Update(ctx, live)
		}, egressTimeout, egressInterval).Should(Succeed())
		Eventually(func() string { return egressOf(gw)().Egress.CycleRequestedAt }, egressTimeout, egressInterval).
			Should(Equal("request-2"))
	})
})
