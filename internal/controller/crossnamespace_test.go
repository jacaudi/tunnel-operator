//go:build integration

package controllers

import (
	"context"
	"strings"
	"time"

	"github.com/jacaudi/wireguard-operator/api/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("cross-namespace attachment", func() {
	// Timeout and Interval in the other Describes are declared inside their closures.
	const (
		gatewayNS = "xns-gateway"
		appNS     = "xns-app"
		timeout   = time.Second * 10
		interval  = time.Millisecond * 250
	)

	// readyGateway creates a Wireguard named name in gatewayNS with allowed as its policy and waits
	// until it is Ready.
	readyGateway := func(name string, allowed *v1alpha1.AllowedNamespaces) types.NamespacedName {
		key := types.NamespacedName{Namespace: gatewayNS, Name: name}
		Expect(k8sClient.Create(context.Background(), &v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
			Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs, AllowedNamespaces: allowed},
		})).Should(Succeed())
		Eventually(func() string {
			wg := &v1alpha1.Wireguard{}
			_ = k8sClient.Get(context.Background(), key, wg)
			return wg.Status.Status
		}, timeout, interval).Should(Equal(v1alpha1.Ready))
		return key
	}

	// createPeer creates the peer ns/name attaching to gateway, and returns its key and public key.
	createPeer := func(ns, name string, gateway types.NamespacedName) (types.NamespacedName, string) {
		publicKey := newPublicKey()
		key := types.NamespacedName{Namespace: ns, Name: name}
		spec := v1alpha1.WireguardPeerSpec{WireguardRef: gateway.Name, PublicKey: publicKey}
		if ns != gateway.Namespace {
			spec.WireguardNamespace = gateway.Namespace
		}
		Expect(k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
			Spec:       spec,
		})).Should(Succeed())
		return key, publicKey
	}

	// readyReason polls the peer's Ready condition as "<reason>|<status.status>|<address>", or "" while it has none.
	readyReason := func(key types.NamespacedName) func() string {
		return func() string {
			got := &v1alpha1.WireguardPeer{}
			_ = k8sClient.Get(context.Background(), key, got)
			if c := meta.FindStatusCondition(got.Status.Conditions, ConditionReady); c != nil {
				return c.Reason + "|" + got.Status.Status + "|" + got.Status.Address
			}
			return ""
		}
	}

	BeforeEach(func() {
		for _, name := range []string{gatewayNS, appNS} {
			err := k8sClient.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
			Expect(client.IgnoreAlreadyExists(err)).Should(Succeed())
		}
	})

	It("admits a peer from another namespace, with an address unique across namespaces", func() {
		gateway := readyGateway("vpn-all", nil)

		// The same name in both namespaces: the gateway must tell them apart.
		local, _ := createPeer(gatewayNS, "app", gateway)
		Eventually(peerAddress(local), timeout, interval).Should(Equal("10.8.0.2"))
		foreign, foreignKey := createPeer(appNS, "app", gateway)

		Eventually(peerAddress(foreign), timeout, interval).Should(Equal("10.8.0.3"), "a foreign peer takes the next free address, not one a local peer holds")
		Eventually(serverState(gateway), timeout, interval).Should(ContainSubstring(foreignKey))
		Consistently(peerAddress(local), "2s", interval).Should(Equal("10.8.0.2"))
	})

	It("carries the gateway's endpoint, public key and localCIDRs in the peer's status", func() {
		gateway := readyGateway("vpn-status", nil)
		peer, _ := createPeer(appNS, "status-app", gateway)

		wg := &v1alpha1.Wireguard{}
		Expect(k8sClient.Get(context.Background(), gateway, wg)).Should(Succeed())
		Expect(wg.Status.Endpoint).ShouldNot(BeEmpty())
		Expect(wg.Status.PublicKey).ShouldNot(BeEmpty())

		Eventually(func() v1alpha1.WireguardPeerStatus {
			got := &v1alpha1.WireguardPeer{}
			_ = k8sClient.Get(context.Background(), peer, got)
			return v1alpha1.WireguardPeerStatus{Endpoint: got.Status.Endpoint, ServerPublicKey: got.Status.ServerPublicKey, LocalCIDRs: got.Status.LocalCIDRs}
		}, timeout, interval).Should(Equal(v1alpha1.WireguardPeerStatus{Endpoint: wg.Status.Endpoint, ServerPublicKey: wg.Status.PublicKey, LocalCIDRs: testLocalCIDRs}))
	})

	It("refuses a foreign peer under Same, and admits it once the gateway allows every namespace", func() {
		gateway := readyGateway("vpn-same", &v1alpha1.AllowedNamespaces{From: v1alpha1.FromSame})
		local, _ := createPeer(gatewayNS, "same-local", gateway)
		foreign, foreignKey := createPeer(appNS, "same-foreign", gateway)

		Eventually(peerAddress(local), timeout, interval).Should(Equal("10.8.0.2"))
		Eventually(readyReason(foreign), timeout, interval).Should(Equal(ReasonNamespaceNotAllowed+"|"+v1alpha1.Error+"|"), "a refused peer is not allocated an address")
		Consistently(serverState(gateway), "2s", interval).ShouldNot(ContainSubstring(foreignKey))

		Eventually(func() error {
			wg := &v1alpha1.Wireguard{}
			if err := k8sClient.Get(context.Background(), gateway, wg); err != nil {
				return err
			}
			wg.Spec.AllowedNamespaces = &v1alpha1.AllowedNamespaces{From: v1alpha1.FromAll}
			return k8sClient.Update(context.Background(), wg)
		}, timeout, interval).Should(Succeed())
		Eventually(peerAddress(foreign), timeout, interval).Should(Equal("10.8.0.3"))
		Eventually(serverState(gateway), timeout, interval).Should(ContainSubstring(foreignKey))
	})

	It("refuses a peer in another namespace that copies an existing peer's public key", func() {
		gateway := readyGateway("vpn-key", nil)
		original, originalKey := createPeer(gatewayNS, "original", gateway)
		Eventually(peerAddress(original), timeout, interval).Should(Equal("10.8.0.2"))

		// A peer created later, in another namespace, with a name that sorts after the original's.
		copied := types.NamespacedName{Namespace: appNS, Name: "zzz-copy"}
		Expect(k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
			ObjectMeta: metav1.ObjectMeta{Name: copied.Name, Namespace: copied.Namespace},
			Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: gateway.Name, WireguardNamespace: gateway.Namespace, PublicKey: originalKey},
		})).Should(Succeed())

		Eventually(readyReason(copied), timeout, interval).Should(Equal(ReasonPublicKeyConflict+"|"+v1alpha1.Pending+"|"), "the copy is refused and given no address")
		Consistently(peerAddress(original), "2s", interval).Should(Equal("10.8.0.2"), "the original keeps its address")
		Expect(strings.Count(serverState(gateway)(), originalKey)).Should(Equal(1), "the key reaches state.json once, for the original")
	})

	It("reports WireguardNotFound naming the resolved namespace when the gateway is missing there", func() {
		peer, _ := createPeer(appNS, "orphan", types.NamespacedName{Namespace: gatewayNS, Name: "absent"})

		Eventually(func() string {
			got := &v1alpha1.WireguardPeer{}
			if err := k8sClient.Get(context.Background(), peer, got); err != nil {
				return "get-failed"
			}
			if c := meta.FindStatusCondition(got.Status.Conditions, ConditionReady); c != nil {
				return c.Reason + "|" + c.Message
			}
			return "no-condition"
		}, timeout, interval).Should(Equal(ReasonWireguardNotFound + "|no Wireguard named absent exists in namespace " + gatewayNS))
	})

	It("defaults allowedNamespaces.from to All and rejects any other value", func() {
		wg := &v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{Name: "vpn-default", Namespace: gatewayNS},
			Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs, AllowedNamespaces: &v1alpha1.AllowedNamespaces{}},
		}
		Expect(k8sClient.Create(context.Background(), wg)).Should(Succeed())
		got := &v1alpha1.Wireguard{}
		Expect(k8sClient.Get(context.Background(), client.ObjectKeyFromObject(wg), got)).Should(Succeed())
		Expect(got.Spec.AllowedNamespaces).ShouldNot(BeNil())
		Expect(got.Spec.AllowedNamespaces.From).Should(Equal(v1alpha1.FromAll))

		bad := &v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{Name: "vpn-bad", Namespace: gatewayNS},
			Spec:       v1alpha1.WireguardSpec{LocalCIDRs: testLocalCIDRs, AllowedNamespaces: &v1alpha1.AllowedNamespaces{From: "Selector"}},
		}
		Expect(apierrors.IsInvalid(k8sClient.Create(context.Background(), bad))).Should(BeTrue())
	})

	It("rejects a wireguardNamespace that is not a DNS label", func() {
		for _, ns := range []string{"Not_A_Namespace", "-leading", strings.Repeat("a", 64)} {
			err := k8sClient.Create(context.Background(), &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "bad-ns", Namespace: appNS},
				Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: "vpn", WireguardNamespace: ns},
			})
			Expect(apierrors.IsInvalid(err)).Should(BeTrue(), "wireguardNamespace %q", ns)
		}
	})
})
