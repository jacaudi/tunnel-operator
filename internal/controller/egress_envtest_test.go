//go:build integration

package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/agent"
	"github.com/jacaudi/tunnel-operator/internal/resources"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
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

	// The operator polls the agent of a Ready server and writes what it reports into status. Nothing watches
	// Pods, so a spec that adds the gateway's pod or changes what the fake reader says nudges the Wireguard.
	Context("status polled from the agent", func() {
		const (
			apiURL = "http://10.8.0.1:8081"
			podIP  = "192.0.2.11"
		)
		finished := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
		cycle := func(reason string, at time.Time) *v1alpha1.CycleResult {
			return &v1alpha1.CycleResult{Reason: reason, OldExitIP: "203.0.113.8", NewExitIP: "203.0.113.9", Trigger: "api:10.8.0.2", FinishedAt: metav1.NewTime(at)}
		}

		AfterEach(func() { egressReader.forget(podIP) })

		// readyGatewayPod creates the pod the gateway's Deployment would run, which envtest has no
		// controller to do, and marks it Ready with podIP as the kubelet would.
		readyGatewayPod := func(gw types.NamespacedName) {
			dep := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name + "-dep"}, dep)).Should(Succeed())
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-pod", Namespace: gw.Namespace, Labels: dep.Spec.Selector.MatchLabels},
				Spec:       corev1.PodSpec{ServiceAccountName: "default", Containers: []corev1.Container{{Name: "app", Image: "busybox"}}},
			}
			Expect(k8sClient.Create(ctx, pod)).Should(Succeed())
			created = append(created, pod)
			pod.Status = corev1.PodStatus{
				Phase:      corev1.PodRunning,
				PodIP:      podIP,
				PodIPs:     []corev1.PodIP{{IP: podIP}},
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			}
			Expect(k8sClient.Status().Update(ctx, pod)).Should(Succeed())
		}

		statusOf := func(gw types.NamespacedName) func() v1alpha1.WireguardStatus {
			return func() v1alpha1.WireguardStatus {
				live := &v1alpha1.Wireguard{}
				_ = k8sClient.Get(ctx, gw, live)
				return live.Status
			}
		}

		// egressDiff is "" once status.egress is semantically what want says, else both as JSON.
		egressDiff := func(gw types.NamespacedName, want *v1alpha1.EgressStatus) func() string {
			return func() string {
				got := statusOf(gw)().Egress
				if equality.Semantic.DeepEqual(got, want) {
					return ""
				}
				g, _ := json.Marshal(got)
				w, _ := json.Marshal(want)
				return "got " + string(g) + ", want " + string(w)
			}
		}

		cycled := func(gw types.NamespacedName) func() string {
			return func() string {
				if c := meta.FindStatusCondition(statusOf(gw)().Conditions, "Cycled"); c != nil {
					return string(c.Status) + "/" + c.Reason
				}
				return ""
			}
		}

		// polled waits until the reconciler has asked the fake reader again after before, which a nudge
		// causes, so a spec that then asserts nothing changed has seen a poll happen.
		polled := func(before int) {
			Eventually(func() int { return egressReader.callsTo(podIP) }, egressTimeout, egressInterval).Should(BeNumerically(">", before))
		}

		// settled brings a gateway to a Ready server whose pod reports rep, and returns the status.egress
		// that results.
		settled := func(name string, rep EgressReport) (types.NamespacedName, *v1alpha1.EgressStatus) {
			gw := gateway(name)
			egressReader.set(podIP, rep, nil)
			readyGatewayPod(gw)
			nudge(gw, "settle")
			Eventually(func() bool { return statusOf(gw)().Egress != nil }, egressTimeout, egressInterval).Should(BeTrue())
			return gw, statusOf(gw)().Egress
		}

		wantEgress := &v1alpha1.EgressStatus{ExitIP: "203.0.113.9", ForwardedPort: 51413, LastHandledAnnotation: "req-1", LastCycle: cycle("Succeeded", finished)}
		wantReport := EgressReport{ExitIP: "203.0.113.9", ForwardedPort: 51413, LastHandledAnnotation: "req-1", LastCycle: cycle("Succeeded", finished)}

		It("status.egress and egressAPI appear from the reader", func() {
			gw := gateway("poll-appear")
			Expect(statusOf(gw)().EgressAPI).Should(Equal(apiURL), "the Ready write carries the API URL")
			Expect(statusOf(gw)().Egress).Should(BeNil(), "no pod has reported yet")
			Expect(cycled(gw)()).Should(BeEmpty(), "the Cycled condition is absent until there is a cycle")

			egressReader.set(podIP, wantReport, nil)
			readyGatewayPod(gw)
			nudge(gw, "1")

			Eventually(egressDiff(gw, wantEgress), egressTimeout, egressInterval).Should(BeEmpty())
			Expect(statusOf(gw)().EgressAPI).Should(Equal(apiURL))
			Expect(statusOf(gw)().Status).Should(Equal(v1alpha1.Ready))
		})

		It("status.egress content is stable across nudges", func() {
			gw, want := settled("poll-stable", wantReport)
			before := egressReader.callsTo(podIP)

			for i := 1; i <= 3; i++ {
				nudge(gw, strconv.Itoa(i))
			}

			polled(before)
			Consistently(egressDiff(gw, want), "3s", egressInterval).Should(BeEmpty())
		})

		It("a reader error keeps the last status.egress", func() {
			gw, want := settled("poll-error", wantReport)
			before := egressReader.callsTo(podIP)

			egressReader.set(podIP, EgressReport{}, errors.New("agent unreachable"))
			nudge(gw, "error")

			polled(before)
			Consistently(egressDiff(gw, want), "3s", egressInterval).Should(BeEmpty())
			Expect(statusOf(gw)().Status).Should(Equal(v1alpha1.Ready))
		})

		It("a LastCycle whose FinishedAt has nanoseconds is stored with second precision", func() {
			gw, _ := settled("poll-nanos", EgressReport{ExitIP: "203.0.113.9", LastCycle: cycle("Succeeded", finished.Add(500*time.Millisecond))})

			got := statusOf(gw)().Egress.LastCycle.FinishedAt
			Expect(got.Time.Nanosecond()).Should(BeZero())
			Expect(got.Time.UTC()).Should(Equal(finished))
		})

		It("Cycled is True after a Succeeded report and False after IPUnchanged", func() {
			gw, _ := settled("poll-cycled", wantReport)
			Eventually(cycled(gw), egressTimeout, egressInterval).Should(Equal("True/Succeeded"))

			egressReader.set(podIP, EgressReport{ExitIP: "203.0.113.9", LastCycle: cycle("IPUnchanged", finished.Add(time.Minute))}, nil)
			nudge(gw, "again")

			Eventually(cycled(gw), egressTimeout, egressInterval).Should(Equal("False/IPUnchanged"))
		})
	})
})

// fakeEgressReader is the EgressReader the envtest reconciler is wired with. A spec sets what each pod IP
// reports; an IP nothing was set for fails, as an unreachable agent does.
type fakeEgressReader struct {
	mu      sync.Mutex
	results map[string]fakeEgressResult
	calls   map[string]int
}

type fakeEgressResult struct {
	report EgressReport
	err    error
}

func newFakeEgressReader() *fakeEgressReader {
	return &fakeEgressReader{results: map[string]fakeEgressResult{}, calls: map[string]int{}}
}

func (f *fakeEgressReader) Read(_ context.Context, podIP string) (EgressReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[podIP]++
	res, ok := f.results[podIP]
	if !ok {
		return EgressReport{}, fmt.Errorf("no result set for pod IP %s", podIP)
	}
	if res.err != nil {
		return EgressReport{}, res.err
	}
	return res.report, nil
}

func (f *fakeEgressReader) set(podIP string, report EgressReport, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results[podIP] = fakeEgressResult{report, err}
}

func (f *fakeEgressReader) forget(podIP string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.results, podIP)
}

func (f *fakeEgressReader) callsTo(podIP string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[podIP]
}
