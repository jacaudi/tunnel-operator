package controllers

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/jacaudi/wireguard-operator/api/v1alpha1"
	"github.com/jacaudi/wireguard-operator/internal/agent"

	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Ready=False reasons the operator records on a WireguardPeer.
const (
	// ReasonPublicKeyMissing: spec.publicKey is empty.
	ReasonPublicKeyMissing = "PublicKeyMissing"
	// ReasonWireguardNotFound: no Wireguard named spec.wireguardRef exists in the namespace
	// gatewayKey resolves, the peer's own unless spec.wireguardNamespace says otherwise.
	ReasonWireguardNotFound = "WireguardNotFound"
	// ReasonNamespaceNotAllowed: the Wireguard's spec.allowedNamespaces excludes the peer's namespace.
	ReasonNamespaceNotAllowed = "NamespaceNotAllowed"
	// ReasonAddressPoolExhausted: the server's peerCIDR has no free address left.
	ReasonAddressPoolExhausted = "AddressPoolExhausted"
	// ReasonInvalidPublicKey: spec.publicKey is not a canonical WireGuard key.
	ReasonInvalidPublicKey = "InvalidPublicKey"
	// ReasonAddressConflict: another, older peer holds this peer's address.
	ReasonAddressConflict = "AddressConflict"
	// ReasonPublicKeyConflict: another peer of the same Wireguard holds this peer's public key.
	ReasonPublicKeyConflict = "PublicKeyConflict"
)

// notReady is a peer state the server cannot admit: the summary fields and the Ready=False
// condition the operator records for it.
type notReady struct {
	Status           string // status.status: v1alpha1.Pending or v1alpha1.Error
	Message          string // status.message
	Reason           string // Ready condition reason
	ConditionMessage string // Ready condition message
}

// publicKeyMissing is the state of a peer with an empty spec.publicKey.
var publicKeyMissing = notReady{
	Status:           v1alpha1.Pending,
	Message:          "Waiting for spec.publicKey",
	Reason:           ReasonPublicKeyMissing,
	ConditionMessage: "spec.publicKey is empty, so the server cannot admit this peer",
}

// invalidPublicKey is the state of a peer whose spec.publicKey is not a canonical WireGuard key.
var invalidPublicKey = notReady{
	Status:           v1alpha1.Error,
	Message:          "spec.publicKey is not a valid WireGuard key",
	Reason:           ReasonInvalidPublicKey,
	ConditionMessage: "spec.publicKey is not a base64-encoded 32-byte WireGuard key, so the server cannot admit this peer",
}

// admissionProblem returns the not-ready record for a peer the server cannot admit, and false
// when the peer is admissible. An empty publicKey is publicKeyMissing. A key is invalidPublicKey
// unless wgtypes.ParseKey accepts it and the parsed key's String() equals it: the agent matches
// peers by the canonical string, so a non-canonical key would be removed and re-added on every sync.
func admissionProblem(peer *v1alpha1.WireguardPeer) (notReady, bool) {
	key := peer.Spec.PublicKey
	if key == "" {
		return publicKeyMissing, true
	}
	if parsed, err := wgtypes.ParseKey(key); err != nil || parsed.String() != key {
		return invalidPublicKey, true
	}
	return notReady{}, false
}

// gatewayKey is the Wireguard peer attaches to: spec.wireguardRef in spec.wireguardNamespace, which
// is the peer's own namespace when empty.
func gatewayKey(peer *v1alpha1.WireguardPeer) types.NamespacedName {
	return types.NamespacedName{Namespace: cmp.Or(peer.Spec.WireguardNamespace, peer.Namespace), Name: peer.Spec.WireguardRef}
}

// namespaceNotAllowed returns the not-ready record for a peer whose namespace wg's
// spec.allowedNamespaces excludes, and false when wg admits it. A nil policy, and an empty or All
// from, admit every namespace.
func namespaceNotAllowed(wg *v1alpha1.Wireguard, peer *v1alpha1.WireguardPeer) (notReady, bool) {
	allowed := wg.Spec.AllowedNamespaces
	if allowed == nil || allowed.From != v1alpha1.FromSame || peer.Namespace == wg.Namespace {
		return notReady{}, false
	}
	return notReady{
		Status:           v1alpha1.Error,
		Message:          fmt.Sprintf("Wireguard %s/%s does not accept peers from namespace %s", wg.Namespace, wg.Name, peer.Namespace),
		Reason:           ReasonNamespaceNotAllowed,
		ConditionMessage: fmt.Sprintf("Wireguard %s/%s sets spec.allowedNamespaces.from to Same, so it admits only peers in namespace %s", wg.Namespace, wg.Name, wg.Namespace),
	}, true
}

// validatePeerCIDR returns nil when cidr is a canonical IPv4 prefix (no host bits set) of length
// 30 or shorter, and an error naming the violated rule otherwise.
func validatePeerCIDR(cidr string) error {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("peerCIDR %q is not a CIDR: %w", cidr, err)
	}
	if !p.Addr().Is4() {
		return fmt.Errorf("peerCIDR %q is not an IPv4 prefix", cidr)
	}
	if p != p.Masked() {
		return fmt.Errorf("peerCIDR %q has host bits set; use %s", cidr, p.Masked())
	}
	if p.Bits() > 30 {
		return fmt.Errorf("peerCIDR %q leaves no address for a peer; use /30 or shorter", cidr)
	}
	return nil
}

// wireguardNotFound is the state of a peer whose gatewayKey names no Wireguard: ref in namespace.
func wireguardNotFound(ref, namespace string) notReady {
	return notReady{
		Status:           v1alpha1.Pending,
		Message:          fmt.Sprintf("Waiting for wireguard resource '%s' to be created", ref),
		Reason:           ReasonWireguardNotFound,
		ConditionMessage: fmt.Sprintf("no Wireguard named %s exists in namespace %s", ref, namespace),
	}
}

// addressPoolExhausted is the not-ready record for a peer that cidr has no free address for.
func addressPoolExhausted(cidr string) notReady {
	return notReady{
		Status:           v1alpha1.Pending,
		Message:          fmt.Sprintf("No free address in %s", cidr),
		Reason:           ReasonAddressPoolExhausted,
		ConditionMessage: fmt.Sprintf("peerCIDR %s has no free address for this peer", cidr),
	}
}

// desiredState renders the agent's state.json content from the server's name, namespace and
// spec and from each peer's name, namespace, spec.publicKey, spec.wireguardRef and
// status.address, sorted by peer name, then namespace. No other status field, no metadata and no
// resourceVersion reach it, so writing them never changes the rendered state. spec.gluetun is dropped: it can carry provider
// credentials, and the agent needs none of it.
func desiredState(wg *v1alpha1.Wireguard, privateKey string, peers []v1alpha1.WireguardPeer) agent.State {
	spec := *wg.Spec.DeepCopy()
	spec.Gluetun = v1alpha1.GluetunSpec{}
	rendered := make([]v1alpha1.WireguardPeer, len(peers))
	for i, peer := range peers {
		rendered[i] = v1alpha1.WireguardPeer{
			ObjectMeta: metav1.ObjectMeta{Name: peer.Name, Namespace: peer.Namespace},
			Spec:       v1alpha1.WireguardPeerSpec{PublicKey: peer.Spec.PublicKey, WireguardRef: peer.Spec.WireguardRef},
			Status:     v1alpha1.WireguardPeerStatus{Address: peer.Status.Address},
		}
	}
	slices.SortFunc(rendered, func(a, b v1alpha1.WireguardPeer) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Namespace, b.Namespace))
	})

	return agent.State{
		Server: v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{Name: wg.Name, Namespace: wg.Namespace},
			Spec:       spec,
		},
		ServerPrivateKey: privateKey,
		Peers:            rendered,
	}
}

// wireguardForPeer maps a WireguardPeer to the Wireguard gatewayKey names. It returns nil for any
// other object and for an empty wireguardRef.
func wireguardForPeer(_ context.Context, obj client.Object) []reconcile.Request {
	peer, ok := obj.(*v1alpha1.WireguardPeer)
	if !ok || peer.Spec.WireguardRef == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: gatewayKey(peer)}}
}

// peerStatusMatches reports whether peer already records nr: status.status, status.message,
// no status.address, endpoint, serverPublicKey or localCIDRs (a peer the server cannot admit holds
// none), and a Ready condition with Status False, nr.Reason, nr.ConditionMessage and
// ObservedGeneration == peer.Generation.
func peerStatusMatches(peer *v1alpha1.WireguardPeer, nr notReady) bool {
	c := meta.FindStatusCondition(peer.Status.Conditions, ConditionReady)
	return peer.Status.Status == nr.Status &&
		peer.Status.Address == "" &&
		peer.Status.Endpoint == "" &&
		peer.Status.ServerPublicKey == "" &&
		len(peer.Status.LocalCIDRs) == 0 &&
		peer.Status.Message == nr.Message &&
		c != nil &&
		c.Status == metav1.ConditionFalse &&
		c.Reason == nr.Reason &&
		c.Message == nr.ConditionMessage &&
		c.ObservedGeneration == peer.Generation
}

// skipPeerWrite reports whether err from a peer status write means "skip this peer for this pass":
// a Conflict (another writer won; its watch event re-enqueues the server) or a NotFound (the peer
// was deleted after the list).
func skipPeerWrite(err error) bool {
	return errors.IsConflict(err) || errors.IsNotFound(err)
}

// addressConflict is the not-ready record for a loser of address to winner, a namespace/name.
func addressConflict(address, winner string) notReady {
	msg := fmt.Sprintf("Address %s is held by peer %s; waiting for a new address", address, winner)
	return notReady{
		Status:           v1alpha1.Pending,
		Message:          msg,
		Reason:           ReasonAddressConflict,
		ConditionMessage: msg,
	}
}

// publicKeyConflict is the not-ready record for a loser of the public key to winner, a namespace/name.
func publicKeyConflict(winner string) notReady {
	return notReady{
		Status:           v1alpha1.Pending,
		Message:          fmt.Sprintf("Public key is held by peer %s; waiting for it to be released", winner),
		Reason:           ReasonPublicKeyConflict,
		ConditionMessage: fmt.Sprintf("spec.publicKey is already held by peer %s of this Wireguard, so this peer cannot be admitted", winner),
	}
}

// addressUsable reports whether addr is a host address inside cidr4 that the allocator could have
// handed out: it parses, lies in the prefix, and is neither the network nor the gateway (first
// host) address.
func addressUsable(addr, cidr4 string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	p, err := netip.ParsePrefix(cidr4)
	if err != nil {
		return false
	}
	p = p.Masked()
	return p.Contains(a) && a != p.Addr() && a != p.Addr().Next()
}

// conflictLoser is a peer that must give up a value (its status.address or its spec.publicKey) to
// Winner, the namespace/name of the peer that keeps it.
type conflictLoser struct {
	Peer   v1alpha1.WireguardPeer
	Winner string
}

// older reports whether a ranks before b: the oldest creationTimestamp, then the lexically smaller
// name, then the smaller namespace.
func older(a, b *v1alpha1.WireguardPeer) bool {
	return cmp.Or(a.CreationTimestamp.Compare(b.CreationTimestamp.Time), cmp.Compare(a.Name, b.Name), cmp.Compare(a.Namespace, b.Namespace)) < 0
}

// dedupeAddresses splits admissible peers into those that keep their state and those that must
// give up a shared status.address. Among the holders of one address the older peer keeps it; every
// other holder is a loser. Peers without an address are kept. keep preserves the input order.
// status.address is written only by the operator, so ordering by age cannot be forged.
func dedupeAddresses(peers []v1alpha1.WireguardPeer) (keep []v1alpha1.WireguardPeer, losers []conflictLoser) {
	holder := map[string]*v1alpha1.WireguardPeer{}
	for i := range peers {
		p := &peers[i]
		if h, ok := holder[p.Status.Address]; p.Status.Address != "" && (!ok || older(p, h)) {
			holder[p.Status.Address] = p
		}
	}
	for i := range peers {
		p := &peers[i]
		h := holder[p.Status.Address]
		if h == nil || h == p {
			keep = append(keep, *p)
			continue
		}
		losers = append(losers, conflictLoser{Peer: *p, Winner: client.ObjectKeyFromObject(h).String()})
	}
	return keep, losers
}

// dedupePublicKeys splits admitted peers into those that keep their state and those that must give
// up a spec.publicKey another peer holds, because the agent keys peers by public key and a second
// holder would take over the first one's AllowedIPs on the server.
//
// spec.publicKey is user-written and mutable, so age cannot decide who holds a key: an old peer
// could edit its key to a victim's and push the victim out. The peer the server's current state
// lists under that key, current[namespace/name] == key, keeps it. The Secret is written only by
// the operator, and a peer that has just edited its key is not listed under the new one; a peer's
// own status, which still reads ready after the edit, would not tell the two apart. Only when no
// contender is listed, or several are, does the older peer win. A refused peer waits, and is
// promoted only when the holder goes away. Peers with no key are kept. keep preserves the input
// order.
func dedupePublicKeys(peers []v1alpha1.WireguardPeer, current map[types.NamespacedName]string) (keep []v1alpha1.WireguardPeer, losers []conflictLoser) {
	listed := func(p *v1alpha1.WireguardPeer) bool {
		return current[client.ObjectKeyFromObject(p)] == p.Spec.PublicKey
	}
	beats := func(a, b *v1alpha1.WireguardPeer) bool {
		if la, lb := listed(a), listed(b); la != lb {
			return la
		}
		return older(a, b)
	}
	holder := map[string]*v1alpha1.WireguardPeer{}
	for i := range peers {
		p := &peers[i]
		if h, ok := holder[p.Spec.PublicKey]; p.Spec.PublicKey != "" && (!ok || beats(p, h)) {
			holder[p.Spec.PublicKey] = p
		}
	}
	for i := range peers {
		p := &peers[i]
		h := holder[p.Spec.PublicKey]
		if h == nil || h == p {
			keep = append(keep, *p)
			continue
		}
		losers = append(losers, conflictLoser{Peer: *p, Winner: client.ObjectKeyFromObject(h).String()})
	}
	return keep, losers
}
