package sidecar

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jacaudi/wireguard-operator/api/v1alpha1"
)

// peerAction is what the client does with the WireguardPeer named after its pod.
type peerAction string

const (
	actionCreate  peerAction = "create"  // no such peer exists
	actionKeep    peerAction = "keep"    // it is this pod's, with this pod's key and wireguardRef
	actionReplace peerAction = "replace" // a Pod controls it, but not this pod, or it carries another key or wireguardRef
	actionRefuse  peerAction = "refuse"  // no Pod controls it, so the client must not delete it
)

// desiredPeer returns the WireguardPeer the pod registers: named after the pod, in its namespace, with
// spec.wireguardRef cfg.Wireguard and spec.publicKey publicKey, and the pod as its only owner and
// controller. blockOwnerDeletion stays unset; setting it would need update on pods/finalizers.
func desiredPeer(cfg Config, publicKey string) *v1alpha1.WireguardPeer {
	return &v1alpha1.WireguardPeer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cfg.PodName,
			Namespace: cfg.PodNamespace,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1",
				Kind:       "Pod",
				Name:       cfg.PodName,
				UID:        cfg.PodUID,
				Controller: new(true),
			}},
		},
		Spec: v1alpha1.WireguardPeerSpec{PublicKey: publicKey, WireguardRef: cfg.Wireguard},
	}
}

// decidePeer returns the action for existing, the peer read under the pod's name (nil when there is
// none), against want, the result of desiredPeer.
func decidePeer(existing, want *v1alpha1.WireguardPeer) peerAction {
	if existing == nil {
		return actionCreate
	}
	ctl := metav1.GetControllerOf(existing)
	if ctl == nil || ctl.APIVersion != "v1" || ctl.Kind != "Pod" {
		return actionRefuse
	}
	if ctl.UID != metav1.GetControllerOf(want).UID {
		return actionReplace
	}
	if existing.Spec.PublicKey != want.Spec.PublicKey || existing.Spec.WireguardRef != want.Spec.WireguardRef {
		return actionReplace
	}
	return actionKeep
}

// ensurePeer makes the WireguardPeer named after the pod this pod's, reading through r and writing
// through w. It returns the peer when it was already this pod's, and nil after it created or replaced
// it; the next pass reads it back. AlreadyExists from the create and NotFound or Conflict from the
// delete are not errors: a later pass sees the outcome.
func ensurePeer(ctx context.Context, r ctrlclient.Reader, w ctrlclient.Writer, cfg Config, publicKey string) (*v1alpha1.WireguardPeer, error) {
	key := types.NamespacedName{Namespace: cfg.PodNamespace, Name: cfg.PodName}
	want := desiredPeer(cfg, publicKey)

	existing := &v1alpha1.WireguardPeer{}
	if err := r.Get(ctx, key, existing); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("get WireguardPeer %s/%s: %w", key.Namespace, key.Name, err)
		}
		existing = nil
	}

	switch decidePeer(existing, want) {
	case actionKeep:
		return existing, nil
	case actionRefuse:
		return nil, fmt.Errorf("WireguardPeer %s/%s exists and no Pod controls it, so this pod cannot register under its name", key.Namespace, key.Name)
	case actionReplace:
		uid := existing.UID
		if err := w.Delete(ctx, existing, ctrlclient.Preconditions{UID: &uid}); err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
			return nil, fmt.Errorf("delete stale WireguardPeer %s/%s: %w", key.Namespace, key.Name, err)
		}
	case actionCreate:
	}

	if err := w.Create(ctx, want); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("create WireguardPeer %s/%s: %w", key.Namespace, key.Name, err)
	}
	return nil, nil
}
