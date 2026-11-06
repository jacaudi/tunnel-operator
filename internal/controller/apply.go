// Package controllers implements the Wireguard reconciler, which also reconciles the WireguardPeers that name each Wireguard.
package controllers

import (
	"context"
	"fmt"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/csaupgrade"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

// FieldManager identifies this operator's Server-Side Apply field manager. It is part of the
// on-cluster contract: changing it orphans field ownership on every existing object and leaves
// stale entries in managedFields. Not a tunable.
const FieldManager = "wireguard-operator"

// legacyFieldManagers names the Update-operation field manager that owns every field of an
// object written by this operator before it used Server-Side Apply. The apiserver takes the
// manager name from the client's User-Agent, whose first segment is the binary name: the image
// runs /manager (images/manager/Dockerfile) and cmd/manager sets no custom User-Agent, so it is
// "manager". Part of the on-cluster contract, like FieldManager. Objects last written by a
// differently named binary, such as a `go run` dev build, are not migrated.
var legacyFieldManagers = sets.New("manager")

// applyOwned renders an operator-owned object into the cluster with Server-Side Apply. The
// apiserver performs the diff; there is deliberately no client-side comparison. obj is
// overwritten with the server's response, so each call needs a freshly built object.
//
// What the operator ends up owning is what the unstructured conversion of the built object emits,
// which matches json.Marshal, and is not the same as "the fields the builder sets", in either
// direction. Zero-valued structs are emitted despite omitempty -- so the operator owns
// spec.strategy and the agent container's resources, neither of which any builder sets.
// Zero-valued scalars with omitempty are dropped -- so a nodePort of 0 is not owned, which is
// what lets the apiserver keep its own allocation.
//
// client.ApplyConfigurationFromUnstructured is used on an object converted from a typed API
// object, despite upstream's warning ("Do not use Unstructured objects here that were generated
// from API objects", controller-runtime applyconfigurations.go). The warning is accepted
// deliberately: the request body is semantically identical to the former json.Marshal body, so
// ownership is exactly as described above.
//
// ForceOwnership is unconditional. A conflict is only raised when the applied value differs from
// a value owned by another manager, so the first apply over an object previously written by
// Create/Update succeeds without it -- but the first apply that actually changes such a field
// would fail, and the operator would wedge. Forcing is also what makes the operator converge an
// object a human edited with kubectl.
//
// Forcing alone does not finish adoption. It transfers only the fields whose value differs, so
// the legacy manager keeps every field the operator renders unchanged, and the apiserver never
// prunes a field another manager still owns: stop rendering one -- the wstunnel sidecar, a
// toleration, a service annotation -- and it stays. So before applying to an object that already
// exists, the legacy manager's fields are merged into FieldManager's apply entry
// (csaupgrade.UpgradeManagedFieldsPatch). That costs one extra write per legacy object, once;
// on every later call the computed patch is nil and nothing is sent. The patch pins the
// resourceVersion that was read, so a stale cache read fails with a conflict and is retried on
// the next reconcile rather than overwriting newer managedFields.
//
// SSA requires apiVersion and kind in the request body, and a typed object's TypeMeta is empty
// after construction, so the GVK is derived from the scheme and stamped on before the call.
// Without this the apiserver rejects the patch with "invalid object type: /, Kind=".
func (r *WireguardReconciler) applyOwned(ctx context.Context, obj client.Object) error {
	gvk, err := apiutil.GVKForObject(obj, r.Scheme)
	if err != nil {
		return fmt.Errorf("resolve GVK for %T: %w", obj, err)
	}
	obj.GetObjectKind().SetGroupVersionKind(gvk)
	key := client.ObjectKeyFromObject(obj)

	// Only managedFields and resourceVersion of the live object are consumed.
	live := obj.DeepCopyObject().(client.Object)
	switch err := r.Get(ctx, key, live); {
	case apierrors.IsNotFound(err):
		// Nothing to migrate: the apply below creates the object, owned by FieldManager alone.
	case err != nil:
		return fmt.Errorf("read %s %s for field-manager migration: %w", gvk.Kind, key, err)
	default:
		patch, err := csaupgrade.UpgradeManagedFieldsPatch(live, legacyFieldManagers, FieldManager)
		if err != nil {
			return fmt.Errorf("compute field-manager migration for %s %s: %w", gvk.Kind, key, err)
		}
		if patch != nil {
			if err := r.Patch(ctx, live, client.RawPatch(types.JSONPatchType, patch)); err != nil {
				return fmt.Errorf("migrate field managers on %s %s: %w", gvk.Kind, key, err)
			}
		}
	}

	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return fmt.Errorf("convert %s %s: %w", gvk.Kind, key, err)
	}
	u := &unstructured.Unstructured{Object: m}
	if err := r.Apply(ctx, client.ApplyConfigurationFromUnstructured(u),
		client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
		return fmt.Errorf("apply %s %s: %w", gvk.Kind, key, err)
	}
	// Callers read the server's response (for example the Service's allocated ClusterIP).
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, obj); err != nil {
		return fmt.Errorf("decode applied %s %s: %w", gvk.Kind, key, err)
	}
	return nil
}

// failDegraded records a Degraded condition and returns the original error for requeue.
//
// Some apply failures are permanent rather than transient -- a Service port colliding with a
// foreign writer's entry, or spec.nodePort set on a ClusterIP Service. Without a status
// condition the operator retries forever with a stale Status and nothing user-visible.
//
// A failure to write the status is logged rather than combined into the returned error: the
// caller needs the original error, and the status write is retried on the next reconcile.
func (r *WireguardReconciler) failDegraded(
	ctx context.Context, wg *v1alpha1.Wireguard, err error, reason, msg string,
) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)
	log.Error(err, msg)

	if serr := r.updateStatus(ctx, wg, metav1.Condition{
		Type:    ConditionDegraded,
		Status:  metav1.ConditionTrue,
		Reason:  reason,
		Message: err.Error(),
	}, nil); serr != nil {
		log.Error(serr, "failed to record Degraded condition", "reason", reason)
	}
	return ctrl.Result{}, err
}
