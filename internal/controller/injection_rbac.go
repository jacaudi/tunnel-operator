package controllers

import (
	"context"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/jacaudi/wireguard-operator/internal/resources"
)

// needsClientRoleBinding reports whether a pod of pods, the labelled pods of namespace ns, is one injection
// applies to: not an operator component, and not in the namespace the policies exclude. Such a pod's
// sidecar needs the client ClusterRole bound in ns; nothing else does.
func needsClientRoleBinding(ns string, pods []corev1.Pod) bool {
	if ns == excludedNamespace {
		return false
	}
	for _, p := range pods {
		if _, component := p.Labels[resources.LabelComponent]; !component {
			return true
		}
	}
	return false
}

// roleBindingAction is what the reconciler does about a namespace's client RoleBinding.
type roleBindingAction int

const (
	// actionNone leaves the namespace as it is: nothing is needed and nothing of the operator's exists,
	// or the name is held by an object that is not the operator's.
	actionNone roleBindingAction = iota
	// actionApply creates or converges the operator's RoleBinding.
	actionApply
	// actionDelete removes the operator's RoleBinding, which no pod needs any more.
	actionDelete
	// actionRefuse declines to create the RoleBinding because another owner's object holds the name.
	actionRefuse
)

// String names the action for logs and test failures.
func (a roleBindingAction) String() string {
	switch a {
	case actionApply:
		return "apply"
	case actionDelete:
		return "delete"
	case actionRefuse:
		return "refuse"
	}
	return "none"
}

// clientRoleBindingAction decides from whether the binding is needed and what already holds its name
// (nil when nothing does). It touches only a RoleBinding the operator labelled managed-by itself, never
// a user's object of the same name.
func clientRoleBindingAction(needed bool, existing *rbacv1.RoleBinding) roleBindingAction {
	ours := existing != nil && existing.Labels[resources.LabelManagedBy] == resources.ManagedByValue
	switch {
	case needed && (existing == nil || ours):
		return actionApply
	case needed:
		return actionRefuse
	case ours:
		return actionDelete
	}
	return actionNone
}

// desiredClientRoleBinding binds the client ClusterRole to every ServiceAccount of ns, so injected pods
// need no ServiceAccount of their own: a pod's default account works. A Group subject is what a user
// would write to reach all of them.
func desiredClientRoleBinding(ns string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{APIVersion: rbacv1.SchemeGroupVersion.String(), Kind: "RoleBinding"},
		ObjectMeta: metav1.ObjectMeta{
			Name: resources.ClientRoleName, Namespace: ns,
			Labels: map[string]string{resources.LabelManagedBy: resources.ManagedByValue},
		},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: resources.ClientRoleName},
		Subjects: []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: "system:serviceaccounts:" + ns}},
	}
}

// CacheOptions is what the manager caches. Pods: only those labelled for injection, so the operator never
// holds the cluster's other pods in memory. That filter applies to every cached Pod read, which is why the
// gateway-pod lookup in WireguardReconciler reads through the API reader instead. RoleBindings: only the
// one name the operator manages.
func CacheOptions() cache.Options {
	return cache.Options{ByObject: map[client.Object]cache.ByObject{
		&corev1.Pod{}: {Label: labels.SelectorFromSet(labels.Set{resources.LabelEnabled: "true"})},
		// By name, never by the managed-by label: a foreign RoleBinding holding the name must stay visible, so
		// the reconciler can see it and refuse.
		&rbacv1.RoleBinding{}: {Field: fields.OneTermEqualSelector("metadata.name", resources.ClientRoleName)},
	}}
}

// ClientRoleBindingReconciler gives the client ClusterRole to the pods that need it: it creates the
// RoleBinding in a namespace when its first labelled pod appears and deletes it after the last is gone,
// so no RBAC lingers in a namespace that no longer has labelled pods.
//
// Its Pod reads go through the manager's cache, which cmd/manager filters to labelled pods: it never
// holds the cluster's other pods in memory. That filter applies to every cached Pod read, which is why the
// gateway-pod lookup in WireguardReconciler reads through the API reader instead.
type ClientRoleBindingReconciler struct {
	client.Client

	// refused remembers the namespaces already logged for a foreign RoleBinding, so a held name is
	// reported once rather than on every pod event.
	refused sync.Map
}

// Every grant is named for the RoleBinding and ClusterRole the operator manages, as rendered in release.yaml
// (see resources.ClientRoleName). kustomize does not prefix a rule's resourceNames, so the prefixed name is
// written here. A list or watch authorized by name needs the metadata.name field selector CacheOptions sets.
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;patch;delete,resourceNames=wireguard-operator-client
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=bind,resourceNames=wireguard-operator-client

// Reconcile converges one namespace, named by req.Name.
func (r *ClientRoleBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ns := req.Name
	log := ctrllog.FromContext(ctx).WithValues("namespace", ns)

	pods := &corev1.PodList{}
	if err := r.List(ctx, pods, client.InNamespace(ns), client.MatchingLabels{resources.LabelEnabled: "true"}); err != nil {
		return ctrl.Result{}, fmt.Errorf("list labelled pods in %s: %w", ns, err)
	}

	var existing *rbacv1.RoleBinding
	found := &rbacv1.RoleBinding{}
	switch err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: resources.ClientRoleName}, found); {
	case err == nil:
		existing = found
	case !apierrors.IsNotFound(err):
		return ctrl.Result{}, fmt.Errorf("get RoleBinding %s/%s: %w", ns, resources.ClientRoleName, err)
	}

	// Forget a refusal once nothing foreign holds the name, so a later one is logged again.
	if existing == nil || existing.Labels[resources.LabelManagedBy] == resources.ManagedByValue {
		r.refused.Delete(ns)
	}

	switch clientRoleBindingAction(needsClientRoleBinding(ns, pods.Items), existing) {
	case actionApply:
		u, err := runtime.DefaultUnstructuredConverter.ToUnstructured(desiredClientRoleBinding(ns))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("convert RoleBinding: %w", err)
		}
		return ctrl.Result{}, applyForced(ctx, r.Client, &unstructured.Unstructured{Object: u})
	case actionDelete:
		// Pinned to the UID read, so a binding recreated by someone else in between is never deleted.
		if err := r.Delete(ctx, existing, client.Preconditions{UID: &existing.UID}); client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, fmt.Errorf("delete RoleBinding %s/%s: %w", ns, resources.ClientRoleName, err)
		}
	case actionRefuse:
		if _, seen := r.refused.LoadOrStore(ns, struct{}{}); !seen {
			log.Info("not creating the client RoleBinding: a RoleBinding of that name exists that the operator did not create; "+
				"labelled pods here cannot register their peers until it is removed or renamed",
				"name", resources.ClientRoleName)
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager reconciles a namespace when a labelled pod is created or deleted in it (a pod update
// never changes whether the namespace needs the binding) and on any change to its client RoleBinding.
func (r *ClientRoleBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("client-rolebinding").
		Watches(&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, pod client.Object) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: pod.GetNamespace()}}}
			}),
			builder.WithPredicates(predicate.Funcs{UpdateFunc: func(event.UpdateEvent) bool { return false }})).
		// A RoleBinding is watched too, so a deleted one comes back while pods need it, and a binding left by a
		// pod deleted while the operator was down is removed at start-up: its create event reaches the
		// same pass.
		Watches(&rbacv1.RoleBinding{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, rb client.Object) []reconcile.Request {
			return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: rb.GetNamespace()}}}
		})).
		Complete(r)
}
