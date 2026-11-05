package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/jacaudi/wireguard-operator/api/v1alpha1"
	"github.com/jacaudi/wireguard-operator/internal/resources"
)

// injectPolicyName names the MutatingAdmissionPolicy and its binding. It is literal, and already
// carries the release's name prefix: the operator writes these at runtime, so kustomize never sees them.
const injectPolicyName = "wireguard-operator-inject"

const (
	admissionGroup = "admissionregistration.k8s.io"

	// inClusterConfigDir is where rest.InClusterConfig looks for the ServiceAccount token, CA and namespace.
	inClusterConfigDir = "/var/run/secrets/kubernetes.io/serviceaccount"
)

// defaultGateway returns the Wireguard injected sidecars attach to: the one Wireguard in operatorNS
// annotated wireguard-operator.io/default=true. Choosing the default is therefore an act of whoever
// controls the operator's namespace, never of a tenant who can edit a Wireguard elsewhere; such an
// annotation is logged and ignored. Zero or several defaults is an error naming them.
func defaultGateway(ctx context.Context, list []v1alpha1.Wireguard, operatorNS string) (types.NamespacedName, error) {
	log := ctrllog.FromContext(ctx)

	var defaults []string
	for _, wg := range list {
		if wg.Annotations[resources.AnnotationDefault] != "true" {
			continue
		}
		if wg.Namespace != operatorNS {
			log.Info("ignoring a default-gateway annotation outside the operator's namespace",
				"wireguard", client.ObjectKeyFromObject(&wg), "operatorNamespace", operatorNS)
			continue
		}
		defaults = append(defaults, wg.Name)
	}

	switch len(defaults) {
	case 0:
		return types.NamespacedName{}, fmt.Errorf("no Wireguard in namespace %s is annotated %s=true", operatorNS, resources.AnnotationDefault)
	case 1:
		return types.NamespacedName{Namespace: operatorNS, Name: defaults[0]}, nil
	}
	sort.Strings(defaults)
	return types.NamespacedName{}, fmt.Errorf("%d Wireguards in namespace %s are annotated %s=true: %s",
		len(defaults), operatorNS, resources.AnnotationDefault, strings.Join(defaults, ", "))
}

// injectedSidecar returns the client container the policy inserts as the pod's first init container, and
// the two volumes it needs. It is the native sidecar of examples/client.yaml, which the end-to-end suite
// has run since M5, plus a mount of the pod's own token (wg-token), which the example gets from its
// ServiceAccount. A unit test holds the two equal.
//
// wg-token is the standard ServiceAccount volume, projected for the sidecar alone: the pod gets a token
// whatever its automountServiceAccountToken says or the order admission plugins run in, and the
// application containers never see it.
func injectedSidecar(image, gateway string) (corev1.Container, []corev1.Volume) {
	downward := func(name, field string) corev1.EnvVar {
		return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: field}}}
	}
	container := corev1.Container{
		Name:          resources.SidecarContainer,
		Image:         image,
		RestartPolicy: new(corev1.ContainerRestartPolicyAlways),
		Args:          []string{"client", "--wireguard", gateway},
		Env: []corev1.EnvVar{
			downward("POD_NAME", "metadata.name"),
			downward("POD_NAMESPACE", "metadata.namespace"),
			downward("POD_UID", "metadata.uid"),
			downward("POD_IP", "status.podIP"),
			downward("HOST_IP", "status.hostIP"),
		},
		SecurityContext: &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}}},
		VolumeMounts: []corev1.VolumeMount{
			{Name: resources.VolumeKey, MountPath: "/var/run/wireguard"},
			{Name: resources.VolumeToken, MountPath: inClusterConfigDir, ReadOnly: true},
		},
		// The startup probe holds the application containers until the tunnel is up and routed.
		StartupProbe: &corev1.Probe{
			ProbeHandler:     corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"agent", "client", "--check"}}},
			PeriodSeconds:    2,
			FailureThreshold: 90,
		},
	}
	volumes := []corev1.Volume{
		{Name: resources.VolumeKey, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}},
		{Name: resources.VolumeToken, VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
			{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}},
			{ConfigMap: &corev1.ConfigMapProjection{
				LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"},
				Items:                []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}},
			}},
			{DownwardAPI: &corev1.DownwardAPIProjection{Items: []corev1.DownwardAPIVolumeFile{
				{Path: "namespace", FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}},
			}}},
		}}}},
	}
	return container, volumes
}

// celLiteral renders v, the decoded JSON of an object, as a CEL literal. JSON is nearly CEL already, but
// the apiserver compiles policy CEL with homogeneous aggregate literals, which reject a map or list whose
// members differ in type: every member is wrapped in dyn() so they all have the one type.
func celLiteral(v any) string {
	switch v := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = strconv.Quote(k) + ": dyn(" + celLiteral(v[k]) + ")"
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case []any:
		parts := make([]string, len(v))
		for i, e := range v {
			parts[i] = "dyn(" + celLiteral(e) + ")"
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case string:
		return strconv.Quote(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default: // bool
		return fmt.Sprint(v)
	}
}

// celOf renders a typed object as a CEL literal through its JSON form.
func celOf(obj any) (string, error) {
	raw, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return "", err
	}
	return celLiteral(decoded), nil
}

// injectMatchResources selects the pods the injection policies apply to. The static backstop in
// config/admission carries the same selectors in YAML, and a unit test holds the two equal.
func injectMatchResources() (map[string]any, error) {
	return runtime.DefaultUnstructuredConverter.ToUnstructured(&admissionregistrationv1.MatchResources{
		ObjectSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{resources.LabelEnabled: "true"},
			// The gateway and operator pods are never tunnelled, whatever else they are labelled.
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: resources.LabelComponent, Operator: metav1.LabelSelectorOpDoesNotExist}},
		},
		NamespaceSelector: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "kubernetes.io/metadata.name", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"kube-system"}}},
		},
	})
}

// renderInjectPolicy returns the MutatingAdmissionPolicy and binding that insert the sidecar and its
// volumes into a labelled pod, in admissionregistration.k8s.io/<version>, which is v1 or v1beta1.
//
// The two versions have the same shape, so the objects are built once as unstructured rather than as two
// near-identical typed builders; a unit test decodes each strictly into its typed API to hold that true.
//
// Pod mutations are JSONPatch, because a strategic merge cannot insert at index 0 of initContainers, and
// the sidecar must come first so later init containers run inside the tunnel. When a pod has no volumes
// or initContainers the array is created, otherwise it is appended or inserted into.
func renderInjectPolicy(version string, sidecar corev1.Container, volumes []corev1.Volume) (policy, binding *unstructured.Unstructured, err error) {
	if version != "v1" && version != "v1beta1" {
		return nil, nil, fmt.Errorf("unsupported %s version %q", admissionGroup, version)
	}
	sidecarCEL, err := celOf(sidecar)
	if err != nil {
		return nil, nil, fmt.Errorf("render the sidecar: %w", err)
	}
	volumesCEL, err := celOf(volumes)
	if err != nil {
		return nil, nil, fmt.Errorf("render the volumes: %w", err)
	}
	match, err := injectMatchResources()
	if err != nil {
		return nil, nil, fmt.Errorf("render the pod selectors: %w", err)
	}

	labels := map[string]any{resources.LabelManagedBy: resources.ManagedByValue}
	meta := func() map[string]any { return map[string]any{"name": injectPolicyName, "labels": labels} }

	policy = &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": admissionGroup + "/" + version,
		"kind":       "MutatingAdmissionPolicy",
		"metadata":   meta(),
		"spec": map[string]any{
			// A mutation error rejects the labelled pod: fail closed, and scoped to labelled pods.
			"failurePolicy":      "Fail",
			"reinvocationPolicy": "IfNeeded",
			"matchConstraints": map[string]any{"resourceRules": []any{map[string]any{
				"apiGroups": []any{""}, "apiVersions": []any{"v1"}, "operations": []any{"CREATE"}, "resources": []any{"pods"},
			}}},
			// Reinvocation and re-admission must never inject twice.
			"matchConditions": []any{map[string]any{
				"name": "not-yet-injected",
				"expression": "!has(object.spec.initContainers) || " +
					"!object.spec.initContainers.exists(c, c.name == " + strconv.Quote(resources.SidecarContainer) + ")",
			}},
			"variables": []any{
				map[string]any{"name": "sidecar", "expression": "dyn(" + sidecarCEL + ")"},
				map[string]any{"name": "volumes", "expression": "dyn(" + volumesCEL + ")"},
			},
			"mutations": []any{map[string]any{
				"patchType": "JSONPatch",
				"jsonPatch": map[string]any{"expression": `(has(object.spec.volumes)
  ? variables.volumes.map(v, JSONPatch{op: "add", path: "/spec/volumes/-", value: v})
  : [JSONPatch{op: "add", path: "/spec/volumes", value: variables.volumes}]) +
(has(object.spec.initContainers)
  ? [JSONPatch{op: "add", path: "/spec/initContainers/0", value: variables.sidecar}]
  : [JSONPatch{op: "add", path: "/spec/initContainers", value: [variables.sidecar]}])`},
			}},
		},
	}}

	binding = &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": admissionGroup + "/" + version,
		"kind":       "MutatingAdmissionPolicyBinding",
		"metadata":   meta(),
		"spec":       map[string]any{"policyName": injectPolicyName, "matchResources": match},
	}}
	return policy, binding, nil
}

// groupVersionLister is the part of discovery the policy version choice reads.
type groupVersionLister interface {
	ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error)
}

// servedPolicyVersion returns the admissionregistration version that serves MutatingAdmissionPolicy:
// v1 (GA, Kubernetes 1.36+), else v1beta1 (1.34-1.35 with the beta enabled), else "" when neither does.
func servedPolicyVersion(d groupVersionLister) (string, error) {
	for _, version := range []string{"v1", "v1beta1"} {
		list, err := d.ServerResourcesForGroupVersion(admissionGroup + "/" + version)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("discover %s/%s: %w", admissionGroup, version, err)
		}
		if slices.ContainsFunc(list.APIResources, func(r metav1.APIResource) bool { return r.Name == "mutatingadmissionpolicies" }) {
			return version, nil
		}
	}
	return "", nil
}

// InjectionPolicyReconciler keeps the operator-written MutatingAdmissionPolicy in step with the default
// gateway: while exactly one Wireguard in the operator's namespace is the default, the policy injects the
// sidecar aimed at it; otherwise the policy is removed and the static backstop refuses labelled pods.
//
// Admission runs in the apiserver, so the policy keeps working while the operator is down; only a change
// of default gateway waits.
type InjectionPolicyReconciler struct {
	client.Client
	Discovery groupVersionLister
	// Image is the operator's --agent-image: the sidecar always runs the operator's own agent, so
	// upgrading the operator upgrades the sidecar of every new pod.
	Image string
	// OperatorNamespace is the one namespace whose default-gateway annotation counts.
	OperatorNamespace string
}

// injectionKey is the singleton reconcile key: every Wireguard event and the startup kick ask the same question.
var injectionKey = types.NamespacedName{Namespace: "injection", Name: "policy"}

// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingadmissionpolicies;mutatingadmissionpolicybindings,verbs=get;list;watch;create;patch;delete

// Reconcile applies the policy for the current default gateway, or removes it.
func (r *InjectionPolicyReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)

	version, err := servedPolicyVersion(r.Discovery)
	if err != nil {
		return ctrl.Result{}, err
	}
	if version == "" {
		// Nothing served means nothing writable or deletable. The backstop refuses labelled pods.
		log.Info("the cluster serves no MutatingAdmissionPolicy; labelled pods are rejected until it does " +
			"(Kubernetes 1.34 and 1.35 need the beta enabled)")
		return ctrl.Result{}, nil
	}

	wgs := &v1alpha1.WireguardList{}
	if err := r.List(ctx, wgs); err != nil {
		return ctrl.Result{}, fmt.Errorf("list Wireguards: %w", err)
	}
	gateway, err := defaultGateway(ctx, wgs.Items, r.OperatorNamespace)
	if err != nil {
		log.Info("sidecar injection is off; labelled pods are rejected: " + err.Error())
		return ctrl.Result{}, r.deleteInjectPolicy(ctx, version)
	}

	container, volumes := injectedSidecar(r.Image, gateway.String())
	policy, binding, err := renderInjectPolicy(version, container, volumes)
	if err != nil {
		return ctrl.Result{}, err
	}
	// Policy before binding: a binding to a policy that does not exist yet is simply inactive.
	for _, obj := range []*unstructured.Unstructured{policy, binding} {
		if err := r.Apply(ctx, client.ApplyConfigurationFromUnstructured(obj),
			client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
			return ctrl.Result{}, fmt.Errorf("apply %s %s: %w", obj.GetKind(), obj.GetName(), err)
		}
	}
	log.Info("sidecar injection is on", "gateway", gateway.String())
	return ctrl.Result{}, nil
}

// deleteInjectPolicy removes the binding, then the policy. Neither existing is the usual case.
func (r *InjectionPolicyReconciler) deleteInjectPolicy(ctx context.Context, version string) error {
	for _, kind := range []string{"MutatingAdmissionPolicyBinding", "MutatingAdmissionPolicy"} {
		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(schema.GroupVersionKind{Group: admissionGroup, Version: version, Kind: kind})
		obj.SetName(injectPolicyName)
		if err := r.Delete(ctx, obj); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("delete %s %s: %w", kind, injectPolicyName, err)
		}
	}
	return nil
}

// SetupWithManager runs the reconciler once at startup, so a policy left by an earlier run is corrected
// even when no Wireguard exists to raise an event, and again whenever a Wireguard is created, deleted or
// has its annotations changed. Status churn on a Wireguard never reaches it.
func (r *InjectionPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	request := reconcile.Request{NamespacedName: injectionKey}
	return ctrl.NewControllerManagedBy(mgr).
		Named("injection-policy").
		Watches(&v1alpha1.Wireguard{},
			handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request { return []reconcile.Request{request} }),
			builder.WithPredicates(predicate.AnnotationChangedPredicate{})).
		WatchesRawSource(source.Func(func(_ context.Context, q workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
			q.Add(request)
			return nil
		})).
		Complete(r)
}
