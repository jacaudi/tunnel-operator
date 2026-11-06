package controllers

import (
	"errors"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/resources"
)

func wgIn(ns, name string, annotations map[string]string) v1alpha1.Wireguard {
	return v1alpha1.Wireguard{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: annotations}}
}

var isDefault = map[string]string{resources.AnnotationDefault: "true"}

func TestDefaultGateway(t *testing.T) {
	tests := []struct {
		name    string
		list    []v1alpha1.Wireguard
		want    types.NamespacedName
		wantErr string
	}{
		{name: "none at all", wantErr: "no Wireguard in namespace network is annotated"},
		{
			name:    "none annotated",
			list:    []v1alpha1.Wireguard{wgIn("network", "vpn", nil)},
			wantErr: "no Wireguard in namespace network is annotated",
		},
		{
			name: "one",
			list: []v1alpha1.Wireguard{wgIn("network", "vpn", isDefault), wgIn("network", "other", nil)},
			want: types.NamespacedName{Namespace: "network", Name: "vpn"},
		},
		{
			name:    "two, named in order",
			list:    []v1alpha1.Wireguard{wgIn("network", "b", isDefault), wgIn("network", "a", isDefault)},
			wantErr: "2 Wireguards in namespace network are annotated tunnel-operator.io/default=true: a, b",
		},
		{
			name:    "only outside the operator's namespace",
			list:    []v1alpha1.Wireguard{wgIn("tenant", "mine", isDefault)},
			wantErr: "no Wireguard in namespace network is annotated",
		},
		{
			name: "a tenant's annotation does not count against the operator's one",
			list: []v1alpha1.Wireguard{wgIn("tenant", "mine", isDefault), wgIn("network", "vpn", isDefault)},
			want: types.NamespacedName{Namespace: "network", Name: "vpn"},
		},
		{
			name:    "any value but true is not a default",
			list:    []v1alpha1.Wireguard{wgIn("network", "vpn", map[string]string{resources.AnnotationDefault: "false"})},
			wantErr: "no Wireguard in namespace network is annotated",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := defaultGateway(t.Context(), tt.list, "network")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("defaultGateway() error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("defaultGateway() = %v, %v, want %v, nil", got, err, tt.want)
			}
		})
	}
}

// clientExample returns the wg-client container of examples/client.yaml, the hand-written sidecar the
// end-to-end suite has proven.
func clientExample(t *testing.T) corev1.Container {
	t.Helper()
	f, err := os.Open("../../examples/client.yaml")
	if err != nil {
		t.Fatalf("open examples/client.yaml: %v", err)
	}
	defer f.Close()
	dec := yaml.NewYAMLOrJSONDecoder(f, 4096)
	for {
		var dep appsv1.Deployment
		if err := dec.Decode(&dep); errors.Is(err, io.EOF) {
			t.Fatal("examples/client.yaml has no Deployment with a wg-client init container")
		} else if err != nil {
			t.Fatalf("decode examples/client.yaml: %v", err)
		}
		if i := slices.IndexFunc(dep.Spec.Template.Spec.InitContainers, func(c corev1.Container) bool {
			return c.Name == resources.SidecarContainer
		}); i >= 0 {
			return dep.Spec.Template.Spec.InitContainers[i]
		}
	}
}

// The injected sidecar must be the proven one. Only the target gateway, the image and the sidecar's own
// token mount may differ from the example.
func TestInjectedSidecarEqualsTheClientExample(t *testing.T) {
	got, _ := injectedSidecar("registry.example/agent:v9", "network/vpn")

	want := clientExample(t)
	want.Image = "registry.example/agent:v9"
	if i := slices.Index(want.Args, "--wireguard"); i < 0 || i+1 >= len(want.Args) {
		t.Fatalf("example args = %v, want a --wireguard value", want.Args)
	} else {
		want.Args[i+1] = "network/vpn"
	}
	want.VolumeMounts = append(want.VolumeMounts, corev1.VolumeMount{
		Name: resources.VolumeToken, MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true,
	})

	if !reflect.DeepEqual(got, want) {
		t.Errorf("injected sidecar differs from examples/client.yaml:\n got %+v\nwant %+v", got, want)
	}
}

func TestInjectedVolumes(t *testing.T) {
	_, got := injectedSidecar("agent:v1", "network/vpn")
	want := []corev1.Volume{
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
	if !reflect.DeepEqual(got, want) {
		t.Errorf("volumes = %+v, want %+v", got, want)
	}
}

func TestRenderInjectPolicy(t *testing.T) {
	for _, version := range []string{"v1", "v1beta1"} {
		t.Run(version, func(t *testing.T) {
			c, vols := injectedSidecar("agent:v1", "network/vpn")
			policy, binding, err := renderInjectPolicy(version, c, vols)
			if err != nil {
				t.Fatalf("renderInjectPolicy: %v", err)
			}

			wantAPIVersion := "admissionregistration.k8s.io/" + version
			for _, u := range []interface{ GetAPIVersion() string }{policy, binding} {
				if u.GetAPIVersion() != wantAPIVersion {
					t.Errorf("apiVersion = %q, want %q", u.GetAPIVersion(), wantAPIVersion)
				}
			}
			if policy.GetKind() != "MutatingAdmissionPolicy" || binding.GetKind() != "MutatingAdmissionPolicyBinding" {
				t.Errorf("kinds = %s, %s", policy.GetKind(), binding.GetKind())
			}
			for _, u := range []metav1.Object{policy, binding} {
				if u.GetName() != injectPolicyName {
					t.Errorf("name = %q, want %q", u.GetName(), injectPolicyName)
				}
				if got := u.GetLabels()[resources.LabelManagedBy]; got != resources.ManagedByValue {
					t.Errorf("%s label = %q, want %q (the uninstall selector)", resources.LabelManagedBy, got, resources.ManagedByValue)
				}
			}

			// The shape must fit the typed API of that version: an unknown or misspelt field would be
			// dropped by the apiserver, silently, and the policy would not mutate.
			decodeStrict(t, policy.Object, version, "MutatingAdmissionPolicy")
			decodeStrict(t, binding.Object, version, "MutatingAdmissionPolicyBinding")

			spec := policy.Object["spec"].(map[string]any)
			if spec["failurePolicy"] != "Fail" || spec["reinvocationPolicy"] != "IfNeeded" {
				t.Errorf("failurePolicy, reinvocationPolicy = %v, %v, want Fail, IfNeeded", spec["failurePolicy"], spec["reinvocationPolicy"])
			}
		})
	}
}

// decodeStrict decodes obj into the typed kind of version, failing on any field the type lacks.
func decodeStrict(t *testing.T, obj map[string]any, version, kind string) {
	t.Helper()
	var into any
	switch {
	case version == "v1" && kind == "MutatingAdmissionPolicy":
		into = &admissionregistrationv1.MutatingAdmissionPolicy{}
	case version == "v1" && kind == "MutatingAdmissionPolicyBinding":
		into = &admissionregistrationv1.MutatingAdmissionPolicyBinding{}
	case version == "v1beta1" && kind == "MutatingAdmissionPolicy":
		into = &admissionregistrationv1beta1.MutatingAdmissionPolicy{}
	default:
		into = &admissionregistrationv1beta1.MutatingAdmissionPolicyBinding{}
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructuredWithValidation(obj, into, true); err != nil {
		t.Errorf("%s %s does not fit the typed API: %v", version, kind, err)
	}
}

// The mutating binding must select exactly the pods the static backstop checks.
func TestInjectBindingSelectsWhatTheBackstopChecks(t *testing.T) {
	f, err := os.Open("../../config/admission/require_injection_binding.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var vap admissionregistrationv1.ValidatingAdmissionPolicyBinding
	if err := yaml.NewYAMLOrJSONDecoder(f, 4096).Decode(&vap); err != nil {
		t.Fatal(err)
	}

	c, vols := injectedSidecar("agent:v1", "network/vpn")
	_, binding, err := renderInjectPolicy("v1", c, vols)
	if err != nil {
		t.Fatal(err)
	}
	var got admissionregistrationv1.MutatingAdmissionPolicyBinding
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(binding.Object, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Spec.MatchResources, vap.Spec.MatchResources) {
		t.Errorf("mutating binding matches %+v, want the backstop's %+v", got.Spec.MatchResources, vap.Spec.MatchResources)
	}
}

// fakeGroupVersions serves the group versions in served, each with the resources listed.
type fakeGroupVersions struct {
	served map[string][]string
	err    error
}

func (f fakeGroupVersions) ServerResourcesForGroupVersion(gv string) (*metav1.APIResourceList, error) {
	if f.err != nil {
		return nil, f.err
	}
	names, ok := f.served[gv]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: gv}, gv)
	}
	list := &metav1.APIResourceList{GroupVersion: gv}
	for _, n := range names {
		list.APIResources = append(list.APIResources, metav1.APIResource{Name: n})
	}
	return list, nil
}

func TestServedPolicyVersion(t *testing.T) {
	mapRes := []string{"mutatingadmissionpolicies", "mutatingadmissionpolicybindings"}
	tests := []struct {
		name    string
		served  map[string][]string
		err     error
		want    string
		wantErr bool
	}{
		{name: "both, v1 wins", served: map[string][]string{"admissionregistration.k8s.io/v1": mapRes, "admissionregistration.k8s.io/v1beta1": mapRes}, want: "v1"},
		{name: "v1beta1 only", served: map[string][]string{"admissionregistration.k8s.io/v1beta1": mapRes}, want: "v1beta1"},
		{name: "v1 serves the group but not the policy", served: map[string][]string{"admissionregistration.k8s.io/v1": {"validatingadmissionpolicies"}}, want: ""},
		{name: "neither", served: map[string][]string{}, want: ""},
		{name: "discovery fails", err: errors.New("connection refused"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := servedPolicyVersion(fakeGroupVersions{served: tt.served, err: tt.err})
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("servedPolicyVersion() = %q, %v, want %q, error=%v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

// Enabling the MutatingAdmissionPolicy beta restarts the API server and raises no event the operator
// watches, so a cluster that served neither version is asked again. Without it the policy would stay
// unwritten until the operator restarted.
func TestReconcileRequeuesWhileNoPolicyVersionIsServed(t *testing.T) {
	r := &InjectionPolicyReconciler{Discovery: fakeGroupVersions{served: map[string][]string{}}}

	got, err := r.Reconcile(t.Context(), ctrl.Request{})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if want := 10 * time.Minute; got.RequeueAfter != want {
		t.Errorf("RequeueAfter = %v, want %v", got.RequeueAfter, want)
	}
}
