package resources

import (
	"errors"
	"io"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// The manager pod carries the component label, so the injection policies skip the operator's own pod
// even though its other labels (control-plane: controller-manager) are too generic to exclude by.
func TestManagerPodTemplateCarriesOperatorComponentLabel(t *testing.T) {
	// manager.yaml opens with the Namespace; the Deployment is its second document.
	f, err := os.Open("../../config/manager/manager.yaml")
	if err != nil {
		t.Fatalf("open manager.yaml: %v", err)
	}
	defer f.Close()
	dec := yaml.NewYAMLOrJSONDecoder(f, 4096)
	var ns map[string]any
	if err := dec.Decode(&ns); err != nil {
		t.Fatalf("decode the Namespace: %v", err)
	}
	var dep appsv1.Deployment
	if err := dec.Decode(&dep); err != nil {
		t.Fatalf("decode the Deployment: %v", err)
	}

	if got := dep.Spec.Template.Labels[LabelComponent]; got != ComponentOperator {
		t.Errorf("manager pod template label %s = %q, want %q", LabelComponent, got, ComponentOperator)
	}
	if _, ok := dep.Spec.Selector.MatchLabels[LabelComponent]; ok {
		t.Errorf("manager selector = %v, want no %s", dep.Spec.Selector.MatchLabels, LabelComponent)
	}
}

// decodeAll decodes every YAML document of path (relative to the repository root) into objects of
// type T, skipping empty documents.
func decodeAll[T any](t *testing.T, path string) []T {
	t.Helper()
	f, err := os.Open("../../" + path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	dec := yaml.NewYAMLOrJSONDecoder(f, 4096)
	var out []T
	for {
		var v T
		if err := dec.Decode(&v); errors.Is(err, io.EOF) {
			return out
		} else if err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		out = append(out, v)
	}
}

// The static YAML necessarily repeats strings that the Go code also names. If either side changes
// alone, the backstop stops recognising the pods the operator injects.
func TestRequireInjectionManifestsMatchTheGoConstants(t *testing.T) {
	policies := decodeAll[admissionregistrationv1.ValidatingAdmissionPolicy](t, "config/admission/require_injection_policy.yaml")
	bindings := decodeAll[admissionregistrationv1.ValidatingAdmissionPolicyBinding](t, "config/admission/require_injection_binding.yaml")
	if len(policies) != 1 || len(bindings) != 1 {
		t.Fatalf("got %d policies and %d bindings, want one of each", len(policies), len(bindings))
	}
	policy, binding := policies[0], bindings[0]

	if binding.Spec.PolicyName != policy.Name {
		t.Errorf("binding policyName = %q, want the policy's name %q", binding.Spec.PolicyName, policy.Name)
	}

	sel := binding.Spec.MatchResources.ObjectSelector
	if want := map[string]string{LabelEnabled: "true"}; !maps.Equal(sel.MatchLabels, want) {
		t.Errorf("binding objectSelector.matchLabels = %v, want %v", sel.MatchLabels, want)
	}
	wantExpr := []metav1.LabelSelectorRequirement{{Key: LabelComponent, Operator: metav1.LabelSelectorOpDoesNotExist}}
	if !reflect.DeepEqual(sel.MatchExpressions, wantExpr) {
		t.Errorf("binding objectSelector.matchExpressions = %v, want %v", sel.MatchExpressions, wantExpr)
	}
	wantNS := []metav1.LabelSelectorRequirement{{Key: "kubernetes.io/metadata.name", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"kube-system"}}}
	if got := binding.Spec.MatchResources.NamespaceSelector.MatchExpressions; !reflect.DeepEqual(got, wantNS) {
		t.Errorf("binding namespaceSelector.matchExpressions = %v, want %v", got, wantNS)
	}
	if want := []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}; !slices.Equal(binding.Spec.ValidationActions, want) {
		t.Errorf("binding validationActions = %v, want %v", binding.Spec.ValidationActions, want)
	}

	if len(policy.Spec.Validations) != 2 {
		t.Fatalf("policy has %d validations, want 2 (hostNetwork, injected)", len(policy.Spec.Validations))
	}
	if got := policy.Spec.Validations[1].Expression; !strings.Contains(got, "'"+SidecarContainer+"'") {
		t.Errorf("injected validation = %q, want it to name the container %q", got, SidecarContainer)
	}
	if policy.Spec.FailurePolicy == nil || *policy.Spec.FailurePolicy != admissionregistrationv1.Fail {
		t.Errorf("policy failurePolicy = %v, want Fail", policy.Spec.FailurePolicy)
	}
}

// kustomize prefixes the policy's name but does not rewrite the binding's policyName unless told to
// (config/admission/kustomizeconfig.yaml). A binding that names a missing policy is ignored by the
// apiserver, which would leave labelled pods unchecked. release.yaml is the rendered output.
func TestReleaseBindingNamesThePrefixedPolicy(t *testing.T) {
	var policy, binding string
	for _, u := range decodeAll[unstructured.Unstructured](t, "release.yaml") {
		switch u.GetKind() {
		case "ValidatingAdmissionPolicy":
			policy = u.GetName()
		case "ValidatingAdmissionPolicyBinding":
			binding, _, _ = unstructured.NestedString(u.Object, "spec", "policyName")
		}
	}
	if policy == "" || binding != policy {
		t.Errorf("release.yaml binding policyName = %q, want the policy's rendered name %q", binding, policy)
	}
}
