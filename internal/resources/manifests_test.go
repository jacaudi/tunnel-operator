package resources

import (
	"os"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
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
