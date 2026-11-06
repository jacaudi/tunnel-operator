package controllers

import "testing"

func TestFieldManagerIsTunnelOperator(t *testing.T) {
	if FieldManager != "tunnel-operator" {
		t.Errorf("FieldManager = %q, want tunnel-operator", FieldManager)
	}
	if injectPolicyName != "tunnel-operator-inject" {
		t.Errorf("injectPolicyName = %q, want tunnel-operator-inject", injectPolicyName)
	}
}
