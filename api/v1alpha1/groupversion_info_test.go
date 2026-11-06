package v1alpha1

import "testing"

func TestGroupVersionIsTunnelOperator(t *testing.T) {
	if GroupVersion.Group != "vpn.tunnel-operator.io" || GroupVersion.Version != "v1alpha1" {
		t.Fatalf("GroupVersion = %s, want vpn.tunnel-operator.io/v1alpha1", GroupVersion)
	}
}
