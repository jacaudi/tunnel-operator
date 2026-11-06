package resources

import "testing"

func TestNamesAreTunnelOperator(t *testing.T) {
	for _, c := range []struct{ name, got, want string }{
		{"LabelEnabled", LabelEnabled, "tunnel-operator.io/enabled"},
		{"LabelComponent", LabelComponent, "tunnel-operator.io/component"},
		{"AnnotationDefault", AnnotationDefault, "tunnel-operator.io/default"},
		{"ManagedByValue", ManagedByValue, "tunnel-operator"},
		{"ClientRoleName", ClientRoleName, "tunnel-operator-client"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}
