package sidecar

import (
	"maps"
	"os"
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// TestClientClusterRoleGrantsOnlyPeers pins the client's RBAC: it manages its own WireguardPeer in
// its own namespace and nothing else, so a pod can attach to a Wireguard it cannot read. The e2e
// cannot catch a widened role, because reading another namespace is forbidden either way.
func TestClientClusterRoleGrantsOnlyPeers(t *testing.T) {
	f, err := os.Open("../../config/rbac/client_clusterrole.yaml")
	if err != nil {
		t.Fatalf("open the client ClusterRole: %v", err)
	}
	defer f.Close()
	var role rbacv1.ClusterRole
	if err := yaml.NewYAMLOrJSONDecoder(f, 4096).Decode(&role); err != nil {
		t.Fatalf("decode the client ClusterRole: %v", err)
	}

	groups, resources, verbs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, rule := range role.Rules {
		for _, s := range []struct {
			set  map[string]bool
			from []string
		}{{groups, rule.APIGroups}, {resources, rule.Resources}, {verbs, rule.Verbs}} {
			for _, v := range s.from {
				s.set[v] = true
			}
		}
	}
	for _, c := range []struct {
		what string
		got  map[string]bool
		want []string
	}{
		{"apiGroups", groups, []string{"vpn.wireguard-operator.io"}},
		{"resources", resources, []string{"wireguardpeers"}},
		{"verbs", verbs, []string{"create", "delete", "get", "list", "watch"}},
	} {
		if got := slices.Sorted(maps.Keys(c.got)); !slices.Equal(got, c.want) {
			t.Errorf("client ClusterRole %s = %v, want exactly %v", c.what, got, c.want)
		}
	}
}
