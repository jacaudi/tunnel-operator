package sidecar

import (
	"os"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// TestClientClusterRoleGrantsOnlyPeers pins the client's RBAC: it reads its own WireguardPeer in its
// own namespace and nothing else, so a pod can attach to a Wireguard it cannot read.
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

	for _, rule := range role.Rules {
		for _, resource := range rule.Resources {
			if resource != "wireguardpeers" {
				t.Errorf("rule grants %v on %q, want only wireguardpeers", rule.Verbs, resource)
			}
		}
	}
	if len(role.Rules) == 0 {
		t.Error("the client ClusterRole has no rules, want one for wireguardpeers")
	}
}
