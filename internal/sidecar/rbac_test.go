package sidecar

import (
	"errors"
	"io"
	"os"
	"reflect"
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
	dec := yaml.NewYAMLOrJSONDecoder(f, 4096)
	var role rbacv1.ClusterRole
	if err := dec.Decode(&role); err != nil {
		t.Fatalf("decode the client ClusterRole: %v", err)
	}
	if err := dec.Decode(&rbacv1.ClusterRole{}); !errors.Is(err, io.EOF) {
		t.Errorf("the client ClusterRole file has a second document (err = %v), want one", err)
	}

	want := []rbacv1.PolicyRule{{
		APIGroups: []string{"vpn.tunnel-operator.io"},
		Resources: []string{"wireguardpeers"},
		Verbs:     []string{"create", "delete", "get", "list", "watch"},
	}}
	if !reflect.DeepEqual(role.Rules, want) {
		t.Errorf("client ClusterRole rules = %+v, want exactly %+v", role.Rules, want)
	}
	if role.AggregationRule != nil {
		t.Errorf("client ClusterRole has an aggregationRule %+v, want none", role.AggregationRule)
	}
}
