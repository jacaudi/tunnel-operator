package controllers

import (
	"errors"
	"io"
	"os"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/jacaudi/tunnel-operator/internal/resources"
)

func podIn(ns string, labels map[string]string) corev1.Pod {
	return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "p", Labels: labels}}
}

func TestNeedsClientRoleBinding(t *testing.T) {
	enabled := map[string]string{resources.LabelEnabled: "true"}
	tests := []struct {
		name string
		ns   string
		pods []corev1.Pod
		want bool
	}{
		{name: "no pods", ns: "apps"},
		{name: "a labelled pod", ns: "apps", pods: []corev1.Pod{podIn("apps", enabled)}, want: true},
		{name: "one of several", ns: "apps", pods: []corev1.Pod{podIn("apps", map[string]string{resources.LabelComponent: resources.ComponentGateway}), podIn("apps", enabled)}, want: true},
		{
			name: "an operator component is never injected, so needs nothing",
			ns:   "network",
			pods: []corev1.Pod{podIn("network", map[string]string{resources.LabelEnabled: "true", resources.LabelComponent: resources.ComponentGateway})},
		},
		{name: "kube-system is never injected", ns: "kube-system", pods: []corev1.Pod{podIn("kube-system", enabled)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := needsClientRoleBinding(tt.ns, tt.pods); got != tt.want {
				t.Errorf("needsClientRoleBinding() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClientRoleBindingAction(t *testing.T) {
	ours := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{resources.LabelManagedBy: resources.ManagedByValue}}}
	foreign := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"owner": "someone-else"}}}
	tests := []struct {
		name     string
		want     bool
		existing *rbacv1.RoleBinding
		action   roleBindingAction
	}{
		{name: "needed, absent: create it", want: true, action: actionApply},
		{name: "needed, ours: keep it converged", want: true, existing: ours, action: actionApply},
		{name: "needed, foreign: refuse", want: true, existing: foreign, action: actionRefuse},
		{name: "not needed, absent: nothing", action: actionNone},
		{name: "not needed, ours: delete it", existing: ours, action: actionDelete},
		{name: "not needed, foreign: leave it alone", existing: foreign, action: actionNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientRoleBindingAction(tt.want, tt.existing); got != tt.action {
				t.Errorf("clientRoleBindingAction() = %v, want %v", got, tt.action)
			}
		})
	}
}

func TestDesiredClientRoleBinding(t *testing.T) {
	got := desiredClientRoleBinding("apps")
	if got.Name != resources.ClientRoleName || got.Namespace != "apps" {
		t.Errorf("name/namespace = %s/%s, want apps/%s", got.Namespace, got.Name, resources.ClientRoleName)
	}
	if got.Labels[resources.LabelManagedBy] != resources.ManagedByValue {
		t.Errorf("labels = %v, want %s=%s", got.Labels, resources.LabelManagedBy, resources.ManagedByValue)
	}
	if want := (rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: resources.ClientRoleName}); got.RoleRef != want {
		t.Errorf("roleRef = %+v, want %+v", got.RoleRef, want)
	}
	want := []rbacv1.Subject{{APIGroup: "rbac.authorization.k8s.io", Kind: "Group", Name: "system:serviceaccounts:apps"}}
	if !slices.Equal(got.Subjects, want) {
		t.Errorf("subjects = %+v, want %+v", got.Subjects, want)
	}
}

// releaseClusterRoles returns every ClusterRole of release.yaml.
func releaseClusterRoles(t *testing.T) []rbacv1.ClusterRole {
	t.Helper()
	f, err := os.Open("../../release.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var roles []rbacv1.ClusterRole
	dec := yaml.NewYAMLOrJSONDecoder(f, 4096)
	for {
		var u unstructured.Unstructured
		if err := dec.Decode(&u); errors.Is(err, io.EOF) {
			return roles
		} else if err != nil {
			t.Fatal(err)
		}
		if u.GetKind() != "ClusterRole" {
			continue
		}
		var role rbacv1.ClusterRole
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &role); err != nil {
			t.Fatal(err)
		}
		roles = append(roles, role)
	}
}

// The client ClusterRole's rendered name, the RoleBinding's roleRef and the manager's `bind` grant must
// all be one string. kustomize adds the wireguard- prefix to the first, not to resourceNames in a rule,
// so the grant carries the already-prefixed name. If any of the three drifts, the manager cannot create
// the RoleBinding (escalation prevention) and no labelled pod can reach the apiserver.
func TestReleaseGrantsBindOnTheRenderedClientRole(t *testing.T) {
	var clientRole string
	var bindNames []string
	for _, role := range releaseClusterRoles(t) {
		if role.Name == resources.ClientRoleName {
			clientRole = role.Name
		}
		for _, r := range role.Rules {
			if slices.Contains(r.Verbs, "bind") {
				if !slices.Equal(r.Resources, []string{"clusterroles"}) {
					t.Errorf("a bind rule on %v, want only clusterroles", r.Resources)
				}
				bindNames = append(bindNames, r.ResourceNames...)
			}
		}
	}
	if clientRole == "" {
		t.Errorf("release.yaml has no ClusterRole named %s", resources.ClientRoleName)
	}
	if !slices.Equal(bindNames, []string{resources.ClientRoleName}) {
		t.Errorf("bind grants resourceNames %v, want exactly [%s]", bindNames, resources.ClientRoleName)
	}
}

// The operator writes exactly one RoleBinding name per namespace and one policy and binding name, so its
// grants on those resources name them: a compromised operator cannot rewrite anyone else's RoleBinding
// or admission policy. Reads are by that name too, which is why the RoleBinding cache selects on it.
func TestReleaseGrantsOnlyTheNamesTheOperatorManages(t *testing.T) {
	grants := map[string][]string{} // resource -> resourceNames, across all rules naming it
	verbs := map[string][]string{}
	for _, role := range releaseClusterRoles(t) {
		if role.Name != "wireguard-manager-role" {
			continue
		}
		for _, r := range role.Rules {
			for _, res := range r.Resources {
				switch res {
				case "rolebindings", "mutatingadmissionpolicies", "mutatingadmissionpolicybindings":
					grants[res] = append(grants[res], r.ResourceNames...)
					verbs[res] = append(verbs[res], r.Verbs...)
					if len(r.ResourceNames) == 0 {
						t.Errorf("%s is granted for every name: %+v", res, r)
					}
				}
			}
		}
	}
	want := map[string]string{
		"rolebindings":                    resources.ClientRoleName,
		"mutatingadmissionpolicies":       injectPolicyName,
		"mutatingadmissionpolicybindings": injectPolicyName,
	}
	for res, name := range want {
		if !slices.Equal(grants[res], []string{name}) {
			t.Errorf("%s grants resourceNames %v, want exactly [%s]", res, grants[res], name)
		}
	}
	for _, res := range []string{"mutatingadmissionpolicies", "mutatingadmissionpolicybindings"} {
		for _, v := range []string{"get", "list", "watch"} {
			if slices.Contains(verbs[res], v) {
				t.Errorf("%s grants %s, which the operator never uses", res, v)
			}
		}
	}
}
