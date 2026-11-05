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

	"github.com/jacaudi/wireguard-operator/internal/resources"
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
		{name: "one of several", ns: "apps", pods: []corev1.Pod{podIn("apps", nil), podIn("apps", enabled)}, want: true},
		{name: "only unlabelled pods", ns: "apps", pods: []corev1.Pod{podIn("apps", nil)}},
		{name: "enabled is not true", ns: "apps", pods: []corev1.Pod{podIn("apps", map[string]string{resources.LabelEnabled: "false"})}},
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

// The client ClusterRole's rendered name, the RoleBinding's roleRef and the manager's `bind` grant must
// all be one string. kustomize adds the wireguard- prefix to the first, not to resourceNames in a rule,
// so the grant carries the already-prefixed name. If any of the three drifts, the manager cannot create
// the RoleBinding (escalation prevention) and no labelled pod can reach the apiserver.
func TestReleaseGrantsBindOnTheRenderedClientRole(t *testing.T) {
	f, err := os.Open("../../release.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var clientRole string
	var bindNames []string
	dec := yaml.NewYAMLOrJSONDecoder(f, 4096)
	for {
		var u unstructured.Unstructured
		if err := dec.Decode(&u); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if u.GetKind() != "ClusterRole" {
			continue
		}
		if u.GetName() == resources.ClientRoleName {
			clientRole = u.GetName()
		}
		var role rbacv1.ClusterRole
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &role); err != nil {
			t.Fatal(err)
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
