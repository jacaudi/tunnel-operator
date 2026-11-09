package resources

import (
	"slices"
	"testing"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSecretHasGluetunKeys(t *testing.T) {
	wg := testWireguard()
	secret, err := NewSecretBuilder(testScheme(t)).ForWireguard(wg, []byte("state"), "priv", "pub", "the-key")
	if err != nil {
		t.Fatalf("ForWireguard: %v", err)
	}

	want := map[string][]byte{
		"state.json":           []byte("state"),
		"privateKey":           []byte("priv"),
		"publicKey":            []byte("pub"),
		SecretKeyGluetunAPIKey: []byte("the-key"),
		SecretKeyGluetunAuth:   GluetunAuthTOML("the-key"),
	}
	if !equality.Semantic.DeepEqual(secret.Data, want) {
		t.Errorf("secret data = %q, want %q", secret.Data, want)
	}
	if secret.Name != wg.Name || secret.Namespace != wg.Namespace {
		t.Errorf("secret = %s/%s, want %s/%s", secret.Namespace, secret.Name, wg.Namespace, wg.Name)
	}
	if !slices.ContainsFunc(secret.OwnerReferences, func(o metav1.OwnerReference) bool { return o.Name == wg.Name }) {
		t.Errorf("owner references = %v, want one naming %s", secret.OwnerReferences, wg.Name)
	}
}
