package v1alpha1

import (
	"bytes"
	"os"
	"regexp"
	"testing"

	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// publicKeyPattern returns the pattern the generated CRD puts on spec.publicKey.
func publicKeyPattern(t *testing.T) *regexp.Regexp {
	t.Helper()
	raw, err := os.ReadFile("../../config/crd/bases/vpn.tunnel-operator.io_wireguardpeers.yaml")
	if err != nil {
		t.Fatalf("read CRD: %v", err)
	}
	var crd map[string]any
	if err := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096).Decode(&crd); err != nil {
		t.Fatalf("decode CRD: %v", err)
	}

	child := func(node any, key string) any {
		m, _ := node.(map[string]any)
		return m[key]
	}
	versions, _ := child(child(crd, "spec"), "versions").([]any)
	if len(versions) == 0 {
		t.Fatal("CRD has no versions")
	}
	props := child(child(child(versions[0], "schema"), "openAPIV3Schema"), "properties")
	pattern, _ := child(child(child(child(props, "spec"), "properties"), "publicKey"), "pattern").(string)
	if pattern == "" {
		t.Fatal("CRD spec.publicKey has no pattern")
	}
	return regexp.MustCompile(pattern)
}

func TestPublicKeyPatternMatchesWireGuardKeys(t *testing.T) {
	re := publicKeyPattern(t)

	for range 1000 {
		priv, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		for _, key := range []string{priv.String(), priv.PublicKey().String()} {
			if !re.MatchString(key) {
				t.Errorf("pattern %q does not match canonical key %q", re, key)
			}
		}
	}

	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key := priv.String()
	tests := []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"trailing = removed", key[:43]},
		{"extra character", key + "A"},
		{"non-canonical padding bits", key[:42] + "B="},
		{"URL-safe alphabet", "-" + key[1:]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if re.MatchString(tt.key) {
				t.Errorf("pattern %q matches %q, want no match", re, tt.key)
			}
		})
	}
}
