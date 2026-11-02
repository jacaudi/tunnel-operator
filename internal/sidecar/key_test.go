package sidecar

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLoadOrCreateKey(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key")

		got, err := LoadOrCreateKey(path)
		if err != nil {
			t.Fatalf("LoadOrCreateKey() error = %v", err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("mode = %o, want 600", perm)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		stored, err := wgtypes.ParseKey(strings.TrimSpace(string(content)))
		if err != nil {
			t.Fatalf("file content %q is no key: %v", content, err)
		}
		if stored != got {
			t.Errorf("stored key %s, returned %s", stored, got)
		}
		again, err := LoadOrCreateKey(path)
		if err != nil {
			t.Fatalf("second LoadOrCreateKey() error = %v", err)
		}
		if again != got {
			t.Errorf("second call returned %s, want the first key %s", again, got)
		}
	})

	t.Run("existing key", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key")
		want, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		if err := os.WriteFile(path, []byte(want.String()+"\n"), 0o600); err != nil {
			t.Fatalf("write key: %v", err)
		}

		got, err := LoadOrCreateKey(path)
		if err != nil {
			t.Fatalf("LoadOrCreateKey() error = %v", err)
		}
		if got != want {
			t.Errorf("LoadOrCreateKey() = %s, want %s", got, want)
		}
	})

	t.Run("garbage", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}

		_, err := LoadOrCreateKey(path)
		if err == nil {
			t.Fatal("LoadOrCreateKey() = nil error for a file holding garbage")
		}
		for _, want := range []string{"holds no valid WireGuard key", path} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q lacks %q", err, want)
			}
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(content) != "garbage" {
			t.Errorf("file holds %q, want it left as garbage", content)
		}
	})
}
