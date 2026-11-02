package sidecar

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LoadOrCreateKey returns the private key stored at path. When the file does not exist it generates a
// key and writes it there with mode 0600. A file that holds no valid key is an error and is left as it is.
func LoadOrCreateKey(path string) (_ wgtypes.Key, err error) {
	// #nosec G304 -- path is DefaultKeyPath, a fixed mount point inside the pod, not attacker-controlled input.
	content, err := os.ReadFile(path)
	if err == nil {
		key, err := wgtypes.ParseKey(strings.TrimSpace(string(content)))
		if err != nil {
			return wgtypes.Key{}, fmt.Errorf("key file %s holds no valid WireGuard key: %w", path, err)
		}
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return wgtypes.Key{}, fmt.Errorf("read key %s: %w", path, err)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("generate key: %w", err)
	}
	// #nosec G304 -- path is DefaultKeyPath, a fixed mount point inside the pod, not attacker-controlled input.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("write key %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("write key %s: %w", path, cerr))
		}
	}()
	if _, err := f.WriteString(key.String()); err != nil {
		return wgtypes.Key{}, fmt.Errorf("write key %s: %w", path, err)
	}
	return key, nil
}
