package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-logr/logr"

	"github.com/fsnotify/fsnotify"
	"github.com/jacaudi/wireguard-operator/api/v1alpha1"
	"github.com/jacaudi/wireguard-operator/internal/ipam"
)

type State struct {
	Server           v1alpha1.Wireguard
	ServerPrivateKey string
	Peers            []v1alpha1.WireguardPeer
}

// PeerCIDR returns the server's peerCIDR from state, or ipam.DefaultPeerCIDR4 when it is empty.
func PeerCIDR(state State) string {
	if state.Server.Spec.PeerCIDR == "" {
		return ipam.DefaultPeerCIDR4
	}
	return state.Server.Spec.PeerCIDR
}

func IsStateValid(state State) error {

	if state.ServerPrivateKey == "" {
		return fmt.Errorf("server private key is not defined")
	}

	if len(state.ServerPrivateKey) != 44 {
		return fmt.Errorf("server private key should be of length 44")
	}

	for i, peer := range state.Peers {
		if peer.Status.Address == "" {
			return fmt.Errorf("peer with index %d does not have the address defined", i)
		}

		if peer.Spec.PublicKey == "" {
			return fmt.Errorf("peer with index %d does not have a public key defined", i)
		}
	}

	return nil
}

func OnStateChange(path string, logger logr.Logger, onFileChange func(State)) (func(), error) {

	dir := filepath.Dir(path)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	close := func() {
		_ = watcher.Close()
	}

	state, hash, err := GetDesiredState(path)

	if err == nil {
		err := IsStateValid(state)

		if err != nil {
			logger.Error(err, "State is not valid")
		} else {
			onFileChange(state)
		}
	}

	// Start listening for events.
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				logger.V(9).Info("Received a new event", "filename", event.Name, "operation", event.Op.String())
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {

					state, newHash, err := GetDesiredState(path)
					if err != nil {
						logger.Error(err, "unable to read or parse state")
						continue
					}

					if newHash == hash {
						logger.V(9).Info("Received a new event but state content did not change")
						continue
					}

					logger.V(9).Info("State content changed", "oldHash", hash, "newHash", newHash)
					hash = newHash

					err = IsStateValid(state)

					if err != nil {
						logger.Error(err, "State is not valid")
						continue
					}

					onFileChange(state)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logger.Error(err, "watcher error")
			}
		}
	}()

	err = watcher.Add(dir)
	if err != nil {
		return close, err
	}
	return close, nil
}

func GetDesiredState(path string) (State, string, error) {
	var state State
	// #nosec G304 -- path is the operator's own --state flag (a fixed mount
	// point inside the pod), not attacker-controlled input. The agent must be
	// able to read whatever file it was pointed at; constraining it to a literal
	// would break the flag it exists to serve.
	jsonFile, err := os.ReadFile(path)
	if err != nil {
		return State{}, "", err
	}
	err = json.Unmarshal(jsonFile, &state)
	if err != nil {
		return State{}, "", err
	}
	// SHA-256 rather than MD5. The digest is only used to detect that the
	// desired state changed, so collision resistance is not strictly required —
	// but this file carries the server private key and every peer's
	// configuration, and shipping a known-broken primitive over that material is
	// not worth the two lines it saves.
	hash := sha256.Sum256(jsonFile)

	return state, hex.EncodeToString(hash[:]), nil
}
