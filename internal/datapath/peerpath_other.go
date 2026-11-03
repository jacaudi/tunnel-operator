//go:build !linux

package datapath

import (
	"errors"
	"net/netip"
)

// lookupPeerPath is unavailable off Linux; the agent runs only on Linux.
func lookupPeerPath(netip.Addr, netip.Addr) (string, error) {
	return "", errors.New("peer path lookup needs Linux")
}
