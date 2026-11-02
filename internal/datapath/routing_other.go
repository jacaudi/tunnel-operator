//go:build !linux

package datapath

import (
	"errors"
	"net/netip"
)

// ensureRouting is unavailable off Linux; the agent runs only on Linux.
func ensureRouting(netip.Prefix) error { return errors.New("datapath routing needs Linux") }
