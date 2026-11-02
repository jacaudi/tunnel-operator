//go:build !linux

package sidecar

import (
	"errors"
	"net/netip"
)

// ensureRoutes and routesVia are unavailable off Linux; the client runs only on Linux.
func ensureRoutes(int, []netip.Prefix) error { return errors.New("client routing needs Linux") } //nolint:unused // the tunnel's Apply and Check call it once they exist

func routesVia(netip.Addr, int) (bool, error) { return false, errors.New("client routing needs Linux") } //nolint:unused // the tunnel's Apply and Check call it once they exist
