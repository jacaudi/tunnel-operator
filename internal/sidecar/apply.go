package sidecar

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jacaudi/wireguard-operator/internal/resources"
	"github.com/jacaudi/wireguard-operator/internal/wireguard"
)

// podDatapath applies a Tunnel to the pod's own network namespace: wg0 at resources.TunnelMTU, its
// address, its one peer, then the routes.
type podDatapath struct{}

// Apply configures wg0 for t with key. It reconfigures the WireGuard device only when it differs from t.
func (podDatapath) Apply(key wgtypes.Key, t Tunnel) (err error) {
	if err := wireguard.SyncLink(resources.WgInterface, resources.TunnelMTU, resources.UserspaceImplementation); err != nil {
		return fmt.Errorf("sync link: %w", err)
	}
	if err := wireguard.SyncAddress(resources.WgInterface, t.Address); err != nil {
		return fmt.Errorf("sync address: %w", err)
	}

	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wgctrl client: %w", err)
	}
	defer func() {
		if cerr := c.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close wgctrl client: %w", cerr))
		}
	}()
	dev, err := c.Device(resources.WgInterface)
	if err != nil {
		return fmt.Errorf("read device: %w", err)
	}
	if cfg, changed := deviceConfig(dev, key, t); changed {
		if err := c.ConfigureDevice(resources.WgInterface, cfg); err != nil {
			return fmt.Errorf("configure device: %w", err)
		}
	}

	link, err := netlink.LinkByName(resources.WgInterface)
	if err != nil {
		return fmt.Errorf("look up %s: %w", resources.WgInterface, err)
	}
	if err := ensureRoutes(link.Attrs().Index, t.LocalCIDRs); err != nil {
		return fmt.Errorf("routes: %w", err)
	}
	return nil
}
