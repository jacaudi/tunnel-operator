package sidecar

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// probeAddress is the internet address the startup check expects to route via wg0.
const probeAddress = "1.1.1.1"

// Check is the startup probe: it returns nil when iface carries exactly one peer with a handshake under
// 180 s old and the kernel routes probeAddress via iface.
func Check(iface string) (err error) {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wgctrl client: %w", err)
	}
	defer func() {
		if cerr := c.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close wgctrl client: %w", cerr))
		}
	}()
	dev, err := c.Device(iface)
	if err != nil {
		return fmt.Errorf("read device %s: %w", iface, err)
	}
	if err := checkDevice(dev, time.Now()); err != nil {
		return err
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("look up %s: %w", iface, err)
	}
	// The same address as probeAddress, built without a Must* call in library code.
	via, err := routesVia(netip.AddrFrom4([4]byte{1, 1, 1, 1}), link.Attrs().Index)
	if err != nil {
		return err
	}
	if !via {
		return fmt.Errorf("%s does not route via %s", probeAddress, iface)
	}
	return nil
}
