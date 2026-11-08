package wireguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"syscall"
	"time"

	"github.com/go-logr/logr"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/agent"
	"github.com/jacaudi/tunnel-operator/internal/ipam"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// MTU is the server link's MTU. A client link uses resources.TunnelMTU.
const MTU = 1420

func syncRoute(iface string, cidr string, gw net.IP, family int) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	routes, err := netlink.RouteList(link, family)
	if err != nil {
		return err
	}

	for _, route := range routes {
		if route.LinkIndex == link.Attrs().Index {
			return nil
		}
	}
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	route := netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Gw:        gw,
	}

	err = netlink.RouteAdd(&route)
	if err != nil {
		return err
	}

	return nil
}

// addressChanges returns the addresses to remove from a link that holds have so that want is its only
// address, in have's order, and whether want must be added.
func addressChanges(have []netip.Prefix, want netip.Prefix) (remove []netip.Prefix, add bool) {
	for _, p := range have {
		if p != want {
			remove = append(remove, p)
		}
	}
	return remove, !slices.Contains(have, want)
}

// netlinkAddr converts p to the form netlink adds and deletes.
func netlinkAddr(p netip.Prefix) *netlink.Addr {
	return &netlink.Addr{IPNet: &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), 32)}}
}

// SyncAddress makes want the only IPv4 address on iface and brings iface up: it removes every other
// IPv4 address and adds want when it is absent.
func SyncAddress(iface string, want netip.Prefix) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	addresses, err := netlink.AddrList(link, syscall.AF_INET)
	if err != nil {
		return fmt.Errorf("netlink addr list: %w", err)
	}

	have := make([]netip.Prefix, 0, len(addresses))
	for _, a := range addresses {
		addr, _ := netip.AddrFromSlice(a.IP.To4())
		bits, _ := a.Mask.Size()
		have = append(have, netip.PrefixFrom(addr, bits))
	}

	remove, add := addressChanges(have, want)
	for _, p := range remove {
		if err := netlink.AddrDel(link, netlinkAddr(p)); err != nil {
			return fmt.Errorf("netlink addr del %s: %w", p, err)
		}
	}
	if add {
		if err := netlink.AddrAdd(link, netlinkAddr(want)); err != nil {
			return fmt.Errorf("netlink addr add: %w", err)
		}
	}

	return netlink.LinkSetUp(link)
}

func createLinkUsingUserspaceImpl(iface string, wgUserspaceImplementationFallback string) error {
	// Ensure /dev/net exists.
	// #nosec G301 -- 0755 is deliberate and not a permissive default. This is
	// the conventional mode for /dev/net, and the directory must stay
	// world-traversable so a non-root process can reach /dev/net/tun through it.
	// Tightening it to 0750 breaks the userspace tunnel it exists to enable.
	if err := os.MkdirAll("/dev/net", 0o755); err != nil {
		return err
	}

	// Ensure /dev/net/tun is a character device; create it if missing
	fi, err := os.Stat("/dev/net/tun")
	if err != nil {
		if os.IsNotExist(err) {
			mode := uint32(syscall.S_IFCHR | 0o666)
			// #nosec G115 -- both arguments are compile-time constants: major 10,
			// minor 200 is the fixed device number for /dev/net/tun. Mkdev packs
			// them into 0x0A000200, which fits an int on every platform this
			// builds for, so the uint64 -> int conversion cannot overflow. No
			// value here is derived from input.
			dev := int(unix.Mkdev(10, 200))
			if err := unix.Mknod("/dev/net/tun", mode, dev); err != nil {
				return fmt.Errorf("mknod /dev/net/tun failed: %w", err)
			}
		} else {
			return err
		}
	} else {
		mode := fi.Mode()
		if mode&os.ModeDevice == 0 || mode&os.ModeCharDevice == 0 {
			return fmt.Errorf("/dev/net/tun exists but is not a character device")
		}
	}

	// Launch userspace implementation (e.g., wireguard-go) to create the interface.
	// #nosec G204 -- neither argument is user input. The binary name comes from
	// the agent's own --wg-userspace-implementation-fallback flag, set by the
	// operator in the Deployment it renders, and iface is the --wg-iface flag
	// from the same place. A peer cannot influence either. exec.Command takes
	// argv directly rather than going through a shell, so there is nothing to
	// quote or inject into.
	cmd := exec.Command(wgUserspaceImplementationFallback, iface)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting userspace implementation %q failed: %w", wgUserspaceImplementationFallback, err)
	}

	return nil
}

// userspaceLinkTimeout bounds how long SyncLink waits for the userspace implementation to
// create the link it was started for.
const userspaceLinkTimeout = 5 * time.Second

// waitForLink polls until iface exists or timeout elapses.
func waitForLink(iface string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		_, err := netlink.LinkByName(iface)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("userspace WireGuard did not create link %q within %s: %w; ensure a userspace implementation (e.g., wireguard-go) is running for this interface", iface, timeout, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func createLinkUsingKernelModule(iface string, mtu int) error {
	// link not created
	wgLink := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{
			Name: iface,
			MTU:  mtu,
		},
		LinkType: "wireguard",
	}

	if err := netlink.LinkAdd(wgLink); err != nil {
		return err
	}
	return nil
}

// SyncLink makes the WireGuard link iface exist with MTU mtu and up. It creates a missing link with
// the kernel module, falling back to the userspace implementation when the module is unavailable,
// and sets the MTU and brings the link up whether it created the link or found it.
func SyncLink(iface string, mtu int, wgUserspaceImplementationFallback string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		if _, ok := errors.AsType[netlink.LinkNotFoundError](err); !ok {
			return err
		}

		if kernelErr := createLinkUsingKernelModule(iface, mtu); kernelErr != nil {
			// Keep both causes: a node with neither the module nor a usable
			// userspace implementation should report why each failed.
			if userspaceErr := createLinkUsingUserspaceImpl(iface, wgUserspaceImplementationFallback); userspaceErr != nil {
				return errors.Join(kernelErr, userspaceErr)
			}

			// The userspace implementation creates the link asynchronously.
			if err := waitForLink(iface, userspaceLinkTimeout); err != nil {
				return err
			}
		}

		// Verify link exists after creation
		link, err = netlink.LinkByName(iface)
		if err != nil {
			return fmt.Errorf("expected link %q after creation, but not found: %w", iface, err)
		}
	}

	if link.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("set link %q MTU to %d: %w", iface, mtu, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bringing link %q up failed: %w", iface, err)
	}

	return nil
}

func (wg *Wireguard) syncWireguard(state agent.State, iface string, listenPort int) (err error) {
	// One client per sync: each wgctrl.New opens a genetlink socket, and
	// /health calls Sync every few seconds.
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wgctrl client: %w", err)
	}
	defer func() { err = errors.Join(err, c.Close()) }()

	cfg, err := CreateWireguardConfiguration(c, state, iface, listenPort)
	if err != nil {
		return err
	}

	err = c.ConfigureDevice(iface, cfg)
	if err != nil {
		return err
	}

	for _, peer := range cfg.Peers {
		// A device peer can carry no AllowedIPs.
		var peerIP string
		if len(peer.AllowedIPs) > 0 {
			peerIP = peer.AllowedIPs[0].String()
		}
		if peer.Remove {
			wg.Logger.V(2).Info("Removed peer", "peerIP", peerIP, "peerPublicKey", peer.PublicKey.String())
		} else if peer.UpdateOnly {
			wg.Logger.V(2).Info("Updated peer", "peerIP", peerIP, "peerPublicKey", peer.PublicKey.String())
		} else {
			wg.Logger.V(2).Info("Added peer", "peerIP", peerIP, "peerPublicKey", peer.PublicKey.String())
		}
	}

	return nil
}

type Wireguard struct {
	Logger                            logr.Logger
	Iface                             string
	ListenPort                        int
	WgUserspaceImplementationFallback string
}

func (wg *Wireguard) Sync(state agent.State) error {
	wg.Logger.V(2).Info("syncing Wireguard")
	// create wg0 link
	err := SyncLink(wg.Iface, MTU, wg.WgUserspaceImplementationFallback)
	if err != nil {
		return err
	}

	cidr4 := agent.PeerCIDR(state)
	prefix4, err := netip.ParsePrefix(cidr4)
	if err != nil {
		return fmt.Errorf("failed to parse IPv4 CIDR %q: %w", cidr4, err)
	}

	addr, err := ipam.ServerAddress(prefix4)
	if err != nil {
		return err
	}

	if err := SyncAddress(wg.Iface, netip.PrefixFrom(addr, 32)); err != nil {
		return err
	}
	if err := syncRoute(wg.Iface, cidr4, net.IP(addr.AsSlice()), syscall.AF_INET); err != nil {
		return err
	}

	// sync wg configuration
	err = wg.syncWireguard(state, wg.Iface, wg.ListenPort)
	if err != nil {
		return err
	}

	return nil
}

func getIP(ip string) ([]net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(ip)
	if err != nil {
		return nil, fmt.Errorf("parse allowed IP %q: %w", ip, err)
	}

	return []net.IPNet{*ipnet}, nil
}

// allowedIPsEqual reports whether a and b hold the same networks in the same order.
func allowedIPsEqual(a, b []net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].IP.Equal(b[i].IP) || a[i].Mask.String() != b[i].Mask.String() {
			return false
		}
	}
	return true
}

func createPeersConfiguration(c *wgctrl.Client, state agent.State, iface string) ([]wgtypes.PeerConfig, error) {
	var peersState = make(map[string]v1alpha1.WireguardPeer)
	for _, peer := range state.Peers {
		peersState[peer.Spec.PublicKey] = peer
	}

	device, err := c.Device(iface)

	if err != nil {
		return []wgtypes.PeerConfig{}, err
	}

	var peerConfigurationByPublicKey = make(map[string]wgtypes.PeerConfig)
	var existingConfgiuredPeersByPublicKey = make(map[string]bool)

	for _, peer := range device.Peers {

		existingConfgiuredPeersByPublicKey[peer.PublicKey.String()] = true

		peerState, ok := peersState[peer.PublicKey.String()]
		if !ok {
			// delete peer
			p := wgtypes.PeerConfig{
				Remove:     true,
				AllowedIPs: peer.AllowedIPs,
				PublicKey:  peer.PublicKey,
			}
			peerConfigurationByPublicKey[p.PublicKey.String()] = p

		} else {
			var desiredAllowed []net.IPNet
			if peerState.Status.Address != "" {
				allowed, err := getIP(peerState.Status.Address + "/32")
				if err != nil {
					return []wgtypes.PeerConfig{}, fmt.Errorf("peer %q: %w", peerState.Name, err)
				}
				desiredAllowed = append(desiredAllowed, allowed...)
			}

			// Only update if AllowedIPs differ.
			if !allowedIPsEqual(desiredAllowed, peer.AllowedIPs) {
				p := wgtypes.PeerConfig{
					UpdateOnly:        true,
					AllowedIPs:        desiredAllowed,
					PublicKey:         peer.PublicKey,
					ReplaceAllowedIPs: true,
				}
				peerConfigurationByPublicKey[p.PublicKey.String()] = p
			}
		}
	}

	// add new peers
	for _, peer := range state.Peers {
		if peer.Spec.PublicKey == "" {
			continue
		}

		if peer.Status.Address == "" {
			continue
		}
		key, err := wgtypes.ParseKey(peer.Spec.PublicKey)
		if err != nil {
			return []wgtypes.PeerConfig{}, err
		}

		_, ok := existingConfgiuredPeersByPublicKey[key.String()]
		if ok {
			continue
		}

		// create peer
		allowed, err := getIP(peer.Status.Address + "/32")
		if err != nil {
			return []wgtypes.PeerConfig{}, fmt.Errorf("peer %q: %w", peer.Name, err)
		}
		p := wgtypes.PeerConfig{
			AllowedIPs: allowed,
			PublicKey:  key,
		}
		peerConfigurationByPublicKey[p.PublicKey.String()] = p
	}

	l := make([]wgtypes.PeerConfig, 0, len(peerConfigurationByPublicKey))

	for _, value := range peerConfigurationByPublicKey {
		l = append(l, value)
	}

	return l, nil
}

// CreateWireguardConfiguration builds the desired device configuration for iface
// from state, reading the device's current peers through c.
func CreateWireguardConfiguration(c *wgctrl.Client, state agent.State, iface string, listenPort int) (wgtypes.Config, error) {
	cfg := wgtypes.Config{}

	key, err := wgtypes.ParseKey(state.ServerPrivateKey)
	if err != nil {
		return wgtypes.Config{}, err
	}
	cfg.PrivateKey = &key

	// make sure we do not interrupt existing sessions
	cfg.ReplacePeers = false
	cfg.ListenPort = &listenPort

	peers, err := createPeersConfiguration(c, state, iface)
	if err != nil {
		return wgtypes.Config{}, err
	}

	cfg.Peers = peers

	return cfg, nil
}
