package datapath

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/jacaudi/tunnel-operator/internal/resources"
)

// EgressRules is what the agent's own chains must hold: the egress API's tunnel address, and the
// forwarded port with the peer holding it. The forwarding rules exist only when Holder is valid and
// Port > 0.
type EgressRules struct {
	TunnelAddr netip.Addr
	Holder     netip.Addr
	Port       int32
}

// egressChain is one of the agent's chains and the built-in chain that jumps to it.
type egressChain struct {
	table   string
	builtin string
	name    string
}

// egressChains lists the chains EnsureEgress creates and jumps to, in order.
var egressChains = []egressChain{
	{"nat", "PREROUTING", resources.ChainPrerouting},
	{"filter", "FORWARD", resources.ChainForward},
	{"filter", "INPUT", resources.ChainInput},
	{"filter", "OUTPUT", resources.ChainOutput},
}

// EnsureEgress creates the agent's chains, inserts a jump to each at position 1 of its built-in
// chain if absent (a jump that drifted down the chain is not moved back), and refills the chains
// from r with one iptables-restore call, atomic per table, not across the nat and filter tables.
// It records the result for Err.
func (d *Datapath) EnsureEgress(ctx context.Context, r EgressRules) error {
	d.ensure.Lock()
	defer d.ensure.Unlock()

	err := d.ensureEgress(ctx, r)
	d.recordEgress(err)
	return err
}

func (d *Datapath) ensureEgress(ctx context.Context, r EgressRules) error {
	if !r.TunnelAddr.IsValid() {
		return errors.New("egress rules: tunnel address is not valid")
	}
	for _, c := range egressChains {
		// An existing chain is the steady state; -N has no "create if missing".
		if err := d.run(ctx, "-w", "5", "-t", c.table, "-N", c.name); err != nil && !strings.Contains(err.Error(), "Chain already exists") {
			return fmt.Errorf("iptables -t %s -N %s: %w", c.table, c.name, err)
		}
	}
	for _, c := range egressChains {
		if d.run(ctx, "-w", "5", "-t", c.table, "-C", c.builtin, "-j", c.name) == nil {
			continue
		}
		if err := d.run(ctx, "-w", "5", "-t", c.table, "-I", c.builtin, "1", "-j", c.name); err != nil {
			return fmt.Errorf("iptables -t %s -I %s 1 -j %s: %w", c.table, c.builtin, c.name, err)
		}
	}
	if err := d.restore(ctx, egressRestoreInput(r)); err != nil {
		return fmt.Errorf("iptables-restore: %w", err)
	}
	return nil
}

// egressRestoreInput returns the iptables-restore input that declares, flushes and refills the agent's
// chains. It never declares or flushes a built-in chain: with --noflush they keep their rules. The
// tunnel address must be valid; ensureEgress refuses a rule set without one.
func egressRestoreInput(r EgressRules) []byte {
	nat := []string{"*nat", ":" + resources.ChainPrerouting + " - [0:0]", "-F " + resources.ChainPrerouting}
	filter := []string{
		"*filter",
		":" + resources.ChainForward + " - [0:0]",
		":" + resources.ChainInput + " - [0:0]",
		":" + resources.ChainOutput + " - [0:0]",
		"-F " + resources.ChainForward,
		"-F " + resources.ChainInput,
		"-F " + resources.ChainOutput,
	}
	if r.Holder.IsValid() && r.Port > 0 {
		for _, proto := range []string{"tcp", "udp"} {
			nat = append(nat, fmt.Sprintf("-A %s -i %s -p %s --dport %d -j DNAT --to-destination %s:%d",
				resources.ChainPrerouting, resources.EgressInterface, proto, r.Port, r.Holder, r.Port))
			filter = append(filter, fmt.Sprintf("-A %s -i %s -o %s -d %s -p %s --dport %d -j ACCEPT",
				resources.ChainForward, resources.EgressInterface, resources.WgInterface, r.Holder, proto, r.Port))
		}
	}
	filter = append(filter,
		fmt.Sprintf("-A %s -i %s -d %s -p tcp --dport %d -j ACCEPT",
			resources.ChainInput, resources.WgInterface, r.TunnelAddr, resources.EgressAPIPort),
		fmt.Sprintf("-A %s -o %s -s %s -p tcp --sport %d -m conntrack --ctstate ESTABLISHED -j ACCEPT",
			resources.ChainOutput, resources.WgInterface, r.TunnelAddr, resources.EgressAPIPort))
	nat = append(nat, "COMMIT")
	filter = append(filter, "COMMIT")
	return []byte(strings.Join(slices.Concat(nat, filter), "\n") + "\n")
}
