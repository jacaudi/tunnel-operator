// Package datapath asserts the server pod's fail-closed routing and its forwarding rules.
package datapath

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"

	"github.com/jacaudi/tunnel-operator/internal/resources"
)

// rule is one iptables rule: its table, its chain and the match and target after the chain.
type rule struct {
	table string
	chain string
	spec  []string
}

// rules returns the iptables rules that forward and masquerade peerCIDR's traffic into the tunnel,
// in order. The FORWARD policy is asserted separately.
func rules(peerCIDR netip.Prefix) []rule {
	cidr := peerCIDR.String()
	return []rule{
		{"filter", "FORWARD", []string{"-i", resources.WgInterface, "-o", resources.EgressInterface, "-s", cidr, "-j", "ACCEPT"}},
		{"filter", "FORWARD", []string{"-i", resources.EgressInterface, "-o", resources.WgInterface, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}},
		{"mangle", "FORWARD", []string{"-o", resources.EgressInterface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"}},
		{"nat", "POSTROUTING", []string{"-s", cidr, "-o", resources.EgressInterface, "-j", "MASQUERADE"}},
	}
}

// Datapath asserts the routes, rules and iptables rules. Ensure and EnsureEgress may be called
// concurrently.
type Datapath struct {
	run       func(ctx context.Context, args ...string) error // runs iptables with args
	restore   func(ctx context.Context, input []byte) error   // runs iptables-restore --noflush with input
	ensure    sync.Mutex                                      // serializes Ensure and EnsureEgress
	mu        sync.Mutex                                      // guards err and egressErr
	err       error                                           // the last Ensure's result
	egressErr error                                           // the last EnsureEgress's result
}

// New returns a Datapath that runs the iptables binary. Err reports "datapath not asserted yet"
// until the first Ensure.
func New() *Datapath {
	return &Datapath{run: runIptables, restore: runIptablesRestore, err: errors.New("datapath not asserted yet")}
}

func runIptables(ctx context.Context, args ...string) error {
	// #nosec G204 -- args are built from the constant rules above and a parsed netip.Prefix; no caller-supplied string reaches the command, and exec takes argv directly with no shell.
	out, err := exec.CommandContext(ctx, "iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

func runIptablesRestore(ctx context.Context, input []byte) error {
	// #nosec G204 -- the command and its arguments are constants; input goes to stdin, never to argv, and exec takes argv directly with no shell.
	cmd := exec.CommandContext(ctx, "iptables-restore", "-w", "5", "--noflush")
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// Ensure asserts the datapath for peerCIDR and records the result for Err. It always runs both the
// routing and the iptables pass, so a routing failure never leaves the FORWARD policy unasserted.
func (d *Datapath) Ensure(ctx context.Context, peerCIDR string) error {
	d.ensure.Lock()
	defer d.ensure.Unlock()

	p, err := netip.ParsePrefix(peerCIDR)
	if err != nil {
		err = fmt.Errorf("parse peerCIDR %q: %w", peerCIDR, err)
		d.record(err)
		return err
	}
	p = p.Masked()

	err = errors.Join(ensureRouting(p), d.ensureIptables(ctx, p))
	d.record(err)
	return err
}

func (d *Datapath) record(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.err = err
}

func (d *Datapath) recordEgress(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.egressErr = err
}

// Err returns the result of the last Ensure joined with the result of the last EnsureEgress: non-nil
// if either failed.
func (d *Datapath) Err() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return errors.Join(d.err, d.egressErr)
}

// ensureIptables asserts the FORWARD policy DROP, then each of rules(p): a rule whose check fails is
// appended. Any check failure counts as absent; an append failure is returned.
func (d *Datapath) ensureIptables(ctx context.Context, p netip.Prefix) error {
	if err := d.run(ctx, "-w", "5", "-P", "FORWARD", "DROP"); err != nil {
		return fmt.Errorf("iptables -P FORWARD DROP: %w", err)
	}
	for _, r := range rules(p) {
		if d.run(ctx, iptablesArgs(r, "-C")...) == nil {
			continue
		}
		if err := d.run(ctx, iptablesArgs(r, "-A")...); err != nil {
			return fmt.Errorf("iptables -t %s -A %s %s: %w", r.table, r.chain, strings.Join(r.spec, " "), err)
		}
	}
	return nil
}

// iptablesArgs returns the argv that applies op (-C or -A) to r.
func iptablesArgs(r rule, op string) []string {
	return append([]string{"-w", "5", "-t", r.table, op, r.chain}, r.spec...)
}
