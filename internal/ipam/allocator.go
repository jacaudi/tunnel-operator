/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package ipam provides IP address management for Wireguard peers.
package ipam

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/korylprince/ipnetgen"
)

const (
	// DefaultPeerCIDR4 is the default IPv4 CIDR range for Wireguard peer IPs.
	DefaultPeerCIDR4 = "10.8.0.0/24"
)

// Allocator manages IP address allocation for Wireguard peers.
type Allocator struct{}

// NewAllocator creates a new IP address allocator.
func NewAllocator() *Allocator {
	return &Allocator{}
}

// AllocateIP allocates an available IP address from the given CIDR range,
// excluding addresses that are already in use.
func (a *Allocator) AllocateIP(cidr string, usedIPs []string) (string, error) {
	gen, err := ipnetgen.New(cidr)
	if err != nil {
		return "", fmt.Errorf("failed to parse CIDR %s: %w", cidr, err)
	}

	for ip := gen.Next(); ip != nil; ip = gen.Next() {
		ipStr := ip.String()
		if !a.isUsed(ipStr, usedIPs) {
			return ipStr, nil
		}
	}

	return "", fmt.Errorf("no available IP found in %s", cidr)
}

// GetUsedIPs returns a list of IPv4 addresses that are currently in use by peers.
// It includes the derived network and gateway addresses (first host) from the
// provided CIDR as reserved.
func (a *Allocator) GetUsedIPs(cidr string, peers *v1alpha1.WireguardPeerList) []string {
	usedIPs := deriveReservedIPs(cidr)

	for _, peer := range peers.Items {
		if peer.Status.Address != "" {
			usedIPs = append(usedIPs, peer.Status.Address)
		}
	}

	return usedIPs
}

// deriveReservedIPs returns a slice containing the network address and the first
// host address derived from the given CIDR. If the CIDR cannot be parsed or has no server address
// (see ServerAddress), it returns an empty slice and leaves validation to callers of AllocateIP.
func deriveReservedIPs(cidr string) []string {
	if cidr == "" {
		return []string{}
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return []string{}
	}

	gateway, err := ServerAddress(prefix)
	if err != nil {
		return []string{}
	}

	return []string{prefix.Masked().Addr().String(), gateway.String()}
}

// ServerAddress returns the server's tunnel address within prefix: the masked prefix's first host.
// It is the single source for that address; the agent configures wg0 with it and the operator
// reserves it and builds the egress API URL from it. A non-IPv4 prefix, or one with fewer than four
// addresses (no network, server, peer and broadcast), is an error.
func ServerAddress(prefix netip.Prefix) (netip.Addr, error) {
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return netip.Addr{}, fmt.Errorf("server address: prefix %q is not IPv4", prefix)
	}
	if prefix.Bits() > 30 {
		return netip.Addr{}, fmt.Errorf("server address: prefix %q has fewer than 4 addresses", prefix)
	}
	return prefix.Addr().Next(), nil
}

// isUsed checks if an IP address is in the list of used IPs.
func (a *Allocator) isUsed(ip string, usedIPs []string) bool {
	return slices.Contains(usedIPs, ip)
}
