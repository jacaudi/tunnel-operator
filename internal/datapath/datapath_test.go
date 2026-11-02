package datapath

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// fakeRun returns a run func that records each argv joined by spaces and fails any call whose
// joined argv is in fail.
func fakeRun(calls *[]string, fail ...string) func(ctx context.Context, args ...string) error {
	return func(_ context.Context, args ...string) error {
		call := strings.Join(args, " ")
		*calls = append(*calls, call)
		if slices.Contains(fail, call) {
			return errors.New("exit status 1")
		}
		return nil
	}
}

const (
	policyCall = "-w 5 -P FORWARD DROP"
	check0     = "-w 5 -t filter -C FORWARD -i wg0 -o tun0 -s 10.8.0.0/24 -j ACCEPT"
	check1     = "-w 5 -t filter -C FORWARD -i tun0 -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
	check2     = "-w 5 -t mangle -C FORWARD -o tun0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
	check3     = "-w 5 -t nat -C POSTROUTING -s 10.8.0.0/24 -o tun0 -j MASQUERADE"
	append1    = "-w 5 -t filter -A FORWARD -i tun0 -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
	append3    = "-w 5 -t nat -A POSTROUTING -s 10.8.0.0/24 -o tun0 -j MASQUERADE"
)

func TestRules(t *testing.T) {
	got := rules(netip.MustParsePrefix("10.8.0.0/24"))
	want := []rule{
		{"filter", "FORWARD", []string{"-i", "wg0", "-o", "tun0", "-s", "10.8.0.0/24", "-j", "ACCEPT"}},
		{"filter", "FORWARD", []string{"-i", "tun0", "-o", "wg0", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}},
		{"mangle", "FORWARD", []string{"-o", "tun0", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"}},
		{"nat", "POSTROUTING", []string{"-s", "10.8.0.0/24", "-o", "tun0", "-j", "MASQUERADE"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rules = %v, want %v", got, want)
	}
}

func TestEnsureIptablesAppendsOnlyMissingRules(t *testing.T) {
	var calls []string
	d := &Datapath{run: fakeRun(&calls, check1, check3)}

	if err := d.ensureIptables(t.Context(), netip.MustParsePrefix("10.8.0.0/24")); err != nil {
		t.Fatalf("ensureIptables: %v", err)
	}

	want := []string{policyCall, check0, check1, append1, check2, check3, append3}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("calls = %q, want %q", calls, want)
	}
}

func TestEnsureIptablesReturnsAppendFailure(t *testing.T) {
	var calls []string
	d := &Datapath{run: fakeRun(&calls, check0, check1, check2, check3, append3)}

	err := d.ensureIptables(t.Context(), netip.MustParsePrefix("10.8.0.0/24"))
	if err == nil {
		t.Fatal("ensureIptables returned nil, want the append failure")
	}

	const prefix = "iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o tun0 -j MASQUERADE: "
	if !strings.HasPrefix(err.Error(), prefix) {
		t.Errorf("error = %q, want prefix %q", err, prefix)
	}
}

func TestEnsureIptablesReturnsPolicyFailure(t *testing.T) {
	var calls []string
	d := &Datapath{run: fakeRun(&calls, policyCall)}

	err := d.ensureIptables(t.Context(), netip.MustParsePrefix("10.8.0.0/24"))
	if err == nil {
		t.Fatal("ensureIptables returned nil, want the policy failure")
	}

	const prefix = "iptables -P FORWARD DROP: "
	if !strings.HasPrefix(err.Error(), prefix) {
		t.Errorf("error = %q, want prefix %q", err, prefix)
	}
	if want := []string{policyCall}; !reflect.DeepEqual(calls, want) {
		t.Errorf("calls = %q, want only %q", calls, want)
	}
}

func TestEnsureRunsIptablesAfterRoutingFailure(t *testing.T) {
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		t.Skip("would change the host's routing as root")
	}

	var calls []string
	d := &Datapath{run: fakeRun(&calls)}

	err := d.Ensure(t.Context(), "10.8.0.0/24")
	if err == nil {
		t.Fatal("Ensure returned nil, want the routing failure")
	}
	if got := d.Err(); got == nil || got.Error() != err.Error() {
		t.Errorf("Err() = %v, want %v", got, err)
	}
	if len(calls) == 0 || calls[0] != policyCall {
		t.Errorf("calls = %q, want the policy call first (the iptables pass must run)", calls)
	}
}

func TestEnsureRecordsParseError(t *testing.T) {
	var calls []string
	d := &Datapath{run: fakeRun(&calls)}

	if err := d.Ensure(t.Context(), "not-a-cidr"); err == nil {
		t.Fatal("Ensure returned nil, want a parse error")
	}
	if d.Err() == nil {
		t.Error("Err() = nil, want the parse error")
	}
	if len(calls) != 0 {
		t.Errorf("calls = %q, want none", calls)
	}
}

func TestNewIsNotAssertedYet(t *testing.T) {
	err := New().Err()
	if err == nil {
		t.Fatal("New().Err() = nil, want an error before the first Ensure")
	}
	if !strings.Contains(err.Error(), "not asserted yet") {
		t.Errorf("Err() = %q, want it to contain %q", err, "not asserted yet")
	}
}
