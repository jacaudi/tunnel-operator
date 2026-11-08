package datapath

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

const (
	goldenNoHolder = `*nat
:TUNNEL-OP-PREROUTING - [0:0]
-F TUNNEL-OP-PREROUTING
COMMIT
*filter
:TUNNEL-OP-FORWARD - [0:0]
:TUNNEL-OP-INPUT - [0:0]
:TUNNEL-OP-OUTPUT - [0:0]
-F TUNNEL-OP-FORWARD
-F TUNNEL-OP-INPUT
-F TUNNEL-OP-OUTPUT
-A TUNNEL-OP-INPUT -i wg0 -d 10.8.0.1 -p tcp --dport 8081 -j ACCEPT
-A TUNNEL-OP-OUTPUT -o wg0 -s 10.8.0.1 -p tcp --sport 8081 -m conntrack --ctstate ESTABLISHED -j ACCEPT
COMMIT
`

	goldenWithHolder = `*nat
:TUNNEL-OP-PREROUTING - [0:0]
-F TUNNEL-OP-PREROUTING
-A TUNNEL-OP-PREROUTING -i tun0 -p tcp --dport 51413 -j DNAT --to-destination 10.8.0.2:51413
-A TUNNEL-OP-PREROUTING -i tun0 -p udp --dport 51413 -j DNAT --to-destination 10.8.0.2:51413
COMMIT
*filter
:TUNNEL-OP-FORWARD - [0:0]
:TUNNEL-OP-INPUT - [0:0]
:TUNNEL-OP-OUTPUT - [0:0]
-F TUNNEL-OP-FORWARD
-F TUNNEL-OP-INPUT
-F TUNNEL-OP-OUTPUT
-A TUNNEL-OP-FORWARD -i tun0 -o wg0 -d 10.8.0.2 -p tcp --dport 51413 -j ACCEPT
-A TUNNEL-OP-FORWARD -i tun0 -o wg0 -d 10.8.0.2 -p udp --dport 51413 -j ACCEPT
-A TUNNEL-OP-INPUT -i wg0 -d 10.8.0.1 -p tcp --dport 8081 -j ACCEPT
-A TUNNEL-OP-OUTPUT -o wg0 -s 10.8.0.1 -p tcp --sport 8081 -m conntrack --ctstate ESTABLISHED -j ACCEPT
COMMIT
`
)

var (
	tunnelAddr = netip.MustParseAddr("10.8.0.1")
	holderAddr = netip.MustParseAddr("10.8.0.2")
)

// fakeRunErrs returns a run func that records each argv joined by spaces and returns errs[call] for a
// call it has an entry for.
func fakeRunErrs(calls *[]string, errs map[string]error) func(ctx context.Context, args ...string) error {
	return func(_ context.Context, args ...string) error {
		call := strings.Join(args, " ")
		*calls = append(*calls, call)
		return errs[call]
	}
}

// fakeRestore returns a restore func that records each input and returns err.
func fakeRestore(inputs *[]string, err error) func(ctx context.Context, input []byte) error {
	return func(_ context.Context, input []byte) error {
		*inputs = append(*inputs, string(input))
		return err
	}
}

var (
	errExitOne     = errors.New("exit status 1")
	errChainExists = fmt.Errorf("%w: %s", errExitOne, "iptables: Chain already exists.") // the shape runIptables returns
	chainCalls     = []string{
		"-w 5 -t nat -N TUNNEL-OP-PREROUTING",
		"-w 5 -t filter -N TUNNEL-OP-FORWARD",
		"-w 5 -t filter -N TUNNEL-OP-INPUT",
		"-w 5 -t filter -N TUNNEL-OP-OUTPUT",
	}
	jumpChecks = []string{
		"-w 5 -t nat -C PREROUTING -j TUNNEL-OP-PREROUTING",
		"-w 5 -t filter -C FORWARD -j TUNNEL-OP-FORWARD",
		"-w 5 -t filter -C INPUT -j TUNNEL-OP-INPUT",
		"-w 5 -t filter -C OUTPUT -j TUNNEL-OP-OUTPUT",
	}
	jumpInserts = []string{
		"-w 5 -t nat -I PREROUTING 1 -j TUNNEL-OP-PREROUTING",
		"-w 5 -t filter -I FORWARD 1 -j TUNNEL-OP-FORWARD",
		"-w 5 -t filter -I INPUT 1 -j TUNNEL-OP-INPUT",
		"-w 5 -t filter -I OUTPUT 1 -j TUNNEL-OP-OUTPUT",
	}
)

func TestEgressRestoreInputNoHolder(t *testing.T) {
	tests := []struct {
		name string
		r    EgressRules
	}{
		{"zero holder and port", EgressRules{TunnelAddr: tunnelAddr}},
		{"port without holder", EgressRules{TunnelAddr: tunnelAddr, Port: 51413}},
		{"holder without port", EgressRules{TunnelAddr: tunnelAddr, Holder: holderAddr}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(egressRestoreInput(tt.r)); got != goldenNoHolder {
				t.Errorf("egressRestoreInput =\n%s\nwant\n%s", got, goldenNoHolder)
			}
		})
	}
}

func TestEgressRestoreInputWithHolder(t *testing.T) {
	r := EgressRules{TunnelAddr: tunnelAddr, Holder: holderAddr, Port: 51413}
	if got := string(egressRestoreInput(r)); got != goldenWithHolder {
		t.Errorf("egressRestoreInput =\n%s\nwant\n%s", got, goldenWithHolder)
	}
}

func TestEgressRestoreInputNeverTouchesBuiltins(t *testing.T) {
	builtins := []string{"INPUT", "FORWARD", "OUTPUT", "PREROUTING"}
	for _, r := range []EgressRules{
		{TunnelAddr: tunnelAddr},
		{TunnelAddr: tunnelAddr, Holder: holderAddr, Port: 51413},
	} {
		for line := range strings.SplitSeq(string(egressRestoreInput(r)), "\n") {
			for _, b := range builtins {
				if strings.HasPrefix(line, ":"+b) {
					t.Errorf("%+v: line %q declares built-in chain %s", r, line, b)
				}
				if f := strings.Fields(line); len(f) >= 2 && f[0] == "-F" && f[1] == b {
					t.Errorf("%+v: line %q flushes built-in chain %s", r, line, b)
				}
			}
		}
	}
}

func TestEnsureEgressCreatesChainsAndJumps(t *testing.T) {
	var calls, inputs []string
	d := &Datapath{
		run:     fakeRunErrs(&calls, map[string]error{jumpChecks[0]: errExitOne, jumpChecks[1]: errExitOne, jumpChecks[2]: errExitOne, jumpChecks[3]: errExitOne}),
		restore: fakeRestore(&inputs, nil),
	}
	r := EgressRules{TunnelAddr: tunnelAddr, Holder: holderAddr, Port: 51413}

	if err := d.EnsureEgress(t.Context(), r); err != nil {
		t.Fatalf("EnsureEgress: %v", err)
	}

	want := append([]string(nil), chainCalls...)
	for i := range jumpChecks {
		want = append(want, jumpChecks[i], jumpInserts[i])
	}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("calls = %q, want %q", calls, want)
	}
	if wantInputs := []string{goldenWithHolder}; !reflect.DeepEqual(inputs, wantInputs) {
		t.Errorf("restore inputs = %q, want %q", inputs, wantInputs)
	}
}

func TestEnsureEgressSkipsPresentJumps(t *testing.T) {
	var calls, inputs []string
	d := &Datapath{run: fakeRunErrs(&calls, nil), restore: fakeRestore(&inputs, nil)}

	if err := d.EnsureEgress(t.Context(), EgressRules{TunnelAddr: tunnelAddr}); err != nil {
		t.Fatalf("EnsureEgress: %v", err)
	}

	want := append([]string(nil), chainCalls...)
	want = append(want, jumpChecks...)
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("calls = %q, want %q", calls, want)
	}
	if len(inputs) != 1 {
		t.Errorf("restore called %d times, want 1", len(inputs))
	}
}

func TestEnsureEgressChainExistsIsNotError(t *testing.T) {
	var calls, inputs []string
	errs := map[string]error{}
	for _, c := range chainCalls {
		errs[c] = errChainExists
	}
	d := &Datapath{run: fakeRunErrs(&calls, errs), restore: fakeRestore(&inputs, nil)}

	if err := d.EnsureEgress(t.Context(), EgressRules{TunnelAddr: tunnelAddr}); err != nil {
		t.Fatalf("EnsureEgress: %v", err)
	}
	if d.Err() != nil {
		t.Errorf("Err() = %v, want nil", d.Err())
	}
	if len(inputs) != 1 {
		t.Errorf("restore called %d times, want 1", len(inputs))
	}
}

func TestEnsureEgressStepFailureSkipsRestore(t *testing.T) {
	tests := []struct {
		name   string
		failed string
		err    error
		prefix string
	}{
		{"chain create", chainCalls[1], errExitOne, "iptables -t filter -N TUNNEL-OP-FORWARD: "},
		{"jump insert", jumpInserts[2], errExitOne, "iptables -t filter -I INPUT 1 -j TUNNEL-OP-INPUT: "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls, inputs []string
			errs := map[string]error{tt.failed: tt.err, jumpChecks[2]: errExitOne}
			d := &Datapath{run: fakeRunErrs(&calls, errs), restore: fakeRestore(&inputs, nil)}

			err := d.EnsureEgress(t.Context(), EgressRules{TunnelAddr: tunnelAddr})
			if err == nil {
				t.Fatal("EnsureEgress returned nil, want the step failure")
			}
			if !strings.HasPrefix(err.Error(), tt.prefix) {
				t.Errorf("error = %q, want prefix %q", err, tt.prefix)
			}
			if len(inputs) != 0 {
				t.Errorf("restore called %d times, want 0", len(inputs))
			}
			if d.Err() == nil {
				t.Error("Err() = nil, want the step failure")
			}
		})
	}
}

func TestEnsureEgressRecordsRestoreFailure(t *testing.T) {
	var calls, inputs []string
	d := &Datapath{run: fakeRunErrs(&calls, nil), restore: fakeRestore(&inputs, errors.New("restore broke"))}

	err := d.EnsureEgress(t.Context(), EgressRules{TunnelAddr: tunnelAddr})
	if err == nil {
		t.Fatal("EnsureEgress returned nil, want the restore failure")
	}
	if !strings.Contains(err.Error(), "restore broke") {
		t.Errorf("error = %q, want it to contain %q", err, "restore broke")
	}
	if d.Err() == nil {
		t.Error("Err() = nil, want the restore failure")
	}
}

func TestEnsureEgressRecoversAfterSuccess(t *testing.T) {
	var calls, inputs []string
	restoreErr := errors.New("restore broke")
	d := &Datapath{
		run: fakeRunErrs(&calls, nil),
		restore: func(_ context.Context, input []byte) error {
			inputs = append(inputs, string(input))
			return restoreErr
		},
	}
	r := EgressRules{TunnelAddr: tunnelAddr}

	if err := d.EnsureEgress(t.Context(), r); err == nil {
		t.Fatal("first EnsureEgress returned nil, want the restore failure")
	}
	restoreErr = nil
	if err := d.EnsureEgress(t.Context(), r); err != nil {
		t.Fatalf("second EnsureEgress: %v", err)
	}
	if d.Err() != nil {
		t.Errorf("Err() = %v, want nil after a successful EnsureEgress", d.Err())
	}
}

func TestEnsureEgressRejectsInvalidTunnelAddr(t *testing.T) {
	var calls, inputs []string
	d := &Datapath{run: fakeRunErrs(&calls, nil), restore: fakeRestore(&inputs, nil)}

	if err := d.EnsureEgress(t.Context(), EgressRules{Holder: holderAddr, Port: 51413}); err == nil {
		t.Fatal("EnsureEgress returned nil, want an error for the invalid tunnel address")
	}
	if len(calls) != 0 || len(inputs) != 0 {
		t.Errorf("calls = %q, restore inputs = %q, want none", calls, inputs)
	}
	if d.Err() == nil {
		t.Error("Err() = nil, want the invalid tunnel address error")
	}
}

func TestErrCombinesEnsureAndEgress(t *testing.T) {
	var calls, inputs []string
	ok := &Datapath{run: fakeRunErrs(&calls, nil), restore: fakeRestore(&inputs, nil)}
	bad := &Datapath{run: fakeRunErrs(&calls, nil), restore: fakeRestore(&inputs, errors.New("restore broke"))}
	r := EgressRules{TunnelAddr: tunnelAddr}
	ensureErr := errors.New("ensure broke")

	tests := []struct {
		name      string
		d         *Datapath
		ensureErr error
		wantErr   bool
	}{
		{"ensure ok, egress fails", bad, nil, true},
		{"egress ok, ensure fails", ok, ensureErr, true},
		{"both ok", ok, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.d.record(tt.ensureErr)
			_ = tt.d.EnsureEgress(t.Context(), r) // outcome is read back through Err
			if got := tt.d.Err(); (got != nil) != tt.wantErr {
				t.Errorf("Err() = %v, want error: %t", got, tt.wantErr)
			}
		})
	}
}
