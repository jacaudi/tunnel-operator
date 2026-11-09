package egress

import (
	"context"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/jacaudi/tunnel-operator/internal/resources"
)

const apiKey = "s3cret"

// gluetunCalls drives each client method through one signature, so a table can cover all four.
var gluetunCalls = []struct {
	name string
	call func(context.Context, *Gluetun) (any, error)
}{
	{"PublicIP", func(ctx context.Context, g *Gluetun) (any, error) { return g.PublicIP(ctx) }},
	{"ForwardedPort", func(ctx context.Context, g *Gluetun) (any, error) { return g.ForwardedPort(ctx) }},
	{"VPNStatus", func(ctx context.Context, g *Gluetun) (any, error) { return g.VPNStatus(ctx) }},
	{"SetVPNStatus", func(ctx context.Context, g *Gluetun) (any, error) { return nil, g.SetVPNStatus(ctx, "running") }},
}

func newGluetunClient(t *testing.T, h http.Handler) *Gluetun {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Gluetun{BaseURL: srv.URL, APIKey: apiKey, HTTP: srv.Client()}
}

func TestGluetunSendsAPIKey(t *testing.T) {
	for _, c := range gluetunCalls {
		t.Run(c.name, func(t *testing.T) {
			var got string
			g := newGluetunClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Get("X-API-Key")
				_, _ = w.Write([]byte(`{}`))
			}))

			if _, err := c.call(t.Context(), g); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}

			if got != apiKey {
				t.Errorf("X-API-Key = %q, want %q", got, apiKey)
			}
		})
	}
}

func TestGluetunNon2xxIsError(t *testing.T) {
	for _, c := range gluetunCalls {
		t.Run(c.name, func(t *testing.T) {
			g := newGluetunClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			}))

			_, err := c.call(t.Context(), g)

			if err == nil || !strings.Contains(err.Error(), "401") {
				t.Errorf("%s = %v, want an error carrying the 401 status", c.name, err)
			}
		})
	}
}

func TestGluetunRoutes(t *testing.T) {
	tests := []struct {
		name     string
		call     int // index into gluetunCalls
		method   string
		path     string
		wantBody string
		response string
		want     any
	}{
		{name: "public ip", call: 0, method: http.MethodGet, path: "/v1/publicip/ip", response: `{"public_ip":"2.2.2.2","country":"x"}`, want: "2.2.2.2"},
		{name: "forwarded port", call: 1, method: http.MethodGet, path: "/v1/portforward", response: `{"port":5914,"ports":[5914]}`, want: int32(5914)},
		{name: "no forwarded port", call: 1, method: http.MethodGet, path: "/v1/portforward", response: `{"port":0,"ports":null}`, want: int32(0)},
		{name: "vpn status", call: 2, method: http.MethodGet, path: "/v1/vpn/status", response: `{"status":"stopped"}`, want: "stopped"},
		{name: "set vpn status", call: 3, method: http.MethodPut, path: "/v1/vpn/status", wantBody: `{"status":"running"}`, response: `{"outcome":"running"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotMethod, gotPath, gotBody string
			g := newGluetunClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				gotMethod, gotPath, gotBody = r.Method, r.URL.Path, strings.TrimSpace(string(b))
				_, _ = w.Write([]byte(tt.response))
			}))

			got, err := gluetunCalls[tt.call].call(t.Context(), g)

			if err != nil {
				t.Fatalf("call: %v", err)
			}
			if got != tt.want {
				t.Errorf("result = %v, want %v", got, tt.want)
			}
			if gotMethod != tt.method || gotPath != tt.path || gotBody != tt.wantBody {
				t.Errorf("request = %s %s %q, want %s %s %q", gotMethod, gotPath, gotBody, tt.method, tt.path, tt.wantBody)
			}
		})
	}
}

func TestPublicIPEmptyIsEmptyString(t *testing.T) {
	g := newGluetunClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"public_ip":""}`))
	}))

	got, err := g.PublicIP(t.Context())

	if err != nil {
		t.Fatalf("PublicIP: %v", err)
	}
	if got != "" {
		t.Errorf("PublicIP = %q, want the empty string (not yet known)", got)
	}
}

// The operator renders gluetun's roles file from resources.GluetunAuthTOML; a route the client calls
// but the role does not name returns 401 from gluetun, and a route the role names but nothing calls
// is access the agent does not need. The two must list the same method and path pairs.
func TestGluetunClientCallsExactlyTheRoutesTheRoleGrants(t *testing.T) {
	// gluetunCalls is kept by hand, so a client method added without a row would go uncompared.
	if n := reflect.TypeFor[*Gluetun]().NumMethod(); n != len(gluetunCalls) {
		t.Fatalf("*Gluetun has %d exported methods but gluetunCalls lists %d; add the new method to gluetunCalls", n, len(gluetunCalls))
	}
	called := map[string]bool{}
	g := newGluetunClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called[r.Method+" "+r.URL.Path] = true
		_, _ = w.Write([]byte(`{}`))
	}))
	for _, c := range gluetunCalls {
		if _, err := c.call(t.Context(), g); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
	}

	line := regexp.MustCompile(`(?m)^routes = \[(.*)\]$`).FindSubmatch(resources.GluetunAuthTOML("k"))
	if line == nil {
		t.Fatal("GluetunAuthTOML has no routes line")
	}
	granted := map[string]bool{}
	for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllSubmatch(line[1], -1) {
		granted[string(m[1])] = true
	}

	if !maps.Equal(called, granted) {
		t.Errorf("client calls %v, role grants %v; want the same set", slices.Sorted(maps.Keys(called)), slices.Sorted(maps.Keys(granted)))
	}
}
