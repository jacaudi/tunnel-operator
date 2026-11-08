// Package egress is the agent's side of the egress API: a client for gluetun's control server and
// the engine that caches the exit IP and forwarded port and cycles the VPN.
package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Gluetun is a client for gluetun's control server (v3.41.x routes). HTTP has no client-wide
// timeout in production: every call is bounded by the context it is given.
type Gluetun struct {
	BaseURL string // for example http://127.0.0.1:8000, without a trailing slash
	APIKey  string
	HTTP    *http.Client
}

// PublicIP returns gluetun's public IP, or "" while it is not yet known (the tunnel is down or just
// came up).
func (g *Gluetun) PublicIP(ctx context.Context) (string, error) {
	var out struct {
		PublicIP string `json:"public_ip"`
	}
	err := g.do(ctx, http.MethodGet, "/v1/publicip/ip", nil, &out)
	return out.PublicIP, err
}

// ForwardedPort returns the VPN-side forwarded port, or 0 when none is forwarded.
func (g *Gluetun) ForwardedPort(ctx context.Context) (int32, error) {
	var out struct {
		Port int32 `json:"port"`
	}
	err := g.do(ctx, http.MethodGet, "/v1/portforward", nil, &out)
	return out.Port, err
}

// VPNStatus returns the VPN loop's status: running, stopped, starting, stopping, crashed or
// completed.
func (g *Gluetun) VPNStatus(ctx context.Context) (string, error) {
	var out struct {
		Status string `json:"status"`
	}
	err := g.do(ctx, http.MethodGet, "/v1/vpn/status", nil, &out)
	return out.Status, err
}

// SetVPNStatus asks gluetun to move the VPN loop to status, "running" or "stopped".
func (g *Gluetun) SetVPNStatus(ctx context.Context, status string) error {
	body, _ := json.Marshal(struct { // a one-string struct cannot fail to marshal
		Status string `json:"status"`
	}{status})
	return g.do(ctx, http.MethodPut, "/v1/vpn/status", body, nil)
}

// do sends the request with the API key and decodes a 2xx JSON response into out (when non-nil).
// Any other status is an error carrying the code and the start of the body.
func (g *Gluetun) do(ctx context.Context, method, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, g.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("gluetun %s %s: %w", method, path, err)
	}
	req.Header.Set("X-API-Key", g.APIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("gluetun %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("gluetun %s %s: status %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("gluetun %s %s: decode: %w", method, path, err)
	}
	return nil
}
