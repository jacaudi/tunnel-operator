package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// GluetunHealthy returns nil when gluetun's health server at url answers 200, and otherwise an error
// naming the status code and the trimmed response body, or the request failure.
func GluetunHealthy(ctx context.Context, c *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("gluetun health %s: %w", url, err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("gluetun health %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("gluetun health %s: %d %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
}
