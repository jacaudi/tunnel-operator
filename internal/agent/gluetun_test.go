package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGluetunHealthy(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{name: "200 with an empty body", status: http.StatusOK},
		{
			name:    "500 names the status and the trimmed body",
			status:  http.StatusInternalServerError,
			body:    "tcp dial: i/o timeout\n",
			wantErr: "500 tcp dial: i/o timeout",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			err := GluetunHealthy(t.Context(), srv.Client(), srv.URL)

			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("GluetunHealthy = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("GluetunHealthy = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestGluetunHealthyFailsWhenServerIsDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url, client := srv.URL, srv.Client()
	srv.Close()

	if err := GluetunHealthy(t.Context(), client, url); err == nil {
		t.Error("GluetunHealthy = nil, want an error for a closed server")
	}
}
