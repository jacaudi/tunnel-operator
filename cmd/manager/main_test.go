package main

import "testing"

func TestOperatorNamespace(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		want    string
		wantErr bool
	}{
		{name: "set", env: "network", want: "network"},
		{name: "empty", env: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", tt.env)
			got, err := operatorNamespace()
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("operatorNamespace() = %q, %v, want %q, error=%v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}
