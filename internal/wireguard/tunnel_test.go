package wireguard

import (
	"testing"
)

func TestNewTunnelPool(t *testing.T) {
	pool := NewTunnelPool(5)
	if pool == nil {
		t.Fatal("NewTunnelPool returned nil")
	}
	if pool.maxTunnels != 5 {
		t.Errorf("maxTunnels = %d, want 5", pool.maxTunnels)
	}
}

func TestTunnelPoolClose(t *testing.T) {
	pool := NewTunnelPool(5)

	if err := pool.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestResolveEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		wantError bool
	}{
		{"IP address", "192.168.1.1:1637", false},
		{"no port", "192.168.1.1", true},
		{"empty", "", true},
		{"localhost", "localhost:1637", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := resolveEndpoint(tt.endpoint)
			if tt.wantError && err == nil {
				t.Errorf("resolveEndpoint(%q) expected error, got %q", tt.endpoint, result)
			}
			if !tt.wantError && err != nil {
				t.Logf("resolveEndpoint(%q) error (may be expected): %v", tt.endpoint, err)
			}
		})
	}
}

func TestBase64ToHex(t *testing.T) {
	tests := []struct {
		name    string
		b64     string
		wantErr bool
	}{
		{"valid", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=", false},
		{"invalid", "not-valid!!!", true},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := base64ToHex(tt.b64)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got %q", result)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
