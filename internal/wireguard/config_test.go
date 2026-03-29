package wireguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractIPv4Address(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"10.128.0.1/32", "10.128.0.1"},
		{"192.168.1.1/24", "192.168.1.1"},
		{"10.0.0.1", "10.0.0.1"},
		{"", ""},
		{"invalid", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractIPv4Address(tt.input)
			if got != tt.want {
				t.Errorf("extractIPv4Address(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseConfigFile(t *testing.T) {
	content := `[Interface]
Address = 10.128.0.1/32
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
MTU = 1320
DNS = 10.128.0.1

[Peer]
PublicKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
PresharedKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Endpoint = vpn.example.com:1637
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 15
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.conf")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := ParseConfigFile(configPath)
	if err != nil {
		t.Fatalf("ParseConfigFile failed: %v", err)
	}

	if cfg.Name != "test.conf" {
		t.Errorf("Name = %q, want %q", cfg.Name, "test.conf")
	}
	if cfg.Address != "10.128.0.1" {
		t.Errorf("Address = %q, want %q", cfg.Address, "10.128.0.1")
	}
	if cfg.MTU != 1320 {
		t.Errorf("MTU = %d, want %d", cfg.MTU, 1320)
	}
	if cfg.DNS != "10.128.0.1" {
		t.Errorf("DNS = %q, want %q", cfg.DNS, "10.128.0.1")
	}
	if cfg.Endpoint != "vpn.example.com:1637" {
		t.Errorf("Endpoint = %q, want %q", cfg.Endpoint, "vpn.example.com:1637")
	}
	if cfg.PersistentKeepalive != 15 {
		t.Errorf("PersistentKeepalive = %d, want %d", cfg.PersistentKeepalive, 15)
	}
}

func TestParseConfigFileMissingFields(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"missing PrivateKey", "[Interface]\nAddress = 10.0.0.1/32\n[Peer]\nPublicKey = YWJj\nEndpoint = 1.2.3.4:51820\n"},
		{"missing PublicKey", "[Interface]\nAddress = 10.0.0.1/32\nPrivateKey = YWJj\n[Peer]\nEndpoint = 1.2.3.4:51820\n"},
		{"missing Endpoint", "[Interface]\nAddress = 10.0.0.1/32\nPrivateKey = YWJj\n[Peer]\nPublicKey = YWJj\n"},
		{"missing Address", "[Interface]\nPrivateKey = YWJj\n[Peer]\nPublicKey = YWJj\nEndpoint = 1.2.3.4:51820\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, "test.conf")
			os.WriteFile(path, []byte(tt.content), 0644)

			_, err := ParseConfigFile(path)
			if err == nil {
				t.Error("Expected error, got nil")
			}
		})
	}
}

