package wireguard

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config represents a parsed WireGuard configuration
type Config struct {
	Name string // Filename

	// Interface section
	Address    string
	PrivateKey string
	MTU        int
	DNS        string

	// Peer section
	PeerPublicKey       string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          string
	PersistentKeepalive int
}

// ParseConfigFile parses a WireGuard .conf file
func ParseConfigFile(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config: %w", err)
	}
	defer func() { _ = file.Close() }()

	config := &Config{
		Name:                filepath.Base(path),
		MTU:                 1320,
		AllowedIPs:          "0.0.0.0/0",
		PersistentKeepalive: 15,
	}

	scanner := bufio.NewScanner(file)
	section := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "[Interface]" {
			section = "interface"
			continue
		}
		if line == "[Peer]" {
			section = "peer"
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch section {
		case "interface":
			switch key {
			case "Address":
				config.Address = extractIPv4Address(value)
			case "PrivateKey":
				config.PrivateKey = value
			case "MTU":
				_, _ = fmt.Sscanf(value, "%d", &config.MTU)
			case "DNS":
				config.DNS = extractIPv4Address(value)
			}
		case "peer":
			switch key {
			case "PublicKey":
				config.PeerPublicKey = value
			case "PresharedKey":
				config.PresharedKey = value
			case "Endpoint":
				config.Endpoint = value
			case "AllowedIPs":
				config.AllowedIPs = value
			case "PersistentKeepalive":
				_, _ = fmt.Sscanf(value, "%d", &config.PersistentKeepalive)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}

	if config.PrivateKey == "" {
		return nil, fmt.Errorf("missing PrivateKey")
	}
	if config.PeerPublicKey == "" {
		return nil, fmt.Errorf("missing peer PublicKey")
	}
	if config.Endpoint == "" {
		return nil, fmt.Errorf("missing peer Endpoint")
	}
	if config.Address == "" {
		return nil, fmt.Errorf("missing interface Address (only IPv4 addresses are supported)")
	}

	return config, nil
}

// extractIPv4Address extracts the first IPv4 address from a comma-separated list
// e.g., "10.180.24.70/32,fd7d:76ee:..." -> "10.180.24.70"
func extractIPv4Address(value string) string {
	parts := strings.Split(value, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, "/"); idx > 0 {
			part = part[:idx]
		}
		if strings.Contains(part, ".") && !strings.Contains(part, ":") {
			return part
		}
	}
	return ""
}
