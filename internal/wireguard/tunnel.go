package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Tunnel represents an active WireGuard tunnel
type Tunnel struct {
	Name       string
	Device     *device.Device
	Net        *netstack.Net
	CreatedAt  time.Time
	lastUsedAt time.Time
	mu         sync.Mutex
}

// Dial creates a TCP connection through the tunnel (resolves hostname if needed)
func (t *Tunnel) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	t.mu.Lock()
	t.lastUsedAt = time.Now()
	t.mu.Unlock()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	// If host is already an IP, dial directly
	if ip := net.ParseIP(host); ip != nil {
		addrPort, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse addr port: %w", err)
		}
		return t.Net.DialContextTCPAddrPort(ctx, addrPort)
	}

	// Resolve hostname via tunnel DNS
	ips, err := t.Net.LookupContextHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", host)
	}

	addrPort, err := netip.ParseAddrPort(ips[0] + ":" + port)
	if err != nil {
		return nil, fmt.Errorf("failed to parse resolved addr: %w", err)
	}

	return t.Net.DialContextTCPAddrPort(ctx, addrPort)
}

// Close shuts down the tunnel
func (t *Tunnel) Close() error {
	if t.Device != nil {
		t.Device.Close()
	}
	return nil
}

// TunnelPool manages a pool of WireGuard tunnels with LRU eviction
type TunnelPool struct {
	maxTunnels int
	tunnels    map[int]*Tunnel // keyed by config index
	mu         sync.RWMutex
}

// NewTunnelPool creates a new tunnel pool with the specified maximum size
func NewTunnelPool(maxTunnels int) *TunnelPool {
	return &TunnelPool{
		maxTunnels: maxTunnels,
		tunnels:    make(map[int]*Tunnel),
	}
}

// GetOrCreate gets an existing tunnel or creates a new one
func (p *TunnelPool) GetOrCreate(ctx context.Context, config *Config, id int) (*Tunnel, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if tunnel, ok := p.tunnels[id]; ok {
		tunnel.mu.Lock()
		tunnel.lastUsedAt = time.Now()
		tunnel.mu.Unlock()
		return tunnel, nil
	}

	// Evict LRU if at capacity
	if len(p.tunnels) >= p.maxTunnels {
		p.evictLRU()
	}

	tunnel, err := createTunnel(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel: %w", err)
	}

	p.tunnels[id] = tunnel
	log.Printf("tunnel up: %s [%d/%d active]", config.Name, len(p.tunnels), p.maxTunnels)

	return tunnel, nil
}

// evictLRU evicts the least recently used tunnel (caller must hold write lock)
func (p *TunnelPool) evictLRU() {
	var oldest *Tunnel
	var oldestID int
	var oldestTime time.Time

	for id, tunnel := range p.tunnels {
		tunnel.mu.Lock()
		lastUsed := tunnel.lastUsedAt
		tunnel.mu.Unlock()

		if oldest == nil || lastUsed.Before(oldestTime) {
			oldest = tunnel
			oldestID = id
			oldestTime = lastUsed
		}
	}

	if oldest != nil {
		log.Printf("tunnel evicted: %s", oldest.Name)
		_ = oldest.Close()
		delete(p.tunnels, oldestID)
	}
}

// Close shuts down all tunnels
func (p *TunnelPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, tunnel := range p.tunnels {
		_ = tunnel.Close()
	}
	p.tunnels = make(map[int]*Tunnel)
	return nil
}

// resolveEndpoint resolves a hostname:port endpoint to IP:port
func resolveEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint format: %w", err)
	}

	if ip := net.ParseIP(host); ip != nil {
		return endpoint, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("failed to resolve %s: %w", host, err)
	}

	// Prefer IPv4
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return fmt.Sprintf("%s:%s", ipv4.String(), port), nil
		}
	}

	if len(ips) > 0 {
		return fmt.Sprintf("%s:%s", ips[0].String(), port), nil
	}

	return "", fmt.Errorf("no IP addresses found for %s", host)
}

// createTunnel creates a new WireGuard tunnel from a config
func createTunnel(config *Config) (*Tunnel, error) {
	addr, err := netip.ParseAddr(config.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse address %s: %w", config.Address, err)
	}

	resolvedEndpoint, err := resolveEndpoint(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve endpoint: %w", err)
	}

	var dnsAddrs []netip.Addr
	if config.DNS != "" {
		if dnsAddr, err := netip.ParseAddr(config.DNS); err == nil {
			dnsAddrs = append(dnsAddrs, dnsAddr)
		}
	}

	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, dnsAddrs, config.MTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create netstack TUN: %w", err)
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("[wg-%s] ", config.Name))
	dev := device.NewDevice(tun, conn.NewDefaultBind(), logger)

	privateKeyHex, err := base64ToHex(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	publicKeyHex, err := base64ToHex(config.PeerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	ipcConfig := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=%d",
		privateKeyHex,
		publicKeyHex,
		resolvedEndpoint,
		config.PersistentKeepalive,
	)

	if config.PresharedKey != "" {
		pskHex, err := base64ToHex(config.PresharedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode preshared key: %w", err)
		}
		ipcConfig = fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=%d",
			privateKeyHex,
			publicKeyHex,
			pskHex,
			resolvedEndpoint,
			config.PersistentKeepalive,
		)
	}

	if err := dev.IpcSet(ipcConfig); err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to configure WireGuard device: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to bring up WireGuard device: %w", err)
	}

	return &Tunnel{
		Name:       config.Name,
		Device:     dev,
		Net:        tnet,
		CreatedAt:  time.Now(),
		lastUsedAt: time.Now(),
	}, nil
}

// base64ToHex converts a base64-encoded key to hex (required by WireGuard IPC)
func base64ToHex(b64 string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}
