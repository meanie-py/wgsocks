package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/meanie-py/wgsocks/internal/wireguard"
)

// SOCKS5 constants
const (
	socks5Version           = 0x05
	socks5AuthNone          = 0x00
	socks5CmdConnect        = 0x01
	socks5AtypIPv4          = 0x01
	socks5AtypDomain        = 0x03
	socks5AtypIPv6          = 0x04
	socks5RepSuccess        = 0x00
	socks5RepServerFailure  = 0x01
	socks5RepHostUnreach    = 0x04
	socks5RepCmdNotSupport  = 0x07
	socks5RepAddrNotSupport = 0x08
)

// Server is the SOCKS5 proxy server backed by WireGuard tunnels
type Server struct {
	listenAddr  string
	configs     []*wireguard.Config
	tunnelPool  *wireguard.TunnelPool
	maxFailover int
	listener    net.Listener
	next        atomic.Uint64 // round-robin counter
}

// NewServer creates a new SOCKS5 server
func NewServer(listenAddr string, configs []*wireguard.Config, maxTunnels, maxFailover int) *Server {
	return &Server{
		listenAddr:  listenAddr,
		configs:     configs,
		tunnelPool:  wireguard.NewTunnelPool(maxTunnels),
		maxFailover: maxFailover,
	}
}

// Close shuts down the server and all tunnels
func (s *Server) Close() error {
	if s.listener != nil {
		_ = s.listener.Close()
	}
	return s.tunnelPool.Close()
}

// Run starts the SOCKS5 server
func (s *Server) Run() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.listenAddr, err)
	}
	s.listener = listener
	defer func() { _ = listener.Close() }()

	log.Printf("SOCKS5 server listening on %s (%d WireGuard configs loaded)", s.listenAddr, len(s.configs))

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("Accept error: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single SOCKS5 connection
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// SOCKS5 greeting
	buf := make([]byte, 258)
	n, err := io.ReadAtLeast(conn, buf, 3)
	if err != nil || buf[0] != socks5Version {
		return
	}
	nmethods := int(buf[1])
	if n < 2+nmethods {
		return
	}

	// No-auth only
	conn.Write([]byte{socks5Version, socks5AuthNone})

	// Read SOCKS5 CONNECT request
	n, err = io.ReadAtLeast(conn, buf, 7)
	if err != nil || buf[0] != socks5Version || buf[1] != socks5CmdConnect {
		s.sendReply(conn, socks5RepCmdNotSupport)
		return
	}

	target, err := s.parseAddress(buf, n)
	if err != nil {
		s.sendReply(conn, socks5RepAddrNotSupport)
		return
	}

	log.Printf("CONNECT %s -> %s", conn.RemoteAddr(), target)

	// Clear handshake deadline before relay
	conn.SetDeadline(time.Time{})

	// Round-robin with failover
	ctx := context.Background()
	start := int(s.next.Add(1) - 1)
	maxAttempts := s.maxFailover + 1
	if maxAttempts > len(s.configs) {
		maxAttempts = len(s.configs)
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		idx := (start + attempt) % len(s.configs)
		cfg := s.configs[idx]

		tunnel, err := s.tunnelPool.GetOrCreate(ctx, cfg, idx)
		if err != nil {
			lastErr = err
			log.Printf("Failed to create tunnel %s: %v", cfg.Name, err)
			continue
		}

		upstreamConn, err := tunnel.DialTCP(ctx, target)
		if err != nil {
			lastErr = err
			log.Printf("Failed to dial via %s: %v", cfg.Name, err)
			continue
		}

		log.Printf("Connected via %s to %s", cfg.Name, target)
		s.sendReply(conn, socks5RepSuccess)
		s.relay(conn, upstreamConn)
		return
	}

	if lastErr != nil {
		log.Printf("All attempts exhausted for %s: %v", target, lastErr)
	}
	s.sendReply(conn, socks5RepHostUnreach)
}

// parseAddress extracts the target address from a SOCKS5 request
func (s *Server) parseAddress(buf []byte, n int) (string, error) {
	addrType := buf[3]
	var host string
	var port uint16

	switch addrType {
	case socks5AtypIPv4:
		if n < 10 {
			return "", fmt.Errorf("too short for IPv4")
		}
		host = net.IP(buf[4:8]).String()
		port = uint16(buf[8])<<8 | uint16(buf[9])

	case socks5AtypDomain:
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return "", fmt.Errorf("too short for domain")
		}
		host = string(buf[5 : 5+domainLen])
		port = uint16(buf[5+domainLen])<<8 | uint16(buf[6+domainLen])

	case socks5AtypIPv6:
		if n < 22 {
			return "", fmt.Errorf("too short for IPv6")
		}
		host = net.IP(buf[4:20]).String()
		port = uint16(buf[20])<<8 | uint16(buf[21])

	default:
		return "", fmt.Errorf("unsupported address type: %d", addrType)
	}

	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

// sendReply sends a SOCKS5 reply
func (s *Server) sendReply(conn net.Conn, status byte) {
	reply := []byte{
		socks5Version, status, 0x00, socks5AtypIPv4,
		0, 0, 0, 0,
		0, 0,
	}
	conn.Write(reply)
}

// relay copies data bidirectionally between client and upstream
func (s *Server) relay(client, upstream net.Conn) {
	defer func() { _ = upstream.Close() }()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, client)
		if tc, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		if tc, ok := client.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}
