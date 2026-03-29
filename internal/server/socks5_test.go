package server

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/meanie-py/wgsocks/internal/wireguard"
)

// mockConn implements net.Conn for testing sendReply and parseAddress
type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
}

func newMockConn() *mockConn {
	return &mockConn{
		readBuf:  new(bytes.Buffer),
		writeBuf: new(bytes.Buffer),
	}
}

func (m *mockConn) Read(b []byte) (int, error)         { return m.readBuf.Read(b) }
func (m *mockConn) Write(b []byte) (int, error)        { return m.writeBuf.Write(b) }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestSendReply(t *testing.T) {
	tests := []struct {
		status byte
	}{
		{socks5RepSuccess},
		{socks5RepHostUnreach},
		{socks5RepCmdNotSupport},
		{socks5RepAddrNotSupport},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("0x%02x", tt.status), func(t *testing.T) {
			conn := newMockConn()
			s := &Server{}
			s.sendReply(conn, tt.status)

			reply := conn.writeBuf.Bytes()
			if len(reply) != 10 {
				t.Fatalf("reply length = %d, want 10", len(reply))
			}
			if reply[0] != socks5Version {
				t.Errorf("version = 0x%02x, want 0x%02x", reply[0], socks5Version)
			}
			if reply[1] != tt.status {
				t.Errorf("status = 0x%02x, want 0x%02x", reply[1], tt.status)
			}
			if reply[3] != socks5AtypIPv4 {
				t.Errorf("atyp = 0x%02x, want 0x%02x", reply[3], socks5AtypIPv4)
			}
		})
	}
}

func TestParseAddressIPv4(t *testing.T) {
	s := &Server{}
	buf := []byte{0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50}
	addr, err := s.parseAddress(buf, len(buf))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "192.168.1.1:80" {
		t.Errorf("addr = %q, want %q", addr, "192.168.1.1:80")
	}
}

func TestParseAddressDomain(t *testing.T) {
	s := &Server{}
	domain := "example.com"
	buf := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	buf = append(buf, []byte(domain)...)
	buf = append(buf, 0x01, 0xBB) // port 443
	addr, err := s.parseAddress(buf, len(buf))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "example.com:443" {
		t.Errorf("addr = %q, want %q", addr, "example.com:443")
	}
}

func TestParseAddressIPv6(t *testing.T) {
	s := &Server{}
	buf := []byte{0x05, 0x01, 0x00, 0x04}
	// ::1
	ipv6 := net.ParseIP("::1")
	buf = append(buf, ipv6.To16()...)
	buf = append(buf, 0x1F, 0x90) // port 8080
	addr, err := s.parseAddress(buf, len(buf))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "[::1]:8080" {
		t.Errorf("addr = %q, want %q", addr, "[::1]:8080")
	}
}

func TestParseAddressTooShort(t *testing.T) {
	s := &Server{}
	tests := []struct {
		name string
		buf  []byte
		n    int
	}{
		{"ipv4 short", []byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3}, 7},
		{"ipv6 short", []byte{0x05, 0x01, 0x00, 0x04, 1, 2, 3}, 7},
		{"domain short", []byte{0x05, 0x01, 0x00, 0x03, 5, 'a', 'b'}, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.parseAddress(tt.buf, tt.n)
			if err == nil {
				t.Error("expected error for truncated address")
			}
		})
	}
}

func TestParseAddressUnsupportedType(t *testing.T) {
	s := &Server{}
	buf := []byte{0x05, 0x01, 0x00, 0xFF, 0, 0, 0, 0, 0, 0}
	_, err := s.parseAddress(buf, len(buf))
	if err == nil {
		t.Error("expected error for unsupported address type")
	}
}

func TestNewServer(t *testing.T) {
	configs := []*wireguard.Config{
		{Name: "a.conf"},
		{Name: "b.conf"},
	}
	srv := NewServer(":0", configs, 3, 2)
	if srv.listenAddr != ":0" {
		t.Errorf("listenAddr = %q, want %q", srv.listenAddr, ":0")
	}
	if len(srv.configs) != 2 {
		t.Errorf("configs len = %d, want 2", len(srv.configs))
	}
	if srv.maxFailover != 2 {
		t.Errorf("maxFailover = %d, want 2", srv.maxFailover)
	}
}

func TestCloseBeforeRun(t *testing.T) {
	srv := NewServer(":0", nil, 1, 1)
	if err := srv.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}

// TestSOCKS5Handshake exercises the real TCP listener with a SOCKS5 no-auth greeting.
// The server has no WireGuard configs so the CONNECT will fail, but the handshake should work.
func TestSOCKS5Handshake(t *testing.T) {
	configs := []*wireguard.Config{{Name: "dummy.conf"}}
	srv := NewServer("127.0.0.1:0", configs, 1, 0)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = ln

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()
	defer func() { _ = srv.Close() }()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// SOCKS5 greeting: version 5, 1 method (no-auth)
	conn.Write([]byte{0x05, 0x01, 0x00})

	resp := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err = conn.Read(resp)
	if err != nil {
		t.Fatalf("read greeting response: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Errorf("greeting response = %v, want [0x05 0x00]", resp)
	}

	// Send CONNECT to 93.184.216.34:80 (example.com)
	conn.Write([]byte{
		0x05, 0x01, 0x00, 0x01, // ver, connect, rsv, ipv4
		93, 184, 216, 34,       // IP
		0x00, 0x50,             // port 80
	})

	// Server will try the dummy WireGuard config, fail, and return host unreachable
	reply := make([]byte, 10)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(reply)
	if err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if reply[0] != 0x05 {
		t.Errorf("reply version = 0x%02x, want 0x05", reply[0])
	}
	// Should be host unreachable since dummy config can't create a real tunnel
	if reply[1] != socks5RepHostUnreach {
		t.Errorf("reply status = 0x%02x, want 0x%02x (host unreachable)", reply[1], socks5RepHostUnreach)
	}
}

func TestSOCKS5BadVersion(t *testing.T) {
	srv := NewServer("127.0.0.1:0", nil, 1, 0)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = ln

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()
	defer func() { _ = srv.Close() }()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send wrong SOCKS version
	conn.Write([]byte{0x04, 0x01, 0x00})

	// Server should close the connection without responding
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 10)
	n, _ := conn.Read(buf)
	if n != 0 {
		t.Errorf("expected no response for bad version, got %d bytes", n)
	}
}

func TestRoundRobin(t *testing.T) {
	configs := []*wireguard.Config{
		{Name: "a.conf"},
		{Name: "b.conf"},
		{Name: "c.conf"},
	}
	srv := NewServer(":0", configs, 1, 0)

	// Simulate the round-robin counter
	for i := 0; i < 9; i++ {
		idx := int(srv.next.Add(1)-1) % len(configs)
		expected := i % 3
		if idx != expected {
			t.Errorf("iteration %d: idx = %d, want %d", i, idx, expected)
		}
	}
}
