package main

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/tls"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

type smokeObfsPacketConn struct {
	base   *net.UDPConn
	remote *net.UDPAddr
	aead   cipher.AEAD
	cfg    *ObfsConfig
	state  *ObfsState
	txMu   sync.Mutex
	rxMu   sync.Mutex
}

func (c *smokeObfsPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.rxMu.Lock()
	defer c.rxMu.Unlock()
	wire := make([]byte, 4096)
	for {
		n, addr, err := c.base.ReadFromUDP(wire)
		if err != nil {
			return 0, addr, err
		}
		if !obfsIsRTPPacket(wire[:n]) {
			continue
		}
		plainLen, err := obfsUnwrapPacketAEAD(c.aead, wire[:n], p)
		if err != nil {
			continue
		}
		return plainLen, addr, nil
	}
}

func (c *smokeObfsPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.txMu.Lock()
	defer c.txMu.Unlock()
	wire := make([]byte, obfsWrapWireLen(len(p), c.cfg))
	n, err := obfsWrapPacketInto(wire, c.aead, p, c.cfg, c.state)
	if err != nil {
		return 0, err
	}
	if _, err := c.base.WriteToUDP(wire[:n], c.remote); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *smokeObfsPacketConn) Close() error                     { return c.base.Close() }
func (c *smokeObfsPacketConn) LocalAddr() net.Addr              { return c.base.LocalAddr() }
func (c *smokeObfsPacketConn) SetDeadline(t time.Time) error      { return c.base.SetDeadline(t) }
func (c *smokeObfsPacketConn) SetReadDeadline(t time.Time) error  { return c.base.SetReadDeadline(t) }
func (c *smokeObfsPacketConn) SetWriteDeadline(t time.Time) error { return c.base.SetWriteDeadline(t) }

func openSmokeDTLS(t *testing.T, serverAddr, wrapPassword string) *dtls.Conn {
	t.Helper()
	remote, err := net.ResolveUDPAddr("udp4", serverAddr)
	if err != nil {
		t.Fatalf("resolve server: %v", err)
	}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	key, err := deriveWrapKey(wrapPassword)
	if err != nil {
		udpConn.Close()
		t.Fatalf("derive WRAP key: %v", err)
	}
	aead, err := getAEAD(key)
	if err != nil {
		udpConn.Close()
		t.Fatalf("create WRAP AEAD: %v", err)
	}
	transport := &smokeObfsPacketConn{
		base:   udpConn,
		remote: remote,
		aead:   aead,
		cfg:    NewObfsConfig(),
		state:  NewObfsState(),
	}
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		transport.Close()
		t.Fatalf("generate DTLS certificate: %v", err)
	}
	conn, err := dtls.Client(transport, remote, &dtls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	})
	if err != nil {
		transport.Close()
		t.Fatalf("create DTLS client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		t.Fatalf("DTLS handshake: %v", err)
	}
	return conn
}

func TestRunningServerProtocol(t *testing.T) {
	serverAddr := os.Getenv("WDTT_SMOKE_ADDR")
	if serverAddr == "" {
		t.Skip("set WDTT_SMOKE_ADDR to run the external server smoke test")
	}
	password := os.Getenv("WDTT_SMOKE_PASSWORD")
	if password == "" {
		t.Fatal("WDTT_SMOKE_PASSWORD is required with WDTT_SMOKE_ADDR")
	}

	conn := openSmokeDTLS(t, serverAddr, password)
	request := "GETCONF:9000|ci-smoke-device-0001|" + password
	if _, err := conn.Write([]byte(request)); err != nil {
		conn.Close()
		t.Fatalf("write GETCONF: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		conn.Close()
		t.Fatalf("set GETCONF deadline: %v", err)
	}
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		conn.Close()
		t.Fatalf("read GETCONF: %v", err)
	}
	config := string(response[:n])
	for _, required := range []string{"[Interface]", "PrivateKey = ", "Address = 10.66.66.", "[Peer]", "Endpoint = 127.0.0.1:9000"} {
		if !strings.Contains(config, required) {
			conn.Close()
			t.Fatalf("GETCONF response lacks %q: %q", required, config)
		}
	}
	if _, err := conn.Write([]byte("READY")); err != nil {
		conn.Close()
		t.Fatalf("write READY: %v", err)
	}
	n, err = conn.Read(response)
	if err != nil {
		conn.Close()
		t.Fatalf("read READY response: %v", err)
	}
	if !bytes.Equal(response[:n], []byte("READY_OK")) {
		conn.Close()
		t.Fatalf("READY response = %q", response[:n])
	}
	conn.Close()

	mismatchConn := openSmokeDTLS(t, serverAddr, password)
	defer mismatchConn.Close()
	if _, err := mismatchConn.Write([]byte("GETCONF:9000|ci-smoke-mismatch|Wrong-Test_8zN4qP6")); err != nil {
		t.Fatalf("write mismatched GETCONF: %v", err)
	}
	if err := mismatchConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set mismatch deadline: %v", err)
	}
	n, err = mismatchConn.Read(response)
	if err != nil {
		t.Fatalf("read mismatch response: %v", err)
	}
	if !bytes.Equal(response[:n], []byte("DENIED:password_mismatch")) {
		t.Fatalf("mismatch response = %q", response[:n])
	}
}
