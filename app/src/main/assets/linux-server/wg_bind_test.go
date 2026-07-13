package main

import (
	"net"
	"testing"
)

func TestLoopbackBindListensOnlyOnIPv4Loopback(t *testing.T) {
	bind := newLoopbackBind()
	_, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer bind.Close()
	if port == 0 {
		t.Fatal("Open returned an invalid port")
	}

	bind.mu.Lock()
	addr := bind.conn.LocalAddr().(*net.UDPAddr)
	bind.mu.Unlock()
	if !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("bind address = %s, want 127.0.0.1", addr.IP)
	}
}
