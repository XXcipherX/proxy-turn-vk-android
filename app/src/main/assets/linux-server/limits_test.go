package main

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestConnectionLimiterCapsConcurrentConnections(t *testing.T) {
	limiter := newConnectionLimiter(2, 100)
	if !limiter.TryAcquire() || !limiter.TryAcquire() {
		t.Fatal("initial connection slots were rejected")
	}
	if limiter.TryAcquire() {
		t.Fatal("connection above the configured limit was accepted")
	}
	limiter.Release()
	if !limiter.TryAcquire() {
		t.Fatal("released connection slot was not reusable")
	}
}

func TestIdentityLimiterReservesCapacityAndCapsTemporaryUsers(t *testing.T) {
	limiter := newIdentityConnectionLimiter(8)
	first := wrapIdentity{Password: "temporary-one"}
	second := wrapIdentity{Password: "temporary-two"}
	owner := wrapIdentity{Password: "main", IsMain: true}
	firstIP := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1000}
	secondIP := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1000}

	if !limiter.TryAcquire(first, firstIP) {
		t.Fatal("first temporary connection was rejected")
	}
	if limiter.TryAcquire(first, secondIP) {
		t.Fatal("one temporary password exceeded its quota")
	}
	if !limiter.TryAcquire(second, secondIP) {
		t.Fatal("independent temporary password was rejected")
	}
	if !limiter.TryAcquire(owner, firstIP) {
		t.Fatal("owner connection did not retain reserved capacity")
	}
	limiter.Release(first, firstIP)
	if !limiter.TryAcquire(first, secondIP) {
		t.Fatal("released temporary-password quota was not reusable")
	}

	reserved := newIdentityConnectionLimiter(8)
	for i := 0; i < reserved.maxGeneratedTotal; i++ {
		identity := wrapIdentity{Password: fmt.Sprintf("temporary-%d", i)}
		addr := &net.UDPAddr{IP: net.ParseIP(fmt.Sprintf("192.0.2.%d", i+1)), Port: 1000}
		if !reserved.TryAcquire(identity, addr) {
			t.Fatalf("temporary connection %d was rejected before the shared quota", i)
		}
	}
	if reserved.TryAcquire(wrapIdentity{Password: "temporary-overflow"}, &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1000}) {
		t.Fatal("temporary users consumed owner-reserved capacity")
	}
	if !reserved.TryAcquire(owner, firstIP) {
		t.Fatal("owner could not use capacity reserved from temporary users")
	}
}

func TestConnectionLimiterRateLimitsHandshakes(t *testing.T) {
	limiter := newConnectionLimiter(10, 2)
	now := limiter.lastRefill
	for i := 0; i < 4; i++ {
		if !limiter.allowHandshake(now) {
			t.Fatalf("burst handshake %d was rejected", i)
		}
	}
	if limiter.allowHandshake(now) {
		t.Fatal("handshake above burst was accepted")
	}
	if !limiter.allowHandshake(now.Add(500 * time.Millisecond)) {
		t.Fatal("refilled handshake token was not accepted")
	}
}
