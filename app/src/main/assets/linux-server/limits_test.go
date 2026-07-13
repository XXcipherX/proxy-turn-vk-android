package main

import (
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
