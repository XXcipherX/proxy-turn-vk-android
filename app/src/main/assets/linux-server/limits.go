package main

import (
	"sync"
	"time"
)

type connectionLimiter struct {
	slots chan struct{}

	mu         sync.Mutex
	rate       float64
	burst      float64
	tokens     float64
	lastRefill time.Time
}

func newConnectionLimiter(maxConnections, handshakesPerSecond int) *connectionLimiter {
	burst := float64(handshakesPerSecond * 2)
	return &connectionLimiter{
		slots:      make(chan struct{}, maxConnections),
		rate:       float64(handshakesPerSecond),
		burst:      burst,
		tokens:     burst,
		lastRefill: time.Now(),
	}
}

func (l *connectionLimiter) allowHandshake(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	elapsed := now.Sub(l.lastRefill).Seconds()
	if elapsed > 0 {
		l.tokens += elapsed * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.lastRefill = now
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

func (l *connectionLimiter) TryAcquire() bool {
	if !l.allowHandshake(time.Now()) {
		return false
	}
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *connectionLimiter) Release() {
	select {
	case <-l.slots:
	default:
	}
}
