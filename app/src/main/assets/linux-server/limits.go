package main

import (
	"net"
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

type identityConnectionLimiter struct {
	mu sync.Mutex

	maxGeneratedTotal int
	maxPerPassword     int
	maxPerSourceIP     int
	generatedTotal     int
	byPassword         map[string]int
	bySourceIP         map[string]int
}

func newIdentityConnectionLimiter(maxConnections int) *identityConnectionLimiter {
	generatedLimit := maxConnections
	if maxConnections > 1 {
		// Keep a quarter of the global slots available for the owner password.
		generatedLimit -= maxConnections / 4
		if generatedLimit == maxConnections {
			generatedLimit--
		}
	}
	perPassword := maxConnections / 8
	if perPassword < 1 {
		perPassword = 1
	} else if perPassword > 32 {
		perPassword = 32
	}
	if perPassword > generatedLimit {
		perPassword = generatedLimit
	}
	perSourceIP := maxConnections / 4
	if perSourceIP < 1 {
		perSourceIP = 1
	} else if perSourceIP > 64 {
		perSourceIP = 64
	}
	if perSourceIP > generatedLimit {
		perSourceIP = generatedLimit
	}
	return &identityConnectionLimiter{
		maxGeneratedTotal: generatedLimit,
		maxPerPassword:     perPassword,
		maxPerSourceIP:     perSourceIP,
		byPassword:         make(map[string]int),
		bySourceIP:         make(map[string]int),
	}
}

func sourceIP(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	if udpAddr, ok := addr.(*net.UDPAddr); ok && udpAddr.IP != nil {
		return udpAddr.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil && host != "" {
		return host
	}
	return addr.String()
}

func (l *identityConnectionLimiter) TryAcquire(identity wrapIdentity, addr net.Addr) bool {
	if l == nil || identity.IsMain {
		return true
	}
	passwordID := wrapKeyID(identity.Password)
	ip := sourceIP(addr)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.generatedTotal >= l.maxGeneratedTotal ||
		l.byPassword[passwordID] >= l.maxPerPassword ||
		l.bySourceIP[ip] >= l.maxPerSourceIP {
		return false
	}
	l.generatedTotal++
	l.byPassword[passwordID]++
	l.bySourceIP[ip]++
	return true
}

func (l *identityConnectionLimiter) Release(identity wrapIdentity, addr net.Addr) {
	if l == nil || identity.IsMain {
		return
	}
	passwordID := wrapKeyID(identity.Password)
	ip := sourceIP(addr)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byPassword[passwordID] == 0 || l.bySourceIP[ip] == 0 || l.generatedTotal == 0 {
		return
	}
	l.generatedTotal--
	l.byPassword[passwordID]--
	l.bySourceIP[ip]--
	if l.byPassword[passwordID] == 0 {
		delete(l.byPassword, passwordID)
	}
	if l.bySourceIP[ip] == 0 {
		delete(l.bySourceIP, ip)
	}
}
