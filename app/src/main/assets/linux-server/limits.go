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
	generatedRate      float64
	generatedBurst     float64
	generatedTokens    float64
	generatedRefill    time.Time
	perPasswordRate    float64
	perPasswordBurst   float64
	passwordRateStates map[string]*identityRateState
}

type identityRateState struct {
	tokens     float64
	lastRefill time.Time
}

func newIdentityConnectionLimiter(maxConnections, handshakesPerSecond int) *identityConnectionLimiter {
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
	now := time.Now()
	globalBurst := handshakesPerSecond * 2
	generatedBurst := globalBurst - globalBurst/4
	if generatedBurst < 1 {
		generatedBurst = 1
	}
	generatedRate := float64(handshakesPerSecond) * 0.75
	if generatedRate < 0.5 {
		generatedRate = 0.5
	}
	perPasswordRate := float64(handshakesPerSecond) / 8
	if perPasswordRate < 1 {
		perPasswordRate = 1
	} else if perPasswordRate > 8 {
		perPasswordRate = 8
	}
	perPasswordBurst := perPassword
	if perPasswordBurst > generatedBurst {
		perPasswordBurst = generatedBurst
	}
	return &identityConnectionLimiter{
		maxGeneratedTotal: generatedLimit,
		maxPerPassword:     perPassword,
		maxPerSourceIP:     perSourceIP,
		byPassword:         make(map[string]int),
		bySourceIP:         make(map[string]int),
		generatedRate:      generatedRate,
		generatedBurst:     float64(generatedBurst),
		generatedTokens:    float64(generatedBurst),
		generatedRefill:    now,
		perPasswordRate:    perPasswordRate,
		perPasswordBurst:   float64(perPasswordBurst),
		passwordRateStates: make(map[string]*identityRateState),
	}
}

func refillIdentityTokens(tokens *float64, lastRefill *time.Time, rate, burst float64, now time.Time) {
	if elapsed := now.Sub(*lastRefill).Seconds(); elapsed > 0 {
		*tokens += elapsed * rate
		if *tokens > burst {
			*tokens = burst
		}
		*lastRefill = now
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
	return l.tryAcquire(identity, addr, false)
}

func (l *identityConnectionLimiter) TryAcquireAdmission(identity wrapIdentity, addr net.Addr) bool {
	return l.tryAcquire(identity, addr, true)
}

func (l *identityConnectionLimiter) tryAcquire(identity wrapIdentity, addr net.Addr, rateLimited bool) bool {
	if l == nil || identity.IsMain {
		return true
	}
	passwordID := wrapKeyID(identity.Password)
	ip := sourceIP(addr)
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()
	var rateState *identityRateState
	if rateLimited {
		refillIdentityTokens(&l.generatedTokens, &l.generatedRefill, l.generatedRate, l.generatedBurst, now)
		rateState = l.passwordRateStates[passwordID]
		if rateState == nil {
			rateState = &identityRateState{tokens: l.perPasswordBurst, lastRefill: now}
			l.passwordRateStates[passwordID] = rateState
		} else {
			refillIdentityTokens(&rateState.tokens, &rateState.lastRefill, l.perPasswordRate, l.perPasswordBurst, now)
		}
	}
	if l.generatedTotal >= l.maxGeneratedTotal ||
		l.byPassword[passwordID] >= l.maxPerPassword ||
		l.bySourceIP[ip] >= l.maxPerSourceIP ||
		(rateLimited && (l.generatedTokens < 1 || rateState.tokens < 1)) {
		return false
	}
	if rateLimited {
		l.generatedTokens--
		rateState.tokens--
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
