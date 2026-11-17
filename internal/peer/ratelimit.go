package peer

import (
	"net/netip"
	"sync"
	"time"
)

// Handshake rate limits. Every handshake that passes the cheap checks costs two
// X25519 operations and runs under the table write lock, which stalls the whole
// data plane, so unauthenticated floods must be bounded. A legitimate node
// handshakes about once per rekey interval; a relay that restarts sees each
// peer reconnect once within seconds, which the bursts absorb.
const (
	hsGlobalRate  = 200 // handshakes per second, all sources together
	hsGlobalBurst = 256
	hsSourceRate  = 16 // handshakes per second from one source address
	hsSourceBurst = 32
	hsMaxSources  = 4096 // bound on tracked source addresses
)

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// take removes one token, refilling at rate per second up to burst.
func (b *tokenBucket) take(now time.Time, rate, burst float64) bool {
	if b.last.IsZero() {
		b.tokens = burst
	} else if dt := now.Sub(b.last).Seconds(); dt > 0 {
		b.tokens = min(burst, b.tokens+dt*rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// handshakeLimiter bounds inbound handshake processing, globally and per
// source address, so one noisy address cannot starve the others.
type handshakeLimiter struct {
	mu     sync.Mutex
	global tokenBucket
	source map[netip.Addr]*tokenBucket
}

func (l *handshakeLimiter) allow(src netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.source == nil {
		l.source = make(map[netip.Addr]*tokenBucket)
	}
	b := l.source[src]
	if b == nil {
		if len(l.source) >= hsMaxSources {
			for k, v := range l.source { // drop idle entries; reset if still full
				if now.Sub(v.last) > 10*time.Second {
					delete(l.source, k)
				}
			}
			if len(l.source) >= hsMaxSources {
				clear(l.source)
			}
		}
		b = new(tokenBucket)
		l.source[src] = b
	}
	if !b.take(now, hsSourceRate, hsSourceBurst) {
		return false
	}
	return l.global.take(now, hsGlobalRate, hsGlobalBurst)
}
