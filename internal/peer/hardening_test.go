package peer

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jecklgamis/microtunnel/internal/proto"
)

func TestJunkFloodLogsAreRateLimited(t *testing.T) {
	logs := captureLogs(t)
	f := newDataFixture(t)
	stranger := netip.MustParseAddrPort("203.0.113.9:4444")
	for i := 0; i < 2000; i++ {
		f.p.handleUDP(stranger, ipv4("10.9.0.2", "10.9.0.1", []byte("junk")), f.w)
	}
	got := strings.Count(logs.String(), "unknown peer")
	if got < 1 || got > 3 {
		t.Fatalf("2000 junk datagrams produced %d log lines, want a handful:\n%s", got, logs)
	}
}

func TestHandshakeLimiterPerSourceAndGlobal(t *testing.T) {
	var l handshakeLimiter
	now := time.Now()
	noisy := netip.MustParseAddr("198.51.100.1")
	other := netip.MustParseAddr("198.51.100.2")

	allowed := 0
	for i := 0; i < 1000; i++ {
		if l.allow(noisy, now) {
			allowed++
		}
	}
	if allowed != hsSourceBurst {
		t.Fatalf("one source got %d handshakes in a burst, want %d", allowed, hsSourceBurst)
	}
	if !l.allow(other, now) {
		t.Fatal("a quiet source was starved by a noisy one")
	}
	// Tokens refill over time.
	if !l.allow(noisy, now.Add(time.Second)) {
		t.Fatal("source not allowed again after refill")
	}

	// Many distinct sources together are capped globally.
	var g handshakeLimiter
	total := 0
	for i := 0; i < 5000; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		if g.allow(a, now) {
			total++
		}
	}
	if total != hsGlobalBurst {
		t.Fatalf("spread-out flood got %d handshakes, want the global burst %d", total, hsGlobalBurst)
	}
}

func TestHandshakeLimiterBoundsTrackedSources(t *testing.T) {
	var l handshakeLimiter
	now := time.Now()
	for i := 0; i < hsMaxSources*3; i++ {
		l.allow(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), now)
	}
	if len(l.source) > hsMaxSources {
		t.Fatalf("tracking %d sources, limit %d", len(l.source), hsMaxSources)
	}
}

func TestBadPSKHandshakeDroppedBeforeAnyWork(t *testing.T) {
	e := newHSEnv(t, "right")
	rp := pubOf(e.relayKey)
	wrong := proto.DeriveKey("wrong")
	msg, _, _ := proto.ClientInit(e.clientKey, rp[:], &wrong)
	logs := captureLogs(t)
	for i := 0; i < 500; i++ { // far beyond the rate limit, yet none reaches the limiter
		e.relay.handleUDP(e.clientAddr, msg, new(workerBufs))
	}
	e.noResponse(t)
	if !strings.Contains(logs.String(), "Invalid handshake") {
		t.Fatalf("bad-HMAC handshake not reported:\n%s", logs)
	}
	if strings.Count(logs.String(), "Invalid handshake") > 3 {
		t.Fatal("bad-HMAC handshakes were not log-limited")
	}
	// The sender's rate-limit budget is untouched by forged packets, so a
	// genuine handshake from the same address still goes through.
	good, st := e.initiate(t)
	e.relay.handleUDP(e.clientAddr, good, new(workerBufs))
	e.finish(t, e.readResponse(t), st)
}

func TestHandshakeFloodIsRateLimited(t *testing.T) {
	e := newHSEnv(t, "")
	msg, _ := e.initiate(t)
	logs := captureLogs(t)
	for i := 0; i < 1000; i++ {
		e.relay.handleUDP(e.clientAddr, msg, new(workerBufs))
	}
	if !strings.Contains(logs.String(), "rate limit exceeded") {
		t.Fatalf("flood was not rate limited:\n%s", logs)
	}
}

func TestSendStopsWhenKeyIsExhausted(t *testing.T) {
	f := newDataFixture(t)
	f.s.mu.Lock()
	f.s.sendSeq = maxPacketsPerKey
	f.s.mu.Unlock()

	f.p.tbl.mu.RLock()
	f.p.forward(f.s, ipv4("10.9.0.1", "10.9.0.2", []byte("x")), f.w)
	f.p.tbl.mu.RUnlock()
	expectNoDatagram(t, f.remote, 150*time.Millisecond)

	// A rekey resets the counter and sending resumes.
	f.s.mu.Lock()
	f.s.sendSeq = 0
	f.s.mu.Unlock()
	f.p.tbl.mu.RLock()
	f.p.forward(f.s, ipv4("10.9.0.1", "10.9.0.2", []byte("x")), f.w)
	f.p.tbl.mu.RUnlock()
	buf := make([]byte, 2048)
	_ = f.remote.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := f.remote.ReadFromUDPAddrPort(buf); err != nil {
		t.Fatalf("no packet after the counter reset: %v", err)
	}
}
