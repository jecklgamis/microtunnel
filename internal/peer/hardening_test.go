package peer

import (
	"bytes"
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

// --- handshake confirmation: a replayed or forged initiation cannot displace a
// live session ----------------------------------------------------------------

func TestReplayedInitiationCannotDisplaceLiveSession(t *testing.T) {
	e := newHSEnv(t, "psk") // the replay carries a valid PSK HMAC, as a captured one would
	e.relay.hsCooldown = 0  // isolate confirmation from the cooldown
	dev := e.relay.dev.(*fakeDev)

	msg, st := e.initiate(t)
	e.relay.handleUDP(e.clientAddr, msg, new(workerBufs))
	key := e.finish(t, e.readResponse(t), st)
	e.confirm(t, e.clientAddr, key, 0)

	// An attacker who recorded the initiation replays it from its own address.
	attacker := listenLoopback(t)
	for i := 0; i < 3; i++ {
		e.relay.handleUDP(addrOf(attacker), msg, new(workerBufs))
	}

	e.relay.tbl.mu.RLock()
	s := e.relay.tbl.findByPub(pubOf(e.clientKey))
	moved, rekeyed := s.addr != e.clientAddr, s.key != key
	e.relay.tbl.mu.RUnlock()
	if moved {
		t.Fatal("replayed initiation re-homed the live session to the attacker's address")
	}
	if rekeyed {
		t.Fatal("replayed initiation replaced the live session key")
	}

	// The real peer's traffic still flows under the original key, and replies
	// still go to the real peer.
	pkt := ipv4("10.9.0.2", "10.9.0.1", []byte("still here"))
	e.relay.handleUDP(e.clientAddr, wirePacket(t, key, 1, pkt), new(workerBufs))
	if got := dev.expect(t, time.Second); !bytes.Equal(got, pkt) {
		t.Fatal("legitimate traffic broken by the replay")
	}
	e.relay.tbl.mu.RLock()
	f := e.relay.tbl.findByPub(pubOf(e.clientKey))
	e.relay.tbl.mu.RUnlock()
	e.relay.tbl.mu.RLock()
	e.relay.forward(f, ipv4("10.9.0.1", "10.9.0.2", []byte("reply")), new(workerBufs))
	e.relay.tbl.mu.RUnlock()
	_ = e.clientConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := e.clientConn.ReadFromUDPAddrPort(make([]byte, 2048)); err != nil {
		t.Fatalf("reply did not reach the real peer: %v", err)
	}
	// The attacker got only handshake responses (which are useless to it), never data.
	for {
		_ = attacker.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := attacker.ReadFromUDPAddrPort(make([]byte, 2048))
		if err != nil {
			break
		}
		if n != e.relay.hsSize {
			t.Fatalf("attacker received a %d-byte datagram that is not a handshake response", n)
		}
	}
}

func TestUnconfirmedInitiationCreatesNoSession(t *testing.T) {
	e := newHSEnv(t, "")
	msg, _ := e.initiate(t)
	e.relay.handleUDP(addrOf(listenLoopback(t)), msg, new(workerBufs)) // replayed from elsewhere
	if e.relay.activeSessions() != 0 {
		t.Fatal("an initiation alone created a session (peer shown as connected, traffic routed to the sender)")
	}
	if _, ok := e.relay.sessionKey(pubOf(e.clientKey)); ok {
		t.Fatal("session key installed without confirmation")
	}
}

func TestConfirmationMustComeFromTheHandshakeAddress(t *testing.T) {
	e := newHSEnv(t, "")
	msg, st := e.initiate(t)
	e.relay.handleUDP(e.clientAddr, msg, new(workerBufs))
	key := e.finish(t, e.readResponse(t), st)

	e.confirm(t, addrOf(listenLoopback(t)), key, 0) // right key, wrong source address
	if e.relay.activeSessions() != 0 {
		t.Fatal("handshake confirmed from an address that never handshook")
	}
	e.confirm(t, e.clientAddr, key, 0)
	if e.relay.activeSessions() != 1 {
		t.Fatal("genuine confirmation rejected")
	}
}

func TestStaleCandidateIsNotConfirmed(t *testing.T) {
	e := newHSEnv(t, "")
	msg, st := e.initiate(t)
	e.relay.handleHandshake(e.clientAddr, msg, time.Now().Add(-2*candidateTTL))
	key := e.finish(t, e.readResponse(t), st)
	e.confirm(t, e.clientAddr, key, 0)
	if e.relay.activeSessions() != 0 {
		t.Fatal("an expired handshake key was confirmed")
	}
}

func TestCandidatesPerPeerAreBounded(t *testing.T) {
	e := newHSEnv(t, "")
	e.relay.hsCooldown = 0
	var first [proto.KeyLen]byte
	var firstAddr netip.AddrPort
	n := maxCandidatesPerPeer * 3
	for i := 0; i < n; i++ {
		msg, st := e.initiate(t)
		conn := listenLoopback(t)
		e.relay.handleHandshake(addrOf(conn), msg, time.Now())
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 512)
		m, _, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatal(err)
		}
		k := e.finish(t, buf[:m], st)
		if i == 0 {
			first, firstAddr = k, addrOf(conn)
		}
	}
	e.relay.tbl.mu.RLock()
	live := 0
	for i := range e.relay.tbl.cands {
		if e.relay.tbl.cands[i].active {
			live++
		}
	}
	e.relay.tbl.mu.RUnlock()
	if live != maxCandidatesPerPeer {
		t.Fatalf("%d unconfirmed keys held for one peer, want %d", live, maxCandidatesPerPeer)
	}
	e.confirm(t, firstAddr, first, 0) // the oldest was evicted
	if e.relay.activeSessions() != 0 {
		t.Fatal("an evicted candidate was confirmed")
	}
}

func TestOutboundHandshakeSendsImmediateKeepalive(t *testing.T) {
	o := newOutEnv(t, "")
	o.p.tbl.mu.Lock()
	_ = o.p.initiate(o.p.cfgs[0], time.Now())
	o.p.tbl.mu.Unlock()
	resp, serverKey, _ := o.serverReceive(t)
	o.p.handleUDP(addrOf(o.server), resp, new(workerBufs))

	// The responder confirms the new key on the first packet under it, so the
	// initiator must not wait for traffic or the keepalive timer.
	_ = o.server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	n, _, err := o.server.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("no packet after completing the handshake: %v", err)
	}
	plain, err := proto.DecryptPacket(serverKey[:], buf[:n])
	if err != nil || len(plain) != proto.HeaderSize+proto.SeqSize {
		t.Fatalf("first packet is not an empty keepalive under the new key (err=%v, len=%d)", err, len(plain))
	}
}
