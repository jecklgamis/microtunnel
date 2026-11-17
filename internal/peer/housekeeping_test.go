package peer

import (
	"strings"
	"testing"
	"time"

	"github.com/jecklgamis/microtunnel/internal/proto"
)

func hk(p *Peer, now time.Time) {
	p.housekeep(testCtx(), now, new(workerBufs))
}

func TestHousekeepExpiresPendingHandshake(t *testing.T) {
	o := newOutEnv(t, "")
	logs := captureLogs(t)
	now := time.Now()
	o.p.tbl.mu.Lock()
	_ = o.p.initiate(o.p.cfgs[0], now)
	o.p.tbl.mu.Unlock()
	o.serverReceive(t)

	hk(o.p, now.Add(o.p.hsTimeout-time.Second)) // not yet
	if !o.p.tbl.pending[0].active {
		t.Fatal("pending handshake expired too early")
	}
	hk(o.p, now.Add(o.p.hsTimeout+time.Second))
	if o.p.tbl.pending[0].active {
		t.Fatal("pending handshake not expired")
	}
	if !strings.Contains(logs.String(), "timed out") {
		t.Fatalf("timeout not logged:\n%s", logs)
	}
}

func TestHousekeepTimeoutClearsRekeyingFlag(t *testing.T) {
	o := newOutEnv(t, "")
	now := time.Now()
	o.p.addSession(t, pubOf(o.serverKey), addrOf(o.server), randKey(1), "10.9.0.0/24")
	o.p.tbl.mu.Lock()
	o.p.tbl.findByPub(pubOf(o.serverKey)).rekeying = true
	_ = o.p.initiate(o.p.cfgs[0], now)
	o.p.tbl.mu.Unlock()
	hk(o.p, now.Add(o.p.hsTimeout+time.Second))
	o.p.tbl.mu.RLock()
	defer o.p.tbl.mu.RUnlock()
	if o.p.tbl.findByPub(pubOf(o.serverKey)).rekeying {
		t.Fatal("rekeying must be cleared so the next attempt can retry")
	}
}

func TestHousekeepExpiresSilentSessions(t *testing.T) {
	f := newDataFixture(t)
	f.p.keepalive = 24 * time.Hour // keep keepalives out of this test
	logs := captureLogs(t)
	start := time.Now()
	f.p.tbl.mu.Lock()
	f.s.lastHandshake = start
	f.p.tbl.mu.Unlock()

	hk(f.p, start.Add(f.p.sessionExpiry-time.Second))
	if f.p.activeSessions() != 1 {
		t.Fatal("session expired too early")
	}
	hk(f.p, start.Add(f.p.sessionExpiry+time.Second))
	if f.p.activeSessions() != 0 {
		t.Fatal("silent session was not expired")
	}
	if !strings.Contains(logs.String(), "Session expired") {
		t.Fatalf("expiry not logged:\n%s", logs)
	}
	// An expired session no longer routes traffic.
	f.p.handleTUN(ipv4("10.9.0.1", "10.9.0.2", nil), f.w)
	expectNoDatagram(t, f.remote, 100*time.Millisecond)
}

func TestHousekeepExpiryMeasuresFromLastSeen(t *testing.T) {
	f := newDataFixture(t)
	start := time.Now()
	f.p.tbl.mu.Lock()
	f.s.lastHandshake = start.Add(-10 * f.p.sessionExpiry) // ancient handshake...
	f.p.tbl.mu.Unlock()
	f.s.mu.Lock()
	f.s.lastSeen = start // ...but recent traffic
	f.s.mu.Unlock()
	hk(f.p, start.Add(time.Second))
	if f.p.activeSessions() != 1 {
		t.Fatal("a session with recent traffic must not expire")
	}
}

func TestHousekeepSendsKeepaliveWhenIdle(t *testing.T) {
	f := newDataFixture(t)
	start := time.Now()
	f.s.mu.Lock()
	f.s.lastSent = start
	f.s.mu.Unlock()

	hk(f.p, start.Add(f.p.keepalive-time.Second))
	expectNoDatagram(t, f.remote, 100*time.Millisecond)

	hk(f.p, start.Add(f.p.keepalive+time.Second))
	seq, payload := readWire(t, f.remote, f.key, time.Second)
	if len(payload) != 0 || seq != 0 {
		t.Fatalf("keepalive should be an empty payload with seq 0, got seq=%d len=%d", seq, len(payload))
	}
	f.dev.expectNone(t, 50*time.Millisecond)
}

func TestKeepaliveRoundtripRefreshesPeerLastSeen(t *testing.T) {
	// A's keepalive, delivered to B, is authenticated traffic and refreshes B's lastSeen.
	f := newDataFixture(t)
	f.deliver(t, 0, nil)
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	if f.s.lastSeen.IsZero() {
		t.Fatal("lastSeen not refreshed by keepalive")
	}
}

func TestDialDueInitiatesWhenNoSession(t *testing.T) {
	o := newOutEnv(t, "")
	o.p.dialDue(testCtx(), time.Now())
	o.serverReceive(t)
	if !o.p.tbl.pending[0].active {
		t.Fatal("handshake not initiated for a peer with no session")
	}
}

func TestDialDueRespectsReconnectInterval(t *testing.T) {
	o := newOutEnv(t, "")
	now := time.Now()
	o.p.dialDue(testCtx(), now)
	o.serverReceive(t)
	// Handshake times out; a retry before reconnect_interval must not be sent.
	o.p.tbl.mu.Lock()
	o.p.tbl.pending[0].active = false
	o.p.tbl.mu.Unlock()
	o.p.dialDue(testCtx(), now.Add(o.p.reconnect-time.Second))
	expectNoDatagram(t, o.server, 100*time.Millisecond)
	o.p.dialDue(testCtx(), now.Add(o.p.reconnect+time.Second))
	o.serverReceive(t)
}

func TestDialDueRekeysAtEightyPercent(t *testing.T) {
	o := newOutEnv(t, "")
	start := time.Now()
	o.p.addSession(t, pubOf(o.serverKey), addrOf(o.server), randKey(1), "10.9.0.0/24")
	o.p.tbl.mu.Lock()
	o.p.tbl.findByPub(pubOf(o.serverKey)).lastHandshake = start
	o.p.tbl.mu.Unlock()

	threshold := o.p.rekeyAfter * 4 / 5 // 144s with the 180s default
	if threshold != 144*time.Second {
		t.Fatalf("threshold=%v, want 144s", threshold)
	}
	o.p.dialDue(testCtx(), start.Add(threshold-time.Second))
	expectNoDatagram(t, o.server, 100*time.Millisecond)

	o.p.dialDue(testCtx(), start.Add(threshold))
	o.serverReceive(t)
	o.p.tbl.mu.RLock()
	rekeying := o.p.tbl.findByPub(pubOf(o.serverKey)).rekeying
	o.p.tbl.mu.RUnlock()
	if !rekeying {
		t.Fatal("rekeying flag not set while a rekey is in flight")
	}
}

func TestDialDueDoesNotStackRekeys(t *testing.T) {
	o := newOutEnv(t, "")
	start := time.Now()
	o.p.reconnect = time.Millisecond
	o.p.addSession(t, pubOf(o.serverKey), addrOf(o.server), randKey(1), "10.9.0.0/24")
	o.p.tbl.mu.Lock()
	o.p.tbl.findByPub(pubOf(o.serverKey)).lastHandshake = start.Add(-time.Hour)
	o.p.tbl.mu.Unlock()

	o.p.dialDue(testCtx(), start)
	o.serverReceive(t)
	o.p.dialDue(testCtx(), start.Add(time.Minute)) // rekey still in flight
	expectNoDatagram(t, o.server, 100*time.Millisecond)
}

func TestDialDueSkipsInboundOnlyPeers(t *testing.T) {
	e := newHSEnv(t, "") // relay: its only peer has no endpoint
	e.relay.dialDue(testCtx(), time.Now())
	if e.relay.tbl.pending[0].active {
		t.Fatal("must never dial a peer without an endpoint")
	}
}

func TestHousekeepStateStaysConsistentUnderConcurrentTraffic(t *testing.T) {
	// Exercised mainly for the race detector: housekeeping, data and TUN paths
	// all touching one session concurrently.
	f := newDataFixture(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		w := new(workerBufs)
		for i := 0; i < 200; i++ {
			f.p.handleTUN(ipv4("10.9.0.1", "10.9.0.2", nil), w)
		}
	}()
	go func() {
		w := new(workerBufs)
		for i := 0; i < 200; i++ {
			f.p.handleUDP(f.remoteAddr, wirePacket(t, f.key, uint64(i), ipv4("10.9.0.2", "10.9.0.1", nil)), w)
			select {
			case <-f.dev.out:
			default:
			}
		}
	}()
	for i := 0; i < 50; i++ {
		hk(f.p, time.Now())
		f.p.PrintSessions()
	}
	<-done
}

func TestPrintSessionsFormat(t *testing.T) {
	f := newDataFixture(t)
	logs := captureLogs(t)
	f.p.PrintSessions()
	out := logs.String()
	if !strings.Contains(out, "Active peers (1):") {
		t.Fatalf("missing header:\n%s", out)
	}
	pub := pubOf(f.remoteKey)
	if !strings.Contains(out, "key="+proto.BytesToHex(pub[:8])+"...") {
		t.Fatalf("short key missing:\n%s", out)
	}
	if !strings.Contains(out, "[in] "+f.remoteAddr.String()+" key=") || !strings.Contains(out, "... routes=1") {
		t.Fatalf("unexpected session line:\n%s", out)
	}
}
