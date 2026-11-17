package peer

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// An end-to-end node: a real Peer running its worker and housekeeping
// goroutines over a real loopback UDP socket, with a fake TUN device.
type node struct {
	p      *Peer
	dev    *fakeDev
	key    *ecdh.PrivateKey
	conn   *net.UDPConn
	cancel context.CancelFunc
	done   chan error
}

func startNode(t *testing.T, spec testPeerSpec, tweak func(*Peer)) *node {
	t.Helper()
	if spec.key == nil {
		spec.key = mustKey(t)
	}
	if spec.conn == nil {
		spec.conn = listenLoopback(t)
	}
	p, dev := newTestPeer(t, spec)
	// Compress the clock so rekeys, retries and expiries happen in milliseconds.
	p.hkTick, p.hkEvery = 5*time.Millisecond, 10*time.Millisecond
	p.reconnect, p.hsTimeout = 100*time.Millisecond, 500*time.Millisecond
	if tweak != nil {
		tweak(p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &node{p: p, dev: dev, key: spec.key, conn: spec.conn, cancel: cancel, done: make(chan error, 1)}
	go func() { n.done <- p.Run(ctx) }()
	t.Cleanup(n.stop)
	return n
}

func (n *node) stop() {
	n.cancel()
	select {
	case <-n.done:
		n.done <- nil
	case <-time.After(5 * time.Second):
	}
}

func (n *node) send(pkt []byte) { n.dev.in <- pkt }

// triangle is the project's reference topology: relay (10.9.0.1) with two
// spokes, peer-1 (10.9.0.2) and peer-2 (10.9.0.3), that dial the relay.
type triangle struct {
	relay, p1, p2    *node
	relayKey, k1, k2 *ecdh.PrivateKey
}

type triangleOpts struct {
	relayPSK, p1PSK, p2PSK       string
	tweakRelay, tweakP1, tweakP2 func(*Peer)
}

func startTriangle(t *testing.T, o triangleOpts) *triangle {
	t.Helper()
	tr := &triangle{relayKey: mustKey(t), k1: mustKey(t), k2: mustKey(t)}
	relayConn := listenLoopback(t)
	endpoint := addrOf(relayConn).String()

	tr.relay = startNode(t, testPeerSpec{key: tr.relayKey, conn: relayConn, psk: o.relayPSK, peers: []testPeerEntry{
		{key: tr.k1, allowed: []string{"10.9.0.2/32"}},
		{key: tr.k2, allowed: []string{"10.9.0.3/32"}},
	}}, o.tweakRelay)
	tr.p1 = startNode(t, testPeerSpec{key: tr.k1, psk: o.p1PSK, peers: []testPeerEntry{
		{key: tr.relayKey, endpoint: endpoint, allowed: []string{"10.9.0.0/24"}},
	}}, o.tweakP1)
	tr.p2 = startNode(t, testPeerSpec{key: tr.k2, psk: o.p2PSK, peers: []testPeerEntry{
		{key: tr.relayKey, endpoint: endpoint, allowed: []string{"10.9.0.0/24"}},
	}}, o.tweakP2)
	return tr
}

func (tr *triangle) waitConnected(t *testing.T) {
	t.Helper()
	waitFor(t, 5*time.Second, "relay, peer-1 and peer-2 to connect", func() bool {
		return tr.relay.p.activeSessions() == 2 && tr.p1.p.activeSessions() == 1 && tr.p2.p.activeSessions() == 1
	})
}

func TestE2EPeerToPeerThroughRelay(t *testing.T) {
	for _, psk := range []string{"", "some-psk"} {
		t.Run("psk="+psk, func(t *testing.T) {
			tr := startTriangle(t, triangleOpts{relayPSK: psk, p1PSK: psk, p2PSK: psk})
			tr.waitConnected(t)

			// peer-1 -> peer-2 and back, transiting the relay in user space.
			a := ipv4("10.9.0.2", "10.9.0.3", []byte("peer-1 says hi"))
			tr.p1.send(a)
			if got := tr.p2.dev.expect(t, 2*time.Second); !bytes.Equal(got, a) {
				t.Fatalf("peer-2 got % x", got)
			}
			b := ipv4("10.9.0.3", "10.9.0.2", []byte("peer-2 replies"))
			tr.p2.send(b)
			if got := tr.p1.dev.expect(t, 2*time.Second); !bytes.Equal(got, b) {
				t.Fatalf("peer-1 got % x", got)
			}
			// The relay's own TUN device never sees transit traffic.
			tr.relay.dev.expectNone(t, 100*time.Millisecond)

			// relay <-> peers use the relay's TUN device.
			c := ipv4("10.9.0.1", "10.9.0.2", []byte("from relay"))
			tr.relay.send(c)
			if got := tr.p1.dev.expect(t, 2*time.Second); !bytes.Equal(got, c) {
				t.Fatalf("peer-1 got % x", got)
			}
			d := ipv4("10.9.0.3", "10.9.0.1", []byte("to relay"))
			tr.p2.send(d)
			if got := tr.relay.dev.expect(t, 2*time.Second); !bytes.Equal(got, d) {
				t.Fatalf("relay got % x", got)
			}

			// A full-size packet survives encapsulation.
			big := ipv4("10.9.0.2", "10.9.0.3", bytes.Repeat([]byte{0x7E}, 1400))
			tr.p1.send(big)
			if got := tr.p2.dev.expect(t, 2*time.Second); !bytes.Equal(got, big) {
				t.Fatal("large packet corrupted in transit")
			}
		})
	}
}

func TestE2ESpoofedSourceBlockedAtRelay(t *testing.T) {
	tr := startTriangle(t, triangleOpts{})
	tr.waitConnected(t)

	// peer-1 pretends to be peer-2 (10.9.0.3). The relay only allows 10.9.0.2/32 from it.
	tr.p1.send(ipv4("10.9.0.3", "10.9.0.2", []byte("spoof")))
	tr.p1.send(ipv4("10.9.0.3", "10.9.0.3", []byte("spoof")))
	tr.p2.dev.expectNone(t, 300*time.Millisecond)

	// Legitimate traffic from the same peer is unaffected.
	ok := ipv4("10.9.0.2", "10.9.0.3", []byte("legit"))
	tr.p1.send(ok)
	if got := tr.p2.dev.expect(t, 2*time.Second); !bytes.Equal(got, ok) {
		t.Fatal("legit packet lost after spoof attempts")
	}
}

func TestE2ENoRouteAndNonIPv4Dropped(t *testing.T) {
	tr := startTriangle(t, triangleOpts{})
	tr.waitConnected(t)
	tr.p1.send(ipv4("10.9.0.2", "172.16.0.9", nil)) // outside every AllowedIPs
	v6 := make([]byte, 60)
	v6[0] = 0x60
	tr.p1.send(v6)
	tr.p2.dev.expectNone(t, 300*time.Millisecond)
	tr.relay.dev.expectNone(t, 50*time.Millisecond)
}

func TestE2ERekeyWithoutPacketLoss(t *testing.T) {
	// peer-1 rekeys at 80% of rekey_after = 400ms; the relay accepts quick repeats.
	tr := startTriangle(t, triangleOpts{
		tweakRelay: func(p *Peer) { p.hsCooldown = 0 },
		tweakP1: func(p *Peer) {
			p.rekeyAfter = 500 * time.Millisecond
			p.reconnect = 50 * time.Millisecond
		},
	})
	tr.waitConnected(t)
	original, _ := tr.relay.p.sessionKey(pubOf(tr.k1))

	var sent, got atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // steady traffic peer-1 -> peer-2 across several rekeys
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			tr.p1.send(ipv4("10.9.0.2", "10.9.0.3", []byte{byte(i), byte(i >> 8)}))
			sent.Add(1)
			time.Sleep(2 * time.Millisecond)
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-tr.p2.dev.out:
				got.Add(1)
			}
		}
	}()

	waitFor(t, 5*time.Second, "the session key to rotate", func() bool {
		k, ok := tr.relay.p.sessionKey(pubOf(tr.k1))
		return ok && k != original
	})
	rotatedAt := sent.Load()
	// Keep traffic flowing across at least a couple more rekeys.
	waitFor(t, 5*time.Second, "traffic after the rekey", func() bool { return sent.Load() > rotatedAt+100 })
	close(stop)
	wg.Wait()
	time.Sleep(200 * time.Millisecond)

	total := sent.Load()
	// Loopback UDP is effectively lossless; the old-key grace window plus the
	// atomic key swap mean a rekey must not drop packets in either direction.
	if delivered := got.Load(); delivered < total*99/100 {
		t.Fatalf("delivered %d of %d packets across rekeys (>1%% loss)", delivered, total)
	}
	if tr.relay.p.activeSessions() != 2 {
		t.Fatalf("relay lost a session during rekey: %d", tr.relay.p.activeSessions())
	}
}

func TestE2EUnknownPeerCannotConnect(t *testing.T) {
	relayKey, stranger := mustKey(t), mustKey(t)
	relayConn := listenLoopback(t)
	relay := startNode(t, testPeerSpec{key: relayKey, conn: relayConn, peers: []testPeerEntry{
		{key: mustKey(t), allowed: []string{"10.9.0.2/32"}}, // someone else
	}}, nil)
	imposter := startNode(t, testPeerSpec{key: stranger, peers: []testPeerEntry{
		{key: relayKey, endpoint: addrOf(relayConn).String(), allowed: []string{"10.9.0.0/24"}},
	}}, nil)

	time.Sleep(500 * time.Millisecond) // several dial attempts
	if relay.p.activeSessions() != 0 || imposter.p.activeSessions() != 0 {
		t.Fatalf("unauthorised peer got a session (relay=%d, imposter=%d)",
			relay.p.activeSessions(), imposter.p.activeSessions())
	}
	imposter.send(ipv4("10.9.0.2", "10.9.0.1", nil))
	relay.dev.expectNone(t, 200*time.Millisecond)
}

func TestE2EPSKMismatchCannotConnect(t *testing.T) {
	tr := startTriangle(t, triangleOpts{relayPSK: "relay-secret", p1PSK: "wrong", p2PSK: "relay-secret"})
	waitFor(t, 5*time.Second, "peer-2 to connect", func() bool { return tr.p2.p.activeSessions() == 1 })
	time.Sleep(300 * time.Millisecond)
	if tr.p1.p.activeSessions() != 0 {
		t.Fatal("peer-1 connected with the wrong PSK")
	}
	if tr.relay.p.activeSessions() != 1 {
		t.Fatalf("relay sessions=%d, want only peer-2", tr.relay.p.activeSessions())
	}
}

func TestE2EKeepalivesHoldSessionOpen(t *testing.T) {
	// The relay would expire an idle session after 600ms, but both sides send
	// keepalives every 50ms, so the session must survive well past that.
	short := func(p *Peer) { p.sessionExpiry = 600 * time.Millisecond; p.keepalive = 50 * time.Millisecond }
	tr := startTriangle(t, triangleOpts{tweakRelay: short, tweakP1: short, tweakP2: short})
	tr.waitConnected(t)
	time.Sleep(1500 * time.Millisecond)
	if tr.relay.p.activeSessions() != 2 || tr.p1.p.activeSessions() != 1 || tr.p2.p.activeSessions() != 1 {
		t.Fatalf("idle sessions expired despite keepalives (relay=%d p1=%d p2=%d)",
			tr.relay.p.activeSessions(), tr.p1.p.activeSessions(), tr.p2.p.activeSessions())
	}
	// Keepalives are consumed silently: nothing reaches the TUN devices.
	tr.relay.dev.expectNone(t, 50*time.Millisecond)
	tr.p1.dev.expectNone(t, 50*time.Millisecond)
}

func TestE2ESessionExpiresWhenPeerGoesSilent(t *testing.T) {
	tr := startTriangle(t, triangleOpts{
		tweakRelay: func(p *Peer) { p.sessionExpiry = 400 * time.Millisecond; p.keepalive = time.Hour },
	})
	tr.waitConnected(t)
	tr.p1.stop() // peer-1 disappears
	waitFor(t, 5*time.Second, "the relay to expire peer-1", func() bool {
		_, ok := tr.relay.p.sessionKey(pubOf(tr.k1))
		return !ok
	})
}

func TestE2EDialerRetriesUntilRelayAppears(t *testing.T) {
	relayKey, k1 := mustKey(t), mustKey(t)
	// Reserve a port, then free it so the relay is genuinely down at first.
	tmp := listenLoopback(t)
	relayAddr := addrOf(tmp)
	_ = tmp.Close()

	p1 := startNode(t, testPeerSpec{key: k1, peers: []testPeerEntry{
		{key: relayKey, endpoint: relayAddr.String(), allowed: []string{"10.9.0.0/24"}},
	}}, func(p *Peer) { p.hsTimeout = 100 * time.Millisecond; p.reconnect = 100 * time.Millisecond })
	time.Sleep(400 * time.Millisecond) // a few failed attempts
	if p1.p.activeSessions() != 0 {
		t.Fatal("connected to a relay that is not running")
	}

	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(relayAddr))
	if err != nil {
		t.Skipf("could not re-bind reserved port %v: %v", relayAddr, err)
	}
	t.Cleanup(func() { conn.Close() })
	relay := startNode(t, testPeerSpec{key: relayKey, conn: conn, peers: []testPeerEntry{
		{key: k1, allowed: []string{"10.9.0.2/32"}},
	}}, nil)
	waitFor(t, 5*time.Second, "peer-1 to connect once the relay is up", func() bool {
		return p1.p.activeSessions() == 1 && relay.p.activeSessions() == 1
	})
	pkt := ipv4("10.9.0.2", "10.9.0.1", []byte("finally"))
	p1.send(pkt)
	if got := relay.dev.expect(t, 2*time.Second); !bytes.Equal(got, pkt) {
		t.Fatal("traffic did not flow after the late connect")
	}
}

func TestE2EPeerRestartReconnects(t *testing.T) {
	tr := startTriangle(t, triangleOpts{tweakRelay: func(p *Peer) { p.hsCooldown = 0 }})
	tr.waitConnected(t)
	tr.p1.stop()

	// peer-1 comes back on a new source port (new NAT mapping) with the same identity.
	endpoint := addrOf(tr.relay.conn).String()
	p1b := startNode(t, testPeerSpec{key: tr.k1, peers: []testPeerEntry{
		{key: tr.relayKey, endpoint: endpoint, allowed: []string{"10.9.0.0/24"}},
	}}, nil)
	waitFor(t, 5*time.Second, "the restarted peer-1 to reconnect", func() bool { return p1b.p.activeSessions() == 1 })

	pkt := ipv4("10.9.0.2", "10.9.0.3", []byte("after restart"))
	p1b.send(pkt)
	if got := tr.p2.dev.expect(t, 2*time.Second); !bytes.Equal(got, pkt) {
		t.Fatal("traffic from the restarted peer did not reach peer-2")
	}
	back := ipv4("10.9.0.3", "10.9.0.2", []byte("reply"))
	tr.p2.send(back)
	if got := p1b.dev.expect(t, 2*time.Second); !bytes.Equal(got, back) {
		t.Fatal("reply did not reach the restarted peer-1's new address")
	}
	if tr.relay.p.activeSessions() != 2 {
		t.Fatalf("relay should reuse peer-1's slot, sessions=%d", tr.relay.p.activeSessions())
	}
}

func TestE2EParallelFlowsAreIntact(t *testing.T) {
	tr := startTriangle(t, triangleOpts{})
	tr.waitConnected(t)

	const flows, perFlow = 4, 100
	var recv sync.Map
	var count atomic.Int64
	stopRx := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopRx:
				return
			case pkt := <-tr.p2.dev.out:
				if _, dup := recv.LoadOrStore(string(pkt[20:]), true); dup {
					t.Errorf("duplicate delivery of % x", pkt[20:])
				}
				count.Add(1)
			}
		}
	}()
	var wg sync.WaitGroup
	for f := 0; f < flows; f++ {
		wg.Add(1)
		go func(f int) {
			defer wg.Done()
			for i := 0; i < perFlow; i++ {
				tr.p1.send(ipv4("10.9.0.2", "10.9.0.3", []byte{byte(f), byte(i), 0xA5}))
				time.Sleep(time.Millisecond)
			}
		}(f)
	}
	wg.Wait()
	waitFor(t, 3*time.Second, "all flows to drain", func() bool { return count.Load() >= flows*perFlow*95/100 })
	time.Sleep(100 * time.Millisecond)
	close(stopRx)
}
