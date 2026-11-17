package peer

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jecklgamis/microtunnel/internal/proto"
)

// A standard fixture: one remote peer "remote" (10.9.0.2/32) at remoteAddr
// with a known session key, reachable through the real UDP listener `remote`.
type dataFixture struct {
	p          *Peer
	dev        *fakeDev
	remoteKey  *ecdh.PrivateKey
	remote     *net.UDPConn
	remoteAddr netip.AddrPort
	key        [proto.KeyLen]byte
	s          *session
	w          *workerBufs
}

func newDataFixture(t *testing.T) *dataFixture {
	t.Helper()
	f := &dataFixture{}
	f.remoteKey = mustKey(t)
	f.remote = listenLoopback(t)
	f.remoteAddr = addrOf(f.remote)
	f.key = randKey(0x5A)
	f.p, f.dev = newTestPeer(t, testPeerSpec{peers: []testPeerEntry{{key: f.remoteKey, allowed: []string{"10.9.0.2/32"}}}})
	f.s = f.p.addSession(t, pubOf(f.remoteKey), f.remoteAddr, f.key, "10.9.0.2/32")
	f.w = new(workerBufs)
	return f
}

func (f *dataFixture) deliver(t *testing.T, seq uint64, payload []byte) {
	t.Helper()
	pkt := wirePacket(t, f.key, seq, payload)
	f.p.handleUDP(f.remoteAddr, pkt, f.w)
}

// --- data path: UDP -> TUN ----------------------------------------------------

func TestDataPacketDeliveredToTUN(t *testing.T) {
	f := newDataFixture(t)
	pkt := ipv4("10.9.0.2", "10.9.0.1", []byte("hello"))
	f.deliver(t, 0, pkt)
	if got := f.dev.expect(t, time.Second); !bytes.Equal(got, pkt) {
		t.Fatalf("got % x want % x", got, pkt)
	}
}

func TestDataReplayDropped(t *testing.T) {
	f := newDataFixture(t)
	logs := captureLogs(t)
	pkt := ipv4("10.9.0.2", "10.9.0.1", []byte("once"))
	wire := wirePacket(t, f.key, 7, pkt)
	f.p.handleUDP(f.remoteAddr, wire, f.w)
	f.dev.expect(t, time.Second)
	f.p.handleUDP(f.remoteAddr, wire, f.w) // identical datagram replayed
	f.dev.expectNone(t, 100*time.Millisecond)
	if !strings.Contains(logs.String(), "Replay from") {
		t.Fatalf("replay not logged:\n%s", logs)
	}
}

func TestDataOutOfOrderAcceptedOnce(t *testing.T) {
	f := newDataFixture(t)
	a, b := ipv4("10.9.0.2", "10.9.0.1", []byte("a")), ipv4("10.9.0.2", "10.9.0.1", []byte("b"))
	f.deliver(t, 10, a)
	f.dev.expect(t, time.Second)
	f.deliver(t, 4, b) // late but inside the window
	if got := f.dev.expect(t, time.Second); !bytes.Equal(got, b) {
		t.Fatal("out-of-order packet not delivered")
	}
	f.deliver(t, 4, b)
	f.dev.expectNone(t, 100*time.Millisecond)
}

func TestDataTamperedDropped(t *testing.T) {
	f := newDataFixture(t)
	wire := wirePacket(t, f.key, 0, ipv4("10.9.0.2", "10.9.0.1", nil))
	wire[len(wire)-1] ^= 1
	f.p.handleUDP(f.remoteAddr, wire, f.w)
	f.dev.expectNone(t, 100*time.Millisecond)
}

func TestDataWrongKeyDropped(t *testing.T) {
	f := newDataFixture(t)
	wire := wirePacket(t, randKey(0x01), 0, ipv4("10.9.0.2", "10.9.0.1", nil))
	f.p.handleUDP(f.remoteAddr, wire, f.w)
	f.dev.expectNone(t, 100*time.Millisecond)
}

func TestDataGarbageDropped(t *testing.T) {
	f := newDataFixture(t)
	for _, n := range []int{0, 1, proto.CryptoOverhead - 1, proto.CryptoOverhead, 300} {
		f.p.handleUDP(f.remoteAddr, make([]byte, n), f.w)
	}
	f.dev.expectNone(t, 100*time.Millisecond)
}

func TestDataFromUnknownAddressDropped(t *testing.T) {
	f := newDataFixture(t)
	logs := captureLogs(t)
	wire := wirePacket(t, f.key, 0, ipv4("10.9.0.2", "10.9.0.1", nil))
	f.p.handleUDP(mustAddr("203.0.113.9:4000"), wire, f.w)
	f.dev.expectNone(t, 100*time.Millisecond)
	if !strings.Contains(logs.String(), "unknown peer 203.0.113.9:4000") {
		t.Fatalf("unknown sender not logged:\n%s", logs)
	}
}

func TestDataSameIPDifferentPortDropped(t *testing.T) {
	f := newDataFixture(t)
	wire := wirePacket(t, f.key, 0, ipv4("10.9.0.2", "10.9.0.1", nil))
	other := netip.AddrPortFrom(f.remoteAddr.Addr(), f.remoteAddr.Port()+1)
	f.p.handleUDP(other, wire, f.w)
	f.dev.expectNone(t, 100*time.Millisecond)
}

func TestDataBadMagicInsideCiphertextDropped(t *testing.T) {
	f := newDataFixture(t)
	plain := make([]byte, 16+20) // valid AEAD, but the magic is zeros
	enc, _ := proto.EncryptPacket(f.key[:], plain)
	f.p.handleUDP(f.remoteAddr, enc, f.w)
	f.dev.expectNone(t, 100*time.Millisecond)
}

func TestDataShortPlaintextDropped(t *testing.T) {
	f := newDataFixture(t)
	enc, _ := proto.EncryptPacket(f.key[:], proto.Header[:]) // magic but no sequence number
	f.p.handleUDP(f.remoteAddr, enc, f.w)
	f.dev.expectNone(t, 100*time.Millisecond)
}

func TestDataSpoofedSourceDropped(t *testing.T) {
	f := newDataFixture(t)
	logs := captureLogs(t)
	f.deliver(t, 0, ipv4("10.9.0.99", "10.9.0.1", nil)) // peer is only allowed 10.9.0.2/32
	f.dev.expectNone(t, 100*time.Millisecond)
	if !strings.Contains(logs.String(), "not in AllowedIPs") {
		t.Fatalf("spoof not logged:\n%s", logs)
	}
	f.deliver(t, 1, ipv4("10.9.0.2", "10.9.0.1", nil)) // legitimate source still works
	f.dev.expect(t, time.Second)
}

func TestDataNonIPv4Dropped(t *testing.T) {
	f := newDataFixture(t)
	v6 := make([]byte, 40)
	v6[0] = 0x60
	f.deliver(t, 0, v6)
	f.deliver(t, 1, []byte{0x45, 0, 0}) // IPv4 version nibble but truncated header
	f.dev.expectNone(t, 100*time.Millisecond)
}

func TestKeepaliveNotDeliveredButRefreshesLastSeen(t *testing.T) {
	f := newDataFixture(t)
	f.s.mu.Lock()
	if !f.s.lastSeen.IsZero() {
		t.Fatal("lastSeen should start unset")
	}
	f.s.mu.Unlock()
	f.deliver(t, 0, nil) // empty payload = keepalive
	f.dev.expectNone(t, 100*time.Millisecond)
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	if f.s.lastSeen.IsZero() {
		t.Fatal("authenticated keepalive must refresh lastSeen")
	}
}

func TestForgedPacketDoesNotRefreshLastSeen(t *testing.T) {
	f := newDataFixture(t)
	f.p.handleUDP(f.remoteAddr, make([]byte, 64), f.w) // unauthenticated junk from the right address
	wire := wirePacket(t, f.key, 3, nil)
	f.p.handleUDP(f.remoteAddr, wire, f.w)
	f.s.mu.Lock()
	first := f.s.lastSeen
	f.s.mu.Unlock()
	time.Sleep(5 * time.Millisecond)
	f.p.handleUDP(f.remoteAddr, wire, f.w) // replayed (authenticated but duplicate)
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	if !f.s.lastSeen.Equal(first) {
		t.Fatal("a replayed packet must not extend the session's life")
	}
}

// --- previous-key grace window ------------------------------------------------

func rekeyedFixture(t *testing.T) (*dataFixture, [proto.KeyLen]byte) {
	t.Helper()
	f := newDataFixture(t)
	oldKey, newKey := f.key, randKey(0xC3)
	f.p.tbl.mu.Lock()
	cfg := f.p.cfgs[0]
	if err := f.p.tbl.sessionInit(f.s, f.remoteAddr, pubOf(f.remoteKey), newKey, cfg, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	f.p.tbl.mu.Unlock()
	f.key = newKey
	return f, oldKey
}

func TestPrevKeyAcceptedWithinGrace(t *testing.T) {
	f, oldKey := rekeyedFixture(t)
	pkt := ipv4("10.9.0.2", "10.9.0.1", []byte("in-flight"))
	f.p.handleUDP(f.remoteAddr, wirePacket(t, oldKey, 5, pkt), f.w)
	if got := f.dev.expect(t, time.Second); !bytes.Equal(got, pkt) {
		t.Fatal("in-flight packet under the previous key was not delivered")
	}
}

func TestPrevKeyRejectedAfterGrace(t *testing.T) {
	f, oldKey := rekeyedFixture(t)
	f.s.mu.Lock()
	f.s.prevKeyExpires = time.Now().Add(-time.Second)
	f.s.mu.Unlock()
	f.p.handleUDP(f.remoteAddr, wirePacket(t, oldKey, 5, ipv4("10.9.0.2", "10.9.0.1", nil)), f.w)
	f.dev.expectNone(t, 100*time.Millisecond)
}

func TestPrevKeyRetiredOnFirstNewKeyPacket(t *testing.T) {
	f, oldKey := rekeyedFixture(t)
	f.deliver(t, 0, ipv4("10.9.0.2", "10.9.0.1", nil)) // initiator switched to the new key
	f.dev.expect(t, time.Second)
	f.p.handleUDP(f.remoteAddr, wirePacket(t, oldKey, 6, ipv4("10.9.0.2", "10.9.0.1", nil)), f.w)
	f.dev.expectNone(t, 100*time.Millisecond)
}

func TestPrevKeyPacketsDoNotPoisonReplayWindow(t *testing.T) {
	f, oldKey := rekeyedFixture(t)
	// A burst of old-key packets with high sequence numbers must not advance the
	// new session's replay window, or its seq 0,1,2... would be rejected.
	f.p.handleUDP(f.remoteAddr, wirePacket(t, oldKey, 100000, ipv4("10.9.0.2", "10.9.0.1", nil)), f.w)
	f.dev.expect(t, time.Second)
	for seq := uint64(0); seq < 3; seq++ {
		f.deliver(t, seq, ipv4("10.9.0.2", "10.9.0.1", nil))
		f.dev.expect(t, time.Second)
	}
}

// --- relaying between peers -----------------------------------------------------

func TestRelayForwardsBetweenPeers(t *testing.T) {
	p1Key, p2Key := mustKey(t), mustKey(t)
	c1, c2 := listenLoopback(t), listenLoopback(t)
	relay, dev := newTestPeer(t, testPeerSpec{peers: []testPeerEntry{
		{key: p1Key, allowed: []string{"10.9.0.2/32"}},
		{key: p2Key, allowed: []string{"10.9.0.3/32"}},
	}})
	k1, k2 := randKey(0x11), randKey(0x22)
	relay.addSession(t, pubOf(p1Key), addrOf(c1), k1, "10.9.0.2/32")
	relay.addSession(t, pubOf(p2Key), addrOf(c2), k2, "10.9.0.3/32")

	pkt := ipv4("10.9.0.2", "10.9.0.3", []byte("via relay"))
	relay.handleUDP(addrOf(c1), wirePacket(t, k1, 0, pkt), new(workerBufs))

	seq, got := readWire(t, c2, k2, time.Second)
	if !bytes.Equal(got, pkt) {
		t.Fatalf("p2 received % x", got)
	}
	if seq != 0 {
		t.Fatalf("relay's first packet to p2 should be seq 0, got %d", seq)
	}
	dev.expectNone(t, 100*time.Millisecond) // never touches the relay's own TUN
	expectNoDatagram(t, c1, 100*time.Millisecond)
}

func TestRelayDoesNotHairpinToSender(t *testing.T) {
	// dst belongs to the *sending* peer's own routes: deliver to TUN, not back.
	f := newDataFixture(t)
	pkt := ipv4("10.9.0.2", "10.9.0.2", nil)
	f.deliver(t, 0, pkt)
	f.dev.expect(t, time.Second)
	expectNoDatagram(t, f.remote, 100*time.Millisecond)
}

// --- data path: TUN -> UDP --------------------------------------------------------

func TestTUNForwardsToRoutedPeer(t *testing.T) {
	f := newDataFixture(t)
	pkt := ipv4("10.9.0.1", "10.9.0.2", []byte("outbound"))
	f.p.handleTUN(pkt, f.w)
	seq, got := readWire(t, f.remote, f.key, time.Second)
	if seq != 0 || !bytes.Equal(got, pkt) {
		t.Fatalf("seq=%d payload=% x", seq, got)
	}
	f.p.handleTUN(pkt, f.w)
	if seq, _ := readWire(t, f.remote, f.key, time.Second); seq != 1 {
		t.Fatalf("second packet seq=%d want 1", seq)
	}
}

func TestTUNLongestPrefixWins(t *testing.T) {
	aKey, bKey := mustKey(t), mustKey(t)
	ca, cb := listenLoopback(t), listenLoopback(t)
	p, _ := newTestPeer(t, testPeerSpec{peers: []testPeerEntry{{key: aKey}, {key: bKey}}})
	ka, kb := randKey(1), randKey(2)
	p.addSession(t, pubOf(aKey), addrOf(ca), ka, "10.9.0.0/16")
	p.addSession(t, pubOf(bKey), addrOf(cb), kb, "10.9.0.0/24")
	w := new(workerBufs)

	p.handleTUN(ipv4("10.9.0.1", "10.9.0.77", nil), w) // /24 wins
	readWire(t, cb, kb, time.Second)
	expectNoDatagram(t, ca, 100*time.Millisecond)

	p.handleTUN(ipv4("10.9.0.1", "10.9.5.5", nil), w) // only the /16 matches
	readWire(t, ca, ka, time.Second)
	expectNoDatagram(t, cb, 100*time.Millisecond)
}

func TestTUNNoRouteDropped(t *testing.T) {
	f := newDataFixture(t)
	f.p.handleTUN(ipv4("10.9.0.1", "192.168.50.50", nil), f.w)
	expectNoDatagram(t, f.remote, 100*time.Millisecond)
}

func TestTUNNonIPv4Dropped(t *testing.T) {
	f := newDataFixture(t)
	v6 := make([]byte, 40)
	v6[0] = 0x60
	f.p.handleTUN(v6, f.w)
	f.p.handleTUN([]byte{0x45, 1, 2}, f.w) // too short
	f.p.handleTUN(nil, f.w)
	expectNoDatagram(t, f.remote, 100*time.Millisecond)
}

func TestTUNInactiveSessionNotRouted(t *testing.T) {
	f := newDataFixture(t)
	f.p.tbl.mu.Lock()
	f.s.active = false
	f.p.tbl.mu.Unlock()
	f.p.handleTUN(ipv4("10.9.0.1", "10.9.0.2", nil), f.w)
	expectNoDatagram(t, f.remote, 100*time.Millisecond)
}

func TestMaxSizePacketRoundtrip(t *testing.T) {
	f := newDataFixture(t)
	pkt := ipv4("10.9.0.1", "10.9.0.2", bytes.Repeat([]byte{0xAB}, proto.TunMTU-20))
	f.p.handleTUN(pkt, f.w)
	_, got := readWire(t, f.remote, f.key, time.Second)
	if !bytes.Equal(got, pkt) {
		t.Fatal("max-MTU packet corrupted")
	}
	// ...and back (from the peer's own allowed source address).
	back := ipv4("10.9.0.2", "10.9.0.1", bytes.Repeat([]byte{0xCD}, proto.TunMTU-20))
	f.deliver(t, 0, back)
	if got := f.dev.expect(t, time.Second); !bytes.Equal(got, back) {
		t.Fatal("max-MTU packet corrupted on delivery")
	}
}

// --- Run ------------------------------------------------------------------------------

func TestRunStopsCleanlyOnCancel(t *testing.T) {
	remote := mustKey(t)
	p, dev := newTestPeer(t, testPeerSpec{peers: []testPeerEntry{{key: remote}}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v on clean shutdown", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	select {
	case <-dev.closed:
	default:
		t.Fatal("Run must close the TUN device")
	}
}

type failingDev struct{ *fakeDev }

func (failingDev) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestRunReturnsFatalTUNError(t *testing.T) {
	remote := mustKey(t)
	p, _ := newTestPeer(t, testPeerSpec{peers: []testPeerEntry{{key: remote}}})
	p.dev = failingDev{newFakeDev()}
	done := make(chan error, 1)
	go func() { done <- p.Run(context.Background()) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "TUN read: boom") {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit on a fatal TUN error")
	}
}

// --- New / endpoint resolution ----------------------------------------------------------

func TestNewResolvesEndpoints(t *testing.T) {
	remote := mustKey(t)
	p, _ := newTestPeer(t, testPeerSpec{peers: []testPeerEntry{
		{key: remote, endpoint: "127.0.0.1:5040"},
		{key: mustKey(t)},
	}})
	if got := p.cfgs[0].endpoint; got != mustAddr("127.0.0.1:5040") {
		t.Fatalf("endpoint=%v", got)
	}
	if p.cfgs[1].hasEndpoint {
		t.Fatal("peer without endpoint must be inbound-only")
	}
}

func TestNewResolvesLocalhost(t *testing.T) {
	p, _ := newTestPeer(t, testPeerSpec{peers: []testPeerEntry{{key: mustKey(t), endpoint: "localhost:5040"}}})
	if got := p.cfgs[0].endpoint; !got.Addr().IsLoopback() || got.Port() != 5040 {
		t.Fatalf("endpoint=%v", got)
	}
}

func TestPSKControlsHandshakeSize(t *testing.T) {
	remote := mustKey(t)
	p, _ := newTestPeer(t, testPeerSpec{peers: []testPeerEntry{{key: remote}}})
	if p.psk != nil || p.hsSize != 88 {
		t.Fatalf("no-PSK: psk=%v hsSize=%d", p.psk, p.hsSize)
	}
	p, _ = newTestPeer(t, testPeerSpec{psk: "x", peers: []testPeerEntry{{key: remote}}})
	if p.psk == nil || p.hsSize != 120 {
		t.Fatalf("PSK: hsSize=%d", p.hsSize)
	}
}
