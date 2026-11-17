package peer

import (
	"bytes"
	"crypto/ecdh"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jecklgamis/microtunnel/internal/proto"
)

// hsEnv is a responder ("relay") that knows one client, plus the client's side
// of the exchange driven by hand.
type hsEnv struct {
	relay      *Peer
	relayKey   *ecdh.PrivateKey
	clientKey  *ecdh.PrivateKey
	clientConn *net.UDPConn
	clientAddr netip.AddrPort
	psk        *[proto.KeyLen]byte
}

func newHSEnv(t *testing.T, psk string) *hsEnv {
	t.Helper()
	e := &hsEnv{relayKey: mustKey(t), clientKey: mustKey(t), clientConn: listenLoopback(t)}
	e.clientAddr = addrOf(e.clientConn)
	e.relay, _ = newTestPeer(t, testPeerSpec{key: e.relayKey, psk: psk,
		peers: []testPeerEntry{{key: e.clientKey, allowed: []string{"10.9.0.2/32"}}}})
	if psk != "" {
		k := proto.DeriveKey(psk)
		e.psk = &k
	}
	return e
}

func (e *hsEnv) initiate(t *testing.T) ([]byte, *proto.ClientState) {
	t.Helper()
	rp := pubOf(e.relayKey)
	msg, st, err := proto.ClientInit(e.clientKey, rp[:], e.psk)
	if err != nil {
		t.Fatal(err)
	}
	return msg, st
}

func (e *hsEnv) finish(t *testing.T, resp []byte, st *proto.ClientState) [proto.KeyLen]byte {
	t.Helper()
	rp := pubOf(e.relayKey)
	key, err := proto.ClientFinish(resp, e.psk, e.clientKey, rp[:], st)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func (e *hsEnv) readResponse(t *testing.T) []byte {
	t.Helper()
	_ = e.clientConn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 512)
	n, _, err := e.clientConn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("no handshake response: %v", err)
	}
	return buf[:n]
}

func (e *hsEnv) noResponse(t *testing.T) {
	t.Helper()
	expectNoDatagram(t, e.clientConn, 150*time.Millisecond)
}

func TestInboundHandshakeEstablishesSession(t *testing.T) {
	for _, psk := range []string{"", "some-psk"} {
		t.Run("psk="+psk, func(t *testing.T) {
			e := newHSEnv(t, psk)
			msg, st := e.initiate(t)
			e.relay.handleUDP(e.clientAddr, msg, new(workerBufs)) // dispatches by size+magic

			clientKey := e.finish(t, e.readResponse(t), st)
			serverKey, ok := e.relay.sessionKey(pubOf(e.clientKey))
			if !ok {
				t.Fatal("no session created")
			}
			if serverKey != clientKey {
				t.Fatal("client and server derived different session keys")
			}
			e.relay.tbl.mu.RLock()
			defer e.relay.tbl.mu.RUnlock()
			s := e.relay.tbl.findByPub(pubOf(e.clientKey))
			if s.isOutbound {
				t.Error("inbound session flagged outbound")
			}
			if len(s.routes) != 1 || s.routes[0].String() != "10.9.0.2/32" {
				t.Errorf("routes=%v", s.routes)
			}
			if s.addr != e.clientAddr {
				t.Errorf("addr=%v want %v", s.addr, e.clientAddr)
			}
		})
	}
}

func TestInboundHandshakeThenDataFlows(t *testing.T) {
	e := newHSEnv(t, "psk")
	msg, st := e.initiate(t)
	e.relay.handleUDP(e.clientAddr, msg, new(workerBufs))
	key := e.finish(t, e.readResponse(t), st)

	pkt := ipv4("10.9.0.2", "10.9.0.1", []byte("post-handshake"))
	dev := e.relay.dev.(*fakeDev)
	e.relay.handleUDP(e.clientAddr, wirePacket(t, key, 0, pkt), new(workerBufs))
	if got := dev.expect(t, time.Second); !bytes.Equal(got, pkt) {
		t.Fatal("data under the negotiated key was not delivered")
	}
}

func TestInboundHandshakeUnknownPeerRejectedWithoutReply(t *testing.T) {
	e := newHSEnv(t, "")
	stranger := mustKey(t)
	rp := pubOf(e.relayKey)
	msg, _, err := proto.ClientInit(stranger, rp[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	logs := captureLogs(t)
	e.relay.handleHandshake(e.clientAddr, msg, time.Now())
	e.noResponse(t)
	if e.relay.activeSessions() != 0 {
		t.Fatal("session created for an unknown peer")
	}
	if !strings.Contains(logs.String(), "Unknown peer public key") {
		t.Fatalf("rejection not logged:\n%s", logs)
	}
}

func TestInboundHandshakePSKMismatchRejected(t *testing.T) {
	e := newHSEnv(t, "right")
	rp := pubOf(e.relayKey)
	wrong := proto.DeriveKey("wrong")
	msg, _, _ := proto.ClientInit(e.clientKey, rp[:], &wrong)
	e.relay.handleHandshake(e.clientAddr, msg, time.Now())
	e.noResponse(t)
	if e.relay.activeSessions() != 0 {
		t.Fatal("session created despite PSK mismatch")
	}
}

func TestInboundHandshakeWithoutPSKWhenRequiredIgnored(t *testing.T) {
	e := newHSEnv(t, "required")
	rp := pubOf(e.relayKey)
	msg, _, _ := proto.ClientInit(e.clientKey, rp[:], nil) // 88 bytes, not 120
	e.relay.handleUDP(e.clientAddr, msg, new(workerBufs))  // wrong size: treated as (undecryptable) data
	e.noResponse(t)
	if e.relay.activeSessions() != 0 {
		t.Fatal("unauthenticated handshake accepted while a PSK is required")
	}
}

func TestInboundHandshakeGarbageIgnored(t *testing.T) {
	e := newHSEnv(t, "")
	junk := append(append([]byte(nil), proto.Header[:]...), make([]byte, proto.HandshakeSize(false)-proto.HeaderSize)...)
	e.relay.handleHandshake(e.clientAddr, junk, time.Now())
	e.noResponse(t)
	if e.relay.activeSessions() != 0 {
		t.Fatal("garbage handshake created a session")
	}
}

func TestHandshakeCooldownIgnoresRapidRepeat(t *testing.T) {
	e := newHSEnv(t, "")
	msg, st := e.initiate(t)
	e.relay.handleHandshake(e.clientAddr, msg, time.Now())
	first := e.finish(t, e.readResponse(t), st)

	// An immediate second initiation (replayed, or a flood) is within the 5s cooldown.
	msg2, _ := e.initiate(t)
	e.relay.handleHandshake(e.clientAddr, msg2, time.Now())
	e.noResponse(t)
	if k, _ := e.relay.sessionKey(pubOf(e.clientKey)); k != first {
		t.Fatal("cooldown violated: session key changed")
	}
}

func TestHandshakeCooldownByPublicKeyAcrossAddresses(t *testing.T) {
	e := newHSEnv(t, "")
	msg, st := e.initiate(t)
	e.relay.handleHandshake(e.clientAddr, msg, time.Now())
	first := e.finish(t, e.readResponse(t), st)

	// Same key from a different source address immediately afterwards: blocked
	// by the per-key cooldown (the per-address check can't see it).
	other := listenLoopback(t)
	msg2, _ := e.initiate(t)
	e.relay.handleHandshake(addrOf(other), msg2, time.Now())
	expectNoDatagram(t, other, 150*time.Millisecond)
	if k, _ := e.relay.sessionKey(pubOf(e.clientKey)); k != first {
		t.Fatal("per-key cooldown violated")
	}
}

func TestRekeyAfterCooldownKeepsPreviousKey(t *testing.T) {
	e := newHSEnv(t, "")
	e.relay.hsCooldown = 0
	msg, st := e.initiate(t)
	e.relay.handleHandshake(e.clientAddr, msg, time.Now())
	first := e.finish(t, e.readResponse(t), st)

	msg2, st2 := e.initiate(t)
	e.relay.handleHandshake(e.clientAddr, msg2, time.Now())
	second := e.finish(t, e.readResponse(t), st2)
	if first == second {
		t.Fatal("rekey produced the same session key")
	}

	e.relay.tbl.mu.RLock()
	defer e.relay.tbl.mu.RUnlock()
	s := e.relay.tbl.findByPub(pubOf(e.clientKey))
	if !s.prevKeyActive || s.prevKey != first || s.key != second {
		t.Fatal("responder must keep the old key as a decrypt fallback")
	}
	if e.relay.tbl.slots != 1 {
		t.Fatalf("rekey consumed a new slot (slots=%d)", e.relay.tbl.slots)
	}
}

func TestHandshakeFromNewAddressRoams(t *testing.T) {
	e := newHSEnv(t, "")
	e.relay.hsCooldown = 0
	msg, st := e.initiate(t)
	e.relay.handleHandshake(e.clientAddr, msg, time.Now())
	e.finish(t, e.readResponse(t), st)

	// The client's NAT mapping changed: same key now arrives from a new port.
	moved := listenLoopback(t)
	msg2, st2 := e.initiate(t)
	e.relay.handleHandshake(addrOf(moved), msg2, time.Now())
	_ = moved.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 512)
	n, _, err := moved.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("no response at the new address: %v", err)
	}
	e.finish(t, buf[:n], st2)

	e.relay.tbl.mu.RLock()
	defer e.relay.tbl.mu.RUnlock()
	if s := e.relay.tbl.findByAddr(addrOf(moved)); s == nil {
		t.Fatal("session not re-homed to the new address")
	}
	if e.relay.tbl.findByAddr(e.clientAddr) != nil {
		t.Fatal("stale address still maps to a session")
	}
	if e.relay.tbl.slots != 1 {
		t.Fatalf("slots=%d, roaming must reuse the slot", e.relay.tbl.slots)
	}
}

func TestHandshakeRejectedWhenTableFull(t *testing.T) {
	e := newHSEnv(t, "")
	for i := 0; i < MaxPeers; i++ {
		e.relay.addSession(t, pubFill(byte(i+1)), mustAddr("198.51.100.1:"+itoa(2000+i)), randKey(byte(i)))
	}
	msg, _ := e.initiate(t)
	e.relay.handleHandshake(e.clientAddr, msg, time.Now())
	e.noResponse(t)
	if _, ok := e.relay.sessionKey(pubOf(e.clientKey)); ok {
		t.Fatal("session created in a full table")
	}
}

// --- outbound handshake (we are the initiator) ------------------------------------

type outEnv struct {
	p         *Peer
	selfKey   *ecdh.PrivateKey
	serverKey *ecdh.PrivateKey
	server    *net.UDPConn
	psk       *[proto.KeyLen]byte
}

func newOutEnv(t *testing.T, psk string) *outEnv {
	t.Helper()
	o := &outEnv{selfKey: mustKey(t), serverKey: mustKey(t), server: listenLoopback(t)}
	o.p, _ = newTestPeer(t, testPeerSpec{key: o.selfKey, psk: psk, peers: []testPeerEntry{
		{key: o.serverKey, endpoint: addrOf(o.server).String(), allowed: []string{"10.9.0.0/24"}},
	}})
	if psk != "" {
		k := proto.DeriveKey(psk)
		o.psk = &k
	}
	return o
}

// serverReceive reads the initiation the peer sent and builds the response a
// real server would.
func (o *outEnv) serverReceive(t *testing.T) (resp []byte, sessionKey [proto.KeyLen]byte, from netip.AddrPort) {
	t.Helper()
	_ = o.server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 512)
	n, from, err := o.server.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("no handshake initiation sent: %v", err)
	}
	resp, _, sessionKey, err = proto.ServerRespond(buf[:n], o.psk, o.serverKey, mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return resp, sessionKey, from
}

func TestInitiateSendsHandshakeAndRecordsPending(t *testing.T) {
	o := newOutEnv(t, "psk")
	o.p.tbl.mu.Lock()
	err := o.p.initiate(0, time.Now())
	o.p.tbl.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	o.serverReceive(t)
	o.p.tbl.mu.RLock()
	defer o.p.tbl.mu.RUnlock()
	if !o.p.tbl.pending[0].active || o.p.tbl.pending[0].serverAddr != addrOf(o.server) {
		t.Fatalf("pending not recorded: %+v", o.p.tbl.pending[0])
	}
}

func TestOutboundHandshakeCompletesOnResponse(t *testing.T) {
	for _, psk := range []string{"", "some-psk"} {
		t.Run("psk="+psk, func(t *testing.T) {
			o := newOutEnv(t, psk)
			o.p.tbl.mu.Lock()
			_ = o.p.initiate(0, time.Now())
			o.p.tbl.mu.Unlock()
			resp, serverKey, from := o.serverReceive(t)

			o.p.handleUDP(addrOf(o.server), resp, new(workerBufs))
			key, ok := o.p.sessionKey(pubOf(o.serverKey))
			if !ok {
				t.Fatal("no session after a valid response")
			}
			if key != serverKey {
				t.Fatal("session keys differ")
			}
			o.p.tbl.mu.RLock()
			defer o.p.tbl.mu.RUnlock()
			s := o.p.tbl.findByPub(pubOf(o.serverKey))
			if !s.isOutbound || s.rekeying {
				t.Errorf("outbound=%v rekeying=%v", s.isOutbound, s.rekeying)
			}
			if o.p.tbl.pending[0].active {
				t.Error("pending entry not cleared")
			}
			if len(s.routes) != 1 || s.routes[0].String() != "10.9.0.0/24" {
				t.Errorf("routes=%v", s.routes)
			}
			_ = from
		})
	}
}

func TestOutboundHandshakeForgedResponseIgnored(t *testing.T) {
	o := newOutEnv(t, "psk")
	o.p.tbl.mu.Lock()
	_ = o.p.initiate(0, time.Now())
	o.p.tbl.mu.Unlock()
	resp, serverKey, _ := o.serverReceive(t)

	forged := append([]byte(nil), resp...)
	forged[len(forged)-1] ^= 1 // break the HMAC
	o.p.handleHandshake(addrOf(o.server), forged, time.Now())
	if o.p.activeSessions() != 0 {
		t.Fatal("session established from a forged response")
	}
	if !o.p.tbl.pending[0].active {
		t.Fatal("a forged packet must not cancel the legitimate pending handshake")
	}

	// The genuine response still completes the handshake afterwards.
	o.p.handleHandshake(addrOf(o.server), resp, time.Now())
	if k, ok := o.p.sessionKey(pubOf(o.serverKey)); !ok || k != serverKey {
		t.Fatal("genuine response rejected after a forged one")
	}
}

func TestOutboundResponseFromWrongAddressIgnored(t *testing.T) {
	o := newOutEnv(t, "")
	o.p.tbl.mu.Lock()
	_ = o.p.initiate(0, time.Now())
	o.p.tbl.mu.Unlock()
	resp, _, _ := o.serverReceive(t)
	o.p.handleHandshake(mustAddr("203.0.113.5:5040"), resp, time.Now()) // spoofed source
	if o.p.activeSessions() != 0 {
		t.Fatal("response accepted from an address we never contacted")
	}
	if !o.p.tbl.pending[0].active {
		t.Fatal("a spoofed response must not consume the pending handshake")
	}
}

func TestInitiateFailsWhenNoPendingSlots(t *testing.T) {
	o := newOutEnv(t, "")
	o.p.tbl.mu.Lock()
	defer o.p.tbl.mu.Unlock()
	for i := range o.p.tbl.pending {
		o.p.tbl.pending[i].active = true
	}
	if err := o.p.initiate(0, time.Now()); err == nil {
		t.Fatal("expected an error with all pending slots in use")
	}
}

// --- simultaneous rekey collision --------------------------------------------------

func keysOrdered(t *testing.T, aHigher bool) (a, b *ecdh.PrivateKey) {
	t.Helper()
	for {
		a, b = mustKey(t), mustKey(t)
		pa, pb := pubOf(a), pubOf(b)
		if (bytes.Compare(pa[:], pb[:]) > 0) == aHigher {
			return a, b
		}
	}
}

// collisionEnv: peer A has an established session with B and has just sent a
// rekey initiation (pending); B's own initiation arrives before B's response.
func collisionEnv(t *testing.T, aHigher bool) (a *Peer, bKey *ecdh.PrivateKey, bConn *net.UDPConn, initFromB []byte, bState *proto.ClientState) {
	t.Helper()
	aKey, bk := keysOrdered(t, aHigher)
	bConn = listenLoopback(t)
	a, _ = newTestPeer(t, testPeerSpec{key: aKey, peers: []testPeerEntry{
		{key: bk, endpoint: addrOf(bConn).String(), allowed: []string{"10.9.0.0/24"}},
	}})
	a.hsCooldown = 0
	a.addSession(t, pubOf(bk), addrOf(bConn), randKey(9), "10.9.0.0/24")

	a.tbl.mu.Lock()
	a.tbl.findByPub(pubOf(bk)).rekeying = true
	if err := a.initiate(0, time.Now()); err != nil {
		t.Fatal(err)
	}
	a.tbl.mu.Unlock()
	readWire := make([]byte, 512)
	_ = bConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := bConn.ReadFromUDPAddrPort(readWire); err != nil { // drain A's initiation
		t.Fatal(err)
	}
	ap := pubOf(aKey)
	initFromB, bState, err := proto.ClientInit(bk, ap[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	return a, bk, bConn, initFromB, bState
}

func TestRekeyCollisionHigherKeyIgnoresInitiation(t *testing.T) {
	a, bk, bConn, initFromB, _ := collisionEnv(t, true)
	before, _ := a.sessionKey(pubOf(bk))
	a.handleHandshake(addrOf(bConn), initFromB, time.Now())

	expectNoDatagram(t, bConn, 150*time.Millisecond) // no response: A's own handshake wins
	if !a.tbl.pending[0].active {
		t.Fatal("the winner's pending handshake must stay active")
	}
	if after, _ := a.sessionKey(pubOf(bk)); after != before {
		t.Fatal("session key changed although the initiation was ignored")
	}
}

func TestRekeyCollisionLowerKeyYields(t *testing.T) {
	a, bk, bConn, initFromB, bState := collisionEnv(t, false)
	before, _ := a.sessionKey(pubOf(bk))
	a.handleHandshake(addrOf(bConn), initFromB, time.Now())

	if a.tbl.pending[0].active {
		t.Fatal("the loser must abandon its own pending handshake")
	}
	_ = bConn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 512)
	n, _, err := bConn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("loser did not answer the winner's initiation: %v", err)
	}
	ap := proto.PubBytes(a.static)
	bKey, err := proto.ClientFinish(buf[:n], nil, mustKeyFrom(t, bk), ap[:], bState)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := a.sessionKey(pubOf(bk))
	if after == before || after != bKey {
		t.Fatal("loser did not adopt the winner's session key")
	}
	a.tbl.mu.RLock()
	defer a.tbl.mu.RUnlock()
	if a.tbl.findByPub(pubOf(bk)).rekeying {
		t.Fatal("rekeying flag must be cleared after yielding")
	}
}

func mustKeyFrom(t *testing.T, k *ecdh.PrivateKey) *ecdh.PrivateKey { t.Helper(); return k }

func TestRekeyCollisionForgedInitiationCannotCancelPending(t *testing.T) {
	// We hold the *lower* key, so a genuine initiation from the peer would make
	// us yield. A forged packet from the peer's address must not.
	a, bk, bConn, initFromB, _ := collisionEnv(t, false)
	forged := append([]byte(nil), initFromB...)
	forged[len(forged)-1] ^= 0xff
	forged[proto.HeaderSize] ^= 0xff // corrupt the ephemeral key too
	before, _ := a.sessionKey(pubOf(bk))
	a.handleHandshake(addrOf(bConn), forged, time.Now())

	if !a.tbl.pending[0].active {
		t.Fatal("a forged initiation cancelled our pending handshake")
	}
	expectNoDatagram(t, bConn, 150*time.Millisecond)
	if after, _ := a.sessionKey(pubOf(bk)); after != before {
		t.Fatal("session changed on a forged initiation")
	}
	a.tbl.mu.RLock()
	defer a.tbl.mu.RUnlock()
	if !a.tbl.findByPub(pubOf(bk)).rekeying {
		t.Fatal("rekeying flag cleared by a forged packet")
	}
}
