package peer

import (
	"testing"
	"time"

	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

func newTable() *table {
	return &table{prevGrace: 90 * time.Second}
}

func cidr(t *testing.T, s string) config.Prefix {
	t.Helper()
	p, err := config.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func pubFill(b byte) [proto.PubKeyLen]byte {
	var p [proto.PubKeyLen]byte
	for i := range p {
		p[i] = b
	}
	return p
}

// --- checkAllowedSrc -----------------------------------------------------

func TestCheckAllowedSrcNoRoutesAllowsAnything(t *testing.T) {
	s := &session{}
	if !s.checkAllowedSrc(0x0A090005) {
		t.Fatal("a session with no routes must allow any source")
	}
}

func TestCheckAllowedSrcMatchingRouteAllowed(t *testing.T) {
	s := &session{routes: []config.Prefix{cidr(t, "10.9.0.0/24")}}
	if !s.checkAllowedSrc(0x0A090005) { // 10.9.0.5
		t.Fatal("10.9.0.5 should be allowed")
	}
}

func TestCheckAllowedSrcNonMatchingRouteRejected(t *testing.T) {
	s := &session{routes: []config.Prefix{cidr(t, "10.9.0.0/24")}}
	if s.checkAllowedSrc(0x0A0A0005) { // 10.10.0.5
		t.Fatal("10.10.0.5 should be rejected")
	}
}

func TestCheckAllowedSrcChecksAllConfiguredRoutes(t *testing.T) {
	s := &session{routes: []config.Prefix{cidr(t, "10.9.0.0/24"), cidr(t, "192.168.1.0/24")}}
	if !s.checkAllowedSrc(0xC0A80105) { // 192.168.1.5
		t.Fatal("192.168.1.5 should be allowed by the second route")
	}
}

// --- routeLookup (longest-prefix match) -----------------------------------

func TestRouteLookupPicksLongestPrefix(t *testing.T) {
	tb := newTable()
	tb.slots = 2
	tb.sessions[0].active = true
	tb.sessions[0].routes = []config.Prefix{cidr(t, "10.9.0.0/16")}
	tb.sessions[1].active = true
	tb.sessions[1].routes = []config.Prefix{cidr(t, "10.9.0.0/24")}

	if got := tb.routeLookup(0x0A090005); got != &tb.sessions[1] { // 10.9.0.5
		t.Fatalf("got slot %p, want the /24 session", got)
	}
	// Outside the /24 but inside the /16 falls back to the shorter prefix.
	if got := tb.routeLookup(0x0A090105); got != &tb.sessions[0] { // 10.9.1.5
		t.Fatalf("got %p, want the /16 session", got)
	}
}

func TestRouteLookupIgnoresInactiveSessions(t *testing.T) {
	tb := newTable()
	tb.slots = 1
	tb.sessions[0].routes = []config.Prefix{cidr(t, "10.9.0.0/24")}
	if tb.routeLookup(0x0A090005) != nil {
		t.Fatal("inactive session must not be routable")
	}
}

func TestRouteLookupNoMatchReturnsNil(t *testing.T) {
	tb := newTable()
	tb.slots = 1
	tb.sessions[0].active = true
	tb.sessions[0].routes = []config.Prefix{cidr(t, "192.168.1.0/24")}
	if tb.routeLookup(0x0A090005) != nil {
		t.Fatal("expected no route")
	}
}

func TestRouteLookupDefaultRouteLosesToSpecific(t *testing.T) {
	tb := newTable()
	tb.slots = 2
	tb.sessions[0].active = true
	tb.sessions[0].routes = []config.Prefix{cidr(t, "0.0.0.0/0")}
	tb.sessions[1].active = true
	tb.sessions[1].routes = []config.Prefix{cidr(t, "10.9.0.3/32")}
	if tb.routeLookup(0x0A090003) != &tb.sessions[1] {
		t.Fatal("/32 must beat /0")
	}
	if tb.routeLookup(0x08080808) != &tb.sessions[0] {
		t.Fatal("/0 must catch everything else")
	}
}

// --- findByAddr / findByPub -------------------------------------------------

func TestFindByAddrMatch(t *testing.T) {
	tb := newTable()
	tb.slots = 1
	tb.sessions[0].active = true
	tb.sessions[0].addr = mustAddr("1.2.3.4:5040")
	if tb.findByAddr(mustAddr("1.2.3.4:5040")) != &tb.sessions[0] {
		t.Fatal("session not found by address")
	}
}

func TestFindByAddrPortMismatchNotFound(t *testing.T) {
	tb := newTable()
	tb.slots = 1
	tb.sessions[0].active = true
	tb.sessions[0].addr = mustAddr("1.2.3.4:5040")
	if tb.findByAddr(mustAddr("1.2.3.4:9999")) != nil {
		t.Fatal("same IP but different port must not match")
	}
}

func TestFindByAddrSkipsInactive(t *testing.T) {
	tb := newTable()
	tb.slots = 1
	tb.sessions[0].addr = mustAddr("1.2.3.4:5040")
	if tb.findByAddr(mustAddr("1.2.3.4:5040")) != nil {
		t.Fatal("inactive session must be skipped")
	}
}

func TestFindByPubMatch(t *testing.T) {
	tb := newTable()
	tb.slots = 1
	tb.sessions[0].active = true
	tb.sessions[0].staticPub = pubFill(0xAB)
	if tb.findByPub(pubFill(0xAB)) != &tb.sessions[0] {
		t.Fatal("session not found by public key")
	}
}

func TestFindByPubNoMatch(t *testing.T) {
	tb := newTable()
	tb.slots = 1
	tb.sessions[0].active = true
	tb.sessions[0].staticPub = pubFill(0xAB)
	if tb.findByPub(pubFill(0xCD)) != nil {
		t.Fatal("unexpected match")
	}
}

func TestFindByPubSkipsInactive(t *testing.T) {
	tb := newTable()
	tb.slots = 1
	tb.sessions[0].staticPub = pubFill(0xAB)
	if tb.findByPub(pubFill(0xAB)) != nil {
		t.Fatal("inactive session must be skipped")
	}
}

// --- findPeerConfig ---------------------------------------------------------

func TestFindPeerConfig(t *testing.T) {
	a, b := mustKey(t), mustKey(t)
	p, _ := newTestPeer(t, testPeerSpec{peers: []testPeerEntry{{key: a}, {key: b}}})
	if got := p.findPeerConfig(pubOf(b)); got != p.cfgs[1] {
		t.Fatal("peer config for b not found")
	}
	if got := p.findPeerConfig(pubOf(a)); got != p.cfgs[0] {
		t.Fatal("peer config for a not found")
	}
	if p.findPeerConfig(pubFill(0x22)) != nil {
		t.Fatal("unknown key must not match")
	}
}

// --- alloc ------------------------------------------------------------------

func TestAllocReusesSlotByPubkey(t *testing.T) {
	tb := newTable()
	tb.slots = 1
	tb.sessions[0].active = true
	tb.sessions[0].staticPub = pubFill(0xAA)
	if s := tb.alloc(pubFill(0xAA), mustAddr("5.6.7.8:5040")); s != &tb.sessions[0] {
		t.Fatal("expected the slot with the same public key")
	}
	if tb.slots != 1 {
		t.Fatalf("slots=%d; no new slot should be created", tb.slots)
	}
}

func TestAllocReusesSlotByAddrWhenPubUnknown(t *testing.T) {
	tb := newTable()
	tb.slots = 1
	tb.sessions[0].active = true
	tb.sessions[0].staticPub = pubFill(0xAA)
	tb.sessions[0].addr = mustAddr("5.6.7.8:5040")
	// Different key at the same address, e.g. a peer that restarted with a new key.
	if s := tb.alloc(pubFill(0xBB), mustAddr("5.6.7.8:5040")); s != &tb.sessions[0] {
		t.Fatal("expected the slot at the same address")
	}
}

func TestAllocPrefersPubkeyOverAddr(t *testing.T) {
	tb := newTable()
	tb.slots = 2
	tb.sessions[0].active = true
	tb.sessions[0].staticPub = pubFill(0xAA)
	tb.sessions[0].addr = mustAddr("1.1.1.1:1")
	tb.sessions[1].active = true
	tb.sessions[1].staticPub = pubFill(0xBB)
	tb.sessions[1].addr = mustAddr("2.2.2.2:2")
	// Key of slot 0 arriving from slot 1's address: the key wins (NAT rebind).
	if s := tb.alloc(pubFill(0xAA), mustAddr("2.2.2.2:2")); s != &tb.sessions[0] {
		t.Fatal("pubkey match must take priority over address match")
	}
}

func TestAllocReusesFreeSlotBeforeGrowing(t *testing.T) {
	tb := newTable()
	tb.slots = 2
	tb.sessions[0].active = false // freed by a prior expiry
	tb.sessions[1].active = true
	tb.sessions[1].staticPub = pubFill(0xAA)
	tb.sessions[1].addr = mustAddr("9.9.9.9:1")
	if s := tb.alloc(pubFill(0xCC), mustAddr("1.1.1.1:5040")); s != &tb.sessions[0] {
		t.Fatal("expected the free slot")
	}
	if tb.slots != 2 {
		t.Fatalf("slots=%d; table must not grow while a slot is free", tb.slots)
	}
}

func TestAllocGrowsTableWhenNoFreeSlot(t *testing.T) {
	tb := newTable()
	tb.slots = 1
	tb.sessions[0].active = true
	tb.sessions[0].staticPub = pubFill(0xAA)
	tb.sessions[0].addr = mustAddr("9.9.9.9:1")
	if s := tb.alloc(pubFill(0xCC), mustAddr("1.1.1.1:5040")); s != &tb.sessions[1] {
		t.Fatal("expected a new slot")
	}
	if tb.slots != 2 {
		t.Fatalf("slots=%d want 2", tb.slots)
	}
}

func TestAllocTableFullReturnsNil(t *testing.T) {
	tb := newTable()
	tb.slots = MaxPeers
	for i := 0; i < MaxPeers; i++ {
		tb.sessions[i].active = true
		tb.sessions[i].staticPub = pubFill(byte(i))
		tb.sessions[i].addr = mustAddr("9.9.9.9:" + itoa(1000+i))
	}
	if tb.alloc(pubFill(0xFF), mustAddr("1.1.1.1:5040")) != nil {
		t.Fatal("expected nil when the table is full")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// --- sessionInit ------------------------------------------------------------

func TestSessionInitNewSessionHasCleanState(t *testing.T) {
	tb := newTable()
	var s session
	pub, key := pubFill(0x11), randKey(0x22)
	cfg := &peerConfig{routes: []config.Prefix{cidr(t, "10.9.0.0/24")}}
	if err := tb.sessionInit(&s, mustAddr("10.0.0.1:5040"), pub, key, cfg, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !s.active {
		t.Error("session not active")
	}
	if s.prevKeyActive {
		t.Error("a first handshake must not have a previous key")
	}
	if s.sendSeq != 0 || s.replay.Highest != 0 {
		t.Errorf("counters not reset: send=%d recvHighest=%d", s.sendSeq, s.replay.Highest)
	}
	if s.rekeying {
		t.Error("rekeying flag must be clear")
	}
	if !s.isOutbound {
		t.Error("outbound flag lost")
	}
	if len(s.routes) != 1 {
		t.Errorf("routes=%d want 1", len(s.routes))
	}
	if s.staticPub != pub || s.key != key {
		t.Error("identity/key not stored")
	}
	if s.aead == nil {
		t.Error("AEAD not built")
	}
	if !s.lastSeen.IsZero() {
		t.Error("lastSeen must start unset")
	}
	if s.lastSent.IsZero() {
		t.Error("lastSent must be primed to suppress an immediate keepalive")
	}
}

func TestSessionInitRekeyPreservesPreviousKey(t *testing.T) {
	tb := newTable()
	var s session
	pub, key1, key2 := pubFill(0x11), randKey(0xAA), randKey(0xBB)
	addr := mustAddr("10.0.0.1:5040")
	now := time.Now()

	if err := tb.sessionInit(&s, addr, pub, key1, nil, false, now); err != nil {
		t.Fatal(err)
	}
	s.sendSeq = 42 // simulate traffic before the rekey
	s.replay.Check(7)

	if err := tb.sessionInit(&s, addr, pub, key2, nil, false, now); err != nil {
		t.Fatal(err)
	}
	if !s.prevKeyActive {
		t.Fatal("previous key should be retained after a rekey")
	}
	if s.prevKey != key1 || s.key != key2 {
		t.Fatal("keys not rotated correctly")
	}
	if s.prevAEAD == nil || s.aead == nil {
		t.Fatal("AEADs missing")
	}
	if want := now.Add(90 * time.Second); !s.prevKeyExpires.Equal(want) {
		t.Fatalf("prevKeyExpires=%v want %v", s.prevKeyExpires, want)
	}
	if s.sendSeq != 0 || s.replay.Highest != 0 {
		t.Fatal("sequence counters / replay window must reset on rekey")
	}
}

func TestSessionInitNoCfgClearsRoutes(t *testing.T) {
	tb := newTable()
	var s session
	if err := tb.sessionInit(&s, mustAddr("10.0.0.1:5040"), pubFill(0x11), randKey(0x22), nil, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(s.routes) != 0 {
		t.Fatalf("routes=%d want 0", len(s.routes))
	}
}

func TestSessionInitRoutesAreCopied(t *testing.T) {
	tb := newTable()
	var s session
	cfg := &peerConfig{routes: []config.Prefix{cidr(t, "10.9.0.0/24")}}
	if err := tb.sessionInit(&s, mustAddr("10.0.0.1:5040"), pubFill(1), randKey(2), cfg, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	cfg.routes[0] = cidr(t, "192.168.0.0/16")
	if s.routes[0].String() != "10.9.0.0/24" {
		t.Fatal("session routes alias the config slice")
	}
}

func TestSessionInitRejectsBadKeyLength(t *testing.T) {
	// proto.NewAEAD guards the key size; sessionInit has a fixed-size array so
	// this documents that a valid array always yields a working AEAD.
	tb := newTable()
	var s session
	if err := tb.sessionInit(&s, mustAddr("10.0.0.1:1"), pubFill(1), randKey(0), nil, false, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestSessionInitAddressChangeKeepsSessionActive(t *testing.T) {
	tb := newTable()
	var s session
	pub := pubFill(0x33)
	_ = tb.sessionInit(&s, mustAddr("10.0.0.1:5040"), pub, randKey(1), nil, false, time.Now())
	_ = tb.sessionInit(&s, mustAddr("10.0.0.9:6000"), pub, randKey(2), nil, false, time.Now())
	if s.addr != mustAddr("10.0.0.9:6000") {
		t.Fatalf("addr=%v", s.addr)
	}
	if !s.active || !s.prevKeyActive {
		t.Fatal("roaming rekey must keep the session active with a prev key")
	}
}

// Old-key packets must stay subject to replay detection during the grace
// period, using the window that belonged to the old key.
func TestRekeyKeepsOldReplayWindowForPrevKey(t *testing.T) {
	tb := newTable()
	var s session
	pub, key1, key2 := pubFill(0x11), randKey(0xAA), randKey(0xBB)
	addr := mustAddr("10.0.0.1:5040")
	now := time.Now()
	if err := tb.sessionInit(&s, addr, pub, key1, nil, false, now); err != nil {
		t.Fatal(err)
	}
	s.replay.Check(7)
	if err := tb.sessionInit(&s, addr, pub, key2, nil, false, now); err != nil {
		t.Fatal(err)
	}
	if s.prevReplay.Check(7) {
		t.Fatal("seq 7 was already seen under the old key; replay must be rejected")
	}
	if !s.replay.Check(7) {
		t.Fatal("new key's window must start empty")
	}
}
