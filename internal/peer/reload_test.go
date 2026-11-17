package peer

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

// parsePeers turns test peer entries into the config.Peer list Reload takes.
func parsePeers(t *testing.T, entries ...testPeerEntry) []config.Peer {
	t.Helper()
	if len(entries) == 0 {
		return nil
	}
	cfg, err := config.Parse([]byte(testPeerSpec{peers: entries}.yaml()))
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Peers
}

// strangerHandshake drives a full inbound handshake as a client that has its
// own key and socket, returning the session key and its address.
func strangerHandshake(t *testing.T, relay *Peer, relayKey, clientKey *ecdh.PrivateKey) (key [proto.KeyLen]byte, ok bool, e *hsEnv) {
	t.Helper()
	e = &hsEnv{relay: relay, relayKey: relayKey, clientKey: clientKey, clientConn: listenLoopback(t)}
	e.clientAddr = addrOf(e.clientConn)
	msg, st := e.initiate(t)
	relay.handleUDP(e.clientAddr, msg, new(workerBufs))
	_ = e.clientConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 512)
	n, _, err := e.clientConn.ReadFromUDPAddrPort(buf)
	if err != nil {
		return key, false, e
	}
	return e.finish(t, buf[:n], st), true, e
}

func TestReloadAddsPeerWhichThenHandshakes(t *testing.T) {
	e := newHSEnv(t, "")
	newcomer := mustKey(t)

	if _, ok, _ := strangerHandshake(t, e.relay, e.relayKey, newcomer); ok {
		t.Fatal("unknown peer must not get a response before it is added")
	}

	res, err := e.relay.Reload(parsePeers(t,
		testPeerEntry{key: e.clientKey, allowed: []string{"10.9.0.2/32"}},
		testPeerEntry{key: newcomer, allowed: []string{"10.9.0.3/32"}}))
	if err != nil {
		t.Fatal(err)
	}
	if res != (ReloadResult{Added: 1}) {
		t.Fatalf("result=%+v", res)
	}

	clientKey, ok, _ := strangerHandshake(t, e.relay, e.relayKey, newcomer)
	if !ok {
		t.Fatal("added peer got no handshake response")
	}
	serverKey, found := e.relay.sessionKey(pubOf(newcomer))
	if !found || serverKey != clientKey {
		t.Fatal("added peer's session not established with matching key")
	}
}

func TestReloadRemovedPeerIsCutOffButOthersSurvive(t *testing.T) {
	relayKey, a, b := mustKey(t), mustKey(t), mustKey(t)
	relay, dev := newTestPeer(t, testPeerSpec{key: relayKey, peers: []testPeerEntry{
		{key: a, allowed: []string{"10.9.0.2/32"}},
		{key: b, allowed: []string{"10.9.0.3/32"}},
	}})
	keyA, okA, envA := strangerHandshake(t, relay, relayKey, a)
	keyB, okB, _ := strangerHandshake(t, relay, relayKey, b)
	if !okA || !okB {
		t.Fatal("setup handshakes failed")
	}
	pkt := ipv4("10.9.0.2", "10.9.0.1", []byte("before"))
	relay.handleUDP(envA.clientAddr, wirePacket(t, keyA, 0, pkt), new(workerBufs))
	if got := dev.expect(t, time.Second); !bytes.Equal(got, pkt) {
		t.Fatal("peer A traffic not delivered before removal")
	}

	res, err := relay.Reload(parsePeers(t, testPeerEntry{key: b, allowed: []string{"10.9.0.3/32"}}))
	if err != nil {
		t.Fatal(err)
	}
	if res != (ReloadResult{Removed: 1}) {
		t.Fatalf("result=%+v", res)
	}

	// A is cut off immediately: no session, its packets are dropped, and it
	// cannot re-handshake.
	if _, ok := relay.sessionKey(pubOf(a)); ok {
		t.Fatal("removed peer still has a session")
	}
	relay.handleUDP(envA.clientAddr, wirePacket(t, keyA, 1, pkt), new(workerBufs))
	dev.expectNone(t, 100*time.Millisecond)
	if _, ok, _ := strangerHandshake(t, relay, relayKey, a); ok {
		t.Fatal("removed peer was able to re-handshake")
	}

	// B is untouched: same session key, still delivering.
	if got, ok := relay.sessionKey(pubOf(b)); !ok || got != keyB {
		t.Fatal("peer B's session was disturbed by removing A")
	}
	if relay.activeSessions() != 1 {
		t.Fatalf("active sessions=%d want 1", relay.activeSessions())
	}
}

func TestReloadUpdatesRoutesOnLiveSession(t *testing.T) {
	e := newHSEnv(t, "")
	key, ok, env := strangerHandshake(t, e.relay, e.relayKey, e.clientKey)
	if !ok {
		t.Fatal("setup handshake failed")
	}
	dev := e.relay.dev.(*fakeDev)

	outside := ipv4("10.9.0.9", "10.9.0.1", []byte("x"))
	e.relay.handleUDP(env.clientAddr, wirePacket(t, key, 0, outside), new(workerBufs))
	dev.expectNone(t, 100*time.Millisecond) // 10.9.0.9 is not in allowed_ips yet

	res, err := e.relay.Reload(parsePeers(t, testPeerEntry{key: e.clientKey, allowed: []string{"10.9.0.0/24"}}))
	if err != nil {
		t.Fatal(err)
	}
	if res != (ReloadResult{Updated: 1}) {
		t.Fatalf("result=%+v", res)
	}
	e.relay.handleUDP(env.clientAddr, wirePacket(t, key, 1, outside), new(workerBufs))
	if got := dev.expect(t, time.Second); !bytes.Equal(got, outside) {
		t.Fatal("packet not delivered after widening allowed_ips")
	}
	if got, _ := e.relay.sessionKey(pubOf(e.clientKey)); got != key {
		t.Fatal("route change must not re-key the session")
	}
}

func TestReloadNoChangeIsNoop(t *testing.T) {
	e := newHSEnv(t, "")
	before := e.relay.cfgs[0]
	res, err := e.relay.Reload(parsePeers(t, testPeerEntry{key: e.clientKey, allowed: []string{"10.9.0.2/32"}}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed() {
		t.Fatalf("result=%+v", res)
	}
	if e.relay.cfgs[0] != before {
		t.Fatal("unchanged peer config was replaced")
	}
}

func TestReloadRejectsBadInputAndChangesNothing(t *testing.T) {
	e := newHSEnv(t, "")
	before := e.relay.cfgs[0]

	dup := parsePeers(t, testPeerEntry{key: e.clientKey}, testPeerEntry{key: mustKey(t)})
	dup[1] = dup[0]
	if _, err := e.relay.Reload(dup); err == nil {
		t.Fatal("duplicate keys must be rejected")
	}

	many := make([]config.Peer, MaxPeers+1)
	for i := range many {
		many[i].PublicKey[0], many[i].PublicKey[1] = byte(i), byte(i>>8)
		many[i].PublicKey[31] = 1
	}
	if _, err := e.relay.Reload(many); err == nil {
		t.Fatal("too many peers must be rejected")
	}
	if len(e.relay.cfgs) != 1 || e.relay.cfgs[0] != before {
		t.Fatal("rejected reload altered the peer set")
	}
}

func TestReloadCancelsPendingHandshakeOfRemovedPeer(t *testing.T) {
	o := newOutEnv(t, "")
	o.p.tbl.mu.Lock()
	_ = o.p.initiate(o.p.cfgs[0], time.Now())
	o.p.tbl.mu.Unlock()
	o.serverReceive(t)

	if _, err := o.p.Reload(nil); err != nil {
		t.Fatal(err)
	}
	o.p.tbl.mu.RLock()
	defer o.p.tbl.mu.RUnlock()
	if o.p.tbl.pending[0].active {
		t.Fatal("pending handshake for a removed peer must be cancelled")
	}
}

func TestReloadRoutesOnlyChangeKeepsPendingHandshake(t *testing.T) {
	o := newOutEnv(t, "")
	o.p.tbl.mu.Lock()
	_ = o.p.initiate(o.p.cfgs[0], time.Now())
	o.p.tbl.mu.Unlock()
	resp, key, from := o.serverReceive(t)

	res, err := o.p.Reload(parsePeers(t, testPeerEntry{
		key: o.serverKey, endpoint: addrOf(o.server).String(), allowed: []string{"10.9.0.0/16"}}))
	if err != nil || res != (ReloadResult{Updated: 1}) {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	// The response to the original initiation must still complete.
	_ = from
	o.p.handleUDP(addrOf(o.server), resp, new(workerBufs))
	if got, ok := o.p.sessionKey(pubOf(o.serverKey)); !ok || got != key {
		t.Fatal("handshake in flight across a routes-only reload did not complete")
	}
}

func TestReloadChangedEndpointCancelsPendingHandshake(t *testing.T) {
	o := newOutEnv(t, "")
	o.p.tbl.mu.Lock()
	_ = o.p.initiate(o.p.cfgs[0], time.Now())
	o.p.tbl.mu.Unlock()
	o.serverReceive(t)

	other := listenLoopback(t)
	if _, err := o.p.Reload(parsePeers(t, testPeerEntry{
		key: o.serverKey, endpoint: addrOf(other).String(), allowed: []string{"10.9.0.0/24"}})); err != nil {
		t.Fatal(err)
	}
	o.p.tbl.mu.RLock()
	defer o.p.tbl.mu.RUnlock()
	if o.p.tbl.pending[0].active {
		t.Fatal("pending handshake to the old endpoint must be cancelled")
	}
	if o.p.cfgs[0].endpoint != addrOf(other) {
		t.Fatalf("endpoint=%v want %v", o.p.cfgs[0].endpoint, addrOf(other))
	}
}

func TestReloadFromFileUsesPeersDir(t *testing.T) {
	dir := t.TempDir()
	pd := filepath.Join(dir, "peers.d")
	if err := os.Mkdir(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	relayKey, a := mustKey(t), mustKey(t)
	cfgPath := filepath.Join(dir, "relay.yaml")
	if err := os.WriteFile(cfgPath, []byte("interface: mt-test\nworker_threads: 1\npeers_dir: peers.d\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, relayKey, newFakeDev(), listenLoopback(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.cfgs) != 0 {
		t.Fatalf("start with no peers, got %d", len(p.cfgs))
	}

	body := "public_key: " + hexOf(a) + "\nallowed_ips: [10.9.0.2/32]\n"
	if err := os.WriteFile(filepath.Join(pd, "a.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if res, err := p.ReloadFrom(cfgPath); err != nil || res.Added != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if p.findPeerConfig(pubOf(a)) == nil {
		t.Fatal("peer from peers_dir not known after ReloadFrom")
	}

	// A broken file must not change anything.
	if err := os.WriteFile(filepath.Join(pd, "bad.yaml"), []byte("public_key: ["), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ReloadFrom(cfgPath); err == nil {
		t.Fatal("broken peer file must fail the reload")
	}
	if p.findPeerConfig(pubOf(a)) == nil {
		t.Fatal("failed reload dropped an existing peer")
	}

	_ = os.Remove(filepath.Join(pd, "bad.yaml"))
	_ = os.Remove(filepath.Join(pd, "a.yaml"))
	if res, err := p.ReloadFrom(cfgPath); err != nil || res.Removed != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

// Reloading while packets flow and handshakes run must be race-free (run with -race).
func TestReloadConcurrentWithTraffic(t *testing.T) {
	relayKey, a, b := mustKey(t), mustKey(t), mustKey(t)
	relay, dev := newTestPeer(t, testPeerSpec{key: relayKey, peers: []testPeerEntry{
		{key: a, allowed: []string{"10.9.0.2/32"}}}})
	keyA, ok, env := strangerHandshake(t, relay, relayKey, a)
	if !ok {
		t.Fatal("setup handshake failed")
	}
	withB := parsePeers(t, testPeerEntry{key: a, allowed: []string{"10.9.0.2/32"}},
		testPeerEntry{key: b, allowed: []string{"10.9.0.3/32"}})
	onlyA := parsePeers(t, testPeerEntry{key: a, allowed: []string{"10.9.0.0/24"}})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // drain the fake TUN so deliveries never block the workers
		defer wg.Done()
		for {
			select {
			case <-dev.out:
			case <-stop:
				return
			}
		}
	}()
	pkt := ipv4("10.9.0.2", "10.9.0.3", []byte("x"))
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := new(workerBufs)
			for seq := uint64(i) << 40; ; seq++ {
				select {
				case <-stop:
					return
				default:
				}
				relay.handleUDP(env.clientAddr, wirePacket(t, keyA, seq, pkt), w)
				relay.handleTUN(ipv4("10.9.0.1", "10.9.0.2", []byte("y")), w)
			}
		}()
	}
	for i := 0; i < 200; i++ {
		var peers []config.Peer
		if i%2 == 0 {
			peers = withB
		} else {
			peers = onlyA
		}
		if _, err := relay.Reload(peers); err != nil {
			t.Fatal(err)
		}
		relay.housekeep(testCtx(), time.Now(), new(workerBufs))
	}
	close(stop)
	wg.Wait()
}

func (p *Peer) knows(pub [proto.PubKeyLen]byte) bool {
	p.tbl.mu.RLock()
	defer p.tbl.mu.RUnlock()
	return p.findPeerConfig(pub) != nil
}

func TestWatchPeersPicksUpDirectoryChanges(t *testing.T) {
	logs := captureLogs(t)
	defer func() {
		if t.Failed() {
			t.Logf("captured logs:\n%s", logs.String())
		}
	}()
	dir := t.TempDir()
	pd := filepath.Join(dir, "peers.d")
	if err := os.Mkdir(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "relay.yaml")
	if err := os.WriteFile(cfgPath, []byte("interface: mt-test\nworker_threads: 1\npeers_dir: peers.d\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, mustKey(t), newFakeDev(), listenLoopback(t))
	if err != nil {
		t.Fatal(err)
	}
	trigger := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); p.WatchPeers(ctx, cfgPath, cfg.PeersDir, 20*time.Millisecond, trigger) }()
	defer func() { cancel(); <-done }()

	a, b := mustKey(t), mustKey(t)
	write := func(name string, k *ecdh.PrivateKey) {
		body := "public_key: " + hexOf(k) + "\nallowed_ips: [10.9.0.2/32]\n"
		if err := os.WriteFile(filepath.Join(pd, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("a.yaml", a)
	waitFor(t, 3*time.Second, "peer a to be added", func() bool { return p.knows(pubOf(a)) })

	// A broken file is rejected without disturbing existing peers...
	if err := os.WriteFile(filepath.Join(pd, "b.yaml"), []byte("public_key: ["), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, "reload failure to be logged", func() bool {
		return strings.Contains(logs.String(), "Peer reload failed")
	})
	if !p.knows(pubOf(a)) {
		t.Fatal("failed reload dropped peer a")
	}
	// ...and fixing it is picked up.
	write("b.yaml", b)
	waitFor(t, 3*time.Second, "peer b to be added after the fix", func() bool { return p.knows(pubOf(b)) })

	_ = os.Remove(filepath.Join(pd, "a.yaml"))
	waitFor(t, 3*time.Second, "peer a to be removed", func() bool { return !p.knows(pubOf(a)) })
	if !p.knows(pubOf(b)) {
		t.Fatal("removing a also dropped b")
	}

	// An explicit trigger (SIGHUP) reloads even though the directory is unchanged.
	n := strings.Count(logs.String(), "Reloading peers (requested)")
	trigger <- struct{}{}
	waitFor(t, 3*time.Second, "triggered reload", func() bool {
		return strings.Count(logs.String(), "Reloading peers (requested)") > n
	})
}

func TestSessionsReportsCountersAndResetsOnReassignment(t *testing.T) {
	e := newHSEnv(t, "")
	if len(e.relay.Sessions()) != 0 {
		t.Fatal("no sessions expected before any handshake")
	}
	key, ok, env := strangerHandshake(t, e.relay, e.relayKey, e.clientKey)
	if !ok {
		t.Fatal("setup handshake failed")
	}
	dev := e.relay.dev.(*fakeDev)
	pkt := ipv4("10.9.0.2", "10.9.0.1", []byte("hello"))
	wire := wirePacket(t, key, 0, pkt)
	e.relay.handleUDP(env.clientAddr, wire, new(workerBufs))
	dev.expect(t, time.Second)

	// One packet toward the peer (TUN -> UDP).
	e.relay.handleTUN(ipv4("10.9.0.1", "10.9.0.2", []byte("reply")), new(workerBufs))

	got := e.relay.Sessions()
	if len(got) != 1 {
		t.Fatalf("sessions=%d", len(got))
	}
	s := got[0]
	if s.PublicKey != pubOf(e.clientKey) || s.Addr != env.clientAddr || s.Outbound {
		t.Fatalf("session = %+v", s)
	}
	if s.RxPackets != 1 || s.RxBytes != uint64(len(wire)) {
		t.Fatalf("rx = %d pkts / %d bytes, want 1 / %d", s.RxPackets, s.RxBytes, len(wire))
	}
	if s.TxPackets != 1 || s.TxBytes == 0 {
		t.Fatalf("tx = %d pkts / %d bytes", s.TxPackets, s.TxBytes)
	}
	if s.LastSeen.IsZero() || s.LastHandshake.IsZero() {
		t.Fatalf("timestamps missing: %+v", s)
	}

	// A replayed packet must not inflate the counters.
	e.relay.handleUDP(env.clientAddr, wire, new(workerBufs))
	if again := e.relay.Sessions()[0]; again.RxPackets != 1 {
		t.Fatalf("replay counted: rx=%d", again.RxPackets)
	}

	// A different peer taking over the slot starts from zero.
	other := mustKey(t)
	e.relay.tbl.mu.Lock()
	sl := e.relay.tbl.findByPub(pubOf(e.clientKey))
	_ = e.relay.tbl.sessionInit(sl, env.clientAddr, pubOf(other), randKey(7), nil, false, time.Now())
	e.relay.tbl.mu.Unlock()
	if c := e.relay.Sessions()[0]; c.RxPackets != 0 || c.TxPackets != 0 {
		t.Fatalf("counters not reset on reassignment: %+v", c)
	}
}
