package peer

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/logx"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

// --- fake TUN device -------------------------------------------------------

// fakeDev is an in-memory TUN device: tests inject packets with `in` (what
// the kernel would hand the program) and observe packets the program writes
// to the "kernel" on `out`.
type fakeDev struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
	once   sync.Once
}

func newFakeDev() *fakeDev {
	return &fakeDev{in: make(chan []byte, 64), out: make(chan []byte, 64), closed: make(chan struct{})}
}

func (d *fakeDev) Read(p []byte) (int, error) {
	select {
	case b := <-d.in:
		return copy(p, b), nil
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

func (d *fakeDev) Write(p []byte) (int, error) {
	select {
	case d.out <- append([]byte(nil), p...):
		return len(p), nil
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

func (d *fakeDev) Close() error { d.once.Do(func() { close(d.closed) }); return nil }

// expect returns the next packet written to the device, failing on timeout.
func (d *fakeDev) expect(t *testing.T, within time.Duration) []byte {
	t.Helper()
	select {
	case b := <-d.out:
		return b
	case <-time.After(within):
		t.Fatalf("no packet reached the TUN device within %v", within)
		return nil
	}
}

// expectNone fails if any packet is written to the device within d.
func (d *fakeDev) expectNone(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case b := <-d.out:
		t.Fatalf("unexpected packet reached the TUN device: % x", b)
	case <-time.After(within):
	}
}

// --- packets ---------------------------------------------------------------

// ipv4 builds a minimal IPv4 packet (checksum not computed; microtunnel only
// inspects the version nibble and the src/dst fields).
func ipv4(src, dst string, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 17
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	copy(pkt[20:], payload)
	return pkt
}

// wirePacket builds a data datagram exactly as a remote peer would.
func wirePacket(t *testing.T, key [proto.KeyLen]byte, seq uint64, payload []byte) []byte {
	t.Helper()
	plain := append([]byte(nil), proto.Header[:]...)
	plain = binary.BigEndian.AppendUint64(plain, seq)
	plain = append(plain, payload...)
	enc, err := proto.EncryptPacket(key[:], plain)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// readWire reads one datagram from conn, decrypts it with key and returns
// (seq, payload).
func readWire(t *testing.T, conn *net.UDPConn, key [proto.KeyLen]byte, within time.Duration) (uint64, []byte) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(within))
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("no datagram within %v: %v", within, err)
	}
	plain, err := proto.DecryptPacket(key[:], buf[:n])
	if err != nil {
		t.Fatalf("datagram does not decrypt with the session key: %v", err)
	}
	if len(plain) < 16 || !bytes.Equal(plain[:8], proto.Header[:]) {
		t.Fatalf("bad plaintext header: % x", plain)
	}
	return binary.BigEndian.Uint64(plain[8:16]), plain[16:]
}

func expectNoDatagram(t *testing.T, conn *net.UDPConn, within time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(within))
	buf := make([]byte, 4096)
	if n, _, err := conn.ReadFromUDPAddrPort(buf); err == nil {
		t.Fatalf("unexpected datagram (%d bytes)", n)
	}
}

// --- keys, sockets, peers ---------------------------------------------------

func mustKey(t testing.TB) *ecdh.PrivateKey {
	t.Helper()
	k, err := proto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pubOf(k *ecdh.PrivateKey) [proto.PubKeyLen]byte { return proto.PubBytes(k) }
func hexOf(k *ecdh.PrivateKey) string                { p := pubOf(k); return proto.BytesToHex(p[:]) }

func listenLoopback(t testing.TB) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func addrOf(c *net.UDPConn) netip.AddrPort {
	return netip.MustParseAddrPort(c.LocalAddr().String())
}

func mustAddr(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// testPeerSpec describes a peer for newTestPeer.
type testPeerSpec struct {
	key   *ecdh.PrivateKey
	conn  *net.UDPConn
	psk   string
	peers []testPeerEntry
}

type testPeerEntry struct {
	key      *ecdh.PrivateKey
	endpoint string // "" = inbound-only
	allowed  []string
}

func (s testPeerSpec) yaml() string {
	var b strings.Builder
	b.WriteString("interface: mt-test\nworker_threads: 2\n")
	if s.psk != "" {
		fmt.Fprintf(&b, "pre_shared_key: %s\n", s.psk)
	}
	b.WriteString("peers:\n")
	for _, p := range s.peers {
		fmt.Fprintf(&b, "  - public_key: %s\n", hexOf(p.key))
		if p.endpoint != "" {
			fmt.Fprintf(&b, "    endpoint: %s\n", p.endpoint)
		}
		if len(p.allowed) > 0 {
			b.WriteString("    allowed_ips:\n")
			for _, a := range p.allowed {
				fmt.Fprintf(&b, "      - %s\n", a)
			}
		}
	}
	return b.String()
}

// newTestPeer builds a Peer with a fake TUN device and a real loopback socket.
// It does not start any goroutines.
func newTestPeer(t testing.TB, spec testPeerSpec) (*Peer, *fakeDev) {
	t.Helper()
	cfg, err := config.Parse([]byte(spec.yaml()))
	if err != nil {
		t.Fatalf("config: %v\n%s", err, spec.yaml())
	}
	if spec.key == nil {
		spec.key = mustKey(t)
	}
	if spec.conn == nil {
		spec.conn = listenLoopback(t)
	}
	dev := newFakeDev()
	p, err := New(cfg, spec.key, dev, spec.conn)
	if err != nil {
		t.Fatal(err)
	}
	return p, dev
}

// addSession installs an active session (as a completed handshake would).
func (p *Peer) addSession(t testing.TB, pub [proto.PubKeyLen]byte, addr netip.AddrPort,
	key [proto.KeyLen]byte, routes ...string) *session {
	t.Helper()
	cfg := &peerConfig{pub: pub}
	for _, r := range routes {
		pfx, err := config.ParseCIDR(r)
		if err != nil {
			t.Fatal(err)
		}
		cfg.routes = append(cfg.routes, pfx)
	}
	p.tbl.mu.Lock()
	defer p.tbl.mu.Unlock()
	s := p.tbl.alloc(pub, addr)
	if s == nil {
		t.Fatal("session table full")
	}
	if err := p.tbl.sessionInit(s, addr, pub, key, cfg, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	return s
}

func (p *Peer) activeSessions() int {
	p.tbl.mu.RLock()
	defer p.tbl.mu.RUnlock()
	n := 0
	for i := 0; i < p.tbl.slots; i++ {
		if p.tbl.sessions[i].active {
			n++
		}
	}
	return n
}

// sessionKey returns the current key for the session with the given public
// key, or false if there is none.
func (p *Peer) sessionKey(pub [proto.PubKeyLen]byte) ([proto.KeyLen]byte, bool) {
	p.tbl.mu.RLock()
	defer p.tbl.mu.RUnlock()
	s := p.tbl.findByPub(pub)
	if s == nil {
		return [proto.KeyLen]byte{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.key, true
}

func randKey(b byte) [proto.KeyLen]byte {
	var k [proto.KeyLen]byte
	for i := range k {
		k[i] = b
	}
	return k
}

// waitFor polls cond until it is true or the timeout elapses.
func waitFor(t testing.TB, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %s", timeout, what)
}

// captureLogs redirects the logger to a buffer for the test's duration.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func captureLogs(t testing.TB) *logBuf {
	t.Helper()
	l := &logBuf{}
	prev := logx.SetOutput(l)
	prevV := logx.Verbose()
	logx.SetVerbose(true)
	t.Cleanup(func() { logx.SetOutput(prev); logx.SetVerbose(prevV) })
	return l
}

// TestMain keeps the (chatty) logger quiet unless a test captures it.
func TestMain(m *testing.M) {
	logx.SetOutput(io.Discard)
	os.Exit(m.Run())
}

func testCtx() context.Context { return context.Background() }
