// Package peer implements microtunnel's symmetric peer: it binds a UDP
// socket, accepts inbound handshakes, dials peers that have a configured
// endpoint, and moves packets between a TUN device and encrypted UDP
// datagrams according to per-peer AllowedIPs.
package peer

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/logx"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

// Device is the packet interface to the TUN device: each Read returns one raw
// IP packet, each Write injects one. Close must unblock pending Reads.
type Device io.ReadWriteCloser

// Peer is a running tunnel endpoint (relay or spoke — the roles are symmetric).
type Peer struct {
	dev       Device
	conn      *net.UDPConn
	static    *ecdh.PrivateKey
	staticPub [proto.PubKeyLen]byte
	psk       *[proto.KeyLen]byte // nil when no pre-shared key is configured
	hsSize    int                 // exact size of a handshake message

	// cfgs is guarded by tbl.mu (Reload write-locks it).
	cfgs     []*peerConfig
	reloadMu sync.Mutex // serialises Reload
	tbl      table

	// precomp is the responder's pre-generated ephemeral key, consumed by the
	// next inbound handshake and immediately regenerated so X25519 keygen never
	// runs on the packet path. Only touched with tbl.mu write-locked.
	precomp *ecdh.PrivateKey

	workers int

	// Tunnel settings applied at startup, kept to flag unrouted allowed_ips on
	// a live reload; warned remembers what was already reported.
	tunnelAddr   netip.Prefix
	tunnelRoutes []netip.Prefix
	warnMu       sync.Mutex
	warned       map[string]bool

	// Timing (seconds in the YAML; Durations here so tests can shrink them).
	keepalive     time.Duration
	rekeyAfter    time.Duration
	reconnect     time.Duration
	sessionExpiry time.Duration
	hsTimeout     time.Duration
	hsCooldown    time.Duration
	hkTick        time.Duration // housekeeping wake-up period
	hkEvery       time.Duration // housekeeping work period
}

// New builds a Peer from a validated config. static is this node's identity
// key; dev and conn are already-open TUN and UDP endpoints, which Run closes
// on exit. Endpoint hostnames are resolved here; resolution failure is fatal
// so misconfigured endpoints surface at startup.
func New(cfg *config.Config, static *ecdh.PrivateKey, dev Device, conn *net.UDPConn) (*Peer, error) {
	p := &Peer{
		dev:           dev,
		conn:          conn,
		static:        static,
		staticPub:     proto.PubBytes(static),
		workers:       cfg.WorkerThreads,
		tunnelAddr:    cfg.TunnelAddress,
		tunnelRoutes:  cfg.TunnelRoutes,
		warned:        map[string]bool{},
		keepalive:     time.Duration(cfg.KeepaliveInterval) * time.Second,
		rekeyAfter:    time.Duration(cfg.RekeyAfter) * time.Second,
		reconnect:     time.Duration(cfg.ReconnectInterval) * time.Second,
		sessionExpiry: time.Duration(cfg.SessionExpiry) * time.Second,
		hsTimeout:     time.Duration(cfg.HandshakeTimeout) * time.Second,
		hsCooldown:    time.Duration(cfg.HandshakeCooldown) * time.Second,
		hkTick:        time.Second,
		hkEvery:       10 * time.Second,
	}
	if p.workers <= 0 {
		p.workers = 1
	}
	p.tbl.prevGrace = time.Duration(cfg.PrevKeyGrace) * time.Second
	if cfg.HasPSK {
		k := proto.DeriveKey(cfg.PreSharedKey)
		p.psk = &k
	}
	p.hsSize = proto.HandshakeSize(p.psk != nil)
	for _, w := range cfg.UnroutedWarnings() { // main logs these at startup
		p.warned[w] = true
	}

	for i := range cfg.Peers {
		pc := newPeerConfig(&cfg.Peers[i])
		if pc.hasEndpoint {
			if err := resolveEndpoint(context.Background(), pc); err != nil {
				return nil, fmt.Errorf("cannot resolve endpoint host %s: %w", pc.host, err)
			}
		}
		p.cfgs = append(p.cfgs, pc)
	}
	if err := p.refreshPrecomp(); err != nil {
		return nil, fmt.Errorf("failed to pre-generate ephemeral keypair: %w", err)
	}
	return p, nil
}

func newPeerConfig(cp *config.Peer) *peerConfig {
	return &peerConfig{
		pub:         cp.PublicKey,
		routes:      cp.AllowedIPs,
		hasEndpoint: cp.HasEndpoint(),
		host:        cp.Host,
		port:        cp.Port,
	}
}

// Run processes packets until ctx is cancelled or a fatal I/O error occurs. It
// closes the TUN device and UDP socket before returning. It returns nil on
// clean shutdown and the fatal error otherwise.
func (p *Peer) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	logx.Infof("Starting %d worker(s) + 1 housekeeping goroutine", p.workers)
	var wg sync.WaitGroup
	spawn := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	for i := 0; i < p.workers; i++ {
		spawn(func() { p.tunLoop(ctx, cancel) })
		spawn(func() { p.udpLoop(ctx, cancel) })
	}
	spawn(func() { p.housekeepingLoop(ctx) })

	<-ctx.Done()
	// Closing the endpoints unblocks every goroutine parked in a Read.
	_ = p.conn.Close()
	_ = p.dev.Close()
	wg.Wait()

	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
	}
	logx.Infof("Caught signal — shutting down")
	return nil
}

// isClosed reports whether err is the expected result of closing a socket/device.
func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF)
}

// workerBufs is the per-goroutine scratch space, so the hot path never allocates.
type workerBufs struct {
	tun   [proto.BufferSize]byte
	wire  [proto.BufferSize + proto.WireOverhead]byte // received datagram / outgoing ciphertext
	plain [proto.HeaderSize + proto.SeqSize + proto.BufferSize]byte
	send  [proto.HeaderSize + proto.SeqSize + proto.BufferSize]byte
	out   [proto.BufferSize + proto.WireOverhead]byte
}

// tunLoop reads packets from the TUN device and forwards them to the peer
// whose AllowedIPs best match the destination (TUN -> UDP).
func (p *Peer) tunLoop(ctx context.Context, cancel context.CancelCauseFunc) {
	w := new(workerBufs)
	for {
		n, err := p.dev.Read(w.tun[:])
		if err != nil {
			if ctx.Err() == nil && !isClosed(err) {
				cancel(fmt.Errorf("TUN read: %w", err))
			}
			return
		}
		if n == 0 {
			continue
		}
		p.handleTUN(w.tun[:n], w)
	}
}

func (p *Peer) handleTUN(pkt []byte, w *workerBufs) {
	dst, ok := ipv4Dst(pkt)
	if !ok {
		return // IPv6 and non-IP traffic are not supported
	}
	p.tbl.mu.RLock()
	defer p.tbl.mu.RUnlock()
	s := p.tbl.routeLookup(dst)
	if s == nil {
		if logx.Verbose() {
			logx.Debugf("No route for %s — dropping", u32Addr(dst))
		}
		return
	}
	if logx.Verbose() {
		logx.Debugf("TUN->UDP: forwarding (dst=%s)", u32Addr(dst))
	}
	p.forward(s, pkt, w)
}

// udpLoop receives datagrams and dispatches them as handshakes or data
// (UDP -> TUN).
func (p *Peer) udpLoop(ctx context.Context, cancel context.CancelCauseFunc) {
	w := new(workerBufs)
	for {
		n, src, err := p.conn.ReadFromUDPAddrPort(w.wire[:])
		if err != nil {
			if ctx.Err() != nil || isClosed(err) {
				return
			}
			logx.Errorf("recvfrom: %v", err)
			select { // avoid a hot loop on a persistent error
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		p.handleUDP(netip.AddrPortFrom(src.Addr().Unmap(), src.Port()), w.wire[:n], w)
	}
}

func (p *Peer) handleUDP(src netip.AddrPort, pkt []byte, w *workerBufs) {
	now := time.Now()
	if len(pkt) == p.hsSize && len(pkt) >= proto.HeaderSize &&
		[proto.HeaderSize]byte(pkt[:proto.HeaderSize]) == proto.Header {
		p.handleHandshake(src, pkt, now)
		return
	}
	p.handleData(src, pkt, now, w)
}

// forward encrypts payload for session s and sends it. An empty payload is a
// keepalive. The caller must hold the table lock (read is enough) across the
// session lookup and this call, so a concurrent rekey — which needs the write
// lock — cannot swap s's key underneath it. Must not be called with s.mu held.
func (p *Peer) forward(s *session, payload []byte, w *workerBufs) {
	s.mu.Lock()
	seq := s.sendSeq
	s.sendSeq++
	aead := s.aead
	dest := s.addr
	s.mu.Unlock()

	plain := w.send[:0]
	plain = append(plain, proto.Header[:]...)
	plain = binary.BigEndian.AppendUint64(plain, seq)
	plain = append(plain, payload...)

	wire, err := proto.Seal(aead, w.out[:0], plain)
	if err != nil {
		logx.Errorf("Encrypt failed for %s: %v", dest, err)
		return
	}
	if _, err := p.conn.WriteToUDPAddrPort(wire, dest); err != nil {
		if !isClosed(err) {
			logx.Warnf("sendto %s: %v", dest, err)
		}
		return
	}
	s.mu.Lock()
	s.lastSent = time.Now()
	s.txBytes += uint64(len(wire))
	s.txPackets++
	s.mu.Unlock()
}

// handleData decrypts a data packet and either delivers it to the TUN device,
// relays it to another peer, or drops it. The table read lock is held for the
// whole span so the session can't be rekeyed or expired out from under us.
func (p *Peer) handleData(src netip.AddrPort, pkt []byte, now time.Time, w *workerBufs) {
	t := &p.tbl
	t.mu.RLock()
	s := t.findByAddr(src)
	if s == nil {
		t.mu.RUnlock()
		logx.Warnf("Packet from unknown peer %s — dropping", src)
		return
	}

	var (
		plain       []byte
		decOK       bool
		usedPrevKey bool
		replay      bool
		seq         uint64
	)
	s.mu.Lock()
	var err error
	if plain, err = proto.Open(s.aead, w.plain[:0], pkt); err == nil {
		decOK = true
		s.prevKeyActive = false
	} else if s.prevKeyActive && !now.After(s.prevKeyExpires) {
		if plain, err = proto.Open(s.prevAEAD, w.plain[:0], pkt); err == nil {
			decOK = true
			usedPrevKey = true
		}
	}
	headerOK := decOK && len(plain) >= proto.HeaderSize+proto.SeqSize &&
		[proto.HeaderSize]byte(plain[:proto.HeaderSize]) == proto.Header
	if headerOK {
		seq = binary.BigEndian.Uint64(plain[proto.HeaderSize:])
		// Skip the replay check for prev-key packets: their old sequence
		// numbers would advance the window and cause the new session's seq
		// 0,1,2,... to be rejected as replays once the initiator switches keys.
		if !usedPrevKey && !s.replay.Check(seq) {
			replay = true
		} else {
			// Only authenticated, non-replayed traffic keeps a session alive.
			s.lastSeen = now
			s.rxBytes += uint64(len(pkt))
			s.rxPackets++
		}
	}
	s.mu.Unlock()

	switch {
	case !decOK:
		t.mu.RUnlock()
		logx.Warnf("Decrypt failed from %s — dropping", src)
		return
	case !headerOK:
		t.mu.RUnlock()
		logx.Warnf("Bad header from %s — dropping", src)
		return
	case replay:
		t.mu.RUnlock()
		logx.Warnf("Replay from %s (seq=%d) — dropping", src, seq)
		return
	}

	payload := plain[proto.HeaderSize+proto.SeqSize:]
	if len(payload) == 0 { // keepalive
		t.mu.RUnlock()
		return
	}
	// IPv4 only. Anything else (IPv6, runt packets) is dropped rather than
	// handed to the kernel, so the AllowedIPs source check below can never be
	// bypassed by a payload it cannot parse.
	srcIP, ok := ipv4Src(payload)
	if !ok {
		t.mu.RUnlock()
		logx.Warnf("Non-IPv4 packet from %s — dropping", src)
		return
	}
	if !s.checkAllowedSrc(srcIP) {
		t.mu.RUnlock()
		logx.Warnf("Source IP %s not in AllowedIPs for %s — dropping", u32Addr(srcIP), src)
		return
	}
	// Relay shortcut: if dst belongs to another peer, forward directly without
	// writing to the TUN device (avoids same-interface kernel routing).
	if dst, ok := ipv4Dst(payload); ok {
		if fwd := t.routeLookup(dst); fwd != nil && fwd != s {
			if logx.Verbose() {
				logx.Debugf("Relay: %s -> (dst=%s)", src, u32Addr(dst))
			}
			p.forward(fwd, payload, w)
			t.mu.RUnlock()
			return
		}
	}
	t.mu.RUnlock()
	if _, err := p.dev.Write(payload); err != nil && !isClosed(err) {
		logx.Warnf("TUN write: %v", err)
	}
}

// handleHandshake processes both the response to a pending outbound handshake
// and inbound initiations. Both mutate pending[]/sessions[] structurally, so
// the whole branch runs under the table write lock.
func (p *Peer) handleHandshake(src netip.AddrPort, pkt []byte, now time.Time) {
	t := &p.tbl
	t.mu.Lock()
	defer t.mu.Unlock()

	// Response to a pending outbound handshake — check before the inbound path.
	// Initiations and responses share one wire layout, so a packet from the
	// address we dialed is only treated as our response if it actually verifies
	// against our pending state. Anything else (notably the peer's own
	// initiation crossing ours on the wire during a simultaneous rekey) falls
	// through to the inbound path and its tie-break below, and a forged packet
	// cannot cancel a legitimate pending handshake.
	for i := range t.pending {
		pe := &t.pending[i]
		if !pe.active || pe.serverAddr != src {
			continue
		}
		cfg := pe.cfg
		key, err := proto.ClientFinish(pkt, p.psk, p.static, cfg.pub[:], pe.state)
		if err != nil {
			logx.Debugf("Handshake message from %s is not a response to our initiation: %v", src, err)
			break
		}
		pe.active, pe.state = false, nil
		logx.Infof("Handshake complete — server identity: %s", shortKey(cfg.pub))
		s := t.alloc(cfg.pub, src)
		if s == nil {
			logx.Warnf("Session table full — dropping handshake with %s", src)
			return
		}
		_ = t.sessionInit(s, src, cfg.pub, key, cfg, true, now)
		p.printSessionsLocked()
		return
	}

	// Inbound handshake. Tie-breaking: if we have a pending outbound handshake
	// to this peer, the side with the higher public key wins and ignores the
	// other's initiation; the loser yields and answers it. The loser only
	// abandons its own handshake once the initiation has authenticated (below),
	// so a forged packet from the peer's address cannot cancel it.
	var yielding *pendingHS
	for i := range t.pending {
		pe := &t.pending[i]
		if !pe.active || pe.serverAddr != src {
			continue
		}
		if bytes.Compare(p.staticPub[:], pe.cfg.pub[:]) > 0 {
			logx.Debugf("Rekey collision from %s — ignoring (we have higher pub key)", src)
			return
		}
		yielding = pe
		break
	}

	if ex := t.findByAddr(src); ex != nil && now.Sub(ex.lastHandshake) < p.hsCooldown {
		logx.Warnf("Handshake cooldown for %s — ignoring", src)
		return
	}
	logx.Infof("Inbound handshake from %s", src)

	eph := p.precomp
	if eph == nil {
		var err error
		if eph, err = proto.GenerateKey(); err != nil {
			logx.Errorf("Failed to generate ephemeral key: %v", err)
			return
		}
	}
	resp, peerPub, key, err := proto.ServerRespond(pkt, p.psk, p.static, eph)
	if err != nil {
		logx.Warnf("Inbound handshake from %s rejected: %v", src, err)
		return
	}
	if yielding != nil {
		logx.Infof("Rekey collision from %s — yielding (we have lower pub key)", src)
		yielding.active, yielding.state = false, nil
		if s := t.findByPub(yielding.cfg.pub); s != nil {
			s.rekeying = false
		}
	}
	// The ephemeral key has been used: never reuse it, and regenerate now so
	// the next handshake finds a fresh one ready.
	p.precomp = nil
	if err := p.refreshPrecomp(); err != nil {
		logx.Warnf("Failed to pre-generate ephemeral keypair: %v", err)
	}

	cfg := p.findPeerConfig(peerPub)
	if cfg == nil {
		logx.Warnf("Unknown peer public key: %s — rejecting", proto.BytesToHex(peerPub[:]))
		return
	}
	if bp := t.findByPub(peerPub); bp != nil && now.Sub(bp.lastHandshake) < p.hsCooldown {
		logx.Warnf("Handshake cooldown for peer key — ignoring")
		return
	}
	s := t.alloc(peerPub, src)
	if s == nil {
		logx.Warnf("Session table full — rejecting %s", src)
		return
	}
	// Install the session before answering, so the peer's first data packet
	// can never race ahead of it.
	_ = t.sessionInit(s, src, peerPub, key, cfg, false, now)
	if _, err := p.conn.WriteToUDPAddrPort(resp, src); err != nil {
		logx.Errorf("sendto() handshake response failed: %v", err)
	}
	p.printSessionsLocked()
}

// refreshPrecomp (re)generates the pre-computed ephemeral key if none is
// ready. Requires the write lock, or exclusive access during construction.
func (p *Peer) refreshPrecomp() error {
	if p.precomp != nil {
		return nil
	}
	k, err := proto.GenerateKey()
	if err != nil {
		return err
	}
	p.precomp = k
	return nil
}

// PrintSessions logs the active session table (the SIGUSR1 action).
func (p *Peer) PrintSessions() {
	p.tbl.mu.RLock()
	defer p.tbl.mu.RUnlock()
	p.printSessionsLocked()
}

// printSessionsLocked requires the table lock (read or write).
func (p *Peer) printSessionsLocked() {
	t := &p.tbl
	active := 0
	for i := 0; i < t.slots; i++ {
		if t.sessions[i].active {
			active++
		}
	}
	logx.Infof("Active peers (%d):", active)
	for i := 0; i < t.slots; i++ {
		s := &t.sessions[i]
		if !s.active {
			continue
		}
		dir := "in"
		if s.isOutbound {
			dir = "out"
		}
		s.mu.Lock()
		addr := s.addr
		s.mu.Unlock()
		logx.Infof("  [%s] %s key=%s routes=%d", dir, addr, shortKey(s.staticPub), len(s.routes))
	}
}
