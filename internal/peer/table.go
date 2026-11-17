package peer

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/logx"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

// MaxPeers bounds both the number of configured peers and live sessions.
const MaxPeers = config.MaxPeers

// peerConfig is a statically configured peer (from the YAML `peers:` list).
// It is created at startup and never removed. endpoint and lastAttempt are
// only touched by the housekeeping goroutine (and by New before any goroutine
// starts); pub and routes are immutable.
type peerConfig struct {
	pub         [proto.PubKeyLen]byte
	routes      []config.Prefix
	hasEndpoint bool
	host        string // original hostname from `endpoint:`, kept for re-resolution
	port        int
	endpoint    netip.AddrPort
	lastAttempt time.Time
}

// session is the runtime state shared with a connected peer.
//
// Locking: the structural fields (active, staticPub, routes, isOutbound,
// rekeying, lastHandshake) are guarded by the table lock: write-locked for the
// rare handshake/rekey/expiry paths, read-locked across the whole
// lookup+forward/decrypt span on the hot path. The per-packet fields below
// the mutex are additionally guarded by the session's own mu, which is what
// lets packets for different peers proceed in parallel — only concurrent
// packets for the *same* peer serialise, which is required anyway for correct
// sequence numbering and replay-window checks. Lock order: table before mu.
type session struct {
	active        bool
	staticPub     [proto.PubKeyLen]byte
	routes        []config.Prefix
	isOutbound    bool
	rekeying      bool
	lastHandshake time.Time

	mu             sync.Mutex
	addr           netip.AddrPort
	key            [proto.KeyLen]byte
	aead           cipher.AEAD
	prevKey        [proto.KeyLen]byte
	prevAEAD       cipher.AEAD
	prevKeyActive  bool
	prevKeyExpires time.Time
	lastSeen       time.Time // zero until the first authenticated packet
	lastSent       time.Time
	sendSeq        uint64
	replay         proto.ReplayWindow
}

// pendingHS is an outbound handshake that has been sent and is awaiting its
// response.
type pendingHS struct {
	active     bool
	cfgIdx     int
	sentAt     time.Time
	state      *proto.ClientState
	serverAddr netip.AddrPort
}

// table is the session table: a flat array (max MaxPeers) guarded by an RWMutex.
type table struct {
	mu       sync.RWMutex
	sessions [MaxPeers]session
	slots    int
	pending  [MaxPeers]pendingHS

	// prevGrace is how long the previous key is kept as a decrypt fallback
	// after a rekey (set from prev_key_grace; used by sessionInit).
	prevGrace time.Duration
}

func shortKey(pub [proto.PubKeyLen]byte) string { return proto.BytesToHex(pub[:8]) + "..." }

// The following helpers assume the caller already holds t.mu (read lock for
// lookups, write lock for alloc/sessionInit); they do not lock internally so
// callers can compose several lookups in one critical section.

func (t *table) findByAddr(addr netip.AddrPort) *session {
	for i := 0; i < t.slots; i++ {
		s := &t.sessions[i]
		// addr is also guarded by s.mu but is only ever *written* by
		// sessionInit under the table write lock, which excludes us.
		if s.active && s.addr == addr {
			return s
		}
	}
	return nil
}

func (t *table) findByPub(pub [proto.PubKeyLen]byte) *session {
	for i := 0; i < t.slots; i++ {
		s := &t.sessions[i]
		if s.active && s.staticPub == pub {
			return s
		}
	}
	return nil
}

// alloc returns the slot to use for a peer: an existing one found by public
// key first, then by address, then any free slot, then a new slot. It returns
// nil when the table is full. Requires the write lock (may grow t.slots).
func (t *table) alloc(pub [proto.PubKeyLen]byte, addr netip.AddrPort) *session {
	if s := t.findByPub(pub); s != nil {
		return s
	}
	if s := t.findByAddr(addr); s != nil {
		return s
	}
	for i := 0; i < t.slots; i++ {
		if !t.sessions[i].active {
			return &t.sessions[i]
		}
	}
	if t.slots >= MaxPeers {
		return nil
	}
	s := &t.sessions[t.slots]
	t.slots++
	return s
}

// routeLookup returns the active session whose AllowedIPs contain dstIP using
// longest-prefix match, or nil. Requires the read lock.
func (t *table) routeLookup(dstIP uint32) *session {
	var best *session
	bestLen := -1
	for i := 0; i < t.slots; i++ {
		s := &t.sessions[i]
		if !s.active {
			continue
		}
		for _, r := range s.routes {
			if r.Contains(dstIP) && r.Len > bestLen {
				bestLen = r.Len
				best = s
			}
		}
	}
	return best
}

// checkAllowedSrc reports whether srcIP is permitted for s. A session with no
// routes allows any source. Requires the read lock.
func (s *session) checkAllowedSrc(srcIP uint32) bool {
	if len(s.routes) == 0 {
		return true
	}
	for _, r := range s.routes {
		if r.Contains(srcIP) {
			return true
		}
	}
	return false
}

// sessionInit (re)keys s. On a rekey the old key is kept as a decrypt
// fallback for prevGrace, sequence counters and the replay window reset.
// Requires the table write lock.
func (t *table) sessionInit(s *session, addr netip.AddrPort, pub [proto.PubKeyLen]byte,
	key [proto.KeyLen]byte, cfg *peerConfig, outbound bool, now time.Time) error {
	aead, err := proto.NewAEAD(key[:])
	if err != nil {
		return err
	}
	wasActive := s.active
	s.active = true
	s.staticPub = pub

	// Lock order: the caller holds the table write lock, so no forward/decrypt
	// is in flight on this session; the mutex still protects against readers
	// that only hold the table read lock being scheduled in between.
	s.mu.Lock()
	oldAddr := s.addr
	s.addr = addr
	if wasActive {
		s.prevKey = s.key
		s.prevAEAD = s.aead
		s.prevKeyActive = true
		s.prevKeyExpires = now.Add(t.prevGrace)
	} else {
		s.prevKeyActive = false
		s.prevAEAD = nil
	}
	s.key = key
	s.aead = aead
	s.lastSeen = time.Time{}
	s.lastSent = now // suppress an immediate keepalive after the handshake
	s.sendSeq = 0
	s.replay.Reset()
	s.mu.Unlock()

	s.lastHandshake = now
	s.rekeying = false
	s.isOutbound = outbound
	if cfg != nil {
		s.routes = slices.Clone(cfg.routes)
	} else {
		s.routes = nil
	}

	switch {
	case !wasActive:
		logx.Infof("Peer connected: %s (key=%s)", addr, shortKey(pub))
	case oldAddr != addr:
		logx.Infof("Peer address changed: %s -> %s (key=%s)", oldAddr, addr, shortKey(pub))
	default:
		logx.Infof("Peer re-keyed: %s (key=%s)", addr, shortKey(pub))
	}
	return nil
}

func (p *Peer) findPeerConfig(pub [proto.PubKeyLen]byte) *peerConfig {
	for _, c := range p.cfgs {
		if bytes.Equal(c.pub[:], pub[:]) {
			return c
		}
	}
	return nil
}

// ipv4Dst/ipv4Src extract addresses (host byte order) from a raw IPv4 packet;
// ok is false for anything that is not a plausible IPv4 header.
func ipv4Dst(pkt []byte) (uint32, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(pkt[16:20]), true
}

func ipv4Src(pkt []byte) (uint32, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(pkt[12:16]), true
}

func u32Addr(ip uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ip)
	return netip.AddrFrom4(b)
}
