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

// peerConfig is a configured peer (from the YAML `peers:` list or peers_dir).
// Reload replaces it wholesale (never mutates one in place) when a peer is
// added, removed or changed, so pointers held by pending handshakes stay
// consistent. endpoint and lastAttempt are only touched by the housekeeping
// goroutine (and by New/Reload before the object is published); pub and
// routes are immutable.
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
	prevReplay     proto.ReplayWindow // window for prevKey, so old-key packets cannot be replayed

	// Traffic counters (wire bytes and datagrams, keepalives included) for
	// this peer since its session slot was assigned; reported by Sessions.
	txBytes, rxBytes     uint64
	txPackets, rxPackets uint64
}

// pendingHS is an outbound handshake that has been sent and is awaiting its
// response.
type pendingHS struct {
	active     bool
	cfg        *peerConfig
	sentAt     time.Time
	state      *proto.ClientState
	serverAddr netip.AddrPort
}

// candidate is a session key negotiated by an inbound handshake whose
// initiator has not yet proven it holds the static private key it claimed.
//
// An initiation carries only public values (and, when configured, an HMAC under
// the shared pre-shared key), so anyone who knows a peer's public key and can
// replay or forge one can make us run the handshake. Installing that key and
// address immediately would let such a packet displace a live session (and
// point the peer's traffic at the sender), so the responder keeps the old
// session untouched and promotes the candidate only when a data packet from the
// handshake's source address decrypts under it. The session key mixes in
// DH(static_initiator, eph_responder), which only the real initiator can
// compute, so a successful decrypt is that proof.
type candidate struct {
	active  bool
	pub     [proto.PubKeyLen]byte
	addr    netip.AddrPort
	key     [proto.KeyLen]byte
	aead    cipher.AEAD
	created time.Time
}

const (
	// candidateTTL is how long an unconfirmed key waits for its first packet.
	// A Go initiator confirms within one round trip; the original C
	// implementation only after its next packet or keepalive.
	candidateTTL = 90 * time.Second
	// maxCandidatesPerPeer bounds unconfirmed keys held per peer, so a flood of
	// initiations cannot evict a genuine one before it confirms.
	maxCandidatesPerPeer = 8
)

// table is the session table: a flat array (max MaxPeers) guarded by an RWMutex.
type table struct {
	mu       sync.RWMutex
	sessions [MaxPeers]session
	slots    int
	pending  [MaxPeers]pendingHS
	cands    [maxCandidatesPerPeer * MaxPeers]candidate

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

// canAlloc reports whether alloc would find or create a slot for the peer. It
// does not modify the table.
func (t *table) canAlloc(pub [proto.PubKeyLen]byte, addr netip.AddrPort) bool {
	if t.findByPub(pub) != nil || t.findByAddr(addr) != nil || t.slots < MaxPeers {
		return true
	}
	for i := 0; i < t.slots; i++ {
		if !t.sessions[i].active {
			return true
		}
	}
	return false
}

// addCandidate records an unconfirmed key for pub. Requires the write lock.
func (t *table) addCandidate(pub [proto.PubKeyLen]byte, addr netip.AddrPort,
	key [proto.KeyLen]byte, now time.Time) error {
	aead, err := proto.NewAEAD(key[:])
	if err != nil {
		return err
	}
	var slot, oldestOfPub, oldest = -1, -1, -1
	n := 0
	for i := range t.cands {
		c := &t.cands[i]
		live := c.active && now.Sub(c.created) <= candidateTTL
		if !live {
			if slot < 0 {
				slot = i
			}
			continue
		}
		if oldest < 0 || c.created.Before(t.cands[oldest].created) {
			oldest = i
		}
		if c.pub == pub {
			n++
			if oldestOfPub < 0 || c.created.Before(t.cands[oldestOfPub].created) {
				oldestOfPub = i
			}
		}
	}
	switch {
	case n >= maxCandidatesPerPeer:
		slot = oldestOfPub
	case slot < 0:
		slot = oldest
	}
	t.cands[slot] = candidate{active: true, pub: pub, addr: addr, key: key, aead: aead, created: now}
	return nil
}

// dropCandidates forgets every unconfirmed key for pub. Requires the write lock.
func (t *table) dropCandidates(pub [proto.PubKeyLen]byte) {
	for i := range t.cands {
		if t.cands[i].pub == pub {
			t.cands[i] = candidate{}
		}
	}
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
	if s.staticPub != pub {
		// The slot is being (re)assigned to a different peer: start its
		// counters from zero. A rekey of the same peer keeps them.
		s.mu.Lock()
		s.txBytes, s.rxBytes, s.txPackets, s.rxPackets = 0, 0, 0, 0
		s.mu.Unlock()
	}
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
		s.prevReplay = s.replay
	} else {
		s.prevKeyActive = false
		s.prevAEAD = nil
		s.prevReplay.Reset()
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

// hasCfg reports whether cfg is still a configured peer. Requires the lock.
func (p *Peer) hasCfg(cfg *peerConfig) bool {
	return slices.Contains(p.cfgs, cfg)
}
