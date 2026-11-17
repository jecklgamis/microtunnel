package peer

import (
	"net/netip"
	"time"

	"github.com/jecklgamis/microtunnel/internal/proto"
)

// SessionInfo is a point-in-time view of one live session, for monitoring.
type SessionInfo struct {
	PublicKey     [proto.PubKeyLen]byte
	Addr          netip.AddrPort
	Outbound      bool      // true if we dialed this peer
	LastHandshake time.Time // when the current key was negotiated
	LastSeen      time.Time // last authenticated packet; zero if none yet
	TxBytes       uint64    // wire bytes sent, keepalives included
	RxBytes       uint64
	TxPackets     uint64
	RxPackets     uint64
}

// Sessions returns a snapshot of every active session.
func (p *Peer) Sessions() []SessionInfo {
	t := &p.tbl
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []SessionInfo
	for i := 0; i < t.slots; i++ {
		s := &t.sessions[i]
		if !s.active {
			continue
		}
		s.mu.Lock()
		out = append(out, SessionInfo{
			PublicKey:     s.staticPub,
			Addr:          s.addr,
			Outbound:      s.isOutbound,
			LastHandshake: s.lastHandshake,
			LastSeen:      s.lastSeen,
			TxBytes:       s.txBytes,
			RxBytes:       s.rxBytes,
			TxPackets:     s.txPackets,
			RxPackets:     s.rxPackets,
		})
		s.mu.Unlock()
	}
	return out
}
