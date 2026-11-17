package peer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/jecklgamis/microtunnel/internal/logx"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

var errNoPendingSlot = errors.New("no pending handshake slots available")

// resolveEndpoint (re)resolves cfg.host to an IPv4 address and updates
// cfg.endpoint. It is blocking, so it only runs at startup and from the
// housekeeping goroutine — never with the session-table lock held and never
// on the packet path.
func resolveEndpoint(ctx context.Context, cfg *peerConfig) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", cfg.host)
	if err != nil {
		logx.Warnf("DNS resolution failed for %s: %v", cfg.host, err)
		return err
	}
	if len(addrs) == 0 {
		return &net.DNSError{Err: "no IPv4 address found", Name: cfg.host}
	}
	next := netip.AddrPortFrom(addrs[0].Unmap(), uint16(cfg.port))
	if cfg.endpoint.IsValid() && cfg.endpoint.Addr() != next.Addr() {
		logx.Infof("Endpoint %s re-resolved: %s -> %s", cfg.host, cfg.endpoint.Addr(), next)
	}
	cfg.endpoint = next
	return nil
}

// housekeepingLoop owns the periodic work that must stay off the packet path:
// outbound (re)connect and rekey checks (including blocking DNS), pending
// handshake timeouts, session expiry and keepalives.
func (p *Peer) housekeepingLoop(ctx context.Context) {
	w := new(workerBufs)
	tick := time.NewTicker(p.hkTick)
	defer tick.Stop()
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			logx.Infof("Housekeeping stopped")
			return
		case <-tick.C:
		}
		if now := time.Now(); now.Sub(last) >= p.hkEvery {
			last = now
			p.housekeep(ctx, now, w)
		}
	}
}

// housekeep runs one pass of periodic maintenance.
func (p *Peer) housekeep(ctx context.Context, now time.Time, w *workerBufs) {
	p.dialDue(ctx, now)

	t := &p.tbl
	t.mu.Lock()
	defer t.mu.Unlock()

	// Expire timed-out pending handshakes.
	for i := range t.pending {
		pe := &t.pending[i]
		if !pe.active || now.Sub(pe.sentAt) < p.hsTimeout {
			continue
		}
		cfg := p.cfgs[pe.cfgIdx]
		logx.Warnf("Handshake to %s timed out — will retry in %ds",
			cfg.endpoint, int(p.reconnect/time.Second))
		pe.active, pe.state = false, nil
		if s := t.findByPub(cfg.pub); s != nil {
			s.rekeying = false
		}
	}

	// Expire sessions that have been silent for too long.
	for i := 0; i < t.slots; i++ {
		s := &t.sessions[i]
		if !s.active {
			continue
		}
		s.mu.Lock()
		ref, addr := s.lastSeen, s.addr
		s.mu.Unlock()
		if ref.IsZero() {
			ref = s.lastHandshake
		}
		if now.Sub(ref) <= p.sessionExpiry {
			continue
		}
		logx.Infof("Session expired (no traffic for %ds): %s key=%s",
			int(now.Sub(ref)/time.Second), addr, shortKey(s.staticPub))
		s.active = false
	}

	// Keepalive for sessions with no recent outbound traffic.
	for i := 0; i < t.slots; i++ {
		s := &t.sessions[i]
		if !s.active {
			continue
		}
		s.mu.Lock()
		due := now.Sub(s.lastSent) >= p.keepalive
		addr := s.addr
		s.mu.Unlock()
		if !due {
			continue
		}
		logx.Debugf("Keepalive -> %s", addr)
		p.forward(s, nil, w)
	}
}

// dialDue starts a handshake with every outbound peer that has no session, or
// whose session is due for rekeying at 80% of rekey_after (~144s by default),
// rate-limited by reconnect_interval. DNS happens between two short critical
// sections, so a slow resolver never stalls packet workers.
func (p *Peer) dialDue(ctx context.Context, now time.Time) {
	t := &p.tbl

	due := func(cfg *peerConfig) bool {
		s := t.findByPub(cfg.pub)
		needs := s == nil || (!s.rekeying && !now.Before(s.lastHandshake.Add(p.rekeyAfter*4/5)))
		return needs && now.Sub(cfg.lastAttempt) >= p.reconnect
	}

	var candidates []int
	t.mu.RLock()
	for i, cfg := range p.cfgs {
		if cfg.hasEndpoint && due(cfg) {
			candidates = append(candidates, i)
		}
	}
	t.mu.RUnlock()

	for _, i := range candidates {
		cfg := p.cfgs[i]
		_ = resolveEndpoint(ctx, cfg) // on failure keep the previous address

		t.mu.Lock()
		if due(cfg) { // state may have changed while we were resolving
			s := t.findByPub(cfg.pub)
			if s != nil {
				s.rekeying = true
			}
			if err := p.initiate(i, now); err != nil && s != nil {
				s.rekeying = false
			}
		}
		t.mu.Unlock()
	}
}

// initiate sends a handshake initiation to an outbound peer and registers a
// pending entry. It returns immediately; the response is handled by a UDP
// worker. The old session (if any) keeps forwarding until the response arrives
// and sessionInit atomically replaces its key. Requires the write lock.
func (p *Peer) initiate(cfgIdx int, now time.Time) error {
	t := &p.tbl
	cfg := p.cfgs[cfgIdx]
	cfg.lastAttempt = now

	slot := -1
	for i := range t.pending {
		if !t.pending[i].active {
			slot = i
			break
		}
	}
	if slot < 0 {
		logx.Warnf("No pending handshake slots available")
		return errNoPendingSlot
	}

	logx.Infof("Initiating handshake to %s", cfg.endpoint)
	msg, st, err := proto.ClientInit(p.static, cfg.pub[:], p.psk)
	if err != nil {
		logx.Warnf("Handshake initiation to %s failed: %v", cfg.endpoint, err)
		return err
	}
	if _, err := p.conn.WriteToUDPAddrPort(msg, cfg.endpoint); err != nil {
		logx.Warnf("Handshake initiation to %s failed: %v", cfg.endpoint, err)
		return err
	}
	t.pending[slot] = pendingHS{
		active:     true,
		cfgIdx:     cfgIdx,
		sentAt:     now,
		state:      st,
		serverAddr: cfg.endpoint,
	}
	return nil
}
