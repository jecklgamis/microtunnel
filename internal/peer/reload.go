package peer

import (
	"context"
	"fmt"
	"slices"

	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/logx"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

// ReloadResult counts what a Reload changed.
type ReloadResult struct {
	Added, Removed, Updated int
}

// Changed reports whether the reload altered anything.
func (r ReloadResult) Changed() bool { return r.Added+r.Removed+r.Updated > 0 }

// ReloadFrom re-reads the config file at path (including peers_dir) and
// applies its peer list. Only peers are reloaded; every other setting needs a
// restart. A config that fails to load or validate changes nothing.
func (p *Peer) ReloadFrom(path string) (ReloadResult, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return ReloadResult{}, err
	}
	return p.Reload(cfg.Peers)
}

// Reload makes the running peer set equal to peers without disturbing
// sessions of peers that did not change:
//
//   - a new peer becomes known (it is dialed if it has an endpoint, or accepted
//     when it initiates);
//   - a removed peer's session and any pending handshake are dropped at once, so
//     it stops being routable and its next handshake is rejected;
//   - a peer whose allowed_ips changed gets the new routes on its live session
//     immediately, with no re-handshake; a changed endpoint is re-resolved and
//     picked up by the next dial.
//
// It is safe to call while the peer is running. Concurrent calls serialise.
func (p *Peer) Reload(peers []config.Peer) (ReloadResult, error) {
	var res ReloadResult
	if len(peers) > MaxPeers {
		return res, fmt.Errorf("too many peers (%d, max %d)", len(peers), MaxPeers)
	}
	seen := make(map[[proto.PubKeyLen]byte]bool, len(peers))
	for i := range peers {
		if seen[peers[i].PublicKey] {
			return res, fmt.Errorf("duplicate peer public_key %s...", proto.BytesToHex(peers[i].PublicKey[:8]))
		}
		seen[peers[i].PublicKey] = true
	}

	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	// p.cfgs only changes here (under reloadMu), so this snapshot stays valid
	// for the whole call even though DNS below runs without the table lock.
	p.tbl.mu.RLock()
	old := slices.Clone(p.cfgs)
	p.tbl.mu.RUnlock()
	oldByPub := make(map[[proto.PubKeyLen]byte]*peerConfig, len(old))
	for _, c := range old {
		oldByPub[c.pub] = c
	}

	next := make([]*peerConfig, 0, len(peers))
	replaced := make(map[*peerConfig]*peerConfig) // old config -> its replacement
	for i := range peers {
		cp := &peers[i]
		prev := oldByPub[cp.PublicKey]
		switch {
		case prev == nil:
			c := newPeerConfig(cp)
			if c.hasEndpoint {
				// Unlike startup, an unresolvable endpoint does not reject the
				// reload; housekeeping keeps retrying the lookup.
				_ = resolveEndpoint(context.Background(), c)
			}
			next = append(next, c)
			res.Added++
			logx.Infof("Peer added: %s (%d route(s))", shortKey(c.pub), len(c.routes))
		case sameConfig(prev, cp):
			next = append(next, prev)
		default:
			c := newPeerConfig(cp)
			if c.hasEndpoint {
				if prev.hasEndpoint && prev.host == c.host && prev.port == c.port {
					c.endpoint, c.lastAttempt = prev.endpoint, prev.lastAttempt
				} else {
					_ = resolveEndpoint(context.Background(), c)
				}
			}
			next = append(next, c)
			replaced[prev] = c
			res.Updated++
			logx.Infof("Peer updated: %s (%d route(s))", shortKey(c.pub), len(c.routes))
		}
	}

	t := &p.tbl
	t.mu.Lock()
	defer t.mu.Unlock()

	nextByPub := make(map[[proto.PubKeyLen]byte]*peerConfig, len(next))
	for _, c := range next {
		nextByPub[c.pub] = c
	}

	for _, c := range old {
		if _, kept := nextByPub[c.pub]; kept {
			continue
		}
		res.Removed++
		logx.Infof("Peer removed: %s", shortKey(c.pub))
		if s := t.findByPub(c.pub); s != nil {
			s.active = false
			s.rekeying = false
		}
	}

	for i := range t.pending {
		pe := &t.pending[i]
		if !pe.active {
			continue
		}
		cur := nextByPub[pe.cfg.pub]
		switch {
		case cur == nil: // removed
			pe.active, pe.state = false, nil
		case cur != pe.cfg: // replaced
			if cur.endpoint == pe.cfg.endpoint {
				pe.cfg = cur // routes-only change: let the handshake finish
			} else {
				pe.active, pe.state = false, nil
				if s := t.findByPub(cur.pub); s != nil {
					s.rekeying = false
				}
			}
		}
	}

	for _, c := range replaced {
		if s := t.findByPub(c.pub); s != nil {
			s.routes = slices.Clone(c.routes)
		}
	}

	p.cfgs = next
	if res.Changed() {
		logx.Infof("Peers reloaded: +%d -%d ~%d (now %d configured)", res.Added, res.Removed, res.Updated, len(next))
		p.printSessionsLocked()
	}
	return res, nil
}

// sameConfig reports whether cp describes the same peer settings as c.
func sameConfig(c *peerConfig, cp *config.Peer) bool {
	return c.hasEndpoint == cp.HasEndpoint() && c.host == cp.Host && c.port == cp.Port &&
		slices.Equal(c.routes, cp.AllowedIPs)
}
