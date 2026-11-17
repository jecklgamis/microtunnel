package peer

import (
	"context"
	"time"

	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/logx"
)

// WatchPeers keeps the running peer set in sync with the config file until ctx
// is cancelled. It reloads when:
//
//   - a value arrives on trigger (main wires SIGHUP to it; may be nil), or
//   - peersDir's contents change. The directory is polled every interval, and a
//     change is applied only once it has been stable for one poll, so a file
//     that is still being written is never half-read.
//
// A reload that fails (bad YAML, duplicate key, ...) is logged and changes
// nothing; the previous peer set keeps running. After a failed automatic
// reload the watcher waits for the directory to change again instead of
// retrying every poll.
func (p *Peer) WatchPeers(ctx context.Context, configPath, peersDir string, interval time.Duration, trigger <-chan struct{}) {
	var tick <-chan time.Time
	if peersDir != "" {
		t := time.NewTicker(interval)
		defer t.Stop()
		tick = t.C
	}
	// There is no baseline yet. The caller loaded the peers before starting us, and a
	// file may have been added in between, so the first stable fingerprint is
	// reconciled with a reload (silent when nothing differs) instead of assumed to
	// match the running peers.
	var applied, seen string
	known := false // applied is valid: the running peers reflect that fingerprint

	reload := func(why string, quiet bool) {
		if !quiet {
			logx.Infof("Reloading peers (%s)", why)
		}
		res, err := p.ReloadFrom(configPath)
		switch {
		case err != nil:
			logx.Errorf("Peer reload failed, keeping current peers: %v", err)
		case !res.Changed() && !quiet:
			logx.Infof("Peer reload: no changes")
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-trigger:
			reload("requested", false)
			applied, known = config.PeersDirFingerprint(peersDir), true
			seen = applied
		case <-tick:
			fp := config.PeersDirFingerprint(peersDir)
			switch {
			case known && fp == applied:
				seen = fp
			case fp != seen:
				seen = fp // changed since last poll: wait for it to settle
			default:
				reload("peers_dir changed", !known)
				applied, known = fp, true
			}
		}
	}
}
