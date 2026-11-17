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
	applied := config.PeersDirFingerprint(peersDir) // what the running peers reflect
	seen := applied                                 // last fingerprint observed

	reload := func(why string) {
		logx.Infof("Reloading peers (%s)", why)
		res, err := p.ReloadFrom(configPath)
		switch {
		case err != nil:
			logx.Errorf("Peer reload failed, keeping current peers: %v", err)
		case !res.Changed():
			logx.Infof("Peer reload: no changes")
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-trigger:
			reload("requested")
			applied = config.PeersDirFingerprint(peersDir)
			seen = applied
		case <-tick:
			fp := config.PeersDirFingerprint(peersDir)
			switch {
			case fp == applied:
				seen = fp
			case fp != seen:
				seen = fp // changed since last poll: wait for it to settle
			default:
				reload("peers_dir changed")
				applied = fp
			}
		}
	}
}
