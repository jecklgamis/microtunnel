// Package logx provides the tiny timestamped logger used throughout microtunnel.
//
// Every line has the form:
//
//	2026-04-23 14:05:32 [INFO]  Peer connected: 1.2.3.4:5040 (key=deadbeef...)
//
// Output goes to stderr. Debug lines are emitted only when verbose logging is
// enabled via SetVerbose(true) (config key `verbose: true`).
package logx

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var (
	verbose atomic.Bool
	mu      sync.Mutex
	out     io.Writer = os.Stderr
	// now is replaceable in tests.
	now = time.Now
)

// SetVerbose enables or disables DEBUG output.
func SetVerbose(v bool) { verbose.Store(v) }

// Verbose reports whether DEBUG output is enabled.
func Verbose() bool { return verbose.Load() }

// SetOutput redirects log output (used by tests). Returns the previous writer.
func SetOutput(w io.Writer) io.Writer {
	mu.Lock()
	defer mu.Unlock()
	prev := out
	out = w
	return prev
}

func logf(level, format string, args ...any) {
	line := fmt.Sprintf("%s %s %s\n", now().Format("2006-01-02 15:04:05"), level, fmt.Sprintf(format, args...))
	mu.Lock()
	defer mu.Unlock()
	_, _ = io.WriteString(out, line)
}

// Errorf logs at ERROR level.
func Errorf(format string, args ...any) { logf("[ERROR]", format, args...) }

// Warnf logs at WARN level.
func Warnf(format string, args ...any) { logf("[WARN] ", format, args...) }

// Infof logs at INFO level.
func Infof(format string, args ...any) { logf("[INFO] ", format, args...) }

// Debugf logs at DEBUG level; it is a no-op unless verbose logging is on.
func Debugf(format string, args ...any) {
	if !verbose.Load() {
		return
	}
	logf("[DEBUG]", format, args...)
}

// Limiter rate-limits log lines that unauthenticated network input can trigger
// (junk datagrams, forged handshakes), so a flood cannot fill the disk or the
// journal. Each key emits at most one line per interval; the next line that
// gets through reports how many were suppressed. Keys must come from a small
// fixed set (never from packet contents). A nil *Limiter logs everything.
type Limiter struct {
	every time.Duration
	mu    sync.Mutex
	state map[string]*limitState
}

type limitState struct {
	last       time.Time
	suppressed int
}

// NewLimiter returns a Limiter allowing one line per key every interval.
func NewLimiter(every time.Duration) *Limiter {
	return &Limiter{every: every, state: make(map[string]*limitState)}
}

func (l *Limiter) allow(key string) (ok bool, suppressed int) {
	t := now()
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.state[key]
	if s == nil {
		l.state[key] = &limitState{last: t}
		return true, 0
	}
	if t.Sub(s.last) < l.every {
		s.suppressed++
		return false, 0
	}
	suppressed, s.suppressed, s.last = s.suppressed, 0, t
	return true, suppressed
}

func (l *Limiter) logf(level, key, format string, args ...any) {
	if l == nil {
		logf(level, format, args...)
		return
	}
	ok, n := l.allow(key)
	if !ok {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if n > 0 {
		msg += fmt.Sprintf(" (%d similar suppressed)", n)
	}
	logf(level, "%s", msg)
}

// Warnf logs at WARN level, rate-limited per key.
func (l *Limiter) Warnf(key, format string, args ...any) { l.logf("[WARN] ", key, format, args...) }

// Infof logs at INFO level, rate-limited per key.
func (l *Limiter) Infof(key, format string, args ...any) { l.logf("[INFO] ", key, format, args...) }
