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
