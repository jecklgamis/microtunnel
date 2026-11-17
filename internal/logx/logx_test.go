package logx

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"
)

func capture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := SetOutput(&buf)
	prevNow := now
	now = func() time.Time { return time.Date(2026, 4, 23, 14, 5, 32, 0, time.UTC) }
	prevVerbose := Verbose()
	t.Cleanup(func() { SetOutput(prev); now = prevNow; SetVerbose(prevVerbose) })
	return &buf
}

func TestLineFormat(t *testing.T) {
	buf := capture(t)
	Infof("Peer connected: %s", "1.2.3.4:5040")
	Warnf("Replay detected (seq=%d)", 42)
	Errorf("boom")
	want := "2026-04-23 14:05:32 [INFO]  Peer connected: 1.2.3.4:5040\n" +
		"2026-04-23 14:05:32 [WARN]  Replay detected (seq=42)\n" +
		"2026-04-23 14:05:32 [ERROR] boom\n"
	if got := buf.String(); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestDebugOnlyWhenVerbose(t *testing.T) {
	buf := capture(t)
	SetVerbose(false)
	Debugf("hidden")
	if buf.Len() != 0 {
		t.Fatalf("debug line emitted while not verbose: %q", buf.String())
	}
	SetVerbose(true)
	Debugf("shown %d", 1)
	if !regexp.MustCompile(`^2026-04-23 14:05:32 \[DEBUG\] shown 1\n$`).MatchString(buf.String()) {
		t.Fatalf("unexpected debug output: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "[DEBUG]") {
		t.Fatal("missing level tag")
	}
}

func TestLimiterSuppressesFloodsAndReportsCount(t *testing.T) {
	buf := capture(t)
	clock := time.Date(2026, 4, 23, 14, 5, 32, 0, time.UTC)
	now = func() time.Time { return clock }
	l := NewLimiter(time.Second)

	for i := 0; i < 100; i++ {
		l.Warnf("junk", "junk datagram %d", i)
	}
	l.Warnf("other", "a different key is independent")
	if got := strings.Count(buf.String(), "\n"); got != 2 {
		t.Fatalf("flood produced %d lines, want 2:\n%s", got, buf)
	}

	clock = clock.Add(1500 * time.Millisecond)
	l.Warnf("junk", "junk datagram again")
	if !strings.Contains(buf.String(), "junk datagram again (99 similar suppressed)") {
		t.Fatalf("suppressed count not reported:\n%s", buf)
	}
}

func TestNilLimiterLogsEverything(t *testing.T) {
	buf := capture(t)
	var l *Limiter
	l.Warnf("k", "one")
	l.Infof("k", "two")
	if got := strings.Count(buf.String(), "\n"); got != 2 {
		t.Fatalf("nil limiter logged %d lines, want 2", got)
	}
}
