package enroll

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "tokens"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var t0 = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func TestTokenLifecycle(t *testing.T) {
	s := newStore(t)
	tok, rec, err := s.Create("laptop", time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "mt1."+rec.ID+".") || rec.Name != "laptop" || !rec.Expires.Equal(t0.Add(time.Hour)) {
		t.Fatalf("token=%q rec=%+v", tok, rec)
	}

	// Never stored in the clear, and not world-readable.
	raw, _ := os.ReadFile(filepath.Join(s.dir, rec.ID+".json"))
	secret := strings.Split(tok, ".")[2]
	if strings.Contains(string(raw), secret) {
		t.Fatal("the token secret was written to disk")
	}
	if fi, _ := os.Stat(filepath.Join(s.dir, rec.ID+".json")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(s.dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("token dir mode %v", fi.Mode().Perm())
	}

	c, err := s.Claim(tok, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if c.Rec.Name != "laptop" {
		t.Fatalf("claim record = %+v", c.Rec)
	}
	// While claimed (and after commit) nobody else can use it.
	if _, err := s.Claim(tok, t0.Add(time.Minute)); err != ErrInvalidToken {
		t.Fatalf("second claim err=%v", err)
	}
	if err := c.Release(); err != nil {
		t.Fatal(err)
	}
	c, err = s.Claim(tok, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("a released token must be usable again: %v", err)
	}
	if err := c.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(tok, t0.Add(time.Minute)); err != ErrInvalidToken {
		t.Fatalf("committed token reusable: %v", err)
	}
	entries, _ := s.List(t0)
	if len(entries) != 1 || entries[0].Status != StatusUsed {
		t.Fatalf("list = %+v", entries)
	}
}

func TestTokenRejections(t *testing.T) {
	s := newStore(t)
	tok, rec, _ := s.Create("", time.Hour, t0)
	parts := strings.Split(tok, ".")

	for name, bad := range map[string]string{
		"empty":           "",
		"garbage":         "hello",
		"wrong prefix":    "mt2." + parts[1] + "." + parts[2],
		"wrong secret":    "mt1." + parts[1] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"unknown id":      "mt1.0000000000000000." + parts[2],
		"path traversal":  "mt1.../../../etc/passwd." + parts[2],
		"traversal 2":     "mt1.." + "/" + parts[2],
		"extra part":      tok + ".x",
		"empty secret":    "mt1." + parts[1] + ".",
		"upper-case id":   "mt1." + strings.ToUpper(parts[1]) + "." + parts[2],
		"oversize secret": "mt1." + parts[1] + "." + strings.Repeat("A", 500),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Claim(bad, t0); err != ErrInvalidToken {
				t.Fatalf("err=%v", err)
			}
		})
	}
	// None of those attempts consumed the real token.
	if _, err := s.Claim(tok, t0); err != nil {
		t.Fatalf("real token damaged by bad attempts: %v", err)
	}
	_ = rec
}

func TestTokenExpiryAndLimits(t *testing.T) {
	s := newStore(t)
	tok, _, _ := s.Create("", time.Minute, t0)
	if _, err := s.Claim(tok, t0.Add(time.Minute)); err != ErrInvalidToken {
		t.Fatalf("expired token accepted: %v", err)
	}
	entries, _ := s.List(t0.Add(time.Hour))
	if entries[0].Status != StatusExpired {
		t.Fatalf("status=%s", entries[0].Status)
	}
	if _, _, err := s.Create("", MaxTTL+time.Second, t0); err == nil {
		t.Fatal("ttl above the maximum must be rejected")
	}
	if _, rec, err := s.Create("", 0, t0); err != nil || !rec.Expires.Equal(t0.Add(DefaultTTL)) {
		t.Fatalf("default ttl: %+v %v", rec, err)
	}
}

func TestTokenClaimedByExactlyOneOfManyConcurrentRedeemers(t *testing.T) {
	s := newStore(t)
	tok, _, _ := s.Create("", time.Hour, t0)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c, err := s.Claim(tok, t0); err == nil {
				wins.Add(1)
				_ = c.Commit()
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d redeemers succeeded, want exactly 1", wins.Load())
	}
}

func TestListAndRevoke(t *testing.T) {
	s := newStore(t)
	a, ra, _ := s.Create("a", time.Hour, t0)
	_, rb, _ := s.Create("b", time.Hour, t0.Add(time.Second))
	c, _ := s.Claim(a, t0)
	_ = c // left in progress
	entries, _ := s.List(t0)
	if len(entries) != 2 || entries[0].ID != rb.ID || entries[0].Status != StatusPending || entries[1].Status != StatusClaimed {
		t.Fatalf("entries = %+v", entries)
	}
	if err := s.Revoke(rb.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ra.ID); err != nil { // in-progress ones can be cleared too
		t.Fatal(err)
	}
	if err := s.Revoke(rb.ID); err == nil {
		t.Fatal("revoking twice must fail")
	}
	if err := s.Revoke("../../etc"); err == nil {
		t.Fatal("path traversal in id must be rejected")
	}
	if entries, _ = s.List(t0); len(entries) != 0 {
		t.Fatalf("entries after revoke: %+v", entries)
	}
}
