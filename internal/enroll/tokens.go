// Package enroll is microtunnel's self-service onboarding: an administrator
// creates a short-lived single-use join token, and a new machine presents it
// together with its own public key over HTTPS. The server registers that
// public key with the relay (through its admin socket) and hands back
// everything the machine needs to connect. The machine's private key is
// generated on the machine and never travels.
//
// This file is the token store. Tokens are random secrets of which only a
// SHA-256 hash is stored, one file per token, and claiming a token is a single
// atomic rename, so concurrent or repeated use can never succeed twice, even
// across processes.
package enroll

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	tokenPrefix = "mt1"
	// DefaultTTL is how long a token lives unless told otherwise.
	DefaultTTL = time.Hour
	// MaxTTL caps a token's lifetime.
	MaxTTL = 7 * 24 * time.Hour
)

var idRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

// ErrInvalidToken is returned for every way a token can be unusable (malformed,
// unknown, wrong secret, expired, already used). The reasons are deliberately
// indistinguishable to callers.
var ErrInvalidToken = errors.New("invalid or expired token")

// Record is the stored form of a token. The secret itself is never stored.
type Record struct {
	ID      string    `json:"id"`
	Hash    string    `json:"hash"` // hex SHA-256 of the secret
	Name    string    `json:"name,omitempty"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}

// Status is a token's state, for listings.
type Status string

const (
	StatusPending Status = "pending"
	StatusClaimed Status = "in progress" // being redeemed, or a redemption crashed midway
	StatusUsed    Status = "used"
	StatusExpired Status = "expired"
)

// Entry is a Record with its current Status.
type Entry struct {
	Record
	Status Status
}

// Store is a directory of token files.
type Store struct{ dir string }

// OpenStore opens (creating, mode 0700) the token directory.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("token store: %w", err)
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(id, ext string) string { return filepath.Join(s.dir, id+ext) }

func randToken() (id, secret string, err error) {
	var b [8]byte
	if _, err = rand.Read(b[:]); err != nil {
		return
	}
	var sec [24]byte
	if _, err = rand.Read(sec[:]); err != nil {
		return
	}
	return hex.EncodeToString(b[:]), base64.RawURLEncoding.EncodeToString(sec[:]), nil
}

func hashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// Create makes a new token. name, if non-empty, binds the token to that peer
// name; ttl <= 0 means DefaultTTL. The returned token string is shown once and
// cannot be recovered later.
func (s *Store) Create(name string, ttl time.Duration, now time.Time) (token string, rec Record, err error) {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if ttl > MaxTTL {
		return "", Record{}, fmt.Errorf("ttl %s exceeds the maximum of %s", ttl, MaxTTL)
	}
	id, secret, err := randToken()
	if err != nil {
		return "", Record{}, err
	}
	rec = Record{ID: id, Hash: hashSecret(secret), Name: name, Created: now.UTC(), Expires: now.Add(ttl).UTC()}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return "", Record{}, err
	}
	f, err := os.OpenFile(s.path(id, ".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", Record{}, err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		_ = os.Remove(s.path(id, ".json"))
		return "", Record{}, err
	}
	if err := f.Close(); err != nil {
		return "", Record{}, err
	}
	return fmt.Sprintf("%s.%s.%s", tokenPrefix, id, secret), rec, nil
}

func parseToken(token string) (id, secret string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != tokenPrefix || !idRE.MatchString(parts[1]) || parts[2] == "" || len(parts[2]) > 64 {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// Claim redeems token: it checks the secret and expiry, then atomically takes
// the token so nobody else can use it. The caller must call Commit on success
// or Release if the enrollment fails, so the token is not burned by an error.
func (s *Store) Claim(token string, now time.Time) (*Claim, error) {
	id, secret, ok := parseToken(token)
	if !ok {
		return nil, ErrInvalidToken
	}
	data, err := os.ReadFile(s.path(id, ".json"))
	if err != nil {
		return nil, ErrInvalidToken
	}
	var rec Record
	if json.Unmarshal(data, &rec) != nil || rec.ID != id {
		return nil, ErrInvalidToken
	}
	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(rec.Hash)) != 1 {
		return nil, ErrInvalidToken
	}
	if !now.Before(rec.Expires) {
		return nil, ErrInvalidToken
	}
	// The atomic step: exactly one caller can rename the file away.
	if err := os.Rename(s.path(id, ".json"), s.path(id, ".claimed")); err != nil {
		return nil, ErrInvalidToken
	}
	return &Claim{store: s, Rec: rec}, nil
}

// Claim is a token taken for redemption.
type Claim struct {
	store *Store
	Rec   Record
}

// Commit marks the token used for good.
func (c *Claim) Commit() error {
	return os.Rename(c.store.path(c.Rec.ID, ".claimed"), c.store.path(c.Rec.ID, ".used"))
}

// Release puts the token back so it can be tried again (the enrollment failed
// for a reason that was not the token's fault).
func (c *Claim) Release() error {
	return os.Rename(c.store.path(c.Rec.ID, ".claimed"), c.store.path(c.Rec.ID, ".json"))
}

// List returns every token with its status, newest first.
func (s *Store) List(now time.Time) ([]Entry, error) {
	files, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, f := range files {
		ext := filepath.Ext(f.Name())
		id := strings.TrimSuffix(f.Name(), ext)
		if f.IsDir() || !idRE.MatchString(id) {
			continue
		}
		var st Status
		switch ext {
		case ".json":
			st = StatusPending
		case ".claimed":
			st = StatusClaimed
		case ".used":
			st = StatusUsed
		default:
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, f.Name()))
		if err != nil {
			continue
		}
		var rec Record
		if json.Unmarshal(data, &rec) != nil {
			continue
		}
		if st == StatusPending && !now.Before(rec.Expires) {
			st = StatusExpired
		}
		out = append(out, Entry{Record: rec, Status: st})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

// Revoke deletes a token by id, in whatever state it is.
func (s *Store) Revoke(id string) error {
	if !idRE.MatchString(id) {
		return fmt.Errorf("invalid token id %q", id)
	}
	removed := false
	for _, ext := range []string{".json", ".claimed", ".used"} {
		if err := os.Remove(s.path(id, ext)); err == nil {
			removed = true
		}
	}
	if !removed {
		return fmt.Errorf("no such token %q", id)
	}
	return nil
}
