package enroll

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jecklgamis/microtunnel/internal/admin"
	"github.com/jecklgamis/microtunnel/internal/adminapi"
	"github.com/jecklgamis/microtunnel/internal/logx"
)

// Registrar registers a peer with the relay; *adminapi.Client implements it.
type Registrar interface {
	Add(ctx context.Context, req adminapi.AddRequest) (*admin.Registration, error)
}

// Request is the body of POST /v1/enroll.
type Request struct {
	Token     string `json:"token"`
	PublicKey string `json:"public_key"`
	Name      string `json:"name,omitempty"`
}

type errBody struct {
	Error string `json:"error"`
}

// Server is the enrollment HTTP service.
type Server struct {
	store *Store
	reg   Registrar
	now   func() time.Time
	lim   *limiter
}

// NewServer returns a Server redeeming tokens from store and registering peers
// through reg.
func NewServer(store *Store, reg Registrar) *Server {
	return &Server{store: store, reg: reg, now: time.Now, lim: newLimiter(10, time.Minute)}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", s.enroll)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	return mux
}

// Serve serves on ln until ctx is cancelled. A non-nil tlsCfg enables HTTPS;
// nil serves plain HTTP, which the caller must have asked for explicitly.
func (s *Server) Serve(ctx context.Context, ln net.Listener, tlsCfg *tls.Config) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      40 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	var err error
	if tlsCfg != nil {
		err = srv.ServeTLS(ln, "", "")
	} else {
		err = srv.Serve(ln)
	}
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.lim.allow(ip) {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, errBody{"too many failed attempts; try again later"})
		return
	}

	var req Request
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"invalid JSON body"})
		return
	}

	claim, err := s.store.Claim(req.Token, s.now())
	if err != nil {
		s.lim.fail(ip)
		logx.Warnf("Enroll: rejected token from %s", ip)
		writeJSON(w, http.StatusUnauthorized, errBody{ErrInvalidToken.Error()})
		return
	}

	name := claim.Rec.Name
	switch {
	case name == "":
		name = req.Name
	case req.Name != "" && req.Name != name:
		_ = claim.Release()
		writeJSON(w, http.StatusBadRequest, errBody{"this token is for a different peer name"})
		return
	}
	if name == "" {
		_ = claim.Release()
		writeJSON(w, http.StatusBadRequest, errBody{"a peer name is required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	reg, err := s.reg.Add(ctx, adminapi.AddRequest{Name: name, PublicKey: req.PublicKey})
	if err != nil {
		// The token was valid; do not burn it over a request or relay problem.
		_ = claim.Release()
		var ae *adminapi.APIError
		code, msg := http.StatusBadGateway, "could not register with the relay"
		if errors.As(err, &ae) {
			switch ae.Status {
			case http.StatusBadRequest, http.StatusConflict:
				// Safe to show: names, key format, duplicates. Never a path or stack.
				code, msg = ae.Status, ae.Message
			default:
				logx.Errorf("Enroll: relay admin API: %v", err)
			}
		} else {
			logx.Errorf("Enroll: relay admin API: %v", err)
		}
		writeJSON(w, code, errBody{msg})
		return
	}
	if err := claim.Commit(); err != nil {
		logx.Errorf("Enroll: could not mark token %s used: %v", claim.Rec.ID, err)
	}
	logx.Infof("Enroll: peer %s (%s) enrolled from %s using token %s", reg.Name, reg.IP, ip, claim.Rec.ID)
	writeJSON(w, http.StatusCreated, reg)
}

// limiter allows up to max failed attempts per key within window.
type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string]*bucket
}

type bucket struct {
	n     int
	start time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, hits: make(map[string]*bucket)}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.hits[key]
	if b == nil {
		return true
	}
	if time.Since(b.start) > l.window {
		delete(l.hits, key)
		return true
	}
	return b.n < l.max
}

func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.hits) > 10000 { // bound memory under a spray of sources
		for k, b := range l.hits {
			if time.Since(b.start) > l.window {
				delete(l.hits, k)
			}
		}
	}
	b := l.hits[key]
	if b == nil || time.Since(b.start) > l.window {
		b = &bucket{start: time.Now()}
		l.hits[key] = b
	}
	b.n++
}
