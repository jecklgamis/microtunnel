// Package adminapi is the relay's local management API: JSON over HTTP on a
// unix socket (mode 0600), so access control is the filesystem's. It lets
// tools add, remove and list peers and read live session state without
// touching peers_dir directly. Mutations go through the same admin package the
// CLI's file mode uses and then reload the running peer immediately.
//
//	GET    /v1/status        version, uptime, peer counts
//	GET    /v1/peers         configured peers merged with live session state
//	POST   /v1/peers         register a peer (allocates its overlay IP)
//	DELETE /v1/peers/{name}  remove a peer and drop its session
package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/jecklgamis/microtunnel/internal/admin"
	"github.com/jecklgamis/microtunnel/internal/logx"
	"github.com/jecklgamis/microtunnel/internal/peer"
)

// Node is the running peer the API controls.
type Node interface {
	ReloadFrom(path string) (peer.ReloadResult, error)
	Sessions() []peer.SessionInfo
}

// AddRequest is the body of POST /v1/peers.
type AddRequest struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	IP        string `json:"ip,omitempty"`
	Subnet    string `json:"subnet,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
}

// PeerInfo is one entry of GET /v1/peers.
type PeerInfo struct {
	Name          string     `json:"name,omitempty"` // empty for peers listed inline in the main config
	PublicKey     admin.Key  `json:"public_key"`
	AllowedIPs    []string   `json:"allowed_ips"`
	Endpoint      string     `json:"endpoint,omitempty"`
	Source        string     `json:"source"` // "peers_dir" or "config"
	Connected     bool       `json:"connected"`
	Addr          string     `json:"addr,omitempty"`
	Outbound      bool       `json:"outbound,omitempty"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	LastSeen      *time.Time `json:"last_seen,omitempty"`
	TxBytes       uint64     `json:"tx_bytes"`
	RxBytes       uint64     `json:"rx_bytes"`
	TxPackets     uint64     `json:"tx_packets"`
	RxPackets     uint64     `json:"rx_packets"`
}

// Status is the body of GET /v1/status.
type Status struct {
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	Peers         int    `json:"peers"`
	Connected     int    `json:"connected"`
}

// Server serves the admin API for one Node.
type Server struct {
	node       Node
	configPath string
	version    string
	started    time.Time

	mu sync.Mutex // serialises mutations: one registration/removal at a time
}

// New returns a Server. configPath is the relay's config file (it names
// peers_dir); version is reported by /v1/status.
func New(node Node, configPath, version string) *Server {
	return &Server{node: node, configPath: configPath, version: version, started: time.Now()}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("GET /v1/peers", s.list)
	mux.HandleFunc("POST /v1/peers", s.add)
	mux.HandleFunc("DELETE /v1/peers/{name}", s.remove)
	return mux
}

// Listen creates the unix socket at path with mode 0600. A stale socket file
// left by a crashed process is replaced; a socket another process is still
// serving is an error.
func Listen(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("admin_socket %s exists and is not a socket", path)
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			_ = c.Close()
			return nil, fmt.Errorf("admin_socket %s is already in use", path)
		}
		_ = os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// Serve serves on ln until ctx is cancelled, then shuts down gracefully.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	err := srv.Serve(ln)
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// fail maps an error to a status code: request errors carry their own Kind,
// anything else is a server-side problem.
func fail(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch admin.KindOf(err) {
	case admin.KindInvalid:
		code = http.StatusBadRequest
	case admin.KindConflict:
		code = http.StatusConflict
	case admin.KindNotFound:
		code = http.StatusNotFound
	}
	if code == http.StatusInternalServerError {
		logx.Errorf("admin API: %v", err)
	}
	writeJSON(w, code, apiError{Error: err.Error()})
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	entries, err := admin.List(s.configPath)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, Status{
		Version:       s.version,
		UptimeSeconds: int64(time.Since(s.started).Seconds()),
		Peers:         len(entries),
		Connected:     len(s.node.Sessions()),
	})
}

func (s *Server) list(w http.ResponseWriter, _ *http.Request) {
	entries, err := admin.List(s.configPath)
	if err != nil {
		fail(w, err)
		return
	}
	live := make(map[admin.Key]peer.SessionInfo)
	for _, si := range s.node.Sessions() {
		live[admin.Key(si.PublicKey)] = si
	}
	out := make([]PeerInfo, 0, len(entries))
	for _, e := range entries {
		pi := PeerInfo{
			Name: e.Name, PublicKey: admin.Key(e.PublicKey), AllowedIPs: e.AllowedIPs,
			Endpoint: e.Endpoint, Source: "peers_dir",
		}
		if pi.AllowedIPs == nil {
			pi.AllowedIPs = []string{}
		}
		if e.Inline {
			pi.Source = "config"
		}
		if si, ok := live[pi.PublicKey]; ok {
			pi.Connected = true
			pi.Addr, pi.Outbound = si.Addr.String(), si.Outbound
			pi.LastHandshake = timePtr(si.LastHandshake)
			pi.LastSeen = timePtr(si.LastSeen)
			pi.TxBytes, pi.RxBytes, pi.TxPackets, pi.RxPackets = si.TxBytes, si.RxBytes, si.TxPackets, si.RxPackets
		}
		out = append(out, pi)
	}
	writeJSON(w, http.StatusOK, out)
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (s *Server) add(w http.ResponseWriter, r *http.Request) {
	var req AddRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid JSON body: " + err.Error()})
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	reg, err := admin.Register(s.configPath, admin.RegisterOptions{
		Name: req.Name, PublicKeyHex: req.PublicKey, IP: req.IP, Subnet: req.Subnet, Endpoint: req.Endpoint,
	})
	if err != nil {
		fail(w, err)
		return
	}
	// Apply it to the running peer now, rather than waiting for the poll.
	if _, err := s.node.ReloadFrom(s.configPath); err != nil {
		_ = os.Remove(reg.PeerFile) // do not leave a registration the relay refused
		fail(w, fmt.Errorf("registered but the reload failed, so it was rolled back: %w", err))
		return
	}
	logx.Infof("Admin API: registered peer %s (%s)", reg.Name, reg.IP)
	writeJSON(w, http.StatusCreated, reg)
}

func (s *Server) remove(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := admin.Remove(s.configPath, name); err != nil {
		fail(w, err)
		return
	}
	if _, err := s.node.ReloadFrom(s.configPath); err != nil {
		fail(w, fmt.Errorf("removed the peer file but the reload failed: %w", err))
		return
	}
	logx.Infof("Admin API: removed peer %s", name)
	writeJSON(w, http.StatusOK, map[string]string{"removed": name})
}
