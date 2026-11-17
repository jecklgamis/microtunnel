package adminapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jecklgamis/microtunnel/internal/admin"
	"github.com/jecklgamis/microtunnel/internal/logx"
	"github.com/jecklgamis/microtunnel/internal/peer"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

func TestMain(m *testing.M) {
	logx.SetOutput(nopWriter{})
	os.Exit(m.Run())
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

type fakeNode struct {
	mu       sync.Mutex
	reloads  int
	reloadFn func() error
	sessions []peer.SessionInfo
}

func (f *fakeNode) ReloadFrom(string) (peer.ReloadResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloads++
	if f.reloadFn != nil {
		return peer.ReloadResult{}, f.reloadFn()
	}
	return peer.ReloadResult{}, nil
}

func (f *fakeNode) Sessions() []peer.SessionInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]peer.SessionInfo(nil), f.sessions...)
}

func (f *fakeNode) reloadCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.reloads }

type env struct {
	dir, cfg, peersDir, sock, relayPub string
	node                               *fakeNode
	client                             *Client
}

// newEnv starts a server on a unix socket. The socket lives under /tmp because
// macOS limits unix socket paths to ~104 bytes, which t.TempDir() can exceed.
func newEnv(t *testing.T) *env {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "mtapi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	e := &env{dir: dir, peersDir: filepath.Join(dir, "peers.d"), sock: filepath.Join(dir, "a.sock"), node: &fakeNode{}}
	if err := os.Mkdir(e.peersDir, 0o755); err != nil {
		t.Fatal(err)
	}
	key, _ := proto.GenerateKey()
	if _, _, err := proto.WriteKeyPair(filepath.Join(dir, "relay"), key); err != nil {
		t.Fatal(err)
	}
	pub := proto.PubBytes(key)
	e.relayPub = proto.BytesToHex(pub[:])
	e.cfg = filepath.Join(dir, "relay.yaml")
	body := "interface: mt0\nport: 5040\nprivate_key_file: relay.key\npre_shared_key: s3cret\ntunnel_address: 10.9.0.1/24\n" +
		"peers_dir: peers.d\npublic_endpoint: relay.example.com:5040\n"
	if err := os.WriteFile(e.cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	ln, err := Listen(e.sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = New(e.node, e.cfg, "test-1.2.3").Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done })
	e.client = NewClient(e.sock)
	return e
}

func randPub(t *testing.T) string {
	t.Helper()
	k, _ := proto.GenerateKey()
	p := proto.PubBytes(k)
	return proto.BytesToHex(p[:])
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func wantStatus(t *testing.T, err error, status int) {
	t.Helper()
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != status {
		t.Fatalf("err=%v, want HTTP %d", err, status)
	}
}

func TestAddListRemoveLifecycle(t *testing.T) {
	e := newEnv(t)
	pub := randPub(t)

	reg, err := e.client.Add(ctx(t), AddRequest{Name: "laptop", PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	if reg.IP.String() != "10.9.0.2" || reg.Subnet.String() != "10.9.0.0/24" || reg.Endpoint != "relay.example.com:5040" ||
		reg.RelayPublicKey.String() != e.relayPub || reg.PreSharedKey != "s3cret" {
		t.Fatalf("registration = %+v", reg)
	}
	if e.node.reloadCount() != 1 {
		t.Fatalf("reloads=%d: the running peer must be reloaded immediately", e.node.reloadCount())
	}
	if _, err := os.Stat(filepath.Join(e.peersDir, "laptop.yaml")); err != nil {
		t.Fatal(err)
	}

	// Not connected yet.
	peers, err := e.client.List(ctx(t))
	if err != nil || len(peers) != 1 {
		t.Fatalf("list: %v %+v", err, peers)
	}
	if p := peers[0]; p.Name != "laptop" || p.Connected || p.Source != "peers_dir" || p.AllowedIPs[0] != "10.9.0.2/32" {
		t.Fatalf("peer = %+v", p)
	}

	// Live state is merged in by public key.
	var k admin.Key
	_ = k.UnmarshalText([]byte(pub))
	now := time.Now()
	e.node.mu.Lock()
	e.node.sessions = []peer.SessionInfo{{PublicKey: k, Addr: netipAP("198.51.100.7:40000"), LastHandshake: now, LastSeen: now,
		TxBytes: 1000, RxBytes: 2000, TxPackets: 10, RxPackets: 20}}
	e.node.mu.Unlock()
	if peers, err = e.client.List(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if p := peers[0]; !p.Connected || p.Addr != "198.51.100.7:40000" || p.TxBytes != 1000 || p.RxPackets != 20 || p.LastSeen == nil {
		t.Fatalf("live state missing: %+v", p)
	}
	if st, err := e.client.Status(ctx(t)); err != nil || st.Version != "test-1.2.3" || st.Peers != 1 || st.Connected != 1 {
		t.Fatalf("status = %+v %v", st, err)
	}

	if err := e.client.Remove(ctx(t), "laptop"); err != nil {
		t.Fatal(err)
	}
	if e.node.reloadCount() != 2 {
		t.Fatalf("reloads=%d after remove", e.node.reloadCount())
	}
	wantStatus(t, e.client.Remove(ctx(t), "laptop"), http.StatusNotFound)
	if peers, _ = e.client.List(ctx(t)); len(peers) != 0 {
		t.Fatalf("peers after remove: %+v", peers)
	}
}

func TestAddErrorsMapToStatusCodes(t *testing.T) {
	e := newEnv(t)
	pub := randPub(t)
	if _, err := e.client.Add(ctx(t), AddRequest{Name: "a", PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	reloads := e.node.reloadCount()

	for name, tc := range map[string]struct {
		req  AddRequest
		want int
	}{
		"duplicate name":  {AddRequest{Name: "a", PublicKey: randPub(t)}, http.StatusConflict},
		"duplicate key":   {AddRequest{Name: "b", PublicKey: pub}, http.StatusConflict},
		"ip taken":        {AddRequest{Name: "c", PublicKey: randPub(t), IP: "10.9.0.2"}, http.StatusConflict},
		"bad name":        {AddRequest{Name: "../x", PublicKey: randPub(t)}, http.StatusBadRequest},
		"empty name":      {AddRequest{PublicKey: randPub(t)}, http.StatusBadRequest},
		"bad key":         {AddRequest{Name: "d", PublicKey: "nothex"}, http.StatusBadRequest},
		"missing key":     {AddRequest{Name: "d"}, http.StatusBadRequest},
		"ip outside":      {AddRequest{Name: "e", PublicKey: randPub(t), IP: "192.168.0.5"}, http.StatusBadRequest},
		"bad endpoint":    {AddRequest{Name: "f", PublicKey: randPub(t), Endpoint: "noport"}, http.StatusBadRequest},
		"bad subnet":      {AddRequest{Name: "g", PublicKey: randPub(t), Subnet: "nope"}, http.StatusBadRequest},
		"relay ip as own": {AddRequest{Name: "h", PublicKey: randPub(t), IP: "10.9.0.1"}, http.StatusConflict},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := e.client.Add(ctx(t), tc.req)
			wantStatus(t, err, tc.want)
		})
	}
	if e.node.reloadCount() != reloads {
		t.Fatal("a rejected request must not trigger a reload")
	}
	entries, _ := os.ReadDir(e.peersDir)
	if len(entries) != 1 {
		t.Fatalf("rejected requests left files: %v", entries)
	}
}

func TestMalformedBodiesAreRejected(t *testing.T) {
	e := newEnv(t)
	hc := &http.Client{Transport: &http.Transport{DialContext: func(c context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(c, "unix", e.sock)
	}}}
	for name, body := range map[string]string{
		"not json":       "{",
		"unknown field":  `{"name":"a","public_key":"` + randPub(t) + `","admin":true}`,
		"wrong type":     `{"name":5}`,
		"huge":           `{"name":"` + string(make([]byte, 1<<17)) + `"}`,
		"trailing array": `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := hc.Post("http://x/v1/peers", "application/json", stringsReader(body))
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status=%d want 400", resp.StatusCode)
			}
		})
	}
	// Unknown routes and wrong methods are not served.
	for _, tc := range []struct{ method, path string }{{"GET", "/"}, {"PUT", "/v1/peers"}, {"GET", "/v1/peers/x"}, {"POST", "/v1/status"}} {
		req, _ := http.NewRequest(tc.method, "http://x"+tc.path, nil)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 404 && resp.StatusCode != 405 {
			t.Errorf("%s %s -> %d", tc.method, tc.path, resp.StatusCode)
		}
	}
}

func TestFailedReloadRollsBackRegistration(t *testing.T) {
	e := newEnv(t)
	e.node.reloadFn = func() error { return errors.New("relay refused the peer set") }
	_, err := e.client.Add(ctx(t), AddRequest{Name: "x", PublicKey: randPub(t)})
	wantStatus(t, err, http.StatusInternalServerError)
	if entries, _ := os.ReadDir(e.peersDir); len(entries) != 0 {
		t.Fatalf("registration not rolled back: %v", entries)
	}
}

func TestConcurrentAddsNeverShareAnIP(t *testing.T) {
	e := newEnv(t)
	const n = 20
	ips := make(chan string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reg, err := e.client.Add(ctx(t), AddRequest{Name: fmt.Sprintf("p%02d", i), PublicKey: randPub(t)})
			if err != nil {
				t.Error(err)
				return
			}
			ips <- reg.IP.String()
		}()
	}
	wg.Wait()
	close(ips)
	seen := map[string]bool{}
	for ip := range ips {
		if seen[ip] {
			t.Fatalf("address %s handed out twice", ip)
		}
		seen[ip] = true
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct addresses, want %d", len(seen), n)
	}
}

func TestSocketPermissionsAndLifecycle(t *testing.T) {
	e := newEnv(t)
	fi, err := os.Stat(e.sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode = %v, want a 0600 socket", fi.Mode())
	}
	// Someone else is serving it: refuse rather than steal it.
	if _, err := Listen(e.sock); err == nil {
		t.Fatal("Listen on a live socket must fail")
	}
	// A regular file in the way is never deleted.
	plain := filepath.Join(e.dir, "plain")
	_ = os.WriteFile(plain, []byte("x"), 0o644)
	if _, err := Listen(plain); err == nil {
		t.Fatal("Listen over a regular file must fail")
	}
	if _, err := os.Stat(plain); err != nil {
		t.Fatal("regular file was removed")
	}
}

func TestListenReplacesStaleSocket(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "mtapi")
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", sock) // a crashed process's socket file
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()
	if _, err := os.Stat(sock); err != nil {
		t.Fatal("setup: stale socket file expected")
	}
	ln2, err := Listen(sock)
	if err != nil {
		t.Fatalf("stale socket should be replaced: %v", err)
	}
	_ = ln2.Close()
}

func TestServeStopsAndRemovesSocket(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "mtapi")
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	c, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- New(&fakeNode{}, "unused", "v").Serve(c, ln) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v on a clean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
	if _, err := os.Stat(sock); err == nil {
		t.Fatal("socket file left behind after shutdown")
	}
}
