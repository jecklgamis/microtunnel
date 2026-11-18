package enroll

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jecklgamis/microtunnel/internal/admin"
	"github.com/jecklgamis/microtunnel/internal/adminapi"
	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/logx"
	"github.com/jecklgamis/microtunnel/internal/peer"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

func TestMain(m *testing.M) {
	logx.SetOutput(discard{})
	os.Exit(m.Run())
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// fakeRegistrar stands in for the relay's admin API.
type fakeRegistrar struct {
	mu    sync.Mutex
	calls []adminapi.AddRequest
	err   error
}

func (f *fakeRegistrar) Add(_ context.Context, r adminapi.AddRequest) (*admin.Registration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r)
	if f.err != nil {
		return nil, f.err
	}
	var k admin.Key
	_ = k.UnmarshalText([]byte(r.PublicKey))
	return &admin.Registration{Name: r.Name, IP: netip.MustParseAddr("10.9.0.2"), Subnet: netip.MustParsePrefix("10.9.0.0/24"),
		PublicKey: k, Endpoint: "relay.example.com:5040", PreSharedKey: "psk"}, nil
}

func (f *fakeRegistrar) n() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

func validPub(t *testing.T) string {
	t.Helper()
	k, _ := proto.GenerateKey()
	p := proto.PubBytes(k)
	return proto.BytesToHex(p[:])
}

func newTestServer(t *testing.T, reg Registrar) (*Server, *Store, *httptest.Server) {
	t.Helper()
	store := newStore(t)
	s := NewServer(store, reg)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, store, ts
}

func enrollReq(t *testing.T, ts *httptest.Server, body any) (*http.Response, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(ts.URL+"/v1/enroll", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func TestEnrollSuccessBurnsTheToken(t *testing.T) {
	reg := &fakeRegistrar{}
	_, store, ts := newTestServer(t, reg)
	tok, _, _ := store.Create("laptop", time.Hour, time.Now())
	pub := validPub(t)

	resp, out := enrollReq(t, ts, Request{Token: tok, PublicKey: pub})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d %v", resp.StatusCode, out)
	}
	if out["name"] != "laptop" || out["ip"] != "10.9.0.2" || out["pre_shared_key"] != "psk" {
		t.Fatalf("registration = %v", out)
	}
	if reg.calls[0].Name != "laptop" || reg.calls[0].PublicKey != pub {
		t.Fatalf("relay saw %+v", reg.calls[0])
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("a response carrying the PSK must not be cacheable")
	}

	resp, _ = enrollReq(t, ts, Request{Token: tok, PublicKey: validPub(t)})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reuse status=%d, want 401", resp.StatusCode)
	}
	if reg.n() != 1 {
		t.Fatalf("relay called %d times; a used token must never reach it", reg.n())
	}
}

func TestEnrollNameRules(t *testing.T) {
	reg := &fakeRegistrar{}
	_, store, ts := newTestServer(t, reg)

	// Unbound token: the client names itself.
	tok, _, _ := store.Create("", time.Hour, time.Now())
	if resp, out := enrollReq(t, ts, Request{Token: tok, PublicKey: validPub(t)}); resp.StatusCode != 400 || !strings.Contains(out["error"].(string), "name") {
		t.Fatalf("missing name: %d %v", resp.StatusCode, out)
	}
	// ...and the failed attempt did not burn the token.
	if resp, _ := enrollReq(t, ts, Request{Token: tok, PublicKey: validPub(t), Name: "phone"}); resp.StatusCode != 201 {
		t.Fatalf("token burned by a name mistake: %d", resp.StatusCode)
	}

	// Bound token: cannot be used under another name.
	tok2, _, _ := store.Create("server1", time.Hour, time.Now())
	if resp, _ := enrollReq(t, ts, Request{Token: tok2, PublicKey: validPub(t), Name: "evil"}); resp.StatusCode != 400 {
		t.Fatalf("bound token accepted another name: %d", resp.StatusCode)
	}
	if resp, _ := enrollReq(t, ts, Request{Token: tok2, PublicKey: validPub(t)}); resp.StatusCode != 201 {
		t.Fatalf("bound token should still work under its own name: %d", resp.StatusCode)
	}
	if last := reg.calls[len(reg.calls)-1]; last.Name != "server1" {
		t.Fatalf("relay saw %+v", last)
	}
}

func TestEnrollRelayErrorsDoNotBurnTheToken(t *testing.T) {
	for name, tc := range map[string]struct {
		err      error
		wantCode int
		wantMsg  string
	}{
		"conflict": {&adminapi.APIError{Status: 409, Message: `peer "x" already exists (/etc/microtunnel/peers.d/x.yaml)`}, 409, "already registered"},
		"invalid":  {&adminapi.APIError{Status: 400, Message: "invalid public key"}, 400, "invalid enrollment request"},
		"internal": {&adminapi.APIError{Status: 500, Message: "open /etc/microtunnel/relay.key: permission denied"}, 502, "could not register"},
		"down":     {errors.New("dial unix /run/mt.sock: connect: no such file or directory"), 502, "could not register"},
	} {
		t.Run(name, func(t *testing.T) {
			reg := &fakeRegistrar{err: tc.err}
			_, store, ts := newTestServer(t, reg)
			tok, _, _ := store.Create("x", time.Hour, time.Now())
			resp, out := enrollReq(t, ts, Request{Token: tok, PublicKey: validPub(t)})
			if resp.StatusCode != tc.wantCode || !strings.Contains(out["error"].(string), tc.wantMsg) {
				t.Fatalf("status=%d body=%v", resp.StatusCode, out)
			}
			// Internal details (paths, socket names) must not reach the client.
			if strings.Contains(out["error"].(string), "/etc/") || strings.Contains(out["error"].(string), "/run/") {
				t.Fatalf("server internals leaked: %v", out)
			}
			reg.mu.Lock()
			reg.err = nil
			reg.mu.Unlock()
			if resp, _ := enrollReq(t, ts, Request{Token: tok, PublicKey: validPub(t)}); resp.StatusCode != 201 {
				t.Fatalf("token was burned by a relay-side failure: %d", resp.StatusCode)
			}
		})
	}
}

func TestEnrollRejectsBadTokensUniformlyAndRateLimits(t *testing.T) {
	reg := &fakeRegistrar{}
	s, store, ts := newTestServer(t, reg)
	s.lim = newLimiter(5, time.Minute)
	expired, _, _ := store.Create("", time.Minute, time.Now().Add(-time.Hour))

	var msgs = map[string]bool{}
	for _, tok := range []string{"nope", "mt1.0000000000000000.AAAA", expired} {
		resp, out := enrollReq(t, ts, Request{Token: tok, PublicKey: validPub(t), Name: "x"})
		if resp.StatusCode != 401 {
			t.Fatalf("token %q: status=%d", tok, resp.StatusCode)
		}
		msgs[out["error"].(string)] = true
	}
	if len(msgs) != 1 {
		t.Fatalf("different failures are distinguishable to a guesser: %v", msgs)
	}

	// Two more failures reach the limit; after that even a good token is refused
	// until the window passes.
	enrollReq(t, ts, Request{Token: "x"})
	enrollReq(t, ts, Request{Token: "y"})
	good, _, _ := store.Create("ok", time.Hour, time.Now())
	resp, _ := enrollReq(t, ts, Request{Token: good, PublicKey: validPub(t)})
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("status=%d, want 429 with Retry-After", resp.StatusCode)
	}
	if reg.n() != 0 {
		t.Fatal("the relay was contacted while rate limited")
	}
}

func TestEnrollRejectsMalformedRequests(t *testing.T) {
	_, _, ts := newTestServer(t, &fakeRegistrar{})
	for name, body := range map[string]string{
		"not json":      "{",
		"unknown field": `{"token":"t","public_key":"k","admin":true}`,
		"huge":          `{"token":"` + strings.Repeat("a", 1<<15) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := http.Post(ts.URL+"/v1/enroll", "application/json", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 400 {
				t.Fatalf("status=%d", resp.StatusCode)
			}
		})
	}
	if resp, _ := http.Get(ts.URL + "/v1/enroll"); resp.StatusCode != 405 {
		t.Fatalf("GET /v1/enroll -> %d", resp.StatusCode)
	}
	if resp, _ := http.Get(ts.URL + "/healthz"); resp.StatusCode != 200 {
		t.Fatalf("healthz -> %d", resp.StatusCode)
	}
}

// --- end to end: join -> TLS enroll server -> real admin API -> peers_dir -----

type stubNode struct{}

func (stubNode) ReloadFrom(string) (peer.ReloadResult, error) { return peer.ReloadResult{}, nil }
func (stubNode) Sessions() []peer.SessionInfo                 { return nil }

type fullEnv struct {
	relayCfg, peersDir string
	store              *Store
	ts                 *httptest.Server
	caFile             string
	relayPub           string
}

func newFullEnv(t *testing.T) *fullEnv {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "mtenr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	e := &fullEnv{peersDir: filepath.Join(dir, "peers.d"), relayCfg: filepath.Join(dir, "relay.yaml")}
	_ = os.Mkdir(e.peersDir, 0o755)
	key, _ := proto.GenerateKey()
	_, _, _ = proto.WriteKeyPair(filepath.Join(dir, "relay"), key)
	pub := proto.PubBytes(key)
	e.relayPub = proto.BytesToHex(pub[:])
	body := "interface: mt0\nport: 5040\nprivate_key_file: relay.key\npre_shared_key: join-psk\ntunnel_address: 10.9.0.1/24\n" +
		"peers_dir: peers.d\npublic_endpoint: relay.example.com:5040\n"
	if err := os.WriteFile(e.relayCfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(dir, "a.sock")
	ln, err := adminapi.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = adminapi.New(stubNode{}, e.relayCfg, "t").Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done })

	e.store, _ = OpenStore(filepath.Join(dir, "tokens"))
	e.ts = httptest.NewTLSServer(NewServer(e.store, adminapi.NewClient(sock)).Handler())
	t.Cleanup(e.ts.Close)
	e.caFile = filepath.Join(dir, "ca.pem")
	crt := e.ts.TLS.Certificates[0].Certificate[0]
	_ = os.WriteFile(e.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt}), 0o644)
	return e
}

func TestJoinEndToEnd(t *testing.T) {
	e := newFullEnv(t)
	tok, _, _ := e.store.Create("laptop", time.Hour, time.Now())
	out := t.TempDir()

	res, err := Join(context.Background(), JoinOptions{URL: e.ts.URL, Token: tok, Dir: out, CAFile: e.caFile, Interface: "microtunnel0"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "laptop" || res.IP != "10.9.0.2" {
		t.Fatalf("result = %+v", res)
	}

	// The relay now has the peer, with the public half of the key we generated.
	cfg, err := config.Load(e.relayCfg)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := proto.LoadStaticKey(res.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0].PublicKey != proto.PubBytes(priv) || cfg.Peers[0].Name != "laptop" {
		t.Fatalf("relay peers = %+v", cfg.Peers)
	}

	// The written config is complete and valid, and points at this relay.
	spoke, err := config.Load(res.ConfigFile)
	if err != nil {
		t.Fatalf("generated config invalid: %v\n%s", err, res.Config)
	}
	abs, _ := filepath.Abs(res.KeyFile)
	if spoke.PrivateKeyFile != abs || spoke.PreSharedKey != "join-psk" || spoke.TunnelAddress.String() != "10.9.0.2/24" ||
		proto.BytesToHex(spoke.Peers[0].PublicKey[:]) != e.relayPub || spoke.Peers[0].Host != "relay.example.com" {
		t.Fatalf("spoke config wrong: %+v\n%s", spoke, res.Config)
	}
	if fi, _ := os.Stat(res.KeyFile); fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(res.ConfigFile); fi.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %v (it holds the PSK)", fi.Mode().Perm())
	}
	// No temp key files left behind.
	entries, _ := os.ReadDir(out)
	for _, en := range entries {
		if strings.HasPrefix(en.Name(), ".join-") {
			t.Fatalf("temp file left behind: %s", en.Name())
		}
	}

	// The token is spent.
	if _, err := Join(context.Background(), JoinOptions{URL: e.ts.URL, Token: tok, Dir: t.TempDir(), CAFile: e.caFile}); err == nil {
		t.Fatal("a token must work only once")
	}
}

func TestJoinFailuresLeaveNothingBehindAndKeepTokenUsable(t *testing.T) {
	e := newFullEnv(t)
	tok, _, _ := e.store.Create("", time.Hour, time.Now())
	out := t.TempDir()
	left := func() []string {
		var names []string
		entries, _ := os.ReadDir(out)
		for _, en := range entries {
			names = append(names, en.Name())
		}
		return names
	}

	// Untrusted certificate (no CA given): nothing sent, nothing left.
	if _, err := Join(context.Background(), JoinOptions{URL: e.ts.URL, Token: tok, Name: "a", Dir: out}); err == nil {
		t.Fatal("an unverifiable server certificate must be refused")
	}
	// Wrong token.
	if _, err := Join(context.Background(), JoinOptions{URL: e.ts.URL, Token: "mt1.0000000000000000.zzzz", Name: "a", Dir: out, CAFile: e.caFile}); err == nil {
		t.Fatal("bad token accepted")
	}
	if got := left(); len(got) != 0 {
		t.Fatalf("failed joins left files: %v", got)
	}

	// Name already taken on the relay: rejected, and the token is not burned.
	if _, err := Join(context.Background(), JoinOptions{URL: e.ts.URL, Token: tok, Name: "dup", Dir: out, CAFile: e.caFile}); err != nil {
		t.Fatal(err)
	}
	tok2, _, _ := e.store.Create("", time.Hour, time.Now())
	out2 := t.TempDir()
	if _, err := Join(context.Background(), JoinOptions{URL: e.ts.URL, Token: tok2, Name: "dup", Dir: out2, CAFile: e.caFile}); err == nil ||
		!strings.Contains(err.Error(), "already registered") {
		t.Fatalf("err=%v", err)
	}
	if entries, _ := os.ReadDir(out2); len(entries) != 0 {
		t.Fatalf("rejected join left files: %v", entries)
	}
	if _, err := Join(context.Background(), JoinOptions{URL: e.ts.URL, Token: tok2, Name: "other", Dir: out2, CAFile: e.caFile}); err != nil {
		t.Fatalf("token should still work after a name clash: %v", err)
	}

	// Refuses to overwrite an existing key before spending the token.
	tok3, _, _ := e.store.Create("", time.Hour, time.Now())
	if _, err := Join(context.Background(), JoinOptions{URL: e.ts.URL, Token: tok3, Name: "other", Dir: out2, CAFile: e.caFile}); err == nil ||
		!strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("err=%v", err)
	}
	if _, err := e.store.Claim(tok3, time.Now()); err != nil {
		t.Fatalf("token spent although join refused up front: %v", err)
	}
}

func TestJoinValidatesURLAndInputs(t *testing.T) {
	dir := t.TempDir()
	for name, o := range map[string]JoinOptions{
		"plain http":    {URL: "http://enroll.example.com", Token: "t", Dir: dir},
		"ftp":           {URL: "ftp://x", Token: "t", Dir: dir},
		"no host":       {URL: "https://", Token: "t", Dir: dir},
		"no token":      {URL: "https://x", Dir: dir},
		"bad name":      {URL: "https://x", Token: "t", Name: "../x", Dir: dir},
		"missing CA":    {URL: "https://x", Token: "t", Dir: dir, CAFile: filepath.Join(dir, "nope")},
		"empty CA file": {URL: "https://x", Token: "t", Dir: dir, CAFile: writeTemp(t, dir, "ca", "not a cert")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Join(context.Background(), o); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func writeTemp(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	_ = os.WriteFile(p, []byte(body), 0o644)
	return p
}

func TestJoinDoesNotFollowRedirects(t *testing.T) {
	var leaked bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer evil.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	dir := t.TempDir()
	_, err := Join(context.Background(), JoinOptions{URL: redir.URL, Token: "secret-token", Name: "a", Dir: dir, AllowHTTP: true})
	if err == nil || leaked {
		t.Fatalf("redirect followed (leaked=%v err=%v): the token must never be forwarded", leaked, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("files left: %v", entries)
	}
}

func TestServeTLSAndShutdown(t *testing.T) {
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS()
	cfg := ts.TLS.Clone()
	ts.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(newStore(t), &fakeRegistrar{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- s.Serve(ctx, ln, &tls.Config{Certificates: cfg.Certificates, MinVersion: tls.VersionTLS12})
	}()

	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 3 * time.Second}
	resp, err := c.Get("https://" + ln.Addr().String() + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz over TLS: %v", err)
	}
	resp.Body.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve=%v on clean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestJoinRejectsSuspiciousServerResponses(t *testing.T) {
	good := admin.Registration{Name: "n", IP: netip.MustParseAddr("10.9.0.2"), Subnet: netip.MustParsePrefix("10.9.0.0/24"),
		Endpoint: "r.example.com:5040"}
	for name, mod := range map[string]func(*admin.Registration){
		"name with traversal": func(r *admin.Registration) { r.Name = "../../etc/cron.d/x" },
		"ip outside subnet":   func(r *admin.Registration) { r.IP = netip.MustParseAddr("192.168.1.1") },
		"endpoint newline":    func(r *admin.Registration) { r.Endpoint = "r.example.com:5040\npeers: []" },
		"endpoint no port":    func(r *admin.Registration) { r.Endpoint = "r.example.com" },
		"endpoint comment":    func(r *admin.Registration) { r.Endpoint = "r.example.com:5040 #x" },
		"missing ip":          func(r *admin.Registration) { r.IP = netip.Addr{} },
	} {
		t.Run(name, func(t *testing.T) {
			reg := good
			mod(&reg)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusCreated, reg)
			}))
			defer srv.Close()
			dir := t.TempDir()
			if _, err := Join(context.Background(), JoinOptions{URL: srv.URL, Token: "t", Name: "n", Dir: dir, AllowHTTP: true}); err == nil {
				t.Fatal("a suspicious registration was accepted")
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Fatalf("files written for a rejected registration: %v", entries)
			}
		})
	}
}
