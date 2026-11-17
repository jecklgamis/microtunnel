package enroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jecklgamis/microtunnel/internal/admin"
	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

// JoinOptions configures Join.
type JoinOptions struct {
	URL   string // enrollment server base URL, e.g. https://enroll.example.com
	Token string
	Name  string // peer name; may be empty when the token carries one
	Dir   string // where the key pair and config are written (default ".")

	CAFile    string // extra trusted CA (PEM) for a private or self-signed server certificate
	AllowHTTP bool   // permit a plain-http URL (tests and trusted networks only)
	Interface string // interface name for the config; default utun on macOS, microtunnel0 elsewhere
}

// JoinResult describes what Join created.
type JoinResult struct {
	Name       string
	IP         string
	KeyFile    string
	CrtFile    string
	ConfigFile string
	Config     string
}

// Join generates a key pair on this machine, enrolls its public key with the
// server and writes a ready-to-run config next to the key. The private key is
// created before the request but only ever written to disk locally; if
// enrollment fails nothing is left behind.
func Join(ctx context.Context, o JoinOptions) (*JoinResult, error) {
	endpoint, err := enrollURL(o.URL, o.AllowHTTP)
	if err != nil {
		return nil, err
	}
	if o.Name != "" && !admin.ValidName(o.Name) {
		return nil, fmt.Errorf("invalid peer name %q (letters, digits, '.', '_', '-')", o.Name)
	}
	if strings.TrimSpace(o.Token) == "" {
		return nil, errors.New("a join token is required")
	}
	dir := o.Dir
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if o.Name != "" { // fail before spending the token if we could not save the result
		if err := checkFree(dir, o.Name); err != nil {
			return nil, err
		}
	}
	hc, err := httpClient(o.CAFile)
	if err != nil {
		return nil, err
	}

	// Key goes to a temporary name until the server tells us the final one.
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	tmpBase := filepath.Join(dir, ".join-"+hex.EncodeToString(rnd[:]))
	key, err := proto.GenerateKey()
	if err != nil {
		return nil, err
	}
	tmpKey, tmpCrt, err := proto.WriteKeyPair(tmpBase, key)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmpKey)
			_ = os.Remove(tmpCrt)
		}
	}()

	pub := proto.PubBytes(key)
	reg, err := post(ctx, hc, endpoint, Request{Token: o.Token, PublicKey: proto.BytesToHex(pub[:]), Name: o.Name})
	if err != nil {
		return nil, err
	}

	// Enrolled. From here on never delete the key: the relay now trusts it.
	keep = true
	res := &JoinResult{Name: reg.Name, IP: reg.IP.String()}
	if err := checkFree(dir, reg.Name); err != nil {
		return nil, fmt.Errorf("enrolled as %q, but %w; your new key was kept as %s", reg.Name, err, tmpKey)
	}
	res.KeyFile = filepath.Join(dir, reg.Name+".key")
	res.CrtFile = filepath.Join(dir, reg.Name+".crt")
	res.ConfigFile = filepath.Join(dir, reg.Name+".yaml")
	if err := os.Rename(tmpKey, res.KeyFile); err != nil {
		return nil, fmt.Errorf("enrolled as %q, but could not rename the key (kept as %s): %w", reg.Name, tmpKey, err)
	}
	if err := os.Rename(tmpCrt, res.CrtFile); err != nil {
		return nil, fmt.Errorf("enrolled as %q, but could not rename %s: %w", reg.Name, tmpCrt, err)
	}
	absKey, err := filepath.Abs(res.KeyFile)
	if err != nil {
		absKey = res.KeyFile
	}
	iface := o.Interface
	if iface == "" && runtime.GOOS == "darwin" {
		iface = "utun"
	}
	res.Config = admin.SpokeConfig(reg, admin.SpokeOptions{KeyFile: absKey, Generated: true, Interface: iface})
	if err := os.WriteFile(res.ConfigFile, []byte(res.Config), 0o600); err != nil {
		return nil, fmt.Errorf("enrolled as %q, but could not write %s: %w\n\n%s", reg.Name, res.ConfigFile, err, res.Config)
	}
	return res, nil
}

func checkFree(dir, name string) error {
	for _, ext := range []string{".key", ".crt", ".yaml"} {
		p := filepath.Join(dir, name+ext)
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s already exists (refusing to overwrite)", p)
		}
	}
	return nil
}

func enrollURL(raw string, allowHTTP bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid enrollment URL %q", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return "", errors.New("refusing to send a join token over plain http (use https, or pass -allow-http for a trusted network)")
		}
	default:
		return "", fmt.Errorf("enrollment URL must be https://..., got %q", raw)
	}
	return strings.TrimRight(u.String(), "/") + "/v1/enroll", nil
}

func httpClient(caFile string) (*http.Client, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %s has no usable certificates", caFile)
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{
		Timeout:   40 * time.Second,
		Transport: tr,
		// Never follow a redirect: it could carry the token somewhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func post(ctx context.Context, hc *http.Client, endpoint string, body Request) (*admin.Registration, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contacting the enrollment server: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusCreated {
		var eb errBody
		if json.Unmarshal(data, &eb) != nil || eb.Error == "" {
			eb.Error = fmt.Sprintf("enrollment server returned HTTP %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("enrollment failed: %s", eb.Error)
	}
	var reg admin.Registration
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("unexpected response from the enrollment server: %w", err)
	}
	if !admin.ValidName(reg.Name) || !reg.IP.IsValid() || !reg.Subnet.IsValid() || !reg.Subnet.Contains(reg.IP) {
		return nil, errors.New("the enrollment server returned an incomplete or inconsistent registration")
	}
	// These end up in a config file: insist they are what they claim to be.
	if _, _, err := config.SplitHostPort(reg.Endpoint); err != nil || strings.ContainsAny(reg.Endpoint, " \t\r\n#'\"") {
		return nil, fmt.Errorf("the enrollment server returned an invalid relay endpoint %q", reg.Endpoint)
	}
	return &reg, nil
}
