package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jecklgamis/microtunnel/internal/config"
)

func enrollCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	err := runEnroll(args, &out, &errb)
	return out.String(), err
}

var tokenRE = regexp.MustCompile(`mt1\.[0-9a-f]{16}\.[A-Za-z0-9_-]+`)

func TestEnrollTokenCreateListRevoke(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tokens")
	out, err := enrollCmd(t, "token", "create", "-tokens", dir, "-name", "laptop", "-ttl", "30m", "-url", "https://enroll.example.com")
	if err != nil {
		t.Fatal(err)
	}
	tok := tokenRE.FindString(out)
	if tok == "" {
		t.Fatalf("no token in output:\n%s", out)
	}
	if !strings.Contains(out, "microtunnel join https://enroll.example.com -token "+tok) {
		t.Fatalf("join command missing:\n%s", out)
	}
	if strings.Contains(out, "-name <name>") {
		t.Fatalf("a name-bound token should not ask for a name:\n%s", out)
	}

	out, err = enrollCmd(t, "token", "list", "-tokens", dir)
	if err != nil || !strings.Contains(out, "laptop") || !strings.Contains(out, "pending") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if strings.Contains(out, strings.Split(tok, ".")[2]) {
		t.Fatalf("list must never print token secrets:\n%s", out)
	}
	id := strings.Split(tok, ".")[1]
	if _, err := enrollCmd(t, "token", "revoke", id, "-tokens", dir); err != nil {
		t.Fatal(err)
	}
	if out, _ = enrollCmd(t, "token", "list", "-tokens", dir); strings.Contains(out, id) {
		t.Fatalf("revoked token still listed:\n%s", out)
	}

	// An unbound token tells the new machine to name itself.
	out, _ = enrollCmd(t, "token", "create", "-tokens", dir)
	if !strings.Contains(out, "-name <name>") || !strings.Contains(out, "<enrollment-url>") {
		t.Fatalf("unbound token output:\n%s", out)
	}
}

func TestEnrollUsageErrors(t *testing.T) {
	dir := t.TempDir()
	for name, args := range map[string][]string{
		"none":             {},
		"unknown":          {"frob"},
		"token none":       {"token"},
		"token unknown":    {"token", "frob"},
		"revoke no id":     {"token", "revoke", "-tokens", dir},
		"revoke bad id":    {"token", "revoke", "../x", "-tokens", dir},
		"bad name":         {"token", "create", "-tokens", dir, "-name", "../x"},
		"ttl too long":     {"token", "create", "-tokens", dir, "-ttl", "9999h"},
		"serve no socket":  {"serve", "-insecure-http"},
		"serve no TLS":     {"serve", "-socket", filepath.Join(dir, "x.sock")},
		"serve half TLS":   {"serve", "-socket", "x", "-tls-cert", "c.pem"},
		"serve bad socket": {"serve", "-socket", filepath.Join(dir, "none.sock"), "-insecure-http", "-tokens", dir},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := enrollCmd(t, args...); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// The whole feature through the CLI entry points: relay admin API, enrollment
// service, token creation and `join`.
func TestEnrollServeAndJoinThroughTheCLI(t *testing.T) {
	cfg, sock, _ := relayWithAPI(t)
	tokens := filepath.Join(filepath.Dir(cfg), "tokens")

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- serveEnroll(ctx, serveOpts{listen: "127.0.0.1:0", socket: sock, tokens: tokens, insecureHTTP: true}, ready)
	}()
	var addr string
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatalf("serve exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("enrollment service did not start")
	}
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve returned %v on shutdown", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("serve did not stop")
		}
	}()

	out, err := enrollCmd(t, "token", "create", "-tokens", tokens)
	if err != nil {
		t.Fatal(err)
	}
	tok := tokenRE.FindString(out)

	dir := t.TempDir()
	var jout, jerr bytes.Buffer
	// Plain http is refused unless explicitly allowed...
	if err := runJoin([]string{"http://" + addr, "-token", tok, "-name", "mac", "-dir", dir}, &jout, &jerr); err == nil ||
		!strings.Contains(err.Error(), "plain http") {
		t.Fatalf("err=%v", err)
	}
	// ...and the token comes from the environment when not on the command line.
	t.Setenv("MICROTUNNEL_JOIN_TOKEN", tok)
	if err := runJoin([]string{"http://" + addr, "-name", "mac", "-dir", dir, "-allow-http"}, &jout, &jerr); err != nil {
		t.Fatalf("join: %v\n%s", err, jerr.String())
	}
	if !strings.Contains(jout.String(), `Enrolled as "mac" with overlay address 10.9.0.2`) ||
		!strings.Contains(jout.String(), "sudo microtunnel -c") {
		t.Fatalf("join output:\n%s", jout.String())
	}

	// The relay's peers_dir now lists it, and the generated config is valid.
	relayCfg, err := config.Load(cfg)
	if err != nil || len(relayCfg.Peers) != 1 || relayCfg.Peers[0].Name != "mac" {
		t.Fatalf("relay peers: %v %+v", err, relayCfg)
	}
	if _, err := config.Load(filepath.Join(dir, "mac.yaml")); err != nil {
		t.Fatalf("generated config invalid: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "mac.key")); err != nil {
		t.Fatal(err)
	}
}

func TestJoinUsageErrors(t *testing.T) {
	var out, errb bytes.Buffer
	for name, args := range map[string][]string{
		"no url":     {},
		"flag first": {"-token", "x"},
		"no token":   {"https://x.example"},
		"extra arg":  {"https://x.example", "-token", "t", "stray"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("MICROTUNNEL_JOIN_TOKEN", "")
			if err := runJoin(args, &out, &errb); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if err := runJoin([]string{"-h"}, &out, &errb); err != nil || !strings.Contains(out.String(), "Usage: microtunnel join") {
		t.Fatalf("help: %v %q", err, out.String())
	}
}
