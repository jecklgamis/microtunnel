package setup

import (
	"os"
	"strings"
	"testing"
)

func TestLabelsAndPaths(t *testing.T) {
	if Label("") != "io.github.jecklgamis.microtunnel" || Label("microtunnel") != Label("") {
		t.Fatal("default label")
	}
	if Label("home") != "io.github.jecklgamis.microtunnel.home" {
		t.Fatal("named label")
	}
	if PlistPath("home") != "/Library/LaunchDaemons/io.github.jecklgamis.microtunnel.home.plist" {
		t.Fatal(PlistPath("home"))
	}
	if LogFile("") != "/var/log/microtunnel.log" || LogFile("home") != "/var/log/microtunnel-home.log" {
		t.Fatal("log files")
	}
}

func TestLaunchdPlistContent(t *testing.T) {
	p := LaunchdPlist("home", "/usr/local/bin/microtunnel", "/etc/microtunnel/home.yaml")
	for _, want := range []string{
		"<string>io.github.jecklgamis.microtunnel.home</string>",
		"<string>/usr/local/bin/microtunnel</string>",
		"<string>-c</string>",
		"<string>/etc/microtunnel/home.yaml</string>",
		"<key>/etc/microtunnel/home.yaml</key>", // KeepAlive PathState
		"/var/log/microtunnel-home.log",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("plist missing %q:\n%s", want, p)
		}
	}
	// Paths are XML-escaped.
	if q := LaunchdPlist("", "/a&b/microtunnel", "/c<d>.yaml"); !strings.Contains(q, "/a&amp;b/microtunnel") || !strings.Contains(q, "/c&lt;d&gt;.yaml") {
		t.Fatalf("not escaped:\n%s", q)
	}
}

// The plist the macOS package installs is this function's output for the default
// instance, so the two never drift apart.
func TestPackagedPlistMatchesGenerator(t *testing.T) {
	got, err := os.ReadFile("../../packaging/macos/" + Label("") + ".plist")
	if err != nil {
		t.Fatal(err)
	}
	want := LaunchdPlist("", "/usr/local/bin/microtunnel", DefaultConfigPath)
	if string(got) != want {
		t.Fatalf("packaging/macos plist is out of date; regenerate it:\n%s", want)
	}
}
