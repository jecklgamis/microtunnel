package config

import (
	"strings"
	"testing"
)

func TestShortPSKWarns(t *testing.T) {
	c := &Config{HasPSK: true, PreSharedKey: "abc"}
	found := false
	for _, w := range c.Warnings() {
		if strings.Contains(w, "short") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a short-PSK warning")
	}
	c.PreSharedKey = "0123456789abcdef0123"
	for _, w := range c.Warnings() {
		if strings.Contains(w, "short") {
			t.Fatalf("unexpected warning %q", w)
		}
	}
}
