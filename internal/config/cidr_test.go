package config

import "testing"

func TestParseCIDRBasic(t *testing.T) {
	p, err := ParseCIDR("10.9.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if p.Len != 24 || p.Network != 0x0A090000 || p.Mask != 0xFFFFFF00 {
		t.Fatalf("got %+v", p)
	}
}

func TestParseCIDRNoPrefixDefaultsTo32(t *testing.T) {
	p, err := ParseCIDR("10.9.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if p.Len != 32 || p.Mask != 0xFFFFFFFF || p.Network != 0x0A090005 {
		t.Fatalf("got %+v", p)
	}
}

func TestParseCIDRZeroPrefix(t *testing.T) {
	p, err := ParseCIDR("0.0.0.0/0")
	if err != nil {
		t.Fatal(err)
	}
	if p.Len != 0 || p.Mask != 0 || p.Network != 0 {
		t.Fatalf("got %+v", p)
	}
	if !p.Contains(0xC0A80101) {
		t.Fatal("/0 must contain every address")
	}
}

func TestParseCIDRMasksHostBits(t *testing.T) {
	p, err := ParseCIDR("10.9.0.5/24")
	if err != nil {
		t.Fatal(err)
	}
	if p.Network != 0x0A090000 {
		t.Fatalf("network=%#x want 0x0A090000", p.Network)
	}
}

func TestParseCIDRRejectsInvalid(t *testing.T) {
	for _, s := range []string{
		"not-an-ip/24",
		"10.9.0.0/33",
		"10.9.0.0/-1",
		"10.9.0.0/",
		"10.9.0.0/abc",
		"10.9.0.0/24x",
		"",
		"256.1.1.1",
		"::1",
		"fe80::1/64",
		"::ffff:10.9.0.1",
	} {
		if _, err := ParseCIDR(s); err == nil {
			t.Errorf("ParseCIDR(%q) succeeded, want error", s)
		}
	}
}

func TestPrefixContains(t *testing.T) {
	p, _ := ParseCIDR("10.9.0.0/24")
	if !p.Contains(0x0A090005) {
		t.Fatal("10.9.0.5 should be inside 10.9.0.0/24")
	}
	if p.Contains(0x0A0A0005) {
		t.Fatal("10.10.0.5 should be outside 10.9.0.0/24")
	}
	h, _ := ParseCIDR("10.9.0.2/32")
	if !h.Contains(0x0A090002) || h.Contains(0x0A090003) {
		t.Fatal("/32 must match exactly one address")
	}
}

func TestPrefixString(t *testing.T) {
	p, _ := ParseCIDR("10.9.0.5/24")
	if got := p.String(); got != "10.9.0.0/24" {
		t.Fatalf("got %q", got)
	}
}
