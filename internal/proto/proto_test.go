package proto

import (
	"bytes"
	"testing"
)

// --- BytesToHex -------------------------------------------------------------

func TestBytesToHex(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"zeros", []byte{0, 0, 0, 0}, "00000000"},
		{"all_ff", []byte{0xff, 0xff, 0xff, 0xff}, "ffffffff"},
		{"known_value", []byte{0xde, 0xad, 0xbe, 0xef}, "deadbeef"},
		{"single_byte", []byte{0x0a}, "0a"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := BytesToHex(c.in); got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

// --- HexToBytes -------------------------------------------------------------

func TestHexToBytesKnownValue(t *testing.T) {
	b, err := HexToBytes("deadbeef", 4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("got %x", b)
	}
}

func TestHexToBytesWrongLength(t *testing.T) {
	if _, err := HexToBytes("dead", 4); err == nil {
		t.Fatal("expected error for short input")
	}
	if _, err := HexToBytes("deadbeef00", 4); err == nil {
		t.Fatal("expected error for long input")
	}
}

func TestHexToBytesUppercase(t *testing.T) {
	b, err := HexToBytes("DEADBEEF", 4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("got %x", b)
	}
}

func TestHexToBytesInvalidDigits(t *testing.T) {
	if _, err := HexToBytes("zzzzzzzz", 4); err == nil {
		t.Fatal("expected error for non-hex digits")
	}
}

func TestHexRoundtrip(t *testing.T) {
	orig := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	got, err := HexToBytes(BytesToHex(orig), len(orig))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(orig, got) {
		t.Fatalf("roundtrip mismatch: %x vs %x", orig, got)
	}
}

// --- DeriveKey --------------------------------------------------------------

func TestDeriveKeyIsDeterministic(t *testing.T) {
	if DeriveKey("test-psk") != DeriveKey("test-psk") {
		t.Fatal("DeriveKey not deterministic")
	}
}

func TestDeriveKeyDifferentPSKsDiffer(t *testing.T) {
	if DeriveKey("psk-alpha") == DeriveKey("psk-beta") {
		t.Fatal("different PSKs produced the same key")
	}
}

func TestDeriveKeyNotZero(t *testing.T) {
	var zero [KeyLen]byte
	if DeriveKey("any-psk") == zero {
		t.Fatal("derived key is all zero")
	}
}

func TestDeriveKeyIsSHA256(t *testing.T) {
	// SHA-256("abc") — the PSK derivation must match the C implementation.
	got := DeriveKey("abc")
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if BytesToHex(got[:]) != want {
		t.Fatalf("got %x", got)
	}
}

// --- Seal / Open ------------------------------------------------------------

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := DeriveKey("test-session-key")
	plain := []byte("Hello, microtunnel!")
	enc, err := EncryptPacket(key[:], plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != len(plain)+CryptoOverhead {
		t.Fatalf("encrypted length %d, want %d", len(enc), len(plain)+CryptoOverhead)
	}
	dec, err := DecryptPacket(key[:], enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatalf("got %q", dec)
	}
}

func TestEncryptEmptyPayload(t *testing.T) {
	key := DeriveKey("k")
	enc, err := EncryptPacket(key[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != CryptoOverhead {
		t.Fatalf("len=%d want %d", len(enc), CryptoOverhead)
	}
	dec, err := DecryptPacket(key[:], enc)
	if err != nil || len(dec) != 0 {
		t.Fatalf("dec=%x err=%v", dec, err)
	}
}

func TestWrongKeyFailsDecrypt(t *testing.T) {
	a, b := DeriveKey("key-a"), DeriveKey("key-b")
	enc, _ := EncryptPacket(a[:], []byte("secret message"))
	if _, err := DecryptPacket(b[:], enc); err == nil {
		t.Fatal("decrypt with wrong key succeeded")
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	key := DeriveKey("test-key")
	enc, _ := EncryptPacket(key[:], []byte("tamper me"))
	enc[IVLen] ^= 0xff
	if _, err := DecryptPacket(key[:], enc); err != ErrDecrypt {
		t.Fatalf("err=%v want ErrDecrypt", err)
	}
}

func TestTamperedTagFails(t *testing.T) {
	key := DeriveKey("test-key")
	enc, _ := EncryptPacket(key[:], []byte("tamper me"))
	enc[len(enc)-1] ^= 0x01
	if _, err := DecryptPacket(key[:], enc); err == nil {
		t.Fatal("tampered tag accepted")
	}
}

func TestTruncatedInputFails(t *testing.T) {
	key := DeriveKey("test-key")
	if _, err := DecryptPacket(key[:], make([]byte, CryptoOverhead-1)); err != ErrShortPacket {
		t.Fatalf("err=%v want ErrShortPacket", err)
	}
}

func TestEncryptUsesFreshIV(t *testing.T) {
	key := DeriveKey("test-key")
	a, _ := EncryptPacket(key[:], []byte("same plaintext"))
	b, _ := EncryptPacket(key[:], []byte("same plaintext"))
	if len(a) != len(b) {
		t.Fatalf("lengths differ: %d vs %d", len(a), len(b))
	}
	if bytes.Equal(a, b) {
		t.Fatal("identical ciphertexts: IV was reused")
	}
}

func TestNewAEADRejectsBadKeyLength(t *testing.T) {
	if _, err := NewAEAD(make([]byte, 16)); err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestConstants(t *testing.T) {
	if WireOverhead != 8+8+12+16 {
		t.Fatalf("WireOverhead=%d", WireOverhead)
	}
	if TunMTU != 1428 {
		t.Fatalf("TunMTU=%d want 1428", TunMTU)
	}
	if BufferSize <= TunMTU {
		t.Fatal("BufferSize must exceed TunMTU")
	}
	if got := HandshakeSize(false); got != 88 {
		t.Fatalf("HandshakeSize(false)=%d want 88", got)
	}
	if got := HandshakeSize(true); got != 120 {
		t.Fatalf("HandshakeSize(true)=%d want 120", got)
	}
	if !bytes.Equal(Header[:], []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe}) {
		t.Fatal("magic header changed")
	}
}
