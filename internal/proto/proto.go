// Package proto implements microtunnel's wire protocol: data-packet
// encryption, the X25519 handshake with identity hiding, session-key
// derivation and the sliding-window replay filter.
//
// The wire format is byte-for-byte identical to the original C implementation
// (lanecove-tunnel), so Go and C nodes can interoperate.
package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Sizes (bytes) of the fixed-width protocol fields.
const (
	KeyLen         = 32 // AES-256 key / SHA-256 output
	IVLen          = 12 // AES-GCM nonce
	TagLen         = 16 // AES-GCM tag
	CryptoOverhead = IVLen + TagLen
	HeaderSize     = 8 // magic
	SeqSize        = 8 // big-endian sequence number
	// WireOverhead is everything a data packet adds around the IP payload.
	WireOverhead = HeaderSize + SeqSize + CryptoOverhead
	// TunMTU is Ethernet - outer IPv4 - UDP - tunnel overhead = 1428.
	TunMTU = 1500 - 20 - 8 - WireOverhead
	// BufferSize bounds a single packet buffer; it must exceed TunMTU.
	BufferSize = 2048
	// PubKeyLen is the size of an X25519 public key.
	PubKeyLen = 32
	// HMACLen is the size of the optional PSK handshake authenticator.
	HMACLen = 32
	// EncryptedPubLen is an AES-GCM-encrypted static public key (32 + 16 tag).
	EncryptedPubLen = PubKeyLen + TagLen
)

// Header is the 8-byte magic that prefixes every plaintext packet and every
// handshake message: 0xdeadbeefcafebabe.
var Header = [HeaderSize]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe}

var (
	// ErrShortPacket is returned when a ciphertext is smaller than IV+tag.
	ErrShortPacket = errors.New("proto: packet shorter than crypto overhead")
	// ErrDecrypt is returned when AES-GCM authentication fails.
	ErrDecrypt = errors.New("proto: decryption failed")
)

// DeriveKey turns a pre-shared key string into a 32-byte HMAC key:
// SHA-256(psk).
func DeriveKey(psk string) [KeyLen]byte {
	return sha256.Sum256([]byte(psk))
}

// BytesToHex renders b as lowercase hex.
func BytesToHex(b []byte) string { return hex.EncodeToString(b) }

// HexToBytes parses exactly expectedLen bytes of hex (either case). It
// returns an error if the string has the wrong length or invalid digits.
func HexToBytes(s string, expectedLen int) ([]byte, error) {
	if len(s) != expectedLen*2 {
		return nil, fmt.Errorf("proto: expected %d hex chars, got %d", expectedLen*2, len(s))
	}
	b, err := hex.DecodeString(strings.ToLower(s))
	if err != nil {
		return nil, fmt.Errorf("proto: invalid hex: %w", err)
	}
	return b, nil
}

// NewAEAD returns an AES-256-GCM AEAD for key. The returned value is safe for
// concurrent use, so one instance can be shared by every worker for a session.
func NewAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("proto: key must be %d bytes, got %d", KeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plain with a fresh random IV and appends
// [12-byte IV][ciphertext][16-byte tag] to dst, returning the extended slice.
func Seal(aead cipher.AEAD, dst, plain []byte) ([]byte, error) {
	var iv [IVLen]byte
	if _, err := rand.Read(iv[:]); err != nil {
		return nil, err
	}
	dst = append(dst, iv[:]...)
	return aead.Seal(dst, iv[:], plain, nil), nil
}

// Open authenticates and decrypts a packet produced by Seal, appending the
// plaintext to dst. It returns ErrShortPacket or ErrDecrypt on failure.
func Open(aead cipher.AEAD, dst, in []byte) ([]byte, error) {
	if len(in) < CryptoOverhead {
		return nil, ErrShortPacket
	}
	out, err := aead.Open(dst, in[:IVLen], in[IVLen:], nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

// EncryptPacket is a convenience wrapper that builds an AEAD from key and
// Seals plain into a new slice.
func EncryptPacket(key, plain []byte) ([]byte, error) {
	aead, err := NewAEAD(key)
	if err != nil {
		return nil, err
	}
	return Seal(aead, make([]byte, 0, len(plain)+CryptoOverhead), plain)
}

// DecryptPacket is a convenience wrapper that builds an AEAD from key and
// Opens in into a new slice.
func DecryptPacket(key, in []byte) ([]byte, error) {
	aead, err := NewAEAD(key)
	if err != nil {
		return nil, err
	}
	return Open(aead, nil, in)
}
