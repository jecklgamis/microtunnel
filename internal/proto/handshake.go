package proto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Handshake wire format (both directions):
//
//	[8 magic][32 eph_pub][48 AES-256-GCM(identity_key, static_pub)][32 HMAC-SHA256(psk, ...)]?
//
// Identity encryption hides static public keys from passive observers:
//
//	client encrypts its static_pub with key = SHA-256(DH(eph_c, server_static))
//	server encrypts its static_pub with key = SHA-256(DH(eph_s, eph_c))
//
// AES-256-GCM uses a zero IV, which is safe because each key comes from a
// fresh ephemeral DH. The HMAC (present only when a PSK is configured) covers
// [eph_pub][encrypted_static_pub].
//
// Session key:
//
//	SHA-256(DH(eph_c,eph_s) || DH(static_c,eph_s) || DH(eph_c,static_s)
//	        || client_eph_pub || server_eph_pub || client_static_pub || server_static_pub)

// HandshakeSize returns the exact size of a handshake message, with or
// without the PSK authenticator.
func HandshakeSize(hasPSK bool) int {
	n := HeaderSize + PubKeyLen + EncryptedPubLen
	if hasPSK {
		n += HMACLen
	}
	return n
}

// GenerateKey creates a fresh X25519 key pair (used for ephemeral keys and
// for generating static keys).
func GenerateKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// PubBytes returns the 32-byte public key of k.
func PubBytes(k *ecdh.PrivateKey) [PubKeyLen]byte {
	var out [PubKeyLen]byte
	copy(out[:], k.PublicKey().Bytes())
	return out
}

// LoadStaticKey reads an X25519 private key from a PKCS#8 PEM file (as
// produced by `openssl genpkey -algorithm x25519`).
func LoadStaticKey(path string) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("static key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM private key from %s", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PEM private key from %s: %w", path, err)
	}
	key, ok := parsed.(*ecdh.PrivateKey)
	if !ok || key.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("%s is not an X25519 private key", path)
	}
	return key, nil
}

// LoadPublicKey reads an X25519 public key from a PKIX PEM file (the `.crt`
// files produced by the key-generation script) and returns its raw bytes.
func LoadPublicKey(path string) ([PubKeyLen]byte, error) {
	var out [PubKeyLen]byte
	data, err := os.ReadFile(path)
	if err != nil {
		return out, fmt.Errorf("public key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return out, fmt.Errorf("failed to parse PEM public key from %s", path)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return out, fmt.Errorf("failed to parse PEM public key from %s: %w", path, err)
	}
	pub, ok := parsed.(*ecdh.PublicKey)
	if !ok || pub.Curve() != ecdh.X25519() {
		return out, fmt.Errorf("%s is not an X25519 public key", path)
	}
	copy(out[:], pub.Bytes())
	return out, nil
}

func dh(priv *ecdh.PrivateKey, peerPub []byte) ([PubKeyLen]byte, error) {
	var out [PubKeyLen]byte
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return out, err
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return out, err
	}
	copy(out[:], secret)
	return out, nil
}

func deriveSessionKey(ecdhEph, ecdhScEs, ecdhEcSs [PubKeyLen]byte,
	clientEphPub, serverEphPub, clientStaticPub, serverStaticPub []byte) [KeyLen]byte {
	h := sha256.New()
	h.Write(ecdhEph[:])
	h.Write(ecdhScEs[:])
	h.Write(ecdhEcSs[:])
	h.Write(clientEphPub)
	h.Write(serverEphPub)
	h.Write(clientStaticPub)
	h.Write(serverStaticPub)
	var out [KeyLen]byte
	copy(out[:], h.Sum(nil))
	return out
}

func computeHMAC(pskKey *[KeyLen]byte, msg []byte) []byte {
	m := hmac.New(sha256.New, pskKey[:])
	m.Write(msg)
	return m.Sum(nil)
}

func identityAEAD(keyMaterial [PubKeyLen]byte) (cipher.AEAD, error) {
	key := sha256.Sum256(keyMaterial[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// encryptIdentity returns the 48-byte AES-GCM encryption of pub under
// SHA-256(keyMaterial) with a zero IV.
func encryptIdentity(keyMaterial [PubKeyLen]byte, pub []byte) ([]byte, error) {
	aead, err := identityAEAD(keyMaterial)
	if err != nil {
		return nil, err
	}
	var iv [IVLen]byte
	return aead.Seal(nil, iv[:], pub, nil), nil
}

func decryptIdentity(keyMaterial [PubKeyLen]byte, in []byte) ([]byte, error) {
	aead, err := identityAEAD(keyMaterial)
	if err != nil {
		return nil, err
	}
	var iv [IVLen]byte
	return aead.Open(nil, iv[:], in, nil)
}

// buildMessage assembles [magic][eph_pub][enc_static][HMAC]?.
func buildMessage(ephPub [PubKeyLen]byte, encStatic []byte, psk *[KeyLen]byte) []byte {
	msg := make([]byte, 0, HandshakeSize(psk != nil))
	msg = append(msg, Header[:]...)
	msg = append(msg, ephPub[:]...)
	msg = append(msg, encStatic...)
	if psk != nil {
		msg = append(msg, computeHMAC(psk, msg[HeaderSize:])...)
	}
	return msg
}

// parseMessage validates size, magic and (if psk != nil) the HMAC, and
// returns the eph_pub and encrypted static key fields.
func parseMessage(msg []byte, psk *[KeyLen]byte) (ephPub, encStatic []byte, err error) {
	if want := HandshakeSize(psk != nil); len(msg) != want {
		return nil, nil, fmt.Errorf("handshake size mismatch: got %d, expected %d", len(msg), want)
	}
	if !bytes.Equal(msg[:HeaderSize], Header[:]) {
		return nil, nil, errors.New("handshake has bad magic")
	}
	body := msg[HeaderSize : HeaderSize+PubKeyLen+EncryptedPubLen]
	if psk != nil {
		got := msg[HeaderSize+PubKeyLen+EncryptedPubLen:]
		if subtle.ConstantTimeCompare(got, computeHMAC(psk, body)) != 1 {
			return nil, nil, errors.New("handshake HMAC verification failed")
		}
	}
	return body[:PubKeyLen], body[PubKeyLen:], nil
}

// ClientState carries the initiator's ephemeral secrets between sending the
// handshake initiation and processing the response.
type ClientState struct {
	eph      *ecdh.PrivateKey
	ephPub   [PubKeyLen]byte
	ecdhEcSs [PubKeyLen]byte
}

// ClientInit builds the handshake initiation message for a server whose
// static public key is serverStaticPub. psk may be nil (no authentication).
// The message must be sent to the server; the returned state is passed to
// ClientFinish when the response arrives.
func ClientInit(static *ecdh.PrivateKey, serverStaticPub []byte, psk *[KeyLen]byte) ([]byte, *ClientState, error) {
	if len(serverStaticPub) != PubKeyLen {
		return nil, nil, errors.New("server static public key required for identity hiding")
	}
	eph, err := GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key pair: %w", err)
	}
	ephPub := PubBytes(eph)

	// DH(eph_c, server_static) doubles as the identity-encryption key.
	ecdhEcSs, err := dh(eph, serverStaticPub)
	if err != nil {
		return nil, nil, fmt.Errorf("X25519 key derivation failed: %w", err)
	}
	staticPub := static.PublicKey().Bytes()
	encStatic, err := encryptIdentity(ecdhEcSs, staticPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt client identity: %w", err)
	}
	return buildMessage(ephPub, encStatic, psk), &ClientState{eph: eph, ephPub: ephPub, ecdhEcSs: ecdhEcSs}, nil
}

// ClientFinish processes the server's response and returns the session key.
// It verifies that the server's decrypted identity equals serverStaticPub.
func ClientFinish(resp []byte, psk *[KeyLen]byte, static *ecdh.PrivateKey,
	serverStaticPub []byte, st *ClientState) ([KeyLen]byte, error) {
	var zero [KeyLen]byte
	serverEphPub, encServerStatic, err := parseMessage(resp, psk)
	if err != nil {
		return zero, fmt.Errorf("server %w", err)
	}
	ecdhEph, err := dh(st.eph, serverEphPub)
	if err != nil {
		return zero, fmt.Errorf("X25519 key derivation failed: %w", err)
	}
	serverStaticRecv, err := decryptIdentity(ecdhEph, encServerStatic)
	if err != nil {
		return zero, errors.New("failed to decrypt server identity — possible MITM")
	}
	if subtle.ConstantTimeCompare(serverStaticRecv, serverStaticPub) != 1 {
		return zero, errors.New("server static public key mismatch — possible MITM")
	}
	ecdhScEs, err := dh(static, serverEphPub)
	if err != nil {
		return zero, fmt.Errorf("X25519 key derivation failed: %w", err)
	}
	return deriveSessionKey(ecdhEph, ecdhScEs, st.ecdhEcSs,
		st.ephPub[:], serverEphPub, static.PublicKey().Bytes(), serverStaticRecv), nil
}

// ServerRespond processes a client's handshake initiation. precompEph is the
// responder's ephemeral key (pre-generated so key generation stays off the
// hot path); the caller must not reuse it for another handshake.
//
// It returns the response message to send, the initiator's static public key
// (for the caller's allowlist check) and the derived session key. Nothing is
// sent by this function, so the caller can reject unknown peers before
// answering.
func ServerRespond(pkt []byte, psk *[KeyLen]byte, static, precompEph *ecdh.PrivateKey) (
	resp []byte, clientStaticPub [PubKeyLen]byte, sessionKey [KeyLen]byte, err error) {
	clientEphPub, encClientStatic, err := parseMessage(pkt, psk)
	if err != nil {
		return nil, clientStaticPub, sessionKey, fmt.Errorf("client %w", err)
	}
	// DH(server_static, eph_c) also decrypts the client identity.
	ecdhEcSs, err := dh(static, clientEphPub)
	if err != nil {
		return nil, clientStaticPub, sessionKey, fmt.Errorf("X25519 key derivation failed: %w", err)
	}
	cs, err := decryptIdentity(ecdhEcSs, encClientStatic)
	if err != nil {
		return nil, clientStaticPub, sessionKey, errors.New("failed to decrypt client identity — invalid key or tampered packet")
	}
	copy(clientStaticPub[:], cs)

	ephPub := PubBytes(precompEph)
	// DH(eph_s, eph_c) also encrypts the server identity.
	ecdhEph, err := dh(precompEph, clientEphPub)
	if err != nil {
		return nil, clientStaticPub, sessionKey, fmt.Errorf("X25519 key derivation failed: %w", err)
	}
	staticPub := static.PublicKey().Bytes()
	encServerStatic, err := encryptIdentity(ecdhEph, staticPub)
	if err != nil {
		return nil, clientStaticPub, sessionKey, fmt.Errorf("failed to encrypt server identity: %w", err)
	}
	ecdhScEs, err := dh(precompEph, clientStaticPub[:])
	if err != nil {
		return nil, clientStaticPub, sessionKey, fmt.Errorf("X25519 key derivation failed: %w", err)
	}
	sessionKey = deriveSessionKey(ecdhEph, ecdhScEs, ecdhEcSs,
		clientEphPub, ephPub[:], clientStaticPub[:], staticPub)
	return buildMessage(ephPub, encServerStatic, psk), clientStaticPub, sessionKey, nil
}
