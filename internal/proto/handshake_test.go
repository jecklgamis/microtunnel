package proto

import (
	"bytes"
	"crypto/ecdh"
	"os"
	"path/filepath"
	"testing"
)

func mustKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pskPtr(s string) *[KeyLen]byte {
	k := DeriveKey(s)
	return &k
}

// handshake runs a full client<->server exchange and returns both session keys
// and the client identity the server saw.
func handshake(t *testing.T, clientPSK, serverPSK *[KeyLen]byte, client, server *ecdh.PrivateKey, expectServerPub []byte) (ck, sk [KeyLen]byte, seenClient [PubKeyLen]byte, err error) {
	t.Helper()
	init, st, err := ClientInit(client, server.PublicKey().Bytes(), clientPSK)
	if err != nil {
		return ck, sk, seenClient, err
	}
	resp, seenClient, sk, err := ServerRespond(init, serverPSK, server, mustKey(t))
	if err != nil {
		return ck, sk, seenClient, err
	}
	ck, err = ClientFinish(resp, clientPSK, client, expectServerPub, st)
	return ck, sk, seenClient, err
}

func TestHandshakeAgreesOnSessionKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		psk  *[KeyLen]byte
	}{{"no_psk", nil}, {"with_psk", pskPtr("some-psk")}} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := mustKey(t), mustKey(t)
			ck, sk, seen, err := handshake(t, tc.psk, tc.psk, client, server, server.PublicKey().Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if ck != sk {
				t.Fatalf("session keys differ:\n client %x\n server %x", ck, sk)
			}
			var zero [KeyLen]byte
			if ck == zero {
				t.Fatal("session key is zero")
			}
			if !bytes.Equal(seen[:], client.PublicKey().Bytes()) {
				t.Fatal("server recovered wrong client identity")
			}
		})
	}
}

func TestHandshakeSessionKeysAreFreshEachTime(t *testing.T) {
	client, server := mustKey(t), mustKey(t)
	a, _, _, err := handshake(t, nil, nil, client, server, server.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	b, _, _, err := handshake(t, nil, nil, client, server, server.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two handshakes produced the same session key (no forward secrecy)")
	}
}

func TestHandshakeMessageSizes(t *testing.T) {
	client, server := mustKey(t), mustKey(t)
	for _, psk := range []*[KeyLen]byte{nil, pskPtr("p")} {
		init, st, err := ClientInit(client, server.PublicKey().Bytes(), psk)
		if err != nil {
			t.Fatal(err)
		}
		if len(init) != HandshakeSize(psk != nil) {
			t.Fatalf("init len %d want %d", len(init), HandshakeSize(psk != nil))
		}
		if !bytes.Equal(init[:HeaderSize], Header[:]) {
			t.Fatal("init missing magic")
		}
		resp, _, _, err := ServerRespond(init, psk, server, mustKey(t))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp) != HandshakeSize(psk != nil) {
			t.Fatalf("resp len %d want %d", len(resp), HandshakeSize(psk != nil))
		}
		_ = st
	}
}

func TestHandshakeHidesStaticKeys(t *testing.T) {
	client, server := mustKey(t), mustKey(t)
	init, _, err := ClientInit(client, server.PublicKey().Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, _, _, err := ServerRespond(init, nil, server, mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, msg := range map[string][]byte{"init": init, "resp": resp} {
		if bytes.Contains(msg, client.PublicKey().Bytes()) || bytes.Contains(msg, server.PublicKey().Bytes()) {
			t.Fatalf("%s leaks a static public key in cleartext", name)
		}
	}
}

func TestHandshakePSKMismatchRejectedByServer(t *testing.T) {
	client, server := mustKey(t), mustKey(t)
	_, _, _, err := handshake(t, pskPtr("a"), pskPtr("b"), client, server, server.PublicKey().Bytes())
	if err == nil {
		t.Fatal("server accepted initiation with wrong PSK")
	}
}

func TestHandshakeMissingPSKRejected(t *testing.T) {
	client, server := mustKey(t), mustKey(t)
	// Client has no PSK but server requires one: the size check must reject it.
	if _, _, _, err := handshake(t, nil, pskPtr("a"), client, server, server.PublicKey().Bytes()); err == nil {
		t.Fatal("server accepted an unauthenticated initiation while a PSK is configured")
	}
}

func TestHandshakePSKMismatchRejectedByClient(t *testing.T) {
	client, server := mustKey(t), mustKey(t)
	init, st, err := ClientInit(client, server.PublicKey().Bytes(), pskPtr("a"))
	if err != nil {
		t.Fatal(err)
	}
	resp, _, _, err := ServerRespond(init, pskPtr("a"), server, mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ClientFinish(resp, pskPtr("other"), client, server.PublicKey().Bytes(), st); err == nil {
		t.Fatal("client accepted response with wrong PSK")
	}
}

func TestHandshakeClientRejectsImpostorServer(t *testing.T) {
	client, server, impostor := mustKey(t), mustKey(t), mustKey(t)
	// Client believes it is talking to `server`, but `impostor` answers. The
	// impostor cannot even decrypt the client's identity, so ServerRespond fails.
	init, _, err := ClientInit(client, server.PublicKey().Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ServerRespond(init, nil, impostor, mustKey(t)); err == nil {
		t.Fatal("impostor decrypted a handshake that was not addressed to it")
	}
}

func TestHandshakeClientPinsServerIdentity(t *testing.T) {
	client, server := mustKey(t), mustKey(t)
	other := mustKey(t)
	// Server is genuine for the handshake, but the client pins a different key.
	init, st, err := ClientInit(client, server.PublicKey().Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, _, _, err := ServerRespond(init, nil, server, mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ClientFinish(resp, nil, client, other.PublicKey().Bytes(), st); err == nil {
		t.Fatal("client accepted a server whose identity differs from the pinned key")
	}
}

func TestHandshakeTamperedMessagesRejected(t *testing.T) {
	client, server := mustKey(t), mustKey(t)
	for _, psk := range []*[KeyLen]byte{nil, pskPtr("p")} {
		init, st, err := ClientInit(client, server.PublicKey().Bytes(), psk)
		if err != nil {
			t.Fatal(err)
		}
		for i := range init {
			bad := append([]byte(nil), init...)
			bad[i] ^= 0x01
			if _, _, _, err := ServerRespond(bad, psk, server, mustKey(t)); err == nil {
				t.Fatalf("psk=%v: flipping init byte %d was accepted", psk != nil, i)
			}
		}
		resp, _, _, err := ServerRespond(init, psk, server, mustKey(t))
		if err != nil {
			t.Fatal(err)
		}
		for i := range resp {
			bad := append([]byte(nil), resp...)
			bad[i] ^= 0x01
			if _, err := ClientFinish(bad, psk, client, server.PublicKey().Bytes(), st); err == nil {
				t.Fatalf("psk=%v: flipping resp byte %d was accepted", psk != nil, i)
			}
		}
	}
}

func TestHandshakeBadSizesAndMagic(t *testing.T) {
	client, server := mustKey(t), mustKey(t)
	init, st, _ := ClientInit(client, server.PublicKey().Bytes(), nil)
	if _, _, _, err := ServerRespond(init[:len(init)-1], nil, server, mustKey(t)); err == nil {
		t.Fatal("truncated initiation accepted")
	}
	if _, _, _, err := ServerRespond(append(append([]byte(nil), init...), 0), nil, server, mustKey(t)); err == nil {
		t.Fatal("oversized initiation accepted")
	}
	// Corrupt only the magic (size is right): must be rejected with a magic error.
	bad := append([]byte(nil), init...)
	bad[0] ^= 0xff
	if _, _, _, err := ServerRespond(bad, nil, server, mustKey(t)); err == nil {
		t.Fatal("initiation with bad magic accepted")
	}
	resp, _, _, _ := ServerRespond(init, nil, server, mustKey(t))
	if _, err := ClientFinish(resp[:10], nil, client, server.PublicKey().Bytes(), st); err == nil {
		t.Fatal("truncated response accepted")
	}
}

func TestClientInitRequiresServerKey(t *testing.T) {
	if _, _, err := ClientInit(mustKey(t), nil, nil); err == nil {
		t.Fatal("expected error without server static key")
	}
	if _, _, err := ClientInit(mustKey(t), make([]byte, 5), nil); err == nil {
		t.Fatal("expected error for malformed server static key")
	}
}

func TestLowOrderPointRejected(t *testing.T) {
	// An all-zero "public key" is a low-order point; X25519 would yield an
	// all-zero shared secret. The handshake must refuse to proceed.
	if _, _, err := ClientInit(mustKey(t), make([]byte, PubKeyLen), nil); err == nil {
		t.Fatal("ClientInit accepted a low-order server key")
	}
}

// --- key files ----------------------------------------------------------------

const (
	repoRelayKey = "../../config/relay.key"
	repoRelayCrt = "../../config/relay.crt"
)

func TestLoadStaticKeyAndPublicKeyFromRepoConfig(t *testing.T) {
	priv, err := LoadStaticKey(repoRelayKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKey(repoRelayCrt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv.PublicKey().Bytes(), pub[:]) {
		t.Fatal("relay.key and relay.crt do not form a pair")
	}
	// The relay public key hard-coded in config/peer-{1,2}.yaml.
	const want = "b2d96646e3461951bac8c557d96a56d502c05bc1b6fb5535635004a60a5db23f"
	if BytesToHex(pub[:]) != want {
		t.Fatalf("relay public key = %x, config expects %s", pub, want)
	}
}

func TestLoadStaticKeyErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadStaticKey(filepath.Join(dir, "missing.key")); err == nil {
		t.Fatal("expected error for missing file")
	}
	junk := filepath.Join(dir, "junk.key")
	if err := os.WriteFile(junk, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStaticKey(junk); err == nil {
		t.Fatal("expected error for non-PEM file")
	}
	// A public key PEM is not a private key.
	if _, err := LoadStaticKey(repoRelayCrt); err == nil {
		t.Fatal("expected error when loading a public key as a private key")
	}
	if _, err := LoadPublicKey(junk); err == nil {
		t.Fatal("expected error for non-PEM public key")
	}
	if _, err := LoadPublicKey(filepath.Join(dir, "missing.crt")); err == nil {
		t.Fatal("expected error for missing public key file")
	}
	if _, err := LoadPublicKey(repoRelayKey); err == nil {
		t.Fatal("expected error when loading a private key as a public key")
	}
}
