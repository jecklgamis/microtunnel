package proto

import (
	"crypto/ecdh"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// WriteKeyPair writes key to base+".key" (PKCS#8 PEM, mode 0600) and its public
// half to base+".crt" (PKIX PEM, mode 0644) — the same formats
// `openssl genpkey -algorithm x25519` produces and LoadStaticKey /
// LoadPublicKey read. It refuses to overwrite existing files, so a private key
// can never be silently replaced.
func WriteKeyPair(base string, key *ecdh.PrivateKey) (keyPath, crtPath string, err error) {
	keyPath, crtPath = base+".key", base+".crt"
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("encode private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		return "", "", fmt.Errorf("encode public key: %w", err)
	}
	if err := writeNew(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return "", "", err
	}
	if err := writeNew(crtPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		_ = os.Remove(keyPath)
		return "", "", err
	}
	return keyPath, crtPath, nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("%w (refusing to overwrite an existing file)", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}
