package config

import (
	"fmt"
	"slices"

	"github.com/jecklgamis/microtunnel/internal/proto"
)

// demoKeys are the public halves of the demo key pairs committed in config/
// (relay, peer-1, peer-2). Their private halves are in the repository, so
// anyone can act as these identities: they are fine for the local Docker demo
// and must never protect a real network. A test keeps this list in sync with
// the files in config/.
var demoKeys = map[string]string{
	"b2d96646e3461951bac8c557d96a56d502c05bc1b6fb5535635004a60a5db23f": "relay",
	"ba54232056ec3b8ff1982904345cea131293ca5daff441d11a23c010c0528442": "peer-1",
	"d6ce2b2246de6ab18b4d12c86889575958ac186e4894b92fdde597c2bcda2b7a": "peer-2",
}

// placeholderPSKs are pre-shared keys that appear in the repository's demo
// configs and documentation, so they are public knowledge.
var placeholderPSKs = []string{"some-psk", "change-me"}

// DemoKeyName reports whether pub is one of the publicly known demo keys, and
// which one.
func DemoKeyName(pub [proto.PubKeyLen]byte) (string, bool) {
	name, ok := demoKeys[proto.BytesToHex(pub[:])]
	return name, ok
}

// Warnings lists insecure settings in the config that are legal but should not
// be used on a real network: a well-known placeholder pre-shared key, or a peer
// identified by a publicly known demo key. They are advisory only, because the
// repository's own demo setup uses all of them.
func (c *Config) Warnings() []string {
	var w []string
	if c.HasPSK && slices.Contains(placeholderPSKs, c.PreSharedKey) {
		w = append(w, fmt.Sprintf("pre_shared_key %q is a well-known placeholder; anyone can compute the handshake authentication. Use a long random secret", c.PreSharedKey))
	}
	for _, p := range c.Peers {
		if name, ok := DemoKeyName(p.PublicKey); ok {
			w = append(w, fmt.Sprintf("a peer uses the publicly known demo key %q (its private key is in the repository); anyone can impersonate it. Generate real keys with `microtunnel keygen`", name))
		}
	}
	return w
}
