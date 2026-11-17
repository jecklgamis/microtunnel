package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jecklgamis/microtunnel/internal/admin"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

const keygenUsage = `Usage: microtunnel keygen <name> [-dir <dir>]

Creates an X25519 key pair <name>.key (private, mode 0600) and <name>.crt in
<dir> (default .) and prints the public key hex, which is what a relay's
"microtunnel peer add <name> -public-key <hex>" needs. Never overwrites files.
`

// runKeygen implements `microtunnel keygen`; args exclude "keygen".
func runKeygen(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, keygenUsage) }
	dir := fs.String("dir", ".", "directory for the key files")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fs.Usage()
		return errors.New("keygen needs a name")
	}
	name := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q (put flags after the name)", fs.Arg(0))
	}
	if !admin.ValidName(name) {
		return fmt.Errorf("invalid name %q (letters, digits, '.', '_', '-')", name)
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}
	key, err := proto.GenerateKey()
	if err != nil {
		return err
	}
	keyPath, crtPath, err := proto.WriteKeyPair(filepath.Join(*dir, name), key)
	if err != nil {
		return err
	}
	pub := proto.PubBytes(key)
	fmt.Fprintf(stdout, "wrote %s (private, keep secret) and %s\npublic key: %s\n", keyPath, crtPath, proto.BytesToHex(pub[:]))
	return nil
}
