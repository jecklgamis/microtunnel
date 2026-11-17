package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// peerFileExts are the extensions LoadPeersDir reads. Anything else (editor
// temp files, ".tmp" files being written atomically, dotfiles) is ignored.
var peerFileExts = []string{".yaml", ".yml"}

func isPeerFile(name string) bool {
	if strings.HasPrefix(name, ".") {
		return false
	}
	for _, e := range peerFileExts {
		if strings.HasSuffix(name, e) {
			return true
		}
	}
	return false
}

// PeerName returns the peer name for a peers_dir file name (the base name
// without its extension).
func PeerName(file string) string {
	file = filepath.Base(file)
	return strings.TrimSuffix(strings.TrimSuffix(file, ".yaml"), ".yml")
}

// LoadPeersDir reads every peer file in dir, sorted by file name. Each file
// holds exactly one peer, using the same keys as an entry of `peers:`:
//
//	public_key: <hex>
//	endpoint: host:port      # optional
//	allowed_ips: [10.9.0.5/32]
//
// A file that fails to parse is an error naming that file, so a half-edited
// file can never silently drop a peer from a reload.
func LoadPeersDir(dir string) ([]Peer, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("peers_dir: %w", err)
	}
	var peers []Peer
	for _, e := range entries {
		if e.IsDir() || !isPeerFile(e.Name()) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("peers_dir: %w", err)
		}
		var raw rawPeer
		if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: YAML parse error: %w", path, err)
		}
		p, err := parsePeer(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		p.Name = PeerName(e.Name())
		peers = append(peers, p)
	}
	return peers, nil
}

// PeersDirFingerprint summarises the peer files in dir (names, sizes and
// modification times) so a watcher can cheaply detect changes. A missing or
// unreadable directory yields "".
func PeersDirFingerprint(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var parts []string
	for _, e := range entries {
		if e.IsDir() || !isPeerFile(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%d:%d", e.Name(), info.Size(), info.ModTime().UnixNano()))
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}
