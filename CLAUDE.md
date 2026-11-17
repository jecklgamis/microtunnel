# microtunnel

## Project Overview
A simple Linux hub-and-spoke layer 3 overlay network using a TUN virtual interface over UDP, written in Go. A working VPN implementation with a deliberately small feature set. Go port of the original C implementation (`lanecove-tunnel`); the wire protocol and YAML config format are unchanged.

## Architecture

Go module `github.com/jecklgamis/microtunnel` (Go 1.26+). Only dependencies: `gopkg.in/yaml.v3`, `golang.org/x/sys`. Crypto is stdlib only.

- `cmd/microtunnel/main.go` — flags (`-c config.yaml`, `-version`), config load, key load, TUN open, UDP bind, signal handling (SIGTERM/SIGINT stop, SIGUSR1 dumps sessions, SIGHUP reloads peers), then `peer.Run` plus `peer.WatchPeers`. `peer.go` implements `microtunnel peer add|remove|list`, `keygen.go` `microtunnel keygen`, `init.go` (`init relay|peer`), `enroll.go` (`enroll serve|token`) and `join` (subcommands are dispatched on `os.Args[1]` before flag parsing). `peer add|remove|list` use the relay's admin socket when `-socket` is given or `-c`'s `admin_socket` is reachable, else edit `peers_dir`.
- `internal/proto` — wire protocol. `proto.go` (constants, hex, AES-256-GCM `Seal`/`Open`, PSK key derivation), `handshake.go` (X25519 handshake with identity hiding: `ClientInit`/`ClientFinish`/`ServerRespond`, PEM key loading), `replay.go` (2048-bit sliding window `ReplayWindow`).
- `internal/config` — `config.go` (YAML parse + validation + defaults), `cidr.go` (IPv4 `Prefix`), `peersdir.go` (`LoadPeersDir`: one-peer-per-file YAML merged into `Config.Peers` by `Load` — `Parse` alone never touches the filesystem; `PeersDirFingerprint` for change detection).
- `internal/setup` — first-run configuration behind `microtunnel init`. `InitRelay` (files named by `Name`, default `microtunnel`; key reused-or-created, random 32-byte hex PSK, `tunnel_address`, `peers_dir`, `admin_socket`, optional `public_endpoint`) and `InitPeer` (key reused-or-created, config rendered by `admin.SpokeConfig`; with no `-address` it leaves a commented `#tunnel_address` line). Rules, all tested: never overwrite a config without `Force`, never replace or delete a private key, validate all input before creating any file, write secrets 0600 atomically, and load the result back through `config.Load` before returning. The CLI passes the PSK via `-psk`, `-psk-file` or `MICROTUNNEL_PSK` and never echoes it from `init peer`; `init relay` prints a peer hint that puts it in an env var, not argv. `-start` only works with the default dir (`/etc/microtunnel`). `join` defaults `-dir` to `/etc/microtunnel` as root.
- systemd: ONE role-agnostic service, because the same program is a relay or a peer and the config decides. `debian/systemd/microtunnel.service` (and the identical `rpm/systemd/` copy) runs `/etc/microtunnel/microtunnel.yaml`, guarded by `ConditionPathExists`, with `RuntimeDirectory=microtunnel` for the admin socket; `microtunnel@.service` runs `/etc/microtunnel/%i.yaml` with `RuntimeDirectory=microtunnel-%i`. `setup.DefaultName`/`Unit`/`AdminSocketFor`/`peersDirFor` encode the naming (default instance: `microtunnel.yaml`, `microtunnel.key`, `peers.d`, `/run/microtunnel/admin.sock`; named: `<name>.yaml`, `<name>.peers.d`, `/run/microtunnel-<name>/admin.sock`). The old `microtunnel-relay|peer|peer-1|peer-2` units and `relay.yaml`/`peer.yaml` package configs are gone.
- `internal/adminapi` — the relay's local management API: JSON over HTTP on a unix socket (`Listen` creates it 0600, replaces stale sockets, refuses live ones/non-sockets). `GET /v1/status`, `GET|POST /v1/peers`, `DELETE /v1/peers/{name}`. Mutations are serialised by a mutex, go through `admin.Register`/`Remove`, then call `Node.ReloadFrom` immediately (a failed reload rolls the registration back). `PeerInfo` merges `admin.List` with `Peer.Sessions()` (live state + counters). `client.go` is the unix-socket client used by the CLI and the enrollment service. Tests use `/tmp` sockets (macOS caps socket paths at ~104 bytes).
- `internal/enroll` — enrollment service. `tokens.go`: one file per token (`<id>.json` → atomically renamed to `.claimed` then `.used`; only a SHA-256 of the secret is stored; ids are validated as 16 hex chars before touching paths). `server.go`: `POST /v1/enroll` claims the token, registers via the `Registrar` (the admin client), commits; any non-token failure `Release`s the token; all token failures are one uniform 401; per-IP failure limiter. `join.go`: generates the key locally (temp name until the server names the peer), verifies TLS, never follows redirects, refuses plain http without `AllowHTTP`, leaves nothing behind on failure.
- `internal/admin` — logic behind the `peer` CLI (`Register` + `SpokeConfig` are shared by the CLI, the admin API and enrollment; errors carry a `Kind` the API maps to 400/404/409): `Add` (validate, allocate lowest free overlay /32, write `<peers_dir>/<name>.yaml` atomically via a dot-prefixed tmp file, optionally generate a key pair and a saved spoke config), `Remove`, `List`. Tested against real temp dirs.
- `internal/peer` — `peer.go` (`Peer`, `New`, `Run`, TUN/UDP worker loops, data + handshake handlers), `table.go` (session table, routing, `sessionInit`), `housekeeping.go` (rekey/expiry/keepalive/DNS), `listen.go` (UDP socket setup), `reload.go` (`Reload`/`ReloadFrom`: live peer-set changes), `watch.go` (`WatchPeers`: polls `peers_dir` every second, applies a change once it is stable for one poll, also reloads on a trigger channel = SIGHUP).
- `internal/tun` — TUN devices behind `tun.Open(name) (io.ReadWriteCloser, name, error)`: `tun_linux.go` (`/dev/net/tun`, `TUNSETIFF`), `tun_darwin.go` (utun kernel-control socket; the 4-byte AF header is stripped/added in `Read`/`Write`), `tun_other.go` (stub error). `utun.go` holds the platform-neutral, unit-tested utun framing/naming helpers; `configure.go` builds and runs the `ifconfig`/`route` (macOS) or `ip` (Linux) commands for `tunnel_address`/`tunnel_routes` (`Commands` is pure and tested for both OSes).
- `internal/logx` — timestamped logger.
- Demo secrets: `config/*.key|crt|yaml` are DEMO identities (private keys are in the repo) used by the Docker scripts/tests. `internal/config/demo.go` lists their public keys and the placeholder PSKs (`some-psk`, `change-me`); `Config.Warnings()` and main log a warning when any is in use (advisory only: the demo itself uses them). Packages must never ship them or any config/keys: the deb/rpm install no config at all, only annotated EXAMPLES from `packaging/config/` (relay.yaml, peer.yaml) into `/usr/share/microtunnel/examples/` (a test requires them to contain no demo key/PSK, to fail to load untouched, and to be valid once filled in), an empty `/etc/microtunnel/peers.d` (0750) and the units below; `config.Parse` rejects a `<placeholder>` pre_shared_key so an untouched copy cannot start, and `.dockerignore` keeps `*.key|crt|pem` out of the image (the run scripts mount keys at run time).

### Topology
```
peer-1 (10.9.0.2) ──┐
                     ├── UDP 5040 ── relay (10.9.0.1, public IP)
peer-2 (10.9.0.3) ──┘
```

- **relay** — public IP, inbound-only, routes traffic between peers
- **peer-1 / peer-2** — behind NAT, connect outbound to relay

### Key Provisioning
Keys are X25519 key pairs stored in PEM files (PKCS#8 private `.key`, PKIX public `.crt`). Use `scripts/generate-peer-keys.sh` (needs `openssl`) to generate them.

```
./scripts/generate-peer-keys.sh relay peer-1 peer-2
# produces: relay.key/crt, peer-1.key/crt, peer-2.key/crt
```

Keys and YAML configs for local testing are kept in `config/`:

| File | Purpose |
|------|---------|
| `config/relay.key` / `config/relay.crt` | Relay identity |
| `config/peer-1.key` / `config/peer-1.crt` | Peer-1 identity |
| `config/peer-2.key` / `config/peer-2.crt` | Peer-2 identity |
| `config/relay.yaml` | Relay runtime config |
| `config/peer.yaml` | Generic peer template (placeholders; intentionally fails to load until edited) |
| `config/peer-1.yaml` | Peer-1 runtime config |
| `config/peer-2.yaml` | Peer-2 runtime config |

### YAML Config Format
```yaml
interface: microtunnel0
port: 5040
address: ""                          # optional: bind to specific local IP (default: 0.0.0.0)
private_key_file: /microtunnel/peer-1.key   # absolute path inside container
pre_shared_key: some-psk             # optional; empty string is rejected
verbose: false
keepalive_interval: 25               # seconds between keepalive packets
rekey_after: 180                     # seconds before initiating a rekey
reconnect_interval: 30               # seconds between reconnect attempts
session_expiry: 540                  # seconds before an idle session expires (must be > rekey_after)
prev_key_grace: 90                   # seconds old key is retained after rekey
handshake_timeout: 5                 # seconds before pending handshake is abandoned
handshake_cooldown: 5                # seconds between handshake attempts to same peer
worker_threads: 4                    # optional: packet workers (default: min(4, NumCPU), max 32)
tunnel_address: 10.9.0.2/24          # optional: program assigns this overlay IP to the TUN itself (required on macOS)
tunnel_routes: [192.168.50.0/24]     # optional: extra CIDRs routed via the TUN (needs tunnel_address)
admin_socket: /run/microtunnel/admin.sock   # optional: serve the admin API on this unix socket (0600); relative paths resolve against this file
public_endpoint: relay.example.com:5040     # optional: host:port handed to newly registered peers
peers_dir: peers.d                   # optional: dir of one-peer-per-file YAML (*.yaml/*.yml); makes `peers:` optional; relative to this file

peers:
  - public_key: <hex>
    endpoint: 1.2.3.4:5040          # omit for inbound-only peers
    allowed_ips:
      - 10.9.0.0/24
```
Unknown keys are ignored. On macOS use `interface: utun` (kernel assigns `utunN`; a non-`utunN` name is ignored) plus `tunnel_address`, because a utun device only exists once opened (`microtunnel init peer` writes this; run `sudo microtunnel`). When `tunnel_address` is unset the interface is expected to be configured externally (Docker entrypoint / `create-tunnel.sh` on Linux). Limits: 64 peers, 16 `allowed_ips` per peer, interface name ≤ 15 chars. Endpoint hostnames are resolved at startup (failure is fatal) and re-resolved before each reconnect.

### Dynamic peers
`peers_dir` files hold one peer each (`public_key`, optional `endpoint`, `allowed_ips`; file name = peer name). Duplicate public keys anywhere are a config error. `Peer.Reload` (SIGHUP or directory change) diffs by public key under the table write lock: added peers become known; removed peers' sessions and pending handshakes are dropped at once; changed `allowed_ips` update the live session's routes with no re-handshake; a changed endpoint cancels a pending handshake and is re-resolved. A failed reload (bad file) changes nothing. `peerConfig` objects are replaced wholesale, never mutated, and `pendingHS` holds a `*peerConfig` (not an index) so reloads cannot invalidate in-flight handshakes. Only peers reload; other settings need a restart. Housekeeping runs `dialDue` every tick (rate-limited by `reconnect_interval`) so a peer rejected before the relay loaded it retries quickly; generated spoke configs set `reconnect_interval: 5`.

### Session Management
- Sessions live in a flat array (`table.sessions[]`, max 64)
- Slot reuse (`table.alloc`): existing slot found by pub key first, then addr, then free slot
- Outbound peers checked every 10 seconds; reconnect attempted every `reconnect_interval` seconds on failure
- Rekeying initiated at 80% of `rekey_after` (default 180s), i.e. at ~144s
- Handshake is **non-blocking**: initiation is sent by the housekeeping goroutine; the response is handled by whichever UDP worker receives it
- Simultaneous rekey collisions resolved by tie-breaking: higher public key wins. A packet from the dialed address is only treated as our response if it verifies; otherwise it is handled as an inbound initiation (so the tie-break is reachable). The loser only yields after the initiation authenticates.
- **Previous session key grace period** (`prev_key_grace`, default 90s): after a rekey the old key stays valid for decrypt, eliminating packet loss during the switchover. Prev-key packets skip the replay check so old sequence numbers can't poison the new window.
- **Pre-generated ephemeral keypair**: the responder keeps its next X25519 ephemeral key ready (`Peer.precomp`) and regenerates it right after use, so keygen stays off the hot path
- The responder identifies the initiator and checks the peer is known/not in cooldown **before** sending its response and installs the session before answering.

### Concurrency
- `worker_threads` workers, each running **two goroutines**: a TUN reader (`tunLoop`, TUN→UDP) and a UDP reader (`udpLoop`, UDP→TUN/handshake). Reads are concurrent on the shared TUN `*os.File` and `*net.UDPConn`; the kernel gives each packet to one reader.
- One housekeeping goroutine (`housekeepingLoop`) owns rekey/dial, pending-handshake timeout, session expiry and keepalives. Blocking DNS happens **outside** the table lock.
- Two lock granularities: `table.mu` (`sync.RWMutex`: read-locked for per-packet lookups and held across lookup+forward/decrypt, write-locked for handshake/expiry/rekey paths) and per-session `session.mu` (`sync.Mutex`: addr, keys, AEADs, sequence numbers, replay window, lastSeen/lastSent). Lock order is always table before session. Only packets for the *same* peer serialise on `session.mu`.
- Each worker goroutine owns its scratch buffers (`workerBufs`), so the hot path does not allocate. AES-GCM `cipher.AEAD` values are safe for concurrent use and are cached per session.
- `Run` closes the TUN device and UDP socket on exit; that is what unblocks the reader goroutines. A fatal TUN read error cancels the whole peer and `Run` returns it.

### Handshake Wire Format
```
[8 magic][32 eph_pub][48 AES-256-GCM(static_pub)][32 HMAC-SHA256(psk,...)]?
```

- **`eph_pub`** — fresh X25519 ephemeral public key, generated per handshake
- **`AES-256-GCM(static_pub)`** — static public key encrypted to hide identity from passive observers:
  - Initiator encrypts its static_pub with `key = SHA-256(DH(eph_c, server_static))`
  - Responder encrypts its static_pub with `key = SHA-256(DH(eph_s, eph_c))`
  - Zero IV is safe because the encryption key is derived from a fresh ephemeral DH every time
- **`HMAC-SHA256`** — optional PSK authentication over `[eph_pub][encrypted_static_pub]` with key `SHA-256(psk)`; omitted if no PSK. Initiation and response share this layout, so message size is 88 bytes without a PSK and 120 with one.

### Session Key Derivation
```
SHA-256(
  DH(eph_c, eph_s)          ||
  DH(static_c, eph_s)       ||
  DH(eph_c, static_s)       ||
  client_eph_pub            ||
  server_eph_pub            ||
  client_static_pub         ||
  server_static_pub
)
```

### Data Packets
Each datagram on the wire is:
```
[12-byte IV][AES-256-GCM ciphertext of (8-byte magic + 8-byte BE seq + payload)][16-byte GCM tag]
```
Magic is `0xdeadbeefcafebabe`. The first packet of a session has seq 0. Packets with a bad magic header, invalid GCM tag, or replayed/too-old sequence number are dropped. The receiver uses a **2048-bit sliding window** (`proto.ReplayWindow`, `32 × uint64`). An empty payload is a keepalive. Max inner packet is `proto.TunMTU` (1428).

### AllowedIPs Routing
On the TUN→UDP path, destination IP is looked up using longest-prefix match across all active sessions' routes (`table.routeLookup`). On the UDP→TUN path, source IP is validated against the sending peer's AllowedIPs, and non-IPv4 payloads are dropped. If the destination belongs to another peer the relay forwards directly in user space (no TUN write).

## Logging
`internal/logx`. `logx.SetVerbose(true)` (config `verbose: true`) enables DEBUG. All lines go to stderr with a timestamp:
```
2026-04-23 14:05:32 [INFO]  Peer connected: 1.2.3.4:5040 (key=deadbeef...)
2026-04-23 14:05:32 [WARN]  Replay from 1.2.3.4:5040 (seq=42) — dropping
```
`scripts/run-integration-test.sh` greps for the log lines `Listening on UDP` and `Active peers (2)` — keep those messages stable.

## Build
```
make build              # build ./microtunnel for the current OS/arch (`make all` is an alias; override with GOOS/GOARCH; on macOS run with sudo)
make linux              # build/microtunnel-linux-{amd64,arm64} (static; the release workflow uploads these)
make macos              # build/microtunnel-darwin-{arm64,amd64}
make test               # go test ./... natively (no root/TUN/Docker needed; works on macOS)
make test-race          # go test -race
make vet                # go vet for host OS and GOOS=linux
make check              # gofmt check + vet + race tests
make test-image         # build golang toolchain image (microtunnel-test:latest)
make test-using-docker  # run the race-detector suite on Linux via Docker
make integration-test   # build image, run relay+peer-1+peer-2 with real TUN in Docker, ping+curl
make dynamic-test       # relay with empty peers_dir; `peer add/remove` while it runs (alice/bob), asserts no relay restart
make init-test          # `init relay` + two `init peer`s + `peer add`, real TUN, ping through the relay
make enroll-test        # admin socket + enrollment: `peer add -socket` (carol), token + `join` (dave), removal, spent token
make image              # build Docker image (microtunnel-peer:latest)
make deb                # build .deb (DEB_ARCH=amd64|arm64; output: build/microtunnel_<ver>_<arch>.deb)
make rpm                # build .rpm (RPM_ARCH=x86_64|aarch64; output: build/rpm/RPMS/)
make pkg                # macOS only: universal installer build/microtunnel-<ver>-universal.pkg (unsigned; launchd plist from internal/setup/launchd.go, regenerate packaging/macos/*.plist if it changes)
make install            # build for this machine and install to $(PREFIX)/bin (default /usr/local)
make clean              # remove binary and build artifacts
```
The binary is built with `CGO_ENABLED=0`, so packages need no libc/OpenSSL/libyaml and cross-compile from any host.

## Testing
- `internal/proto`: hex/PSK/AEAD/replay unit tests, handshake roundtrip + tamper/MITM/PSK tests, key-file loading (uses `config/relay.*`).
- `internal/config`: defaults, every validation rule, shipped `config/*.yaml` must parse.
- `internal/peer`: ported session-table tests (`table_test.go`), data path / handshake state machine / housekeeping unit tests driven directly via `handleUDP`/`handleTUN`/`handleHandshake`/`housekeep`, and `e2e_test.go` which runs relay + 2 peers through the real `Run` loops over loopback UDP with in-memory TUN (`fakeDev`). Tests shrink timings by setting `Peer` duration fields (`rekeyAfter`, `hkTick`, ...).
- Logging is discarded in `internal/peer` tests unless a test calls `captureLogs`.

## Running With Docker
```bash
# Setup (once)
make image

# Local testing (all on one Mac — 3 terminals)
./scripts/run-relay-in-docker.sh
./scripts/run-peer-1-in-docker.sh
./scripts/run-peer-2-in-docker.sh
```

## Docker
- `Dockerfile` — multi-stage, multi-arch (builder runs on `$BUILDPLATFORM` and cross-compiles for `$TARGETARCH`; `build.yaml` publishes linux/amd64 + linux/arm64) (`golang:1.26-bookworm` builder → `debian:bookworm-slim`); includes iproute2, nginx, curl, ping, ifconfig, ssh, Envoy proxy; bundles `config/` into the image. No libssl/libyaml needed.
- `scripts/docker-entrypoint.sh` — creates TUN, starts nginx, optionally starts Envoy (when `ENVOY_UPSTREAM_HOST` is set), execs `microtunnel -c $PEER_CONFIG`
- `scripts/extract-keys-hex.sh <file.key>` — prints private and public key hex from an X25519 `.key` PEM file
- `scripts/extract-pubkey-hex.sh <file.crt>` — prints public key hex from an X25519 `.crt` PEM file
- `scripts/generate-peer-keys.sh <name> [name2 ...]` — generates X25519 key pairs (`.key` / `.crt`) for each given name
- `config/envoy.yaml.tmpl` — Envoy static config template; two listeners sharing one upstream cluster:
  - **TCP proxy** on `0.0.0.0:15040` — transparent L4 pass-through, one upstream connection per downstream connection
  - **HTTP proxy** on `0.0.0.0:15050` — L7 with upstream connection pooling (~130 requests/connection); recommended for HTTP workloads
  - Admin interface on `0.0.0.0:9901`
- `scripts/create-tunnel.sh <tunnel> <ip/cidr> [routes...]` — creates TUN interface, assigns overlay IP, disables ICMP redirects
- `scripts/run-relay-in-docker.sh` — runs relay container from `config/relay.yaml` on the shared `microtunnel-net` Docker network (created if missing); mounts key, exposes UDP 5040 and Envoy admin 9901
- `scripts/run-peer-1-in-docker.sh` / `scripts/run-peer-2-in-docker.sh` — run peer containers on `microtunnel-net`; mount key, expose ports for UDP tunnel, Envoy TCP/HTTP proxy, and admin
- `scripts/test-tunnel-relay.sh` — ping + curl both peers (10.9.0.2, 10.9.0.3) from relay
- `scripts/test-tunnel-using-peer-1.sh [target_ip]` — ping + curl from peer-1 (default target: 10.9.0.3)
- `scripts/test-tunnel-using-peer-2.sh [target_ip]` — ping + curl from peer-2 (default target: 10.9.0.2)
- `scripts/run-integration-test.sh` — end-to-end test behind `make integration-test`
- `scripts/run-init-test.sh` — end-to-end test behind `make init-test` (container-local admin socket, same reason as below)
- `scripts/run-enroll-test.sh` — end-to-end test behind `make enroll-test` (the admin socket lives at `/tmp/admin.sock` inside the relay container because Docker Desktop for Mac bind mounts cannot chmod sockets)
- `scripts/run-dynamic-peers-test.sh` — end-to-end test behind `make dynamic-test` (work dir `build/dyn-test`, removed on exit)
- `scripts/create-tag.sh` — creates a git tag; auto-increments the rc number from the latest tag if `VERSION` env var is not set

## CLI Options

### microtunnel binary
```
microtunnel [-c <config.yaml>] [-version]
```
| Option | Description |
|--------|-------------|
| `-c`   | YAML config file (default: `/etc/microtunnel/microtunnel.yaml`) |
| `-version` | Print the build version (set with `-ldflags "-X main.version=..."`) and exit |

## Tunnel Interface
- Interface name: `microtunnel0`
- Overlay network: `10.9.0.0/24` (relay=`10.9.0.1`, peer-1=`10.9.0.2`, peer-2=`10.9.0.3`)

## Docker Environment Variables
Consumed by `scripts/docker-entrypoint.sh`:

| Variable | Default | Description |
|----------|---------|-------------|
| `TUNNEL_NAME` | `microtunnel0` | TUN interface name |
| `PEER_IP` | `10.9.0.1/24` | This peer's overlay IP/CIDR |
| `PEER_ROUTES` | _(none)_ | Space-separated extra CIDRs to route via TUN |
| `PEER_CONFIG` | `peer.yaml` | Path to YAML config file inside container |
| `ENVOY_UPSTREAM_HOST` | — | Upstream host for Envoy proxy; if unset, Envoy is not started |
| `ENVOY_UPSTREAM_PORT` | `80` | Upstream port for Envoy proxy |

## Platform Notes
- Runs on Linux (`/dev/net/tun`) and macOS (utun, needs root). The tests need neither (in-memory TUN). The utun open path itself is only verifiable on a real Mac with sudo; its pure logic is unit-tested.
- Docker containers require `--cap-add=NET_ADMIN` and `--device=/dev/net/tun`; systemd units use `AmbientCapabilities=CAP_NET_ADMIN`
- Building needs only Go; `openssl` is needed only by the key-generation scripts


## Port Mapping (Docker)
| Service | Container port | relay host port | peer-1 host port | peer-2 host port |
|---------|---------------|-----------------|-----------------|-----------------|
| UDP tunnel | 5040 | 5040 | 5042 | 5043 |
| nginx | 80 | — | — | — |
| Envoy TCP proxy | 15040 | — | 15042 | 15043 |
| Envoy HTTP proxy | 15050 | — | 15052 | 15053 |
| Envoy admin | 9901 | 9901 | 9902 | 9903 |
