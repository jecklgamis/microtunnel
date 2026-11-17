## microtunnel

[![build](https://github.com/jecklgamis/microtunnel/actions/workflows/build.yaml/badge.svg)](https://github.com/jecklgamis/microtunnel/actions/workflows/build.yaml)

📖 [User Guide](https://jecklgamis.github.io/microtunnel/)

A simple Linux **hub-and-spoke layer 3 overlay network** using a TUN virtual interface over UDP. A working VPN implementation with a deliberately small feature set.

Inspired by [WireGuard](https://www.wireguard.com/), this project implements similar concepts — X25519 key exchange, identity hiding, AllowedIPs routing, and session rekeying — reimplemented from scratch in Go. It is a port of the original C implementation (`lanecove-tunnel`) and uses the same wire protocol and configuration format.

It creates a virtual IP network (`10.9.0.0/24`) layered on top of an existing underlay network, with traffic encapsulated inside UDP datagrams. Layer 3 means the tunnel operates at the IP (network) layer — it forwards raw IP packets between peers, not Ethernet frames. Each peer has a TUN interface with an IP address, and routing rules direct traffic through it. Broadcast, multicast, and non-IP traffic are not supported.

The topology is **hub-and-spoke**: peers behind NAT connect outbound to a relay with a public IP, and all traffic between peers transits through the relay. The relay forwards packets between peers in user space — no kernel IP forwarding required. Peers do not connect directly to each other (no NAT hole-punching).

```
                        ┌─────────────────────────┐
                        │  relay (public IP)       │
                        │  overlay: 10.9.0.1       │
                        │  UDP :5040               │
                        └────────────┬────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    │ UDP (encrypted)                  │ UDP (encrypted)
                    │                                  │
        ┌───────────┴──────────┐          ┌───────────┴──────────┐
        │  peer-1 (behind NAT) │          │  peer-2 (behind NAT) │
        │  overlay: 10.9.0.2   │          │  overlay: 10.9.0.3   │
        └──────────────────────┘          └──────────────────────┘
```

Peers communicate with each other via the relay — traffic from peer-1 to peer-2 travels peer-1 → relay → peer-2.

## Common Use Cases

- **Connecting peers behind NAT** — machines that can't reach each other directly (home networks, cloud VMs, mobile) communicate securely through a relay with a public IP.
- **Secure service access** — a peer runs a service (e.g. a web server or database) accessible only over the overlay IP, keeping it off the public internet.
- **Multi-site connectivity** — linking servers across different cloud providers or regions through a single relay without needing cloud VPN products.
- **Development and testing** — exposing a local dev machine's services to a remote peer (e.g. a CI runner or a colleague's machine) without port forwarding.

The relay is suited for low-to-moderate traffic between a small number of peers, not high-throughput production workloads.

## Features

### Security
X25519 key exchange with forward secrecy, AES-256-GCM, identity hiding, optional PSK, replay protection, per-peer AllowedIPs and automatic rekeying. Details, the handshake and the review notes are in [docs/security.md](docs/security.md); how it compares with WireGuard, OpenVPN and others is in [docs/comparison.md](docs/comparison.md).

### Limitations
- **Linux and macOS** — Linux uses `/dev/net/tun`, macOS uses a `utun` device (see [Running Natively](#macos)). Windows and BSD are not supported. The whole test suite runs natively on both, since the tests use in-memory TUN devices
- **IPv4 only** — TUN packets are validated as IPv4; IPv6 and non-IP traffic are dropped
- **UDP transport** — no packet ordering guarantees; packet loss is not retransmitted
- **Single-process** — a configurable pool of worker goroutines (`worker_threads`, default `min(4, nproc)`) parallelizes packet crypto across cores, but it's still one process per peer/relay with no multi-host failover
- **Not audited** — not hardened for production use

## Requirements

**To run:** Linux with `iproute2` (for the helper script that creates the TUN interface), or macOS 12+ (no extra tools; see below). The binary is a static Go executable — no OpenSSL, libyaml or libc version requirements. `openssl` is only needed by the key-generation scripts.

**To build:** Go 1.26+ and `make`. Docker is optional (image builds, running the tests on Linux, local end-to-end testing).

```
sudo apt install iproute2 make openssl   # plus Go 1.26+ from https://go.dev/dl/
```

## Running Natively

Install the package, then configure each machine with `microtunnel init`. This walkthrough sets up one relay and one peer. A peer is any machine behind NAT that dials out to the relay; the same program is both, and the config decides the role.

You need a relay with a public address (below it is `relay.example.com`) and UDP 5040 open to it. Replace `relay.example.com` with your own host or IP.

### Linux (deb package)

**1. Install** on both machines. Download the package for your architecture from the [releases page](https://github.com/jecklgamis/microtunnel/releases) (use the `.rpm` and `rpm -i` on Red Hat family systems):

```bash
sudo apt install ./microtunnel_<version>_amd64.deb
```

**2. On the relay:** create its config and start it.

```bash
sudo microtunnel init relay --endpoint relay.example.com:5040
sudo systemctl enable --now microtunnel
```

`init relay` generates the relay's key and a random pre-shared key, and writes `/etc/microtunnel/microtunnel.yaml`. It prints the relay's **public key** and a ready-made `init peer` line that contains the pre-shared key. Send that line to the peer over a secure channel.

**3. On the peer:** create its config with the line the relay printed.

```bash
MICROTUNNEL_PSK=<psk> sudo -E microtunnel init peer \
  --relay relay.example.com:5040 --relay-key <relay public key>
#   public key:  d3eb...
```

**4. On the relay:** register the peer's public key. It prints the overlay address assigned to the peer.

```bash
sudo microtunnel peer add laptop -public-key d3eb...
# laptop: 10.9.0.2/32
```

The relay picks this up live; no restart is needed.

**5. On the peer:** apply that address (the peer's key is kept) and start it.

```bash
MICROTUNNEL_PSK=<psk> sudo -E microtunnel init peer \
  --relay relay.example.com:5040 --relay-key <relay public key> --address 10.9.0.2/24 --force
sudo systemctl enable --now microtunnel
```

**6. Test**

```bash
ping 10.9.0.1                       # on the peer: the relay
sudo microtunnel peer list          # on the relay: laptop should be "connected"
sudo journalctl -u microtunnel -f   # logs, on either machine
```

Running a relay and several peers as native processes on **one** host does not work: once `10.9.0.2` and `10.9.0.3` are both local addresses, the kernel routes replies back through `lo` instead of the TUN device. This applies to any TUN overlay, WireGuard included. For same-machine testing use [Docker](#running-with-docker), which gives each peer its own network namespace.

### macOS

A Mac is an ordinary peer; the relay side is the same as above. macOS has no `systemctl` and creates the tunnel as a `utun` device, which needs root, so you run microtunnel in the foreground with `sudo`.

**1. Install.** Easiest is the installer package: download `microtunnel-<version>-universal.pkg` (Apple silicon and Intel) from the [releases page](https://github.com/jecklgamis/microtunnel/releases) and open it. It isn't signed yet, so macOS will block a double-click: right-click the file and choose Open (or run `sudo installer -pkg microtunnel-<version>-universal.pkg -target /`). It installs `/usr/local/bin/microtunnel`, a launchd job, `/etc/microtunnel/peers.d` and `/usr/local/share/microtunnel/uninstall.sh`, and starts nothing. Or build from source (Go 1.26+, `brew install go`):

```bash
git clone git@github.com:jecklgamis/microtunnel.git && cd microtunnel
make install                 # builds for this Mac and installs /usr/local/bin/microtunnel
make pkg                     # or build the installer yourself: build/microtunnel-<version>-universal.pkg
```

A bare binary also works: download `microtunnel-darwin-arm64` or `microtunnel-darwin-amd64`, then `xattr -d com.apple.quarantine <file>`, `chmod +x <file>` and move it to `/usr/local/bin/microtunnel`.

**2. Set up the relay** as in step 2 of the Linux walkthrough (any Linux relay works).

**3. On the Mac:** create its config. `sudo env` passes the pre-shared key through `sudo`.

```bash
sudo env MICROTUNNEL_PSK=<psk> microtunnel init peer \
  --relay relay.example.com:5040 --relay-key <relay public key>
#   public key:  d3eb...
```

**4. On the relay:** `sudo microtunnel peer add mac -public-key d3eb...` (prints the assigned address, e.g. `10.9.0.2/32`).

**5. On the Mac:** apply the address, then run it.

```bash
sudo env MICROTUNNEL_PSK=<psk> microtunnel init peer \
  --relay relay.example.com:5040 --relay-key <relay public key> --address 10.9.0.2/24 --force
sudo microtunnel             # foreground: reads /etc/microtunnel/microtunnel.yaml; Ctrl-C stops it
```

To run it in the background and at every boot instead, load the launchd job (add `--start` to the `init peer` command in this step and it does this for you):

```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.jecklgamis.microtunnel.plist
sudo tail -f /var/log/microtunnel.log                  # logs
sudo launchctl bootout system/io.github.jecklgamis.microtunnel   # stop it
```

The job starts only while `/etc/microtunnel/microtunnel.yaml` exists and restarts the daemon if it exits. To uninstall: `sudo /usr/local/share/microtunnel/uninstall.sh` (add `--purge` to delete `/etc/microtunnel`, config and keys included).

**6. Test** from another terminal:

```bash
ping 10.9.0.1                       # the relay
ifconfig | grep -A3 utun            # the tunnel interface and its overlay address
netstat -rn | grep 10.9.0           # route for the overlay subnet
```

Notes:
- The admin socket defaults to `/var/run/microtunnel/admin.sock` here (there is no `/run` on macOS), so `microtunnel peer ...` works the same way.
- The interface is named `utunN` and chosen by the kernel, so `interface:` in the config is ignored on macOS. The MTU is set to 1428.
- To also send another network through the tunnel, add it to `tunnel_routes` in the Mac's config and restart.
- macOS may ask once whether to allow incoming connections for the binary; allow it.
- The utun code needs root, so it isn't covered by the automated tests. The framing, command generation and config logic are unit-tested, and the Linux equivalent is verified in Docker. Please report anything odd on real hardware.

---

## Dynamic Peers (no restarts)

A relay normally lists every peer in its YAML, and editing that means a restart that drops every session. Instead, point the relay at a directory with **`peers_dir`** and manage peers with the built-in CLI. A running relay notices changes within a second or two, and **sessions of unaffected peers are never interrupted**.

```yaml
# /etc/microtunnel/microtunnel.yaml
interface: microtunnel0
private_key_file: microtunnel.key
pre_shared_key: some-psk
tunnel_address: 10.9.0.1/24     # the overlay subnet peers are allocated from
peers_dir: peers.d              # relative paths are resolved against this file's directory
# `peers:` is now optional; inline peers and peers_dir peers can be mixed
```

```bash
mkdir peers.d                   # once

# Recommended: the new machine makes its own key, so its private key never leaves it
microtunnel keygen laptop                      # on the laptop: writes laptop.key/.crt, prints the public key
microtunnel peer add laptop -public-key <hex> -endpoint relay.example.com:5040
#   -> picks the next free overlay IP (10.9.0.2), writes peers.d/laptop.yaml,
#      and prints a ready-made config for the laptop; save it there as laptop.yaml

# Or let the relay admin create everything (bundle of .key, .crt and .yaml to copy over)
microtunnel peer add phone -generate -key-dir ./phone -endpoint relay.example.com:5040

microtunnel peer list            # name, allowed IPs, key, source (peers_dir or config)
microtunnel peer remove laptop   # cut off immediately
```

What a reload does (also triggered by `kill -HUP <relay pid>`, which re-reads the whole peer list):

| Change | Effect |
|--------|--------|
| peer added | becomes known at once: accepted when it connects (or dialed, if it has an `endpoint`) |
| peer removed | its session and any pending handshake are dropped immediately; its packets are discarded and its next handshake is rejected |
| `allowed_ips` changed | applied to the live session straight away, with no re-handshake |
| `endpoint` changed | re-resolved and used for the next dial; a handshake in flight to the old address is cancelled |
| anything else in the main config | needs a restart (reload only touches peers) |

A peer file holds one peer, using the same keys as an entry of `peers:`:

```yaml
# peers.d/laptop.yaml  (the file name is the peer name)
public_key: <hex>
allowed_ips: [10.9.0.2/32]
endpoint: host:port        # optional, only for peers the relay should dial
```

Safeguards: a file that fails to parse, or a duplicate public key, makes the whole reload fail and **the previous peer set keeps running** (the error is logged). The CLI writes files atomically, never overwrites an existing key, refuses an IP that is already taken or outside the subnet, and a peer's spoke config is created with `reconnect_interval: 5` so a freshly added peer connects within seconds even if it starts before the relay has noticed it. The 64-peer limit still applies.

Verify it end to end with real TUN devices: `make dynamic-test` (relay starts empty, adds alice and bob, alice and bob ping each other through the relay, alice is removed and cut off, and the relay process is shown never to have restarted).

### Admin API (local socket)

Set **`admin_socket`** on the relay and it serves a small JSON API on a unix socket (created with mode `0600`, so only its owner and root can use it). It is the safest way to manage a relay from tools or over SSH, because the relay itself allocates addresses (no race between two admins), applies changes **immediately**, and reports **live state**:

```yaml
# /etc/microtunnel/microtunnel.yaml
admin_socket: /run/microtunnel/admin.sock   # the directory must exist (the packaged unit creates /run/microtunnel)
public_endpoint: relay.example.com:5040     # handed to new peers as the address to dial
```

The same `microtunnel peer ...` commands use it automatically when the config (`-c`, default `/etc/microtunnel/microtunnel.yaml`) names a reachable `admin_socket`, or explicitly with `-socket`:

```bash
microtunnel peer list
# NAME    ALLOWED IPS   STATE      ADDRESS            LAST SEEN  RX     TX     SOURCE
# laptop  10.9.0.2/32   connected  198.51.100.7:40000 now        1.2MiB 3.4MiB peers_dir
# phone   10.9.0.3/32   offline    -                  -          0B     0B     peers_dir

microtunnel peer add laptop -generate -key-dir ./laptop   # key made locally; only the public half is sent
```

**Managing a remote relay:** forward the socket over SSH and point the CLI at it; no extra port is opened and SSH is the authentication:

```bash
ssh -N -L /tmp/mt.sock:/run/microtunnel/admin.sock relay.example.com &
microtunnel peer list -socket /tmp/mt.sock
microtunnel peer add laptop -socket /tmp/mt.sock -public-key <hex>
```

Endpoints (JSON; for scripts): `GET /v1/status`, `GET /v1/peers`, `POST /v1/peers` (`{"name","public_key","ip","subnet","endpoint"}` → the registration), `DELETE /v1/peers/{name}`; errors are `{"error": "..."}` with 400 / 404 / 409 for bad requests, unknown peers and clashes.

Notes: the socket must live on a local filesystem that supports `chmod` (a host directory bind-mounted into a container on Docker Desktop for Mac does not; use a container-local path). Anyone who can open the socket can add a peer, which means network access, so never expose it, for example by proxying it to a TCP port.

### Enrollment service (self-service join)

For many devices, run the enrollment service next to the relay. An admin creates a **single-use, short-lived join token**; the new machine presents it with its **own public key** and gets back everything it needs. The private key is generated on that machine and never travels.

```bash
# On the relay host (the service talks to the relay's admin socket):
microtunnel enroll serve -tokens /var/lib/microtunnel/tokens \
  -tls-cert /etc/microtunnel/enroll.crt -tls-key /etc/microtunnel/enroll.key      # listens on :8443

microtunnel enroll token create -tokens /var/lib/microtunnel/tokens -name laptop -ttl 1h \
  -url https://enroll.example.com
#   Join token (shown once; valid until ..., single use):  mt1.3f9a....
#   On the new machine:  microtunnel join https://enroll.example.com -token mt1.3f9a....

# On the new machine:
microtunnel join https://enroll.example.com -token mt1.3f9a....
#   Enrolled as "laptop" with overlay address 10.9.0.2
#   -> writes laptop.key (0600), laptop.crt and laptop.yaml; then: sudo systemctl enable --now microtunnel@laptop
```

`microtunnel enroll token list|revoke <id>` manage tokens. Properties:

| | |
|---|---|
| **Token** | random secret; only its SHA-256 is stored (one file per token, directory mode `0700`); `mt1.<id>.<secret>` |
| **Single use** | redeeming is one atomic file rename, so concurrent or repeated use can succeed only once. If registering with the relay fails (name taken, relay down) the token is put back, not burned |
| **Short-lived** | default 1 hour, maximum 7 days; optionally bound to one peer name |
| **Transport** | HTTPS required (`-tls-cert/-tls-key`); `-insecure-http` exists for use behind a TLS-terminating proxy. `join` verifies the certificate (`-ca-file` for a private CA), refuses plain `http://` without `-allow-http`, and never follows redirects, so the token cannot be sent elsewhere |
| **Abuse** | all token failures return the same 401 (no oracle); 10 failures a minute per client address, then 429; request bodies are size-limited; the response carries the pre-shared key and is marked `no-store` |
| **Blast radius** | the service holds no relay keys; it can only call the relay's admin API, and if it is down existing tunnels and the CLI are unaffected |

The pre-shared key is handed to each enrolled machine (as it is today when you copy a config), so protect the tokens and the enrollment endpoint accordingly. `MICROTUNNEL_JOIN_TOKEN` can supply the token to `join` instead of `-token`, keeping it out of shell history.

Verify it all with real TUN devices: `make enroll-test`.

---

## Running With Docker

The easiest way to try it on one machine: a relay and two peers in containers, each with its own network namespace. Build the image once, then start each container in its own terminal:

```bash
make image
./scripts/run-relay-in-docker.sh
./scripts/run-peer-1-in-docker.sh
./scripts/run-peer-2-in-docker.sh
```

Then test the tunnel:

```bash
./scripts/test-tunnel-using-peer-1.sh       # ping + curl peer-2 from peer-1
curl http://localhost:15052                 # peer-1's Envoy HTTP proxy -> tunnel -> peer-2's nginx
```

`./scripts/test-tunnel-using-peer-2.sh` and `./scripts/test-tunnel-relay.sh` check the other directions. A multi-arch image (amd64 and arm64) is published as `jecklgamis/microtunnel`. Ports, the Envoy proxy and the container environment variables are in [docs/docker.md](docs/docker.md).

## Development

```bash
make test               # unit + in-process end-to-end tests, natively (no root, TUN device or Docker needed)
make test-race          # same, with the race detector
make check              # gofmt check + go vet (macOS and Linux) + race tests
make test-using-docker  # run the race-detector suite on Linux in a golang container
make integration-test   # full test with real TUN devices: relay + 2 peers in Docker, ping + curl
make dynamic-test       # real-TUN test of `peers_dir` + `microtunnel peer add/remove` against a running relay
make enroll-test        # real-TUN test of the admin socket + enrollment service (`peer add -socket`, `enroll`, `join`)
make init-test          # real-TUN test of `init relay` / `init peer` (relay + two peers set up with one command each)
make build              # build ./microtunnel for the machine you're on (current OS and architecture)
make linux              # static Linux binaries (amd64 + arm64) into build/
make macos              # macOS binaries (arm64 + amd64) into build/
make image              # build the Docker image (microtunnel-peer:latest)
make deb | make rpm     # build packages (DEB_ARCH=amd64|arm64, RPM_ARCH=x86_64|aarch64)
```

Layout:

| Path | Contents |
|------|----------|
| `cmd/microtunnel` | `main`: flags, config loading, signal handling, wiring; `init`, `peer add/remove/list`, `keygen`, `enroll` and `join` subcommands |
| `internal/proto` | wire protocol: AES-256-GCM data packets, X25519 handshake with identity hiding, session-key derivation, 2048-bit replay window |
| `internal/config` | YAML config parsing/validation, CIDR parsing, `peers_dir` loading |
| `internal/admin` | the logic behind `microtunnel peer add/remove/list`: IP allocation, peer files, spoke-config generation |
| `internal/setup` | `microtunnel init relay/peer`: generate keys and write complete, validated configs |
| `internal/adminapi` | the relay's unix-socket JSON API and its client |
| `internal/enroll` | enrollment service: single-use token store, HTTPS server, `join` client |
| `internal/peer` | session table, AllowedIPs routing, worker goroutines, handshake state machine, housekeeping (rekey/expiry/keepalive), live peer reload (`reload.go`, `watch.go`) |
| `internal/tun` | TUN devices: Linux `/dev/net/tun`, macOS `utun`; optional interface address/route setup |
| `internal/logx` | timestamped logger |

The `peer` tests run complete relay/peer topologies inside one process over loopback UDP with in-memory TUN devices, so rekeying, expiry, roaming and spoofing are all exercised without privileges.

## References
* https://www.kernel.org/doc/Documentation/networking/tuntap.txt
* https://www.wireguard.com/papers/wireguard.pdf
