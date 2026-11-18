## microtunnel

Minimal WireGuard-inspired overlay network: TUN + UDP + X25519/AES-GCM, with a relay for peers behind NAT.

[![build](https://github.com/jecklgamis/microtunnel/actions/workflows/build.yaml/badge.svg)](https://github.com/jecklgamis/microtunnel/actions/workflows/build.yaml)

📖 [User Guide](https://jecklgamis.github.io/microtunnel/)

> [!WARNING]
> **Alpha software.** microtunnel is in an early alpha state: the configuration format, CLI and wire protocol may still change. Don't rely on it to protect sensitive traffic or for production workloads. See [Limitations](#limitations) and [docs/security.md](docs/security.md).

A small, self-hosted **hub-and-spoke layer 3 VPN** for Linux and macOS. Machines behind NAT dial out to a relay with a public IP, and microtunnel gives them all addresses on one private network (`10.9.0.0/24`) over encrypted UDP. One static Go binary, one YAML file, no kernel module and no control-plane service.

Inspired by [WireGuard](https://www.wireguard.com/): X25519 key exchange, identity hiding, AllowedIPs routing and automatic rekeying, reimplemented from scratch in Go. It is a port of the original C implementation (`lanecove-tunnel`) and uses the same wire protocol and configuration format.

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

Each node has a TUN interface carrying raw IP packets (layer 3, not Ethernet). Traffic from peer-1 to peer-2 travels peer-1 → relay → peer-2; the relay forwards in user space, so no kernel IP forwarding is needed. The same program is the relay or a peer, and the config decides which.

## Try it

With Docker, from a checkout of this repo:

```bash
docker compose up --build
```

It starts a relay and two peers on your machine, then pings and curls one peer from the other through the tunnel and prints `TUNNEL OK`. The peers keep running, so in another terminal you can test the tunnel yourself:

```bash
curl http://localhost:15052    # peer-1's proxy -> tunnel -> relay -> peer-2's web page
```

Stop it with Ctrl+C, then `docker compose down`. For real machines, see [Running](#running).

## Features

**Simple to run**
- **One static binary** — pure Go, no OpenSSL, libyaml or libc requirements; `linux` and `macOS`, `amd64` and `arm64`.
- **One-command setup** — `microtunnel init relay` and `init peer` generate keys and write a complete, validated config; `keygen` makes a key pair on its own.
- **Packages for every platform** — `.deb`, `.rpm`, a universal macOS `.pkg` (launchd job included), a Homebrew formula (`packaging/homebrew`), and a multi-arch Docker image (`jecklgamis/microtunnel`).
- **Real services** — systemd units (`microtunnel` and `microtunnel@<name>` for several tunnels on one machine) and a launchd job that starts only while a config exists.
- **Configures the interface for you** — set `tunnel_address` and the binary assigns the overlay address and adds the routes (Linux and macOS).

**Manage peers without restarts**
- **Live peer reload** — point the relay at a `peers_dir`; adding, removing or editing a peer takes effect within a second and never interrupts anyone else's session.
- **Peer CLI and admin API** — `microtunnel peer add|remove|list` talks to a local unix socket (mode 0600): the relay allocates overlay IPs, applies changes immediately and reports live state (connected, address, last seen, traffic).
- **Self-service enrollment** — an optional service hands out single-use, short-lived join tokens; a new machine runs `microtunnel join` and its private key never leaves it.

**Secure by design**
- **Modern crypto, standard library only** — X25519 key exchange with forward secrecy, AES-256-GCM, identity hiding (peers' keys are never visible on the wire), optional pre-shared key, and a 2048-bit replay window.
- **Per-peer AllowedIPs** — packets are routed to the matching peer, and traffic with an unexpected source address is dropped.
- **Automatic rekeying** — every few minutes, with a grace period for the old key so rekeys lose no packets.
- **Hardened handshake** — a replayed or forged handshake cannot displace a live session, and floods are dropped and rate limited before they cost anything. The service units are sandboxed.

**Dependable**
- **Multi-core** — a pool of worker goroutines encrypts and decrypts in parallel (`worker_threads`).
- **Roaming and NAT-friendly** — peers can change address or NAT mapping and keepalives hold mappings open; outbound peers reconnect on their own.
- **Compatible** — same wire protocol and config format as the original C implementation.
- **Well tested** — unit tests and complete relay/peer topologies run in-process without privileges, plus Docker end-to-end tests with real TUN devices; CI runs them all on every push.

Details on the protocol and its review are in [docs/security.md](docs/security.md).

## Common Use Cases

- **Connecting peers behind NAT** — machines that can't reach each other directly (home networks, cloud VMs, mobile) communicate through a relay with a public IP.
- **Secure service access** — a peer runs a service (a web server, a database) reachable only over the overlay IP, keeping it off the public internet.
- **Multi-site connectivity** — link servers across cloud providers or regions through a single relay, without cloud VPN products.
- **Development and testing** — expose a local dev machine's services to a remote peer (a CI runner, a colleague) without port forwarding.

The relay suits low-to-moderate traffic between a small number of peers (up to 64), not high-throughput production workloads.

## Requirements

**To run:** Linux with `iproute2` (the binary shells out to `ip` to address the TUN interface and add routes), or macOS 12+ (no extra tools; see below). The binary is a static Go executable — no OpenSSL, libyaml or libc version requirements.

**To build:** Go 1.26+ and `make`. Docker is optional (image builds, running the tests on Linux, local end-to-end testing).

```
sudo apt install iproute2 make   # plus Go 1.26+ from https://go.dev/dl/
```

## Running

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

## Managing Peers

A relay can list peers in its YAML, but editing that means a restart. Three built-in ways avoid it; each is described in full in the [User Guide](https://jecklgamis.github.io/microtunnel/).

**Dynamic peers.** Give the relay a `peers_dir` and manage it with the CLI. Changes apply within a second, and a bad file never breaks the running peer set.

```yaml
# /etc/microtunnel/microtunnel.yaml (relay)
tunnel_address: 10.9.0.1/24     # the overlay subnet peers are allocated from
peers_dir: peers.d
```

```bash
microtunnel peer add laptop -public-key <hex>   # next free overlay IP, applied live
microtunnel peer list                           # name, address, state, last seen, traffic
microtunnel peer remove laptop                  # cut off immediately
```

**Admin API.** With `admin_socket` set, the same commands use a local unix socket, so the relay allocates addresses without races and reports live state. Reach a remote relay by forwarding the socket over SSH: `ssh -N -L /tmp/mt.sock:/run/microtunnel/admin.sock relay` then `microtunnel peer list -socket /tmp/mt.sock`. Never expose the socket on a network port.

**Enrollment.** For many devices, run `microtunnel enroll serve` next to the relay (HTTPS required), create a token with `microtunnel enroll token create -name laptop -ttl 1h`, and the new machine runs `microtunnel join https://enroll.example.com -token <token>`. Tokens are single use, expire (1 hour by default, 7 days at most) and are stored only as hashes.

See [Dynamic Peers](docs/index.md#adding-peers-without-a-restart), the [Admin Socket](docs/index.md#admin-socket) and [Enrollment](docs/index.md#self-service-enrollment) for the full reference, including what a reload changes and the enrollment security properties. To also reach a network *behind* a peer, see [Routing a network behind a peer](docs/index.md#routing-a-network-behind-a-peer).

## Running With Docker

The easiest way to try it on one machine: a relay and two peers in containers, each with its own network namespace. With Docker Compose it is one command:

```bash
docker compose up --build
```

It starts the relay and both peers, waits for the tunnel, then pings and curls peer-2 from peer-1 and prints `TUNNEL OK`. The peers keep running afterwards: `curl http://localhost:15052` goes through peer-1's Envoy proxy and the tunnel to peer-2's nginx. Stop everything with `docker compose down`. It uses the public demo keys in `config/`, so it is for trying things out only.

Or build the image once and start each container yourself, one terminal each:

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

## Limitations

- **Linux and macOS** — Linux uses `/dev/net/tun`, macOS uses a `utun` device (see [Running](#macos)). Windows and BSD are not supported. The whole test suite runs natively on both, since the tests use in-memory TUN devices
- **IPv4 only** — TUN packets are validated as IPv4; IPv6 and non-IP traffic (including broadcast and multicast) are dropped
- **UDP transport** — no packet ordering guarantees; packet loss is not retransmitted
- **Single-process** — worker goroutines parallelize packet crypto across cores, but it is still one process per interface (one config, one TUN device) with no multi-host failover
- **Hub-and-spoke only** — peer-to-peer traffic always goes through the relay; there are no direct connections or NAT traversal between peers
- **Routes are static** — `tunnel_routes` are applied once at startup, and `allowed_ips` never create kernel routes, so a network behind a peer needs both (see [Routing a network behind a peer](docs/index.md#routing-a-network-behind-a-peer))
- **Alpha** — expect breaking changes; not hardened for production use

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
make all                # vet + test + build, natively
make ci                 # the full quality gate (check + every end-to-end test), as CI runs it
make e2e                # all Docker end-to-end tests
make build              # build ./microtunnel for the machine you're on (current OS and architecture)
make linux              # static Linux binaries (amd64 + arm64) into build/
make macos              # macOS binaries (arm64 + amd64) into build/
make image              # build the Docker image (microtunnel-peer:latest)
make deb | make rpm     # build packages (DEB_ARCH=amd64|arm64, RPM_ARCH=x86_64|aarch64)
make pkg                # macOS universal installer (macOS only)
make install            # build and install to /usr/local/bin
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
