# microtunnel

A small, self-hosted **hub-and-spoke layer 3 VPN** for Linux and macOS. Machines behind NAT dial out to a relay with a public IP, and microtunnel gives them all addresses on one private network (`10.9.0.0/24`) over encrypted UDP. One static Go binary, one YAML file, no kernel module and no control-plane service.

> **Alpha**: the configuration format, CLI and wire protocol may still change. Don't rely on it to protect sensitive traffic or for production workloads. See [Security](security.md).

```
                    ┌─────────────────────────┐
                    │  relay (public IP)       │
                    │  overlay: 10.9.0.1       │
                    │  UDP :5040               │
                    └────────────┬────────────┘
                                 │
            ┌────────────────────┴────────────────┐
            │ UDP (encrypted)                      │ UDP (encrypted)
┌───────────┴──────────┐              ┌────────────┴─────────┐
│  peer-1 (behind NAT) │              │  peer-2 (behind NAT) │
│  overlay: 10.9.0.2   │              │  overlay: 10.9.0.3   │
└──────────────────────┘              └──────────────────────┘
```

Each node has a TUN interface carrying raw IP packets. Traffic from peer-1 to peer-2 travels peer-1 → relay → peer-2; the relay forwards in user space. The same program is the relay or a peer, and the config decides which.

This site covers **installing and running** microtunnel. For building and testing the project itself, see the [repository README](https://github.com/jecklgamis/microtunnel#readme).

## Features

| Feature | Details |
| --- | --- |
| One static binary | Pure Go, no OpenSSL, libyaml or libc requirements. Linux and macOS, amd64 and arm64. See [Install](install.md) |
| One-command setup | `microtunnel init relay` and `init peer` generate keys and write a complete, validated config. See [Quick Start](quick-start.md) |
| Real services | systemd units (`microtunnel` and `microtunnel@<name>` for several tunnels on one machine) and a launchd job. See [Running](running.md) |
| Interface setup | Set `tunnel_address` and the binary assigns the overlay address and adds routes. See [Configuration](configuration.md) |
| Live peer reload | Point the relay at a `peers_dir`; adding or removing a peer takes effect within a second and never interrupts another session. See [Dynamic Peers](dynamic-peers.md) |
| Peer CLI and admin API | `microtunnel peer add\|remove\|list` over a local unix socket; the relay allocates overlay IPs. See [Admin Socket](admin-socket.md) |
| Self-service enrollment | Single-use, short-lived join tokens; a new machine runs `microtunnel join` and its private key never leaves it. See [Enrollment](enrollment.md) |
| Modern crypto | X25519 key exchange with forward secrecy, AES-256-GCM, identity hiding, an optional pre-shared key and replay protection. See [Security](security.md) |
| Per-peer AllowedIPs | Packets are routed to the matching peer, and traffic with an unexpected source address is dropped. See [Configuration](configuration.md#routing-a-network-behind-a-peer) |
| Automatic rekeying | Every few minutes, with a grace period for the old key, so rekeys lose no packets |
| Hardened handshake | Replayed or forged handshakes cannot displace a live session, and floods are rate limited. The service units are sandboxed |
| Roaming and NAT-friendly | Peers can change address; keepalives hold NAT mappings open; outbound peers reconnect on their own |
| Multi-core | A pool of worker goroutines encrypts and decrypts in parallel (`worker_threads`) |
| Docker demo | A relay and two peers on one machine with `docker compose up`. See [Docker](docker.md) |

## Quick Start

### 1. Try it in containers

From a checkout of the repository:

```bash
docker compose up --build
```

It starts a relay and two peers, pings and curls one peer from the other through the tunnel, and prints `TUNNEL OK`. See [Docker](docker.md).

### 2. Install on real machines

Download a package from the [releases page](https://github.com/jecklgamis/microtunnel/releases) (`.deb`, `.rpm`, or a macOS `.pkg`), then:

```bash
# on the relay (a machine with a public IP)
sudo microtunnel init relay -endpoint relay.example.com:5040 -start

# on each peer, using the line the relay printed
sudo microtunnel init peer -relay relay.example.com:5040 -relay-key <hex> -psk <secret> -start
```

The full walkthrough, including adding the peer on the relay, is in [Quick Start](quick-start.md).

### 3. Check the tunnel

```bash
ping 10.9.0.1        # from a peer: the relay's overlay address
```

More in [Verifying](verify.md).

## Where next

- **[Install](install.md)** — packages for Debian, Red Hat and macOS, and uninstalling
- **[Quick Start](quick-start.md)** — a relay and a peer in a few commands
- **[Configuration](configuration.md)** — every option, and routing a network behind a peer
- **[Dynamic Peers](dynamic-peers.md)**, **[Admin Socket](admin-socket.md)**, **[Enrollment](enrollment.md)** — manage peers without restarts
- **[Security](security.md)** — handshake, wire format and hardening
- **[CLI Reference](cli.md)** — every command and flag
