---
title: microtunnel
layout: default
---

# microtunnel

A simple Linux hub-and-spoke layer 3 overlay network using a TUN virtual interface over UDP.

```
                    ┌─────────────────────────┐
                    │  relay (public IP)       │
                    │  overlay: 10.9.0.1       │
                    │  UDP :5040               │
                    └────────────┬────────────┘
                                 │
            ┌────────────────────┴────────────────┐
            │                                      │
┌───────────┴──────────┐              ┌────────────┴─────────┐
│  peer-1 (behind NAT) │              │  peer-2 (behind NAT) │
│  overlay: 10.9.0.2   │              │  overlay: 10.9.0.3   │
└──────────────────────┘              └──────────────────────┘
```

Peers behind NAT connect outbound to a relay with a public IP. All peer-to-peer traffic transits through the relay.

---

## Installation

Download the latest release package from the [releases page](https://github.com/jecklgamis/microtunnel/releases).

Each release provides, for both **amd64/x86_64** and **arm64/aarch64**:

| Asset | Use |
|-------|-----|
| `microtunnel_<version>_<arch>.deb` | Debian / Ubuntu package (see below) |
| `microtunnel-<version>-<release>.<arch>.rpm` | Red Hat / Fedora / CentOS package (see below) |
| `microtunnel-linux-amd64`, `microtunnel-linux-arm64` | Plain static Linux binary: `chmod +x`, then run it. No packages or libraries needed |
| `microtunnel-darwin-arm64`, `microtunnel-darwin-amd64` | macOS binary (Apple silicon / Intel). Unsigned: run `xattr -d com.apple.quarantine <file>` after downloading |

A multi-architecture Docker image (linux/amd64 and linux/arm64) is published as `jecklgamis/microtunnel`.

### Debian / Ubuntu

```bash
sudo dpkg -i microtunnel_<version>_amd64.deb
```

### Red Hat / Fedora / CentOS

```bash
sudo rpm -i microtunnel-<version>-1.x86_64.rpm
```

Both packages install:

| Path | Description |
|------|-------------|
| `/usr/bin/microtunnel` | The tunnel binary |
| `/usr/bin/microtunnel-generate-peer-keys.sh` | Key pair generator |
| `/usr/bin/microtunnel-extract-keys-hex.sh` | Extract private + public key hex |
| `/usr/bin/microtunnel-extract-pubkey-hex.sh` | Extract public key hex from `.crt` |
| `/usr/share/microtunnel/microtunnel-create-tunnel.sh` | TUN interface setup helper |
| `/etc/microtunnel/relay.yaml` | Relay config template |
| `/etc/microtunnel/peer.yaml` | Generic peer config template |
| `/etc/microtunnel/peer-1.yaml` | Peer-1 config template |
| `/etc/microtunnel/peer-2.yaml` | Peer-2 config template |

---

## Key Generation

Each node (relay and every peer) needs its own X25519 key pair. Generate it **locally on that machine** — pass only that node's own name, so the private key never has to leave the machine it belongs to:

```bash
cd /etc/microtunnel && sudo microtunnel-generate-peer-keys.sh <relay|peer-1|peer-2>
```

This produces a `.key` (private) and `.crt` (public) file for that node in `/etc/microtunnel/`.

Copy only the `.crt` (public key) files between machines — **never** the `.key` files:

| Machine | `.crt` files it needs from other machines |
|---------|-------------|
| relay   | `peer-1.crt`, `peer-2.crt` |
| peer-1  | `relay.crt` |
| peer-2  | `relay.crt` |

To extract the public key hex from a `.crt` file (needed when editing configs):

```bash
microtunnel-extract-pubkey-hex.sh /etc/microtunnel/relay.crt
```

**Without `openssl`:** the `microtunnel` binary can generate keys itself. It writes `<name>.key` (private, mode 0600) and `<name>.crt`, prints the public key hex, and never overwrites existing files:

```bash
microtunnel keygen peer-3 -dir /etc/microtunnel
# wrote /etc/microtunnel/peer-3.key (private, keep secret) and /etc/microtunnel/peer-3.crt
# public key: 3f9a...
```

To add peers to a running relay without editing its YAML, see [Adding Peers Without a Restart](#adding-peers-without-a-restart).

---

## Configuration

### Relay

The relay has a public IP and accepts inbound connections from peers. It does not have an `endpoint` set — it never initiates outbound connections.

Edit `/etc/microtunnel/relay.yaml`:

```yaml
interface: microtunnel0
port: 5040
private_key_file: /etc/microtunnel/relay.key
pre_shared_key: change-me
verbose: false
keepalive_interval: 25
rekey_after: 180
reconnect_interval: 30
session_expiry: 540
prev_key_grace: 90
handshake_timeout: 5
handshake_cooldown: 5

peers:
  - public_key: <peer-1-public-key-hex>
    allowed_ips:
      - 10.9.0.2/32
  - public_key: <peer-2-public-key-hex>
    allowed_ips:
      - 10.9.0.3/32
```

- `pre_shared_key` — must match on all nodes. Used for HMAC authentication of handshakes.
- `allowed_ips` — the relay uses `/32` per peer, accepting packets only from each peer's specific overlay IP.
- No `endpoint` — the relay never initiates connections.
- All timing fields are optional; values shown are the defaults.

### Peer

Each peer connects outbound to the relay. It must know the relay's public key and address.

Edit `/etc/microtunnel/peer.yaml` (or `peer-1.yaml`, `peer-2.yaml`):

```yaml
interface: microtunnel0
port: 5040
private_key_file: /etc/microtunnel/peer-1.key
pre_shared_key: change-me
verbose: false
keepalive_interval: 25
rekey_after: 180
reconnect_interval: 30
session_expiry: 540
prev_key_grace: 90
handshake_timeout: 5
handshake_cooldown: 5

peers:
  - public_key: <relay-public-key-hex>
    endpoint: <relay-host-or-ip>:5040
    allowed_ips:
      - 10.9.0.0/24
```

- `endpoint` — the relay's public hostname or IP and UDP port. Required on peers; omit on the relay.
- `allowed_ips` — peers use `/24` (the full overlay subnet) so all overlay traffic is routed through the relay.
- `pre_shared_key` — must match the relay and all other peers.
- All timing fields are optional; values shown are the defaults.

### Config Reference

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `interface` | Yes | — | TUN interface name |
| `port` | Yes | — | UDP port to bind |
| `address` | No | `0.0.0.0` | Local IP address to bind the UDP socket to |
| `private_key_file` | Yes | — | Path to this node's X25519 private key PEM file |
| `pre_shared_key` | No | — | PSK for HMAC handshake authentication |
| `verbose` | No | `false` | `true` to enable debug logging |
| `keepalive_interval` | No | `25` | Seconds between keepalive packets |
| `rekey_after` | No | `180` | Seconds before initiating a rekey |
| `reconnect_interval` | No | `30` | Seconds between reconnect attempts to outbound peers |
| `session_expiry` | No | `540` | Seconds before an idle session is considered expired |
| `prev_key_grace` | No | `90` | Seconds the old session key is retained after rekeying |
| `handshake_timeout` | No | `5` | Seconds before a pending handshake is abandoned |
| `handshake_cooldown` | No | `5` | Seconds between handshake attempts to the same peer |
| `worker_threads` | No | `min(4, nproc)` | Packet-processing worker threads |
| `tunnel_address` | No | — | This node's overlay IP with prefix (e.g. `10.9.0.2/24`). When set, `microtunnel` configures the interface itself (address, link up, route) instead of you running `microtunnel-create-tunnel.sh` |
| `tunnel_routes` | No | — | Extra CIDRs to route through the tunnel (requires `tunnel_address`) |
| `admin_socket` | No | — | Path of a unix socket (mode 0600) on which the relay serves its admin API: manage peers and read live state. See [Admin Socket](#admin-socket). The directory must exist; the packaged relay service creates `/run/microtunnel` |
| `public_endpoint` | No | — | The relay's public `host:port`, handed to newly registered peers as the address to dial |
| `peers_dir` | No | — | Directory of one-peer-per-file YAML, reloaded live. Relative paths are resolved against the config file's directory. Makes `peers:` optional. See [Adding Peers Without a Restart](#adding-peers-without-a-restart) |
| `peers[].public_key` | Yes | — | Peer's public key (hex) |
| `peers[].endpoint` | No | — | `host:port` to connect to; omit for inbound-only nodes |
| `peers[].allowed_ips` | Yes | — | CIDRs allowed from this peer |

A config needs at least one peer, either under `peers:` or as a file in `peers_dir`. The same public key may not appear twice.

---

## Adding Peers Without a Restart

Editing `peers:` in the relay's YAML and restarting drops every session. Instead, keep peers in a directory and manage them with the `microtunnel` command. The running relay notices changes within a second or two, and **other peers' sessions are never interrupted**.

### One-time relay setup

```bash
sudo mkdir -p /etc/microtunnel/peers.d
```

Add one line to `/etc/microtunnel/relay.yaml` (you can keep any peers already listed under `peers:`) and restart the relay once:

```yaml
peers_dir: /etc/microtunnel/peers.d
```

```bash
sudo systemctl restart microtunnel-relay
```

### Add a peer

The recommended flow keeps each peer's private key on its own machine.

**1. On the new machine**, generate a key pair and note the public key:

```bash
microtunnel keygen laptop -dir /etc/microtunnel
# public key: 3f9a...
```

**2. On the relay**, register it. `-subnet` is the overlay network the address is allocated from (the relay itself is the first address, `10.9.0.1`), and `-endpoint` is the relay's public address, which goes into the config printed for the new peer:

```bash
sudo microtunnel peer add laptop -c /etc/microtunnel/relay.yaml \
  -public-key 3f9a... -subnet 10.9.0.0/24 -endpoint relay.example.com:5040
```

```
Added peer "laptop": 10.9.0.2/32 (public key 3f9a...)
  wrote /etc/microtunnel/peers.d/laptop.yaml
  a running relay loads it within a second or two

Config for laptop:

# microtunnel config for laptop, generated by `microtunnel peer add`.
interface: microtunnel0   # on macOS use: interface: utun
private_key_file: laptop.key     # path to the private key whose public half you registered
pre_shared_key: change-me
tunnel_address: 10.9.0.2/24
reconnect_interval: 5
peers:
  - public_key: <relay public key>
    endpoint: relay.example.com:5040
    allowed_ips:
      - 10.9.0.0/24
```

**3. On the new machine**, save that printed config as `/etc/microtunnel/peer.yaml`, point `private_key_file` at the real key path (e.g. `/etc/microtunnel/laptop.key`), and start it:

```bash
sudo systemctl enable --now microtunnel-peer
```

The printed config includes `tunnel_address`, so `microtunnel` assigns the overlay IP and brings the interface up itself. **Skip** the [Create the TUN Interface](#create-the-tun-interface) step for such a peer; doing both would try to assign the address twice.

### Let the relay create the keys instead

If you would rather create everything on the relay and copy it over (the private key then exists on the relay until you delete it):

```bash
sudo microtunnel peer add phone -c /etc/microtunnel/relay.yaml -subnet 10.9.0.0/24 \
  -endpoint relay.example.com:5040 -generate -key-dir /root/phone
# creates /root/phone/phone.key, phone.crt and phone.yaml (mode 0600; it contains the PSK)
```

Copy `phone.key` and `phone.yaml` to the new machine over a secure channel, then delete them from the relay.

### List and remove peers

```bash
sudo microtunnel peer list   -c /etc/microtunnel/relay.yaml
sudo microtunnel peer remove laptop -c /etc/microtunnel/relay.yaml
```

Removing a peer cuts it off immediately: its session is dropped, its packets are discarded and its next handshake is rejected. Peers listed inline under `peers:` appear in `peer list` as source `config` and can only be removed by editing the YAML.

### What reloads, and what does not

| Change | Effect |
|--------|--------|
| Peer added | Accepted when it connects (or dialed, if its file has an `endpoint`) |
| Peer removed | Session and pending handshake dropped at once |
| `allowed_ips` edited in a peer file | Applied to the live session with no re-handshake |
| `endpoint` edited | Used for the next dial |
| Anything else in `relay.yaml` | Needs a restart |

You can also edit files in `peers.d/` by hand (one peer per file; the file name is the peer name):

```yaml
# /etc/microtunnel/peers.d/laptop.yaml
public_key: <hex>
allowed_ips: [10.9.0.2/32]
endpoint: host:port        # optional, only for peers the relay should dial
```

To force a reload, send `SIGHUP`: `sudo systemctl kill -s HUP microtunnel-relay`.

### If something goes wrong

- **A reload failed** (for example a half-edited or invalid file): the relay logs `Peer reload failed, keeping current peers` and keeps running with the previous peer set. Fix the file and it is picked up automatically. Check with `journalctl -u microtunnel-relay`.
- **`peer add` says the address is taken or outside the subnet:** pick another with `-ip 10.9.0.20`, or check `peer list`.
- **`has no peers_dir`:** the config passed to `-c` has no `peers_dir` line.
- **`cannot tell which subnet to allocate from`:** pass `-subnet`, or set `tunnel_address` in `relay.yaml`.
- Run `peer add` one at a time. Two started at the same instant could choose the same free address.

## Admin Socket

With **`admin_socket`** set, the relay serves a small API on a unix socket that only root (or the socket's owner) can open. Compared with editing `peers_dir`, the relay itself picks the IP (so two admins cannot collide), applies changes **immediately** instead of within a second or two, and can report **live state**.

Add to `/etc/microtunnel/relay.yaml` and restart the relay once (the packaged `microtunnel-relay` service creates `/run/microtunnel` for it):

```yaml
admin_socket: /run/microtunnel/admin.sock
public_endpoint: relay.example.com:5040     # the address peers should dial; goes into generated peer configs
```

After that, the same commands as before use the socket automatically (they find it through `-c`):

```bash
sudo microtunnel peer list -c /etc/microtunnel/relay.yaml
```
```
NAME    ALLOWED IPS   STATE      ADDRESS             LAST SEEN  RX      TX      SOURCE
laptop  10.9.0.2/32   connected  198.51.100.7:40000  now        1.2MiB  3.4MiB  peers_dir
phone   10.9.0.3/32   offline    -                   -          0B      0B      peers_dir
```

```bash
# the subnet comes from tunnel_address if set; otherwise pass -subnet 10.9.0.0/24
sudo microtunnel peer add laptop -c /etc/microtunnel/relay.yaml -subnet 10.9.0.0/24 -public-key <hex>
sudo microtunnel peer add phone  -c /etc/microtunnel/relay.yaml -subnet 10.9.0.0/24 -generate -key-dir /root/phone
sudo microtunnel peer remove laptop -c /etc/microtunnel/relay.yaml
```

With `-generate` the key pair is created on the machine where you run the command and **only the public key is sent to the relay**.

### Managing a remote relay

Do not expose the socket. Forward it over SSH instead; SSH provides the authentication and encryption, and no extra port is opened:

```bash
ssh -N -L /tmp/mt.sock:/run/microtunnel/admin.sock admin@relay.example.com &
microtunnel peer list -socket /tmp/mt.sock
microtunnel peer add laptop -socket /tmp/mt.sock -public-key <hex>
```

Anyone who can open the socket can add a peer, which grants network access, so keep its permissions as they are and never proxy it to a TCP port. The socket must be on a local filesystem (not a network or container bind mount that cannot `chmod` sockets).

---

## Self-Service Enrollment

For many devices, run the **enrollment service** next to the relay. An admin creates a one-time **join token**; the new machine runs one command with it. The machine generates its own key, so its private key never leaves it, and receives its overlay IP, the relay's key and address, and the pre-shared key.

It needs the [admin socket](#admin-socket) enabled and a TLS certificate for the service (the `join` command checks it).

### Run the service

```bash
sudo microtunnel enroll serve -c /etc/microtunnel/relay.yaml \
  -tokens /var/lib/microtunnel/tokens \
  -tls-cert /etc/microtunnel/enroll.crt -tls-key /etc/microtunnel/enroll.key
```

It listens on `:8443` (change with `-listen`). To keep it running, add a unit such as `/etc/systemd/system/microtunnel-enroll.service`:

```ini
[Unit]
Description=Microtunnel - enrollment service
After=microtunnel-relay.service
Requires=microtunnel-relay.service

[Service]
ExecStart=/usr/bin/microtunnel enroll serve -c /etc/microtunnel/relay.yaml -tokens /var/lib/microtunnel/tokens -tls-cert /etc/microtunnel/enroll.crt -tls-key /etc/microtunnel/enroll.key
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Open TCP 8443 in your [firewall](#firewall). If TLS is terminated by a reverse proxy in front, run the service with `-insecure-http` and bind it to localhost (`-listen 127.0.0.1:8443`); never expose plain HTTP to the internet, because the response carries the pre-shared key.

### Enroll a machine

```bash
# On the relay: make a token (shown once; single use; valid 1 hour unless -ttl says otherwise)
sudo microtunnel enroll token create -tokens /var/lib/microtunnel/tokens -name laptop -url https://enroll.example.com
#   Join token: mt1.3f9a....
#   On the new machine:  microtunnel join https://enroll.example.com -token mt1.3f9a....

# On the new machine:
sudo microtunnel join https://enroll.example.com -token mt1.3f9a.... -dir /etc/microtunnel
#   Enrolled as "laptop" with overlay address 10.9.0.2
sudo microtunnel -c /etc/microtunnel/laptop.yaml
```

- `-name laptop` on `token create` fixes the machine's name; omit it and the machine passes `-name` to `join` itself.
- If the service uses a private CA, give `join` `-ca-file ca.pem`. Plain `http://` URLs are refused unless you pass `-allow-http`.
- `MICROTUNNEL_JOIN_TOKEN` can carry the token instead of `-token`, keeping it out of shell history.
- `join` writes `<name>.key` (0600), `<name>.crt` and `<name>.yaml` (0600, it contains the pre-shared key) and refuses to overwrite existing files. On macOS the config uses `interface: utun`.

### Manage tokens

```bash
sudo microtunnel enroll token list   -tokens /var/lib/microtunnel/tokens
sudo microtunnel enroll token revoke 3f9a1c0d5e7b2a44 -tokens /var/lib/microtunnel/tokens
```

`list` shows each token's state (`pending`, `used`, `expired`, or `in progress`) and never prints secrets. Tokens expire after 1 hour by default (maximum 7 days), work once, and only a hash of the secret is stored.

### Notes

- If registering fails for a reason that is not the token's fault (the name is taken, the relay is unreachable), the token is **not** burned and can be retried.
- After 10 failed token attempts a minute from one address the service answers 429. A wrong, expired and used token all return the same 401. Behind a reverse proxy the service sees only the proxy's address, so the limit then applies to all clients together; rate-limit per client at the proxy as well.
- If the enrollment service is down, existing tunnels and the CLI keep working; only new self-service enrollments fail.
- To remove an enrolled machine use `microtunnel peer remove <name>`.

---

## Create the TUN Interface

Installing the package does **not** create the TUN interface — `microtunnel` opens `microtunnel0` at startup but does not assign it an IP or bring it up. Create it manually before starting the service, using the appropriate overlay IP for this node's role:

```bash
sudo microtunnel-create-tunnel.sh microtunnel0 10.9.0.1/24                    # relay
sudo microtunnel-create-tunnel.sh microtunnel0 10.9.0.2/24 10.9.0.0/24        # peer-1
sudo microtunnel-create-tunnel.sh microtunnel0 10.9.0.3/24 10.9.0.0/24        # peer-2
```

---

## Running as a Service

### Relay

```bash
sudo systemctl enable --now microtunnel-relay
```

### Peer

```bash
# Generic peer (uses /etc/microtunnel/peer.yaml)
sudo systemctl enable --now microtunnel-peer

# Named peers
sudo systemctl enable --now microtunnel-peer-1
sudo systemctl enable --now microtunnel-peer-2
```

Only enable the service that matches this machine's role. Running more than one service on the same machine will conflict on the `microtunnel0` TUN interface and UDP port.

### Stop / Restart

```bash
sudo systemctl restart microtunnel-relay
sudo systemctl restart microtunnel-peer
sudo systemctl stop microtunnel-peer-1
```

### View Logs

```bash
sudo journalctl -u microtunnel-relay -f
sudo journalctl -u microtunnel-peer -f
```

---

## Firewall

The relay must allow inbound UDP on port 5040:

```bash
# ufw
sudo ufw allow 5040/udp

# firewalld
sudo firewall-cmd --permanent --add-port=5040/udp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p udp --dport 5040 -j ACCEPT
```

Peers behind NAT do not need any inbound firewall rules — they connect outbound only.

---

## Verifying the Tunnel

Once relay and peers are running, verify connectivity using overlay IPs:

```bash
# From peer-1, ping the relay and peer-2
ping 10.9.0.1
ping 10.9.0.3

# From the relay, ping both peers
ping 10.9.0.2
ping 10.9.0.3
```

---

## Uninstalling

### Debian / Ubuntu

```bash
sudo dpkg -r microtunnel
```

### Red Hat / Fedora / CentOS

```bash
sudo rpm -e microtunnel
```

Configs in `/etc/microtunnel/` and keys are preserved on uninstall.
