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

See also: [Security](security) (handshake, wire format, review notes) and [Comparison](comparison) with WireGuard, OpenVPN and others. For a local demo in containers see the [Docker demo](docker).

---

## Installation

Download the latest release package from the [releases page](https://github.com/jecklgamis/microtunnel/releases).

Each release provides, for both **amd64/x86_64** and **arm64/aarch64**:

| Asset | Use |
|-------|-----|
| `microtunnel_<version>_<arch>.deb` | Debian / Ubuntu package (see below) |
| `microtunnel-<version>-<release>.<arch>.rpm` | Red Hat / Fedora / CentOS package (see below) |
| `microtunnel-linux-amd64`, `microtunnel-linux-arm64` | Plain static Linux binary: `chmod +x`, then run it. No packages or libraries needed |
| `microtunnel-<version>-universal.pkg` | macOS installer (Apple silicon and Intel), see [macOS](#macos). Unsigned for now |
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

### macOS

Open `microtunnel-<version>-universal.pkg` (it is not signed yet, so right-click it and choose Open, or run `sudo installer -pkg <file> -target /`). It installs:

| Path | Description |
|------|-------------|
| `/usr/local/bin/microtunnel` | The tunnel binary (universal: arm64 + amd64) |
| `/Library/LaunchDaemons/io.github.jecklgamis.microtunnel.plist` | The service: runs `/etc/microtunnel/microtunnel.yaml` as root while that file exists |
| `/etc/microtunnel/peers.d/` | Empty directory for the relay's peer files |
| `/usr/local/share/microtunnel/examples/`, `uninstall.sh` | Sample configs; uninstaller |

Nothing is started and no config or keys are installed. Configure with `sudo microtunnel init ...` as in [Quick Start](#quick-start), but start the service with `sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.jecklgamis.microtunnel.plist` (or pass `--start` to `init`, which loads it for you) instead of `systemctl`. Logs are in `/var/log/microtunnel.log`; stop it with `sudo launchctl bootout system/io.github.jecklgamis.microtunnel`. A named instance (`--name home`) gets its own job, `io.github.jecklgamis.microtunnel.home`. The admin socket is `/var/run/microtunnel/admin.sock`.

Uninstall: `sudo /usr/local/share/microtunnel/uninstall.sh` (`--purge` also deletes `/etc/microtunnel`).

**Homebrew:** `packaging/homebrew/microtunnel.rb` is a formula that builds from source (copy it into a tap as `Formula/microtunnel.rb`). After `brew install`, run `sudo microtunnel init ...` as above and use `sudo brew services start microtunnel` instead of `launchctl`.

Both packages install:

| Path | Description |
|------|-------------|
| `/usr/bin/microtunnel` | The tunnel binary |
| `/usr/bin/microtunnel-create-tunnel.sh` | TUN interface setup helper (only needed if your config has no `tunnel_address`) |
| `/usr/share/microtunnel/examples/relay.yaml`, `peer.yaml` | Annotated sample configs (`microtunnel init` writes a finished one for you) |
| `/lib/systemd/system/microtunnel.service` | The service: runs `/etc/microtunnel/microtunnel.yaml` (a relay or a peer: the config decides) |
| `/lib/systemd/system/microtunnel@.service` | Template for extra instances: `microtunnel@home` runs `/etc/microtunnel/home.yaml` |
| `/etc/microtunnel/peers.d/` | Empty directory for the relay's peer files |

The package installs **no config and no keys**: run `microtunnel init` (see [Quick Start](#quick-start)).

---

## Quick Start

After installing the package, a relay and a peer each need one command. `microtunnel init` generates the machine's key (an existing key is reused, never replaced), a strong random pre-shared key where needed, and writes a complete, validated config. It never overwrites an existing config unless you pass `-force`.

**On the relay:**

```bash
sudo microtunnel init relay --endpoint relay.example.com:5040
sudo systemctl enable --now microtunnel
```

`init relay` prints the relay's public key and a ready-to-use line for the peers. (`--start` runs the `systemctl` step for you.) Open UDP 5040 in your [firewall](#firewall).

**On each peer**, using the line the relay printed. It contains the pre-shared key, so pass it over a secure channel; it is given through an environment variable so it never appears in the process list:

```bash
MICROTUNNEL_PSK=<printed by init relay> sudo -E microtunnel init peer \
  --relay relay.example.com:5040 --relay-key <relay public key>
#   public key:  d3eb...
```

Then register that public key on the relay and apply the address it assigns:

```bash
# on the relay
sudo microtunnel peer add laptop -public-key d3eb...        # prints: laptop: 10.9.0.2/32

# on the peer: apply the address (your key is kept), then start it
MICROTUNNEL_PSK=<same> sudo -E microtunnel init peer --relay relay.example.com:5040 --relay-key <key> \
  --address 10.9.0.2/24 --force
sudo systemctl enable --now microtunnel
```

For several machines, [self-service enrollment](#self-service-enrollment) is shorter: one `microtunnel join https://... -token ...` on each new machine does all of this. The same unit runs a relay or a peer, because the config decides the role. `init` and `join` write `microtunnel.yaml` by default; with `--name home` (or a `join` token named `home`) they write `home.yaml`, which runs as `systemctl enable --now microtunnel@home`.

`init relay` options: `--address` (overlay address, default `10.9.0.1/24`), `--port`, `--admin-socket` (`none` turns the API off), `--dir`. `init peer` options: `--name`, `--psk-file` (instead of the environment variable), `--subnet`, `--dir`. See `microtunnel init help`.

---

## Key Generation

Each node (relay and every peer) needs its own X25519 key pair, generated **locally on that machine** so the private key never leaves it. `microtunnel init` does this for you; to do it by hand:

```bash
sudo microtunnel keygen microtunnel -dir /etc/microtunnel      # writes microtunnel.key (private) and microtunnel.crt (public)
```

Exchange only **public keys** between machines, never the `.key` files: the relay needs each peer's public key, and each peer needs the relay's. `keygen` and `init` print the public key hex, and the daemon logs it at startup (`journalctl -u microtunnel | grep "public key"`). `keygen` writes `<name>.key` (private, mode 0600) and `<name>.crt`, and never overwrites existing files. No `openssl` is needed.

```bash
microtunnel keygen peer-3 -dir /etc/microtunnel
# wrote /etc/microtunnel/peer-3.key (private, keep secret) and /etc/microtunnel/peer-3.crt
# public key: 3f9a...
```

To add peers to a running relay without editing its YAML, see [Adding Peers Without a Restart](#adding-peers-without-a-restart).

---

## Configuration

> **The package ships no config.** `microtunnel init` writes a finished one ([Quick Start](#quick-start)); the sample configs in `/usr/share/microtunnel/examples/` contain `<placeholders>` and **no keys or secrets**, so a copy of one refuses to run until you fill it in. To do it by hand, create keys with `microtunnel keygen`, set your own long random `pre_shared_key`, and fill in the public keys and endpoint as shown below.
>
> The repository's demo keys and the pre-shared keys `some-psk` / `change-me` are public. `microtunnel` logs a warning at startup if it finds any of them in use; never rely on them for a real network.

### Relay

The relay has a public IP and accepts inbound connections from peers. It does not have an `endpoint` set — it never initiates outbound connections.

Edit `/etc/microtunnel/microtunnel.yaml`:

```yaml
interface: microtunnel0
port: 5040
private_key_file: /etc/microtunnel/microtunnel.key
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

Edit `/etc/microtunnel/microtunnel.yaml`:

```yaml
interface: microtunnel0
port: 5040
private_key_file: /etc/microtunnel/microtunnel.key
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

### Routing a network behind a peer

Two separate settings decide where a packet goes:

| | `tunnel_routes` | `allowed_ips` |
|---|---|---|
| Question | Should the OS send this into the tunnel? | Which peer gets it, and is the source allowed? |
| Where | The node's own config | Each peer entry |
| Layer | OS routing table | microtunnel's own lookup and filter |
| Changes | Applied at startup; restart to change | Live (`peer add`, `peers.d`) |

The overlay subnet (from `tunnel_address`) is routed automatically, so overlay-to-overlay traffic needs only `allowed_ips`. To reach a network that sits *behind* a peer, list it in **both** places. Example: peer-1 fronts a LAN `192.168.50.0/24`, and you want to reach it from peer-2.

```yaml
# peer-2: send the LAN into the tunnel
tunnel_address: 10.9.0.3/24
tunnel_routes: [192.168.50.0/24]
peers:
  - public_key: <relay-public-key>
    endpoint: relay.example.com:5040
    allowed_ips: [10.9.0.0/24, 192.168.50.0/24]   # accept replies from the LAN via the relay

# relay: forward the LAN to peer-1 (peers.d/peer-1.yaml)
allowed_ips: [10.9.0.2/32, 192.168.50.0/24]
```

Peer-1 itself needs IP forwarding enabled and a way back (a route on the LAN, or NAT). Notes:

- `allowed_ips` never creates kernel routes, and routes are not added when a peer is added later. Add the CIDR to `tunnel_routes` and restart, or run `ip route add <cidr> dev <interface>` by hand.
- WireGuard works the same way internally, but `wg-quick` derives its routes from `AllowedIPs` when the interface comes up, so there is one list instead of two.
- Do not route `0.0.0.0/0`: it would also capture the packets to the relay and loop.

---

## Adding Peers Without a Restart

Editing `peers:` in the relay's YAML and restarting drops every session. Instead, keep peers in a directory and manage them with the `microtunnel` command. The running relay notices changes within a second or two, and **other peers' sessions are never interrupted**.

### Relay setup

`microtunnel init relay` already sets this up: it creates `/etc/microtunnel/peers.d` and writes `peers_dir: /etc/microtunnel/peers.d` into the config, so there is nothing more to do: start the relay and add peers.

If your relay config is written by hand, create the directory and add one line, then restart the relay once. Any peers already listed under `peers:` keep working:

```bash
sudo mkdir -p /etc/microtunnel/peers.d
```

```yaml
peers_dir: /etc/microtunnel/peers.d
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
sudo microtunnel peer add laptop \
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

**3. On the new machine**, save that printed config as `/etc/microtunnel/microtunnel.yaml`, point `private_key_file` at the real key path (e.g. `/etc/microtunnel/laptop.key`), and start it:

```bash
sudo systemctl enable --now microtunnel
```

The printed config includes `tunnel_address`, so `microtunnel` assigns the overlay IP and brings the interface up itself. **Skip** the [Create the TUN Interface](#create-the-tun-interface) step for such a peer; doing both would try to assign the address twice.

### Let the relay create the keys instead

If you would rather create everything on the relay and copy it over (the private key then exists on the relay until you delete it):

```bash
sudo microtunnel peer add phone -subnet 10.9.0.0/24 \
  -endpoint relay.example.com:5040 -generate -key-dir /root/phone
# creates /root/phone/phone.key, phone.crt and phone.yaml (mode 0600; it contains the PSK)
```

Copy `phone.key` and `phone.yaml` to the new machine over a secure channel, then delete them from the relay.

### List and remove peers

```bash
sudo microtunnel peer list  
sudo microtunnel peer remove laptop
```

Removing a peer cuts it off immediately: its session is dropped, its packets are discarded and its next handshake is rejected. Peers listed inline under `peers:` appear in `peer list` as source `config` and can only be removed by editing the YAML.

### What reloads, and what does not

| Change | Effect |
|--------|--------|
| Peer added | Accepted when it connects (or dialed, if its file has an `endpoint`) |
| Peer removed | Session and pending handshake dropped at once |
| `allowed_ips` edited in a peer file | Applied to the live session with no re-handshake |
| `endpoint` edited | Used for the next dial |
| Anything else in `microtunnel.yaml` | Needs a restart |

You can also edit files in `peers.d/` by hand (one peer per file; the file name is the peer name):

```yaml
# /etc/microtunnel/peers.d/laptop.yaml
public_key: <hex>
allowed_ips: [10.9.0.2/32]
endpoint: host:port        # optional, only for peers the relay should dial
```

To force a reload, send `SIGHUP`: `sudo systemctl kill -s HUP microtunnel`.

### If something goes wrong

- **A reload failed** (for example a half-edited or invalid file): the relay logs `Peer reload failed, keeping current peers` and keeps running with the previous peer set. Fix the file and it is picked up automatically. Check with `journalctl -u microtunnel`.
- **`peer add` says the address is taken or outside the subnet:** pick another with `-ip 10.9.0.20`, or check `peer list`.
- **`has no peers_dir`:** the config passed to `-c` has no `peers_dir` line.
- **`cannot tell which subnet to allocate from`:** pass `-subnet`, or set `tunnel_address` in `microtunnel.yaml`.
- Run `peer add` one at a time. Two started at the same instant could choose the same free address.

## Admin Socket

With **`admin_socket`** set, the relay serves a small API on a unix socket that only root (or the socket's owner) can open. Compared with editing `peers_dir`, the relay itself picks the IP (so two admins cannot collide), applies changes **immediately** instead of within a second or two, and can report **live state**.

`microtunnel init relay` **already enables it** (`admin_socket: /run/microtunnel/admin.sock`), and the `microtunnel` service creates `/run/microtunnel` for it, so there is nothing to do. For a hand-written config, add this and restart the relay once:

```yaml
admin_socket: /run/microtunnel/admin.sock
public_endpoint: relay.example.com:5040     # the address peers should dial; goes into generated peer configs
```

After that, the same commands as before use the socket automatically (they find it through `-c`):

```bash
sudo microtunnel peer list
```
```
NAME    ALLOWED IPS   STATE      ADDRESS             LAST SEEN  RX      TX      SOURCE
laptop  10.9.0.2/32   connected  198.51.100.7:40000  now        1.2MiB  3.4MiB  peers_dir
phone   10.9.0.3/32   offline    -                   -          0B      0B      peers_dir
```

```bash
# the subnet comes from tunnel_address if set; otherwise pass -subnet 10.9.0.0/24
sudo microtunnel peer add laptop -subnet 10.9.0.0/24 -public-key <hex>
sudo microtunnel peer add phone  -subnet 10.9.0.0/24 -generate -key-dir /root/phone
sudo microtunnel peer remove laptop
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
sudo microtunnel enroll serve -c /etc/microtunnel/microtunnel.yaml \
  -tokens /var/lib/microtunnel/tokens \
  -tls-cert /etc/microtunnel/enroll.crt -tls-key /etc/microtunnel/enroll.key
```

It listens on `:8443` (change with `-listen`). To keep it running, add a unit such as `/etc/systemd/system/microtunnel-enroll.service`:

```ini
[Unit]
Description=Microtunnel - enrollment service
After=microtunnel.service
Requires=microtunnel.service

[Service]
ExecStart=/usr/bin/microtunnel enroll serve -c /etc/microtunnel/microtunnel.yaml -tokens /var/lib/microtunnel/tokens -tls-cert /etc/microtunnel/enroll.crt -tls-key /etc/microtunnel/enroll.key
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
sudo microtunnel join https://enroll.example.com -token mt1.3f9a....
#   Enrolled as "laptop" with overlay address 10.9.0.2
sudo systemctl enable --now microtunnel@laptop
```

- `-name laptop` on `token create` fixes the machine's name; omit it and the machine passes `-name` to `join` itself.
- If the service uses a private CA, give `join` `-ca-file ca.pem`. Plain `http://` URLs are refused unless you pass `-allow-http`.
- `MICROTUNNEL_JOIN_TOKEN` can carry the token instead of `-token`, keeping it out of shell history.
- `join` writes `<name>.key` (0600), `<name>.crt` and `<name>.yaml` (0600, it contains the pre-shared key) into `/etc/microtunnel` when run as root (otherwise the current directory; override with `-dir`) and refuses to overwrite existing files. The `microtunnel` service runs `microtunnel.yaml`; the `microtunnel@<name>` template runs `<name>.yaml`. On macOS the config uses `interface: utun`.

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

With `tunnel_address` in the config (which `microtunnel init` and `join` always write), `microtunnel` creates and configures its own interface: it opens `microtunnel0`, assigns the overlay address, brings it up and adds the route. **No manual step is needed.**

Only if your config has no `tunnel_address` do you have to prepare the interface yourself before starting the service, with the overlay IP for this node:

```bash
sudo microtunnel-create-tunnel.sh microtunnel0 10.9.0.1/24                    # a relay
sudo microtunnel-create-tunnel.sh microtunnel0 10.9.0.2/24 10.9.0.0/24        # a peer (second argument: route to the overlay)
```

---

## Running as a Service

One service runs every machine; the config decides whether it is a relay or a peer:

```bash
sudo systemctl enable --now microtunnel        # runs /etc/microtunnel/microtunnel.yaml
```

The service will not start until `/etc/microtunnel/microtunnel.yaml` exists (run `microtunnel init` first), and says so instead of failing in a loop.

### Several instances on one machine

For a machine in more than one overlay, or running a relay and a peer side by side, use the template unit: `microtunnel@<name>` runs `/etc/microtunnel/<name>.yaml`.

```bash
sudo microtunnel init peer --name home --relay ... --relay-key ... --address ...     # writes home.yaml and home.key
sudo systemctl enable --now microtunnel@home
```

Give each config its own `interface:` name (and `port:` if they listen), otherwise instances conflict on the `microtunnel0` interface and the UDP port.

### Stop / Restart

```bash
sudo systemctl restart microtunnel
sudo systemctl stop microtunnel@home
```

### View Logs

```bash
sudo journalctl -u microtunnel -f
sudo journalctl -u microtunnel@home -f
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
