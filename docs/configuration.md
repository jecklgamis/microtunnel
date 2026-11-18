# Configuration

> **The package ships no config.** `microtunnel init` writes a finished one ([Quick Start](quick-start.md)); the sample configs in `/usr/share/microtunnel/examples/` contain `<placeholders>` and **no keys or secrets**, so a copy of one refuses to run until you fill it in. To do it by hand, create keys with `microtunnel keygen`, set your own long random `pre_shared_key`, and fill in the public keys and endpoint as shown below.
>
> The repository's demo keys and the pre-shared keys `some-psk` / `change-me` are public. `microtunnel` logs a warning at startup if it finds any of them in use; never rely on them for a real network.

## Relay

The relay has an address every peer can reach (a public IP, or a LAN or port-forwarded address) and accepts inbound connections from peers. It does not have an `endpoint` set — it never initiates outbound connections.

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

## Peer

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

- `endpoint` — the relay's reachable hostname or IP and UDP port. Required on peers; omit on the relay.
- `allowed_ips` — peers use `/24` (the full overlay subnet) so all overlay traffic is routed through the relay.
- `pre_shared_key` — must match the relay and all other peers.
- All timing fields are optional; values shown are the defaults.

## Config Reference

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
| `admin_socket` | No | — | Path of a unix socket (mode 0600) on which the relay serves its admin API: manage peers and read live state. See [Admin Socket](admin-socket.md). The directory must exist; the packaged relay service creates `/run/microtunnel` |
| `public_endpoint` | No | — | The relay's public `host:port`, handed to newly registered peers as the address to dial |
| `peers_dir` | No | — | Directory of one-peer-per-file YAML, reloaded live. Relative paths are resolved against the config file's directory. Makes `peers:` optional. See [Adding Peers Without a Restart](dynamic-peers.md) |
| `peers[].public_key` | Yes | — | Peer's public key (hex) |
| `peers[].endpoint` | No | — | `host:port` to connect to; omit for inbound-only nodes |
| `peers[].allowed_ips` | Yes | — | CIDRs allowed from this peer |

A config needs at least one peer, either under `peers:` or as a file in `peers_dir`. The same public key may not appear twice.

## Routing a network behind a peer

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
