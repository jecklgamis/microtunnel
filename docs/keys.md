# Key Generation

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

To add peers to a running relay without editing its YAML, see [Adding Peers Without a Restart](dynamic-peers.md).
