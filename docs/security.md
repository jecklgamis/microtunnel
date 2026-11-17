---
title: Security
layout: default
---

# Security

microtunnel is a small, from-scratch implementation of WireGuard-style ideas. It has **not** been independently audited; see [Security review](#security-review).

## Features
- **X25519 Diffie-Hellman key exchange** — ephemeral + static key pairs for forward secrecy and mutual authentication
- **AES-256-GCM encryption** — all tunnel traffic is authenticated and encrypted
- **Identity hiding** — static public keys are encrypted inside the handshake; passive observers cannot identify peers
- **PSK authentication** — optional HMAC-SHA256 over the handshake using a pre-shared key
- **Replay protection** — 2048-bit sliding window per session rejects replayed or reordered packets
- **AllowedIPs routing** — enforces a per-peer IP allowlist; packets with unexpected source IPs are dropped
- **Session rekeying** — peers re-handshake every 3 minutes, rotating the session key automatically
- **DoS mitigations** — 5-second handshake cooldown per address and per public key

## Handshake Flow

```
INITIATOR (peer-1)                             RESPONDER (relay)
──────────────────                             ─────────────────

Generate eph_c keypair
Encrypt static_pub_c with
  SHA-256(DH(eph_c, static_pub_s))
Compute HMAC-SHA256(psk, ...)

  ──── HANDSHAKE INIT ────────────────────────────>
       [8 magic]
       [32 eph_pub_c]
       [48 AES-GCM(static_pub_c)]
       [32 HMAC(psk)]  (if PSK)

                                                Verify HMAC (if PSK)
                                                Decrypt static_pub_c
                                                  using DH(eph_c, static_s)
                                                Look up peer config by static_pub_c
                                                Generate eph_s keypair (pre-generated)
                                                Encrypt static_pub_s with
                                                  SHA-256(DH(eph_s, eph_c))
                                                Derive session key (see below)
                                                Save old key as prev_key (90s grace)
                                                Reset replay window
                                                Pre-generate next eph keypair

  <─── HANDSHAKE RESPONSE ────────────────────────
       [8 magic]
       [32 eph_pub_s]
       [48 AES-GCM(static_pub_s)]
       [32 HMAC(psk)]  (if PSK)

Verify HMAC (if PSK)
Decrypt static_pub_s
  using DH(eph_s, eph_c)
Verify static_pub_s matches config
Derive same session key
Save old key as prev_key (90s grace)
Reset replay window, send_seq=0

  ──── DATA (AES-256-GCM, seq=1) ─────────────────>
  <─── DATA (AES-256-GCM, seq=1) ─────────────────
```

Both sides retain the old session key for 90 seconds (`prev_key` grace period) to decrypt in-flight packets during the switchover. Prev-key packets bypass the replay window to prevent old sequence numbers from poisoning the new session.

## Handshake Wire Format

```
[8 magic][32 eph_pub][48 AES-256-GCM(static_pub)][32 HMAC-SHA256(psk,...)]?
```

## Session Key Derivation

```
SHA-256(
  DH(eph_c, eph_s)        ||
  DH(static_c, eph_s)     ||
  DH(eph_c, static_s)     ||
  client_eph_pub          ||
  server_eph_pub          ||
  client_static_pub       ||
  server_static_pub
)
```

## Data Packets

```
[12-byte IV][AES-256-GCM ciphertext of (8-byte magic + 8-byte seq + payload)][16-byte GCM tag]
```

Magic is `0xdeadbeefcafebabe`. Packets with a bad magic header, invalid GCM tag, or replayed sequence number are silently dropped.

## Security Review

The original C implementation was reviewed for memory safety, injection vulnerabilities and cryptographic correctness; no high-confidence exploitable vulnerabilities were found. The Go port has **not** been independently audited. Notes carried over from that review:

| Finding (C implementation) | Status in the Go port |
|---------|------------------------|
| `strcpy()` after TUNSETIFF ioctl, unbounded `sprintf()` in `bytes_to_hex()` | No longer applicable — Go is memory-safe, and the TUN name goes through `unix.Ifreq` |
| Unquoted `${PEER_ROUTES}` expansion in `scripts/docker-entrypoint.sh` | Unchanged; false positive — intentional word-splitting of a trusted operator-set Docker env var; no untrusted input path |
| `TUNNEL_NAME` in sysctl command in `scripts/create-tunnel.sh` | Unchanged; false positive — always hardcoded or set by the container operator who already has root |

Cryptography uses only the Go standard library (`crypto/ecdh` X25519, `crypto/aes` + GCM, `crypto/hmac`, `crypto/sha256`). X25519 results that are all-zero (low-order peer points) are rejected, and HMAC and identity comparisons are constant-time.

## Behavior differences from the C implementation

The wire protocol and YAML format are unchanged. The port deliberately tightens a few behaviors:

- **Keepalive/expiry:** only authenticated, non-replayed packets refresh a session's idle timer. (The C code refreshed it for any datagram from the peer's address, so spoofed junk could keep a dead session alive.)
- **Non-IPv4 payloads** received from a peer are dropped. (The C code passed them to the TUN device without applying the AllowedIPs source check.)
- **Simultaneous-rekey tie-break** now works when both sides dial each other. (In C, a peer's initiation arriving from the address we had dialed was classified as a failed *response*, so the "higher public key wins" branch was unreachable there.) A forged packet can no longer cancel a pending handshake.
- **Unknown peers get no reply:** the responder checks the initiator's identity *before* answering the handshake.
- **DNS** re-resolution no longer happens while holding the session-table lock.
- **Dynamic peers** (new): `peers_dir`, hot reload (`SIGHUP` or automatic), the admin socket, the enrollment service and the `peer`/`keygen`/`enroll`/`join` subcommands have no C equivalent. Duplicate peer public keys are now rejected.
- **Config:** an empty `pre_shared_key`, a peer without `public_key`, and interface names longer than 15 characters are rejected instead of being silently accepted.
