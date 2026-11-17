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
- **Handshake confirmation** — a handshake never displaces a live session by itself; the new key is used only once the initiator's first packet authenticates under it (see [Handshake confirmation](#handshake-confirmation))
- **DoS mitigations** — handshakes are validated before any lock is taken, rate limited per source address and globally, and subject to a 5-second cooldown per address and per public key; logging of unauthenticated junk is rate limited

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

## Handshake confirmation

A handshake initiation contains only public values (plus an HMAC under the shared pre-shared key). Anyone who has recorded one can replay it, and, without a PSK, anyone who knows a peer's public key can forge one. If the responder switched that peer's session key and address as soon as it answered, such a packet would black-hole a live peer: its traffic would be re-homed to the sender's address under a key nobody holds.

The responder therefore answers the initiation but keeps the new key as a **candidate**. The live session (key and address) changes only when a data packet from the handshake's source address authenticates under the candidate. The session key mixes in `DH(static_initiator, eph_responder)`, which only the real initiator can compute, so a successful decrypt proves it holds the static private key it claimed.

- The initiator sends a keepalive immediately after completing a handshake, so the responder confirms within one round trip. The original C implementation sends its first packet only with traffic or at its next keepalive, so against a C initiator the relay's session appears (and traffic toward that peer starts) at that point.
- Candidates expire after 90 seconds and at most 8 are held per peer.
- An unconfirmed handshake creates no session: the peer is not shown as connected and no traffic is routed to the sender.
- A peer that roams to a new address is confirmed the same way, from its new address.

What remains: during a rekey, a replayed initiation still earns the sender one handshake response (the same size as the request, so no amplification), and without a PSK an off-path attacker who can spoof the *responder's* address can feed an initiator a forged response, which only wastes that handshake because it cannot derive the session key. Always configure a pre-shared key.

## Hardening

- **Flood handling** — a handshake costs two X25519 operations under the session-table lock, so junk is dropped first: wrong size, magic or PSK HMAC cost one hash and nothing else; well-formed initiations are limited to 16/s per source address (burst 32) and 200/s overall (burst 256). Log lines that unauthenticated packets can trigger are limited to one per kind per second.
- **Nonce safety** — data packets use random 96-bit AES-GCM IVs, so a key stops sending after 2^32 packets until it is rekeyed (the dialing side rekeys every ~144 s, long before).
- **Service sandboxing** — the systemd units run with `NoNewPrivileges`, a read-only file system except `/etc/microtunnel`, no access to `/home`, a private `/tmp`, a reduced capability set (`CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`) and restricted address families and namespaces. If `peers_dir` points outside `/etc/microtunnel`, add it to `ReadWritePaths`.
- **Secrets on disk** — private keys, configs holding the PSK and generated peer configs are created mode 0600 (keys never overwritten); the admin socket is created 0600 and only reachable by root.
- **Enrollment** — join tokens are 192-bit random secrets stored as SHA-256 hashes, single use, short lived, and redeemed with an atomic rename; the service refuses to run without TLS unless `-insecure-http` is given, and limits failed attempts per client address. Behind a reverse proxy every client shares the proxy's address, so one noisy client can exhaust the allowance for all; rate limit at the proxy instead.
- **Docker image** — the demo image runs as root and bundles the repository's public demo keys; it is for demonstrations and tests only.

## Security Review

The original C implementation was reviewed for memory safety, injection vulnerabilities and cryptographic correctness; no high-confidence exploitable vulnerabilities were found. The Go port has **not** been independently audited. Notes carried over from that review:

| Finding (C implementation) | Status in the Go port |
|---------|------------------------|
| `strcpy()` after TUNSETIFF ioctl, unbounded `sprintf()` in `bytes_to_hex()` | No longer applicable — Go is memory-safe, and the TUN name goes through `unix.Ifreq` |
| Unquoted `${PEER_ROUTES}` expansion in `scripts/docker-entrypoint.sh` | Unchanged; false positive — intentional word-splitting of a trusted operator-set Docker env var; no untrusted input path |
| `TUNNEL_NAME` in sysctl command in `scripts/create-tunnel.sh` | Unchanged; false positive — always hardcoded or set by the container operator who already has root |

A review of the Go code base (protocol, session handling, admin API, enrollment, setup and packaging) found one significant issue and several smaller ones, now fixed:

| Finding | Severity | Fix |
|---------|----------|-----|
| A replayed or forged handshake initiation replaced a live peer's session key and address immediately | Medium (denial of service for any peer; trivial without a PSK) | [Handshake confirmation](#handshake-confirmation) |
| Junk datagrams from anyone could write a log line each (disk or journal filling) | Medium | Per-kind log rate limit |
| A flood of well-formed initiations stalled the data plane (X25519 under the table write lock) | Medium | Pre-lock validation and rate limits |
| No upper bound on packets per key with random GCM IVs | Low | Stop sending at 2^32 packets until rekeyed |
| Admin socket briefly existed with the process umask before being restricted | Low | Created under a restrictive umask |
| Services ran with no sandboxing | Low | systemd hardening directives |

Not changed, by design: the pre-shared key authenticates the handshake but is not mixed into the session key (it protects against unauthenticated handshakes, not against a later key compromise), and its HMAC key is a plain SHA-256 of the string, so use the long random value `microtunnel init` generates rather than a passphrase.

Cryptography uses only the Go standard library (`crypto/ecdh` X25519, `crypto/aes` + GCM, `crypto/hmac`, `crypto/sha256`). X25519 results that are all-zero (low-order peer points) are rejected, and HMAC and identity comparisons are constant-time.

## Behavior differences from the C implementation

The wire protocol and YAML format are unchanged. The port deliberately tightens a few behaviors:

- **Keepalive/expiry:** only authenticated, non-replayed packets refresh a session's idle timer. (The C code refreshed it for any datagram from the peer's address, so spoofed junk could keep a dead session alive.)
- **Non-IPv4 payloads** received from a peer are dropped. (The C code passed them to the TUN device without applying the AllowedIPs source check.)
- **Simultaneous-rekey tie-break** now works when both sides dial each other. (In C, a peer's initiation arriving from the address we had dialed was classified as a failed *response*, so the "higher public key wins" branch was unreachable there.) A forged packet can no longer cancel a pending handshake.
- **Handshake keys are confirmed before use:** an inbound handshake no longer re-keys or re-homes a live session until the initiator's first packet authenticates under the new key.
- **Unknown peers get no reply:** the responder checks the initiator's identity *before* answering the handshake.
- **DNS** re-resolution no longer happens while holding the session-table lock.
- **Dynamic peers** (new): `peers_dir`, hot reload (`SIGHUP` or automatic), the admin socket, the enrollment service and the `peer`/`keygen`/`enroll`/`join` subcommands have no C equivalent. Duplicate peer public keys are now rejected.
- **Config:** an empty `pre_shared_key`, a peer without `public_key`, and interface names longer than 15 characters are rejected instead of being silently accepted.
