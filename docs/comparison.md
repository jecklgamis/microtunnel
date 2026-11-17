---
title: Comparison
layout: default
---

# Comparison with Alternatives

| | **microtunnel** | **WireGuard** | **OpenVPN** | **IPsec (strongSwan)** | **GRE** | **Tinc** |
|---|---|---|---|---|---|---|
| **Layer** | L3 (TUN) | L3 (TUN) | L3/L2 (TUN/TAP) | L3 | L3 | L2/L3 |
| **Transport** | UDP | UDP | UDP/TCP | ESP/UDP | IP proto 47 | UDP/TCP |
| **Topology** | Hub-and-spoke | Mesh or point-to-point | Hub-and-spoke or mesh | Point-to-point or mesh | Point-to-point | Mesh |
| **Key exchange** | X25519 (custom) | X25519 (Noise protocol) | TLS (RSA/ECDSA) | IKEv2 (RSA/ECC) | None | Ed25519 |
| **Encryption** | AES-256-GCM | ChaCha20-Poly1305 | AES-256-GCM | AES-256-GCM | None | AES-256-GCM |
| **Identity hiding** | Yes | Yes | No | No | No | No |
| **NAT traversal** | Yes (outbound peers) | Yes | Yes | Partial (NAT-T) | No | Yes |
| **Replay protection** | Yes (2048-bit window) | Yes | Yes | Yes | No | Yes |
| **PSK support** | Yes | Yes | No | Yes | No | No |
| **Rekeying** | Every 3 min | Every 3 min (180s) | Configurable | IKEv2 rekeying | No | No |
| **Kernel module** | No (userspace) | Yes | No (userspace) | Partial (xfrm) | Yes | No |
| **IPv6 support** | No | Yes | Yes | Yes | Yes | Yes |
| **Platforms** | Linux, macOS | Linux, macOS, Windows, BSD | Cross-platform | Cross-platform | Linux | Cross-platform |
| **Throughput** | Low-medium (userspace, multi-goroutine) | High (kernel) | Medium | High (kernel) | High (kernel) | Medium |
| **Lines of code** | ~2,100 (Go) | ~4,000 (kernel) | ~100,000+ | ~500,000+ | — | ~50,000 |
| **Purpose** | Simple/small-scale | Production | Production | Production | Infrastructure | Mesh VPN |
