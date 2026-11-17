---
title: Docker demo
layout: default
---

# Docker demo: ports, Envoy and environment

Details for the local demo described in the [README](https://github.com/jecklgamis/microtunnel#running-with-docker): a relay and two peers in containers on one machine.

## Port Mapping

| Service | Container port | relay host | peer-1 host | peer-2 host |
|---------|---------------|------------|-------------|-------------|
| UDP tunnel | 5040 | 5040 | 5042 | 5043 |
| nginx | 80 | — | — | — |
| Envoy TCP proxy | 15040 | — | 15042 | 15043 |
| Envoy HTTP proxy | 15050 | — | 15052 | 15053 |
| Envoy admin | 9901 | 9901 | 9902 | 9903 |

## Envoy Proxy

Each peer container includes an [Envoy](https://www.envoyproxy.io/) proxy. When `ENVOY_UPSTREAM_HOST` is set, Envoy starts and forwards connections to the configured upstream.

Two listeners:

| Listener | Port | Mode |
|----------|------|------|
| TCP proxy | 15040 | L4 pass-through |
| HTTP proxy | 15050 | L7 with connection pooling (~130 req/connection) |
| Admin | 9901 | HTTP stats |

```bash
curl http://localhost:15052   # HTTP proxy through peer-1 → peer-2's nginx
curl http://localhost:15042   # TCP proxy
curl http://localhost:9902/stats  # Envoy admin
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TUNNEL_NAME` | `microtunnel0` | TUN interface name |
| `PEER_IP` | `10.9.0.1/24` | This peer's overlay IP/CIDR |
| `PEER_ROUTES` | _(none)_ | Space-separated extra CIDRs to route via TUN |
| `PEER_CONFIG` | `peer.yaml` | Path to YAML config file inside container |
| `ENVOY_UPSTREAM_HOST` | — | Upstream host for Envoy; if unset, Envoy is not started |
| `ENVOY_UPSTREAM_PORT` | `80` | Upstream port for Envoy |
