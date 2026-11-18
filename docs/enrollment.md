# Self-Service Enrollment

For many devices, run the **enrollment service** next to the relay. An admin creates a one-time **join token**; the new machine runs one command with it. The machine generates its own key, so its private key never leaves it, and receives its overlay IP, the relay's key and address, and the pre-shared key.

It needs the [admin socket](admin-socket.md) enabled and a TLS certificate for the service (the `join` command checks it).

## Run the service

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

Open TCP 8443 in your [firewall](firewall.md). If TLS is terminated by a reverse proxy in front, run the service with `-insecure-http` and bind it to localhost (`-listen 127.0.0.1:8443`); never expose plain HTTP to the internet, because the response carries the pre-shared key.

## Enroll a machine

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

## Manage tokens

```bash
sudo microtunnel enroll token list   -tokens /var/lib/microtunnel/tokens
sudo microtunnel enroll token revoke 3f9a1c0d5e7b2a44 -tokens /var/lib/microtunnel/tokens
```

`list` shows each token's state (`pending`, `used`, `expired`, or `in progress`) and never prints secrets. Tokens expire after 1 hour by default (maximum 7 days), work once, and only a hash of the secret is stored.

## Notes

- If registering fails for a reason that is not the token's fault (the name is taken, the relay is unreachable), the token is **not** burned and can be retried.
- After 10 failed token attempts a minute from one address the service answers 429. A wrong, expired and used token all return the same 401. Behind a reverse proxy the service sees only the proxy's address, so the limit then applies to all clients together; rate-limit per client at the proxy as well.
- If the enrollment service is down, existing tunnels and the CLI keep working; only new self-service enrollments fail.
- To remove an enrolled machine use `microtunnel peer remove <name>`.
