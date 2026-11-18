# CLI Reference

The same binary is the daemon and its management CLI. These sections are the output of `microtunnel <command> -h`.

## microtunnel (run the daemon)

```text
Usage: microtunnel [-c <config.yaml>]   (default /etc/microtunnel/microtunnel.yaml)
       microtunnel peer add|remove|list ...  (see `microtunnel init help`, `peer help`, `enroll help`, `join -h`)
  -c string
    	YAML config file (default "/etc/microtunnel/microtunnel.yaml")
  -version
    	print version and exit
```

## microtunnel init

```text
Usage:
  microtunnel init relay [flags]    set this machine up as a relay
  microtunnel init peer  [flags]    set this machine up as a peer of an existing relay

The same program is a relay or a peer; the config decides which. Both commands generate the
machine's key (an existing key is reused, never replaced) and write a complete, validated config. An existing config is never overwritten unless you pass -force.

init relay:
  -dir <dir>            config directory (default /etc/microtunnel)
  -name <name>          names the files <name>.key/.yaml (default "microtunnel": the config the
                        'microtunnel' service runs; another name runs as microtunnel@<name>)
  -endpoint <host:port> the relay's reachable address; handed to peers and shown in the peer hint
  -address <ip/len>     the relay's overlay address (default 10.9.0.1/24)
  -port <n>             UDP port (default 5040)
  -admin-socket <path>  admin API socket (default /run/microtunnel/admin.sock, /var/run/... on macOS; "none" turns it off)
  -force                replace an existing config (a NEW pre-shared key is generated)
  -start                also start it: systemctl enable --now microtunnel (macOS: install and load the launchd job)

init peer:
  -dir <dir>            config directory (default /etc/microtunnel)
  -name <name>          names the files <name>.key/.yaml (default "microtunnel": the config the
                        'microtunnel' service runs; another name runs as microtunnel@<name>)
  -relay <host:port>    the relay's reachable address                      (required)
  -relay-key <hex>      the relay's public key                          (required)
  -psk <secret>         the relay's pre-shared key; or -psk-file <file>, or the MICROTUNNEL_PSK
                        environment variable, which keep it out of the process list   (required)
  -address <ip/len>     this peer's overlay address, once the relay's admin has assigned one
  -subnet <cidr>        overlay subnet when no -address is given (default 10.9.0.0/24)
  -force                replace an existing <name>.yaml (the key is kept)
  -start                also start it: systemctl enable --now <the service> (macOS: install and load the launchd job)
```

## microtunnel keygen

```text
Usage: microtunnel keygen <name> [-dir <dir>]

Creates an X25519 key pair <name>.key (private, mode 0600) and <name>.crt in
<dir> (default .) and prints the public key hex, which is what a relay's
"microtunnel peer add <name> -public-key <hex>" needs. Never overwrites files.
```

## microtunnel peer

```text
Usage:
  microtunnel peer add <name> [flags]     register a peer with a relay
  microtunnel peer remove <name> [flags]  unregister a peer
  microtunnel peer list [flags]           show peers (with live state when the relay is reachable)

Where it acts:
  -socket <path>     the relay's admin socket: the relay allocates the IP, applies the
                     change immediately and reports live session state. Reach a remote
                     relay by forwarding its socket over SSH:
                       ssh -L /tmp/mt.sock:/run/microtunnel/admin.sock relay
  -c <file>          relay config file (default /etc/microtunnel/microtunnel.yaml). If it sets admin_socket and the
                     socket is reachable that is used; otherwise the CLI edits peers_dir
                     directly (a running relay loads the change within a second or two).

peer add:
  -public-key <hex>  the peer's own public key (recommended: its private key never leaves it)
  -generate          instead, create a key pair for the peer here
  -key-dir <dir>     where -generate writes <name>.key, .crt and .yaml (default .)
  -ip <addr>         fixed overlay IP (default: the lowest free address)
  -subnet <cidr>     overlay subnet (default: the relay's tunnel_address network)
  -endpoint <h:p>    the relay's reachable host:port for the peer's config
                     (default: the relay's public_endpoint)
```

## microtunnel enroll

```text
Usage:
  microtunnel enroll serve [flags]            run the enrollment service next to a relay
  microtunnel enroll token create [flags]     make a single-use join token
  microtunnel enroll token list [flags]       show tokens and their state
  microtunnel enroll token revoke <id>        delete a token
  microtunnel join <url> -token <token>       (on a new machine) enroll and write a config

enroll serve:
  -listen <addr>     address to listen on (default :8443)
  -socket <path>     the relay's admin socket  (or -c <relay.yaml>: use its admin_socket)
  -tokens <dir>      token directory (default enroll-tokens)
  -tls-cert <file> -tls-key <file>   serve HTTPS (required unless -insecure-http)
  -insecure-http     serve plain HTTP: only behind a TLS-terminating proxy or on a trusted network

enroll token create:
  -tokens <dir>      token directory (default enroll-tokens)
  -name <name>       bind the token to this peer name (otherwise the new machine picks one)
  -ttl <duration>    lifetime (default 1h, max 168h)
  -url <url>         the service's public URL, to print a complete join command
```

## microtunnel join

```text
Usage: microtunnel join <url> -token <token> [flags]

Generates a key pair on this machine, enrolls its public key with the service at
<url> and writes <name>.key, <name>.crt and <name>.yaml. The private key never
leaves this machine.
  -token <token>     the join token (or set MICROTUNNEL_JOIN_TOKEN, which keeps it out of shell history)
  -name <name>       peer name (not needed if the token carries one)
  -dir <dir>         where to write the files (default /etc/microtunnel when run as root, else .)
  -ca-file <file>    trust this CA for the service's certificate (private/self-signed CA)
  -allow-http        permit a plain http:// URL (trusted networks only)
```
