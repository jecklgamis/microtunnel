# Admin Socket

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

## Managing a remote relay

Do not expose the socket. Forward it over SSH instead; SSH provides the authentication and encryption, and no extra port is opened:

```bash
ssh -N -L /tmp/mt.sock:/run/microtunnel/admin.sock admin@relay.example.com &
microtunnel peer list -socket /tmp/mt.sock
microtunnel peer add laptop -socket /tmp/mt.sock -public-key <hex>
```

Anyone who can open the socket can add a peer, which grants network access, so keep its permissions as they are and never proxy it to a TCP port. The socket must be on a local filesystem (not a network or container bind mount that cannot `chmod` sockets).
