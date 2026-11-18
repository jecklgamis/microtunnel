# Quick Start

After installing the package, a relay and a peer each need one command. `microtunnel init` generates the machine's key (an existing key is reused, never replaced), a strong random pre-shared key where needed, and writes a complete, validated config. It never overwrites an existing config unless you pass `-force`.

**On the relay:**

```bash
sudo microtunnel init relay --endpoint relay.example.com:5040
sudo systemctl enable --now microtunnel
```

`init relay` prints the relay's public key and a ready-to-use line for the peers. (`--start` runs the `systemctl` step for you.) Open UDP 5040 in your [firewall](firewall.md).

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

For several machines, [self-service enrollment](enrollment.md) is shorter: one `microtunnel join https://... -token ...` on each new machine does all of this. The same unit runs a relay or a peer, because the config decides the role. `init` and `join` write `microtunnel.yaml` by default; with `--name home` (or a `join` token named `home`) they write `home.yaml`, which runs as `systemctl enable --now microtunnel@home`.

`init relay` options: `--address` (overlay address, default `10.9.0.1/24`), `--port`, `--admin-socket` (`none` turns the API off), `--dir`. `init peer` options: `--name`, `--psk-file` (instead of the environment variable), `--subnet`, `--dir`. See `microtunnel init help`.
