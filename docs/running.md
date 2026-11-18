# Running

## Create the TUN Interface

With `tunnel_address` in the config (which `microtunnel init` and `join` always write), `microtunnel` creates and configures its own interface: it opens `microtunnel0`, assigns the overlay address, brings it up and adds the route. **No manual step is needed.**

Only if your config has no `tunnel_address` do you have to prepare the interface yourself before starting the service, with the overlay IP for this node:

```bash
sudo microtunnel-create-tunnel.sh microtunnel0 10.9.0.1/24                    # a relay
sudo microtunnel-create-tunnel.sh microtunnel0 10.9.0.2/24 10.9.0.0/24        # a peer (second argument: route to the overlay)
```

---

## Running as a Service

One service runs every machine; the config decides whether it is a relay or a peer:

```bash
sudo systemctl enable --now microtunnel        # runs /etc/microtunnel/microtunnel.yaml
```

The service will not start until `/etc/microtunnel/microtunnel.yaml` exists (run `microtunnel init` first), and says so instead of failing in a loop.

### Several instances on one machine

For a machine in more than one overlay, or running a relay and a peer side by side, use the template unit: `microtunnel@<name>` runs `/etc/microtunnel/<name>.yaml`.

```bash
sudo microtunnel init peer --name home --relay ... --relay-key ... --address ...     # writes home.yaml and home.key
sudo systemctl enable --now microtunnel@home
```

Give each config its own `interface:` name (and `port:` if they listen), otherwise instances conflict on the `microtunnel0` interface and the UDP port.

### Stop / Restart

```bash
sudo systemctl restart microtunnel
sudo systemctl stop microtunnel@home
```

### View Logs

```bash
sudo journalctl -u microtunnel -f
sudo journalctl -u microtunnel@home -f
```
