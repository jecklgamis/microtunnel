# Installation

Download the latest release package from the [releases page](https://github.com/jecklgamis/microtunnel/releases).

Each release provides, for both **amd64/x86_64** and **arm64/aarch64**:

| Asset | Use |
|-------|-----|
| `microtunnel_<version>_<arch>.deb` | Debian / Ubuntu package (see below) |
| `microtunnel-<version>-<release>.<arch>.rpm` | Red Hat / Fedora / CentOS package (see below) |
| `microtunnel-linux-amd64`, `microtunnel-linux-arm64` | Plain static Linux binary: `chmod +x`, then run it. No packages or libraries needed |
| `microtunnel-<version>-universal.pkg` | macOS installer (Apple silicon and Intel), see [macOS](#macos). Unsigned for now |
| `microtunnel-darwin-arm64`, `microtunnel-darwin-amd64` | macOS binary (Apple silicon / Intel). Unsigned: run `xattr -d com.apple.quarantine <file>` after downloading |

A multi-architecture Docker image (linux/amd64 and linux/arm64) is published as `jecklgamis/microtunnel`, and macOS users can use [Homebrew](#homebrew).

## Debian / Ubuntu

```bash
sudo dpkg -i microtunnel_<version>_amd64.deb
```

## Red Hat / Fedora / CentOS

```bash
sudo rpm -i microtunnel-<version>-1.x86_64.rpm
```

Both packages install:

| Path | Description |
|------|-------------|
| `/usr/bin/microtunnel` | The tunnel binary |
| `/usr/bin/microtunnel-create-tunnel.sh` | TUN interface setup helper (only needed if your config has no `tunnel_address`) |
| `/usr/share/microtunnel/examples/relay.yaml`, `peer.yaml` | Annotated sample configs (`microtunnel init` writes a finished one for you) |
| `/lib/systemd/system/microtunnel.service` | The service: runs `/etc/microtunnel/microtunnel.yaml` (a relay or a peer: the config decides) |
| `/lib/systemd/system/microtunnel@.service` | Template for extra instances: `microtunnel@home` runs `/etc/microtunnel/home.yaml` |
| `/etc/microtunnel/peers.d/` | Empty directory for the relay's peer files |

The package installs **no config and no keys**: run `microtunnel init` (see [Quick Start](quick-start.md)).

## macOS

Open `microtunnel-<version>-universal.pkg` (it is not signed yet, so right-click it and choose Open, or run `sudo installer -pkg <file> -target /`). It installs:

| Path | Description |
|------|-------------|
| `/usr/local/bin/microtunnel` | The tunnel binary (universal: arm64 + amd64) |
| `/Library/LaunchDaemons/io.github.jecklgamis.microtunnel.plist` | The service: runs `/etc/microtunnel/microtunnel.yaml` as root while that file exists |
| `/etc/microtunnel/peers.d/` | Empty directory for the relay's peer files |
| `/usr/local/share/microtunnel/examples/`, `uninstall.sh` | Sample configs; uninstaller |

Nothing is started and no config or keys are installed. Configure with `sudo microtunnel init ...` as in [Quick Start](quick-start.md), but start the service with `sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.jecklgamis.microtunnel.plist` (or pass `--start` to `init`, which loads it for you) instead of `systemctl`. Logs are in `/var/log/microtunnel.log`; stop it with `sudo launchctl bootout system/io.github.jecklgamis.microtunnel`. A named instance (`--name home`) gets its own job, `io.github.jecklgamis.microtunnel.home`. The admin socket is `/var/run/microtunnel/admin.sock`.

Uninstall: `sudo /usr/local/share/microtunnel/uninstall.sh` (`--purge` also deletes `/etc/microtunnel`).


## Homebrew

On macOS, Homebrew can install it from the [jecklgamis/tap](https://github.com/jecklgamis/homebrew-tap) tap. It builds from source, so Go is pulled in as a build dependency and there is no Gatekeeper prompt:

```bash
brew install jecklgamis/tap/microtunnel
```

This installs `microtunnel` into Homebrew's `bin` and the sample configs into its `share/microtunnel/examples`. Nothing is started and no config or keys are created. Run `sudo microtunnel init ...` as in [Quick Start](quick-start.md), then either run `sudo microtunnel` in the foreground or use `sudo brew services start microtunnel` instead of `launchctl`. The service runs `/etc/microtunnel/microtunnel.yaml`, so `init` has to have written it first. Logs are in `$(brew --prefix)/var/log/microtunnel.log`.

`brew install --HEAD jecklgamis/tap/microtunnel` builds the `main` branch instead of the latest release. To remove it: `brew uninstall microtunnel`.

## Uninstalling

### Debian / Ubuntu

```bash
sudo dpkg -r microtunnel
```

### Red Hat / Fedora / CentOS

```bash
sudo rpm -e microtunnel
```

Configs in `/etc/microtunnel/` and keys are preserved on uninstall.
