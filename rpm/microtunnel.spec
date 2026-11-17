Name:           microtunnel
Version:        %{pkg_version}
Release:        %{pkg_release}%{?dist}
Summary:        Hub-and-spoke layer 3 overlay network over UDP
License:        MIT
URL:            https://github.com/jecklgamis/microtunnel

Requires:       iproute

# Static Go binary: nothing to strip or scan for debuginfo, and the host's
# strip may not understand a cross-built architecture.
%global debug_package %{nil}
%global __os_install_post %{nil}
# Don't package the /usr/lib/.build-id/* symlinks rpm would generate from the Go build ID.
%global _build_id_links none

%description
A simple VPN written in Go, using a TUN virtual interface and UDP transport.
Implements X25519 key exchange, AES-256-GCM encryption, identity hiding,
AllowedIPs routing, replay protection, and session rekeying.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/share/microtunnel/examples
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}/etc/microtunnel
install -d -m 750 %{buildroot}/etc/microtunnel/peers.d

install -m 755 %{_sourcedir}/%{bin_path}                 %{buildroot}/usr/bin/microtunnel
install -m 755 %{_sourcedir}/scripts/create-tunnel.sh        %{buildroot}/usr/share/microtunnel/microtunnel-create-tunnel.sh
install -m 755 %{_sourcedir}/scripts/extract-keys-hex.sh    %{buildroot}/usr/bin/microtunnel-extract-keys-hex.sh
install -m 755 %{_sourcedir}/scripts/extract-pubkey-hex.sh  %{buildroot}/usr/bin/microtunnel-extract-pubkey-hex.sh
install -m 755 %{_sourcedir}/scripts/generate-peer-keys.sh  %{buildroot}/usr/bin/microtunnel-generate-peer-keys.sh
install -m 755 %{_sourcedir}/scripts/create-tunnel.sh       %{buildroot}/usr/bin/microtunnel-create-tunnel.sh
install -m 644 %{_sourcedir}/rpm/systemd/microtunnel.service    %{buildroot}/usr/lib/systemd/system/
install -m 644 %{_sourcedir}/rpm/systemd/microtunnel@.service   %{buildroot}/usr/lib/systemd/system/
install -m 644 %{_sourcedir}/packaging/config/relay.yaml  %{buildroot}/usr/share/microtunnel/examples/relay.yaml
install -m 644 %{_sourcedir}/packaging/config/peer.yaml   %{buildroot}/usr/share/microtunnel/examples/peer.yaml

%files
/usr/bin/microtunnel
/usr/share/microtunnel/microtunnel-create-tunnel.sh
/usr/share/microtunnel/examples/relay.yaml
/usr/share/microtunnel/examples/peer.yaml
/usr/bin/microtunnel-extract-keys-hex.sh
/usr/bin/microtunnel-extract-pubkey-hex.sh
/usr/bin/microtunnel-generate-peer-keys.sh
/usr/bin/microtunnel-create-tunnel.sh
/usr/lib/systemd/system/microtunnel.service
/usr/lib/systemd/system/microtunnel@.service
%dir %attr(0755,root,root) /etc/microtunnel
%dir %attr(0750,root,root) /etc/microtunnel/peers.d

%post
systemctl daemon-reload
echo "Microtunnel installed."
echo ""
echo "The same program is a relay or a peer; its config decides which. Set this machine up:"
echo "  sudo microtunnel init relay --endpoint <this-host>:5040                     # on the relay"
echo "  sudo microtunnel init peer --relay <host>:5040 --relay-key <hex> --psk-file <file>   # on a peer"
echo "then:  sudo systemctl enable --now microtunnel"
echo ""
echo "Sample configs to copy from: /usr/share/microtunnel/examples/"

%preun
instances=$(systemctl list-units --all --plain --no-legend 'microtunnel@*.service' 2>/dev/null | awk '{print $1}')
for svc in microtunnel $instances; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc"
    fi
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        systemctl disable "$svc"
    fi
done

%postun
systemctl daemon-reload
