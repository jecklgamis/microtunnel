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
A simple Linux VPN written in Go, using a TUN virtual interface and UDP transport.
Implements X25519 key exchange, AES-256-GCM encryption, identity hiding,
AllowedIPs routing, replay protection, and session rekeying.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/share/microtunnel
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}/etc/microtunnel
install -d -m 750 %{buildroot}/etc/microtunnel/peers.d

install -m 755 %{_sourcedir}/%{bin_path}                 %{buildroot}/usr/bin/microtunnel
install -m 755 %{_sourcedir}/scripts/create-tunnel.sh        %{buildroot}/usr/share/microtunnel/microtunnel-create-tunnel.sh
install -m 755 %{_sourcedir}/scripts/extract-keys-hex.sh    %{buildroot}/usr/bin/microtunnel-extract-keys-hex.sh
install -m 755 %{_sourcedir}/scripts/extract-pubkey-hex.sh  %{buildroot}/usr/bin/microtunnel-extract-pubkey-hex.sh
install -m 755 %{_sourcedir}/scripts/generate-peer-keys.sh  %{buildroot}/usr/bin/microtunnel-generate-peer-keys.sh
install -m 755 %{_sourcedir}/scripts/create-tunnel.sh       %{buildroot}/usr/bin/microtunnel-create-tunnel.sh
install -m 644 %{_sourcedir}/rpm/systemd/microtunnel-relay.service    %{buildroot}/usr/lib/systemd/system/
install -m 644 %{_sourcedir}/rpm/systemd/microtunnel-peer.service      %{buildroot}/usr/lib/systemd/system/
install -m 644 %{_sourcedir}/rpm/systemd/microtunnel-peer-1.service   %{buildroot}/usr/lib/systemd/system/
install -m 644 %{_sourcedir}/rpm/systemd/microtunnel-peer-2.service   %{buildroot}/usr/lib/systemd/system/
install -m 644 %{_sourcedir}/rpm/systemd/microtunnel-peer@.service    %{buildroot}/usr/lib/systemd/system/
install -m 640 %{_sourcedir}/packaging/config/relay.yaml   %{buildroot}/etc/microtunnel/relay.yaml
install -m 640 %{_sourcedir}/packaging/config/peer.yaml    %{buildroot}/etc/microtunnel/peer.yaml
install -m 640 %{_sourcedir}/packaging/config/peer-1.yaml  %{buildroot}/etc/microtunnel/peer-1.yaml
install -m 640 %{_sourcedir}/packaging/config/peer-2.yaml  %{buildroot}/etc/microtunnel/peer-2.yaml

%files
/usr/bin/microtunnel
/usr/share/microtunnel/microtunnel-create-tunnel.sh
/usr/bin/microtunnel-extract-keys-hex.sh
/usr/bin/microtunnel-extract-pubkey-hex.sh
/usr/bin/microtunnel-generate-peer-keys.sh
/usr/bin/microtunnel-create-tunnel.sh
/usr/lib/systemd/system/microtunnel-relay.service
/usr/lib/systemd/system/microtunnel-peer.service
/usr/lib/systemd/system/microtunnel-peer-1.service
/usr/lib/systemd/system/microtunnel-peer-2.service
/usr/lib/systemd/system/microtunnel-peer@.service
%dir %attr(0750,root,root) /etc/microtunnel/peers.d
%config(noreplace) /etc/microtunnel/relay.yaml
%config(noreplace) /etc/microtunnel/peer.yaml
%config(noreplace) /etc/microtunnel/peer-1.yaml
%config(noreplace) /etc/microtunnel/peer-2.yaml

%post
systemctl daemon-reload
echo "Microtunnel installed."
echo ""
echo "Set this machine up with one command:"
echo "  sudo microtunnel init relay --endpoint <this-host>:5040          # on the relay"
echo "  sudo microtunnel init peer --relay <host>:5040 --relay-key <hex> --psk-file <file>   # on a peer"
echo "then:  systemctl enable --now microtunnel-relay   (or microtunnel-peer)"
echo ""
echo "The sample configs in /etc/microtunnel/ are TEMPLATES with <placeholders>; the services"
echo "will not start from them until you fill them in (or use the init commands above)."

%preun
instances=$(systemctl list-units --all --plain --no-legend 'microtunnel-peer@*.service' 2>/dev/null | awk '{print $1}')
for svc in microtunnel-relay microtunnel-peer microtunnel-peer-1 microtunnel-peer-2 $instances; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc"
    fi
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        systemctl disable "$svc"
    fi
done

%postun
systemctl daemon-reload
