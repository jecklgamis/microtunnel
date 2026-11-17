#!/bin/sh
# Removes microtunnel from this Mac. Your config and keys in /etc/microtunnel are
# kept unless you pass --purge.
#
#   sudo /usr/local/share/microtunnel/uninstall.sh [--purge]
set -u

if [ "$(id -u)" -ne 0 ]; then
    echo "run this with sudo" >&2
    exit 1
fi

# Stop and remove every launchd job (the default instance and any named ones).
for plist in /Library/LaunchDaemons/io.github.jecklgamis.microtunnel*.plist; do
    [ -e "$plist" ] || continue
    label=$(basename "$plist" .plist)
    launchctl bootout "system/$label" >/dev/null 2>&1
    rm -f "$plist"
    echo "removed $plist"
done

rm -f /usr/local/bin/microtunnel /etc/newsyslog.d/microtunnel.conf /var/log/microtunnel*.log*
rm -rf /usr/local/share/microtunnel
rm -rf /var/run/microtunnel /var/run/microtunnel-*

if [ "${1:-}" = "--purge" ]; then
    rm -rf /etc/microtunnel
    echo "removed /etc/microtunnel (config and keys)"
else
    echo "kept /etc/microtunnel (config and keys); pass --purge to delete it"
fi

pkgutil --forget io.github.jecklgamis.microtunnel >/dev/null 2>&1
echo "microtunnel uninstalled"
