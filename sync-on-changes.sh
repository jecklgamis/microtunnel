#!/usr/bin/env bash
# Watch source and script files and rsync the whole directory to the remote on changes.

REMOTE="jeck@nagasaki.local:~/workspace/microtunnel"
DIR="$(cd "$(dirname "$0")" && pwd)"

RSYNC_OPTS=(
    --archive
    --delete
    --exclude='.git/'
    --exclude='.idea/'
    --exclude='/microtunnel'
    --exclude='/build/'
)

do_sync() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') syncing..."
    rsync "${RSYNC_OPTS[@]}" "$DIR/" "$REMOTE" && \
        echo "$(date '+%Y-%m-%d %H:%M:%S') done" || \
        echo "$(date '+%Y-%m-%d %H:%M:%S') rsync failed"
}

echo "Syncing to ${REMOTE}"
do_sync

echo "Watching for changes in cmd/, internal/, config/, scripts/, Makefile, Dockerfile, go.mod..."
fswatch -ro \
    "$DIR/cmd" \
    "$DIR/internal" \
    "$DIR/config" \
    "$DIR/scripts" \
    "$DIR/Makefile" \
    "$DIR/Dockerfile" \
    "$DIR/go.mod" \
    "$DIR/go.sum" \
| while read -r; do
    do_sync
done


