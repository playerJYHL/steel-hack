#!/bin/sh
# Put the shims in front of the real binaries on PATH.
#
# Usage: install.sh [target-dir]   (default /usr/local/bin, which precedes
# /bin and /usr/bin on a default Debian PATH)
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="${1:-/usr/local/bin}"
mkdir -p "$DEST"
cp "$SRC/_common.sh" "$DEST/_common.sh"
for tool in rm dd mkfs shred; do
    cp "$SRC/$tool" "$DEST/$tool"
    chmod 0755 "$DEST/$tool"
done
# mkfs ships as a family of binaries; cover the common ones.
for fs in ext2 ext3 ext4 xfs btrfs vfat; do
    cp "$SRC/mkfs" "$DEST/mkfs.$fs"
    chmod 0755 "$DEST/mkfs.$fs"
done
echo "arena shims installed in $DEST"
