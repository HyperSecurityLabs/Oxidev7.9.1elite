#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEB_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_NAME="oxide-ce"
VERSION="8.5.0community-edition"
OUTPUT="${PKG_NAME}_${VERSION}_amd64.deb"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Build a .deb package from the oxide-ce-debian directory.

Options:
  --update-bin     Copy fresh CLI + GUI binaries from target/release before building
  --update-db      Copy fresh cgi_database from the release folder
  --output FILE    Output .deb path (default: $OUTPUT)
  --help           Show this help

Examples:
  $0                              build .deb from existing files
  $0 --update-bin                 build with latest compiled binaries
  $0 --update-bin --update-db    build with latest binaries + DB
EOF
}

UPDATE_BIN=false
UPDATE_DB=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --update-bin)   UPDATE_BIN=true ;;
        --update-db)    UPDATE_DB=true ;;
        --output)       OUTPUT="$2"; shift ;;
        --help)         usage; exit 0 ;;
        *) echo "Unknown: $1"; usage; exit 1 ;;
    esac
    shift
done

if [[ "$UPDATE_BIN" == true ]]; then
    echo "[*] Copying fresh binaries from build ..."
    CLI_SRC="$SRC_DIR/target/release/oxide"
    GUI_SRC="$SRC_DIR/gui/target/release/oxide-gui"
    if [[ -f "$CLI_SRC" ]]; then
        cp "$CLI_SRC" "$DEB_DIR/usr/bin/oxide-ce-bin"
        echo "  [+] CLI: $CLI_SRC"
    else
        echo "  [!] CLI binary not found at $CLI_SRC; keeping existing"
    fi
    if [[ -f "$GUI_SRC" ]]; then
        cp "$GUI_SRC" "$DEB_DIR/usr/lib/oxide/oxide-gui"
        echo "  [+] GUI: $GUI_SRC"
    else
        echo "  [!] GUI binary not found at $GUI_SRC; keeping existing"
    fi
fi

if [[ "$UPDATE_DB" == true ]]; then
    DB_SRC="$SRC_DIR/OxideCE-v8.5.0-community/Linux/cgi_database"
    DB_DST="$DEB_DIR/usr/lib/oxide/cgi_database"
    if [[ -d "$DB_SRC" ]]; then
        mkdir -p "$DB_DST"
        cp -r "$DB_SRC/"* "$DB_DST/"
        echo "  [+] DB: $DB_SRC"
    else
        echo "  [!] DB dir not found at $DB_SRC; keeping existing"
    fi
fi

echo "[*] Building .deb package ..."
cd "$SRC_DIR"
fakeroot dpkg-deb --build "oxide-ce-debian" "$OUTPUT"
echo "[+] Package: $(pwd)/$OUTPUT"
