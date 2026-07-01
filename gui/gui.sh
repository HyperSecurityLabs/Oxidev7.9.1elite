#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
PREFIX="[oxide-gui]"

info()  { echo -e "\e[36m$PREFIX\e[0m $*"; }
ok()    { echo -e "\e[32m$PREFIX ✔\e[0m $*"; }
err()   { echo -e "\e[31m$PREFIX ✘\e[0m $*"; }

MISSING=()

check_pkg() {
    local pkg=$1 apt=$2
    if dpkg -s "$pkg" &>/dev/null; then
        ok "found $pkg"
    else
        info "missing $pkg → $apt"
        MISSING+=("$apt")
    fi
}

info "checking system libraries required by Cargo.toml …"

# ── gui deps: wry + tao (webkit2gtk / gtk3) ──────────────────────────
check_pkg libgtk-3-dev             libgtk-3-dev
check_pkg libwebkit2gtk-4.1-dev    libwebkit2gtk-4.1-dev
check_pkg libjavascriptcoregtk-4.1-dev libjavascriptcoregtk-4.1-dev
check_pkg libsoup-3.0-dev          libsoup-3.0-dev
check_pkg libglib2.0-dev           libglib2.0-dev
check_pkg libcairo2-dev            libcairo2-dev
check_pkg libpango1.0-dev          libpango1.0-dev
check_pkg libgdk-pixbuf-2.0-dev    libgdk-pixbuf-2.0-dev
check_pkg libatk1.0-dev            libatk1.0-dev
check_pkg libx11-dev               libx11-dev

# ── root workspace deps: pnet → libpcap ──────────────────────────────
check_pkg libpcap-dev              libpcap-dev

# ── build tooling ─────────────────────────────────────────────────────
check_pkg pkg-config               pkg-config
check_pkg cargo                    cargo

# ── install if missing ────────────────────────────────────────────────
if [ ${#MISSING[@]} -gt 0 ]; then
    echo
    info "installing missing packages …"
    if [ "$(id -u)" -eq 0 ]; then
        apt-get update -qq
        apt-get install -y -qq "${MISSING[@]}"
    else
        info "not root — trying sudo …"
        sudo apt-get update -qq
        sudo apt-get install -y -qq "${MISSING[@]}"
    fi
    ok "system dependencies installed"
else
    ok "all system libraries present"
fi

# ── build ─────────────────────────────────────────────────────────────
echo
info "building gui …"
cd "$ROOT"
cargo build --release
ok "build complete — binary at $ROOT/target/release/oxide-gui"
