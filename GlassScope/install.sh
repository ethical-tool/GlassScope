#!/usr/bin/env bash
# GlassScope Studio — Kali Linux installer
# Installs the app to /opt/glassscope with a launcher and desktop entry.
set -euo pipefail

APP_NAME="GlassScope Studio"
PREFIX="/opt/glassscope"
BIN="/usr/local/bin/glassscope"
DESKTOP="/usr/share/applications/glassscope.desktop"
ICON="/usr/share/pixmaps/glassscope.png"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }

# --- 1. Kali-only gate ------------------------------------------------------
if [ -r /etc/os-release ]; then
    . /etc/os-release
else
    echo "Cannot read /etc/os-release — refusing to install." >&2
    exit 1
fi
case "${ID:-}${ID_LIKE:-}${PRETTY_NAME:-}" in
    *kali*|*Kali*) : ;;
    *)
        bold "$APP_NAME installs on Kali Linux only."
        echo "Detected: ${PRETTY_NAME:-unknown}. Aborting." >&2
        exit 1
        ;;
esac

# --- 2. Root check ------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    bold "Run the installer with sudo:  sudo ./install.sh"
    exit 1
fi

# --- 3. Dependencies -----------------------------------------------------------
bold "Checking dependencies..."
if ! command -v python3 >/dev/null 2>&1; then
    apt-get update && apt-get install -y python3
fi
if ! python3 -c "import tkinter" >/dev/null 2>&1; then
    bold "Installing python3-tk (GUI toolkit)..."
    apt-get update && apt-get install -y python3-tk
fi

# --- 4. Files -------------------------------------------------------------------
bold "Installing to $PREFIX ..."
mkdir -p "$PREFIX"
cp -r glassscope.py glassscope_core glassscope_gui assets uninstall.sh "$PREFIX/"
chmod 755 "$PREFIX/glassscope.py"

# --- 5. Launcher + desktop entry ---------------------------------------------------
cat > "$BIN" << 'LAUNCHER'
#!/bin/sh
exec /usr/bin/python3 /opt/glassscope/glassscope.py "$@"
LAUNCHER
chmod 755 "$BIN"

cp "$PREFIX/assets/logo.png" "$ICON"

cat > "$DESKTOP" << 'DESKTOP'
[Desktop Entry]
Type=Application
Name=GlassScope Studio
GenericName=Reverse Engineering Studio
Comment=Light-themed static analysis for ELF binaries, Electron/ASAR archives, JavaScript apps and websites
Exec=glassscope
Icon=glassscope
Terminal=false
Categories=Development;Security;Utility;
Keywords=reverse;engineering;binary;elf;asar;electron;analysis;
DESKTOP

# --- 6. Done -------------------------------------------------------------------------
bold "$APP_NAME installed."
echo "  Launch:      Applications menu -> GlassScope Studio, or run: glassscope"
echo "  Remove:      sudo /opt/glassscope/uninstall.sh   (copied alongside the app)"
echo
echo "Analyze only software you own or are authorized to examine."
