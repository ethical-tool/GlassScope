#!/usr/bin/env bash
# GlassScope Studio — uninstaller (copied to /opt/glassscope at install time)
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo:  sudo /opt/glassscope/uninstall.sh"
    exit 1
fi
rm -f /usr/local/bin/glassscope
rm -f /usr/share/applications/glassscope.desktop
rm -f /usr/share/pixmaps/glassscope.png
rm -rf /opt/glassscope
echo "GlassScope Studio removed."
