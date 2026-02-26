#!/bin/bash
set -e

# Proje kökünü bul
ROOT=$(dirname $(dirname "$0"))

# Çıktı klasörünü hazırla
mkdir -p "$ROOT/logs"
rm -f "$ROOT/logs/"*

echo "[*] Compiling Spicy..."
spicyz -o "$ROOT/spicy/cifs.hlto" "$ROOT/spicy/cifs.spicy" "$ROOT/spicy/cifs.evt"

echo "[*] Running Zeek..."
zeek -Cr "$ROOT/pcaps/cifs.pcap" "$ROOT/spicy/cifs.hlto" "$ROOT/zeek"

echo "[*] Logs saved under $ROOT/logs"
mv *.log "$ROOT/logs/" 2>/dev/null || true
