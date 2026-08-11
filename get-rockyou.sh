#!/bin/bash
# Download rockyou.txt into the SeaLion directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="$SCRIPT_DIR/rockyou.txt"

if [ -f "$TARGET" ]; then
    echo "[*] rockyou.txt already exists at $TARGET"
    wc -l "$TARGET"
    exit 0
fi

echo "[*] Downloading rockyou.txt.tar.gz from SecLists..."
TMP="$SCRIPT_DIR/rockyou.txt.tar.gz"
curl -L -o "$TMP" \
    "https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz" \
    2>/dev/null || wget -q -O "$TMP" \
    "https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz"

if [ ! -f "$TMP" ]; then
    echo "[!] Download failed. Try manually:"
    echo "    curl -L -o rockyou.txt.tar.gz https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz"
    exit 1
fi

echo "[*] Extracting..."
tar xzf "$TMP" -C "$SCRIPT_DIR" 2>/dev/null
rm -f "$TMP"

if [ -f "$TARGET" ]; then
    echo "[+] Done! rockyou.txt saved to $TARGET"
    wc -l "$TARGET"
else
    echo "[!] Extraction failed — file not found after tar."
    exit 1
fi
