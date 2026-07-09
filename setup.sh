#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENTRY="$SCRIPT_DIR/sealion.py"
BIN_DIR="$HOME/.local/bin"
CMD_NAMES=("slconsole" "sealsay")

echo "=== SeaLion Console — Setup ==="
echo ""

# Assicura che sealion.py sia eseguibile
chmod +x "$ENTRY"

# Crea la cartella bin se non esiste
mkdir -p "$BIN_DIR"

# Crea i launcher (wrapper sottile, non symlink — funziona anche su NTFS/WSL)
for CMD_NAME in "${CMD_NAMES[@]}"; do
    cat > "$BIN_DIR/$CMD_NAME" <<EOF
#!/usr/bin/env bash
exec python3 "$ENTRY" "\$@"
EOF
    chmod +x "$BIN_DIR/$CMD_NAME"
    echo "Launcher creato: $BIN_DIR/$CMD_NAME"
done
echo ""

# Verifica PATH
if echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
    echo "  ✓ $BIN_DIR è già nel PATH"
else
    # Aggiunge al .bashrc se non c'è già
    EXPORT_LINE="export PATH=\"\$HOME/.local/bin:\$PATH\""
    if ! grep -qF '.local/bin' "$HOME/.bashrc" 2>/dev/null; then
        echo "" >> "$HOME/.bashrc"
        echo "# SeaLion Console" >> "$HOME/.bashrc"
        echo "$EXPORT_LINE" >> "$HOME/.bashrc"
        echo "  ✓ PATH aggiornato in ~/.bashrc"
        echo "    Esegui: source ~/.bashrc  (oppure apri un nuovo terminale)"
    else
        echo "  ✓ ~/.local/bin già presente in ~/.bashrc"
    fi
    export PATH="$BIN_DIR:$PATH"
fi

echo ""
echo "Installazione completata. Scrivi 'slconsole' o 'sealsay' per avviare."
