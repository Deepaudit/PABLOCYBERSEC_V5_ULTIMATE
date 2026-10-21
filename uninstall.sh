#!/usr/bin/env bash
#
# uninstall.sh — Remove o ambiente virtual e os atalhos criados pelo install.sh.
#
# Este script NÃO apaga seus relatórios (reports/), logs (logs/), dados de
# FlagHunter (data/) ou wordlists (wordlists/) por padrão — eles são
# removidos apenas se você confirmar explicitamente cada um.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }

echo "=================================================="
echo "   PABLOCYBERSEC V5 — Desinstalador"
echo "=================================================="
echo

if [ -d "$SCRIPT_DIR/.venv" ]; then
    read -r -p "Remover o ambiente virtual (.venv/)? [s/N] " remove_venv
    if [[ "$remove_venv" =~ ^[sS]$ ]]; then
        rm -rf "$SCRIPT_DIR/.venv"
        ok "Ambiente virtual removido."
    else
        info "Ambiente virtual mantido."
    fi
fi

if [ -f "$SCRIPT_DIR/pablocybersec" ]; then
    read -r -p "Remover o script de inicialização 'pablocybersec'? [s/N] " remove_wrapper
    if [[ "$remove_wrapper" =~ ^[sS]$ ]]; then
        rm -f "$SCRIPT_DIR/pablocybersec"
        ok "Script de inicialização removido."
    fi
fi

SHORTCUT="$HOME/.local/bin/pablocybersec"
if [ -L "$SHORTCUT" ] || [ -f "$SHORTCUT" ]; then
    read -r -p "Remover atalho em ~/.local/bin/pablocybersec? [s/N] " remove_shortcut
    if [[ "$remove_shortcut" =~ ^[sS]$ ]]; then
        rm -f "$SHORTCUT"
        ok "Atalho removido."
    fi
fi

for dir in logs reports data; do
    if [ -d "$SCRIPT_DIR/$dir" ] && [ -n "$(ls -A "$SCRIPT_DIR/$dir" 2>/dev/null)" ]; then
        read -r -p "Remover TODO o conteúdo de '$dir/' (relatórios/dados gerados)? [s/N] " remove_data
        if [[ "$remove_data" =~ ^[sS]$ ]]; then
            rm -rf "${SCRIPT_DIR:?}/$dir"
            mkdir -p "$SCRIPT_DIR/$dir"
            ok "'$dir/' limpo."
        else
            info "'$dir/' mantido."
        fi
    fi
done

echo
ok "Desinstalação concluída. O código-fonte do projeto não foi removido —"
echo "    apague a pasta manualmente se desejar remover tudo:"
echo "    rm -rf \"$SCRIPT_DIR\""
