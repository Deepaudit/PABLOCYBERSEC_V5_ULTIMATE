#!/usr/bin/env bash
#
# install.sh — Instalador da PABLOCYBERSEC V5
#
# O que este script FAZ:
#   1. Detecta a distribuição Linux e avisa sobre compatibilidade conhecida.
#   2. Verifica se Python 3.10+ e pip estão disponíveis.
#   3. Cria um ambiente virtual Python em .venv/ (não instala nada globalmente).
#   4. Instala as dependências de requirements.txt dentro do venv.
#   5. Cria os diretórios de apoio (logs/, reports/, data/, config/).
#   6. Torna cli.py executável e oferece criar um atalho opcional em ~/.local/bin.
#
# O que este script NÃO FAZ:
#   - Não exige root para nada, exceto se você mesmo rodar com sudo por escolha.
#   - Não desativa firewall, SELinux, AppArmor ou qualquer proteção do sistema.
#   - Não baixa nem executa scripts remotos de terceiros.
#   - Não sobrescreve configurações existentes sem perguntar.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[x]${NC} $1"; }

echo "=================================================="
echo "   PABLOCYBERSEC V5 — Instalador"
echo "   ONE FRAMEWORK. MULTIPLE CAPABILITIES."
echo "=================================================="
echo

# ---------------------------------------------------------------------------
# 1. Detecção de distribuição
# ---------------------------------------------------------------------------
DISTRO_ID="desconhecida"
DISTRO_NAME="Linux genérico"
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    DISTRO_ID="${ID:-desconhecida}"
    DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"
fi

info "Distribuição detectada: $DISTRO_NAME"

case "$DISTRO_ID" in
    kali)
        ok "Kali Linux é oficialmente testado para a PABLOCYBERSEC V5."
        ;;
    debian)
        ok "Debian é oficialmente testado para a PABLOCYBERSEC V5."
        ;;
    ubuntu)
        ok "Ubuntu é oficialmente testado para a PABLOCYBERSEC V5."
        ;;
    fedora|arch|opensuse*|centos|rhel)
        warn "Distribuição '$DISTRO_NAME' não está na lista oficialmente testada,"
        warn "mas deve funcionar normalmente (dependência principal é Python 3.10+)."
        ;;
    *)
        warn "Distribuição não reconhecida automaticamente. A instalação prosseguirá,"
        warn "mas recomenda-se verificar manualmente os requisitos no README.md."
        ;;
esac
echo

# ---------------------------------------------------------------------------
# 2. Verificação do Python
# ---------------------------------------------------------------------------
PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    fail "Python 3 não encontrado no PATH."
    echo "    Instale com uma das opções abaixo e execute este script novamente:"
    echo "      Debian/Ubuntu/Kali: sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
    echo "      Fedora:             sudo dnf install -y python3 python3-pip"
    echo "      Arch:               sudo pacman -S python python-pip"
    exit 1
fi

PY_VERSION="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJOR="$("$PYTHON_BIN" -c 'import sys; print(sys.version_info[0])')"
PY_MINOR="$("$PYTHON_BIN" -c 'import sys; print(sys.version_info[1])')"

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    fail "Python 3.10+ é necessário. Encontrado: $PY_VERSION ($PYTHON_BIN)"
    exit 1
fi
ok "Python $PY_VERSION encontrado em $(command -v "$PYTHON_BIN")"

# Verifica módulo venv
if ! "$PYTHON_BIN" -c "import venv" >/dev/null 2>&1; then
    fail "O módulo 'venv' do Python não está disponível."
    case "$DISTRO_ID" in
        debian|ubuntu|kali)
            echo "    Instale com: sudo apt install -y python3-venv"
            ;;
        *)
            echo "    Instale o pacote de ambiente virtual da sua distribuição."
            ;;
    esac
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# 3. Criação do ambiente virtual
# ---------------------------------------------------------------------------
VENV_DIR="$SCRIPT_DIR/.venv"
if [ -d "$VENV_DIR" ]; then
    warn "Ambiente virtual já existe em $VENV_DIR"
    read -r -p "Deseja recriá-lo do zero? [s/N] " recreate
    if [[ "$recreate" =~ ^[sS]$ ]]; then
        rm -rf "$VENV_DIR"
        info "Ambiente virtual removido. Recriando..."
        "$PYTHON_BIN" -m venv "$VENV_DIR"
    fi
else
    info "Criando ambiente virtual em $VENV_DIR ..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi
ok "Ambiente virtual pronto."
echo

# ---------------------------------------------------------------------------
# 4. Instalação de dependências
# ---------------------------------------------------------------------------
VENV_PY="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

info "Atualizando pip dentro do ambiente virtual..."
"$VENV_PY" -m pip install --upgrade pip --quiet || warn "Não foi possível atualizar o pip (prosseguindo mesmo assim)."

if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    info "Instalando dependências de requirements.txt..."
    if "$VENV_PIP" install -r "$SCRIPT_DIR/requirements.txt"; then
        ok "Dependências instaladas com sucesso."
    else
        warn "Falha ao instalar uma ou mais dependências opcionais (ex.: scapy)."
        warn "A ferramenta funcionará com funcionalidade reduzida nos módulos afetados."
        warn "Você pode tentar novamente mais tarde com:"
        warn "  $VENV_PIP install -r requirements.txt"
    fi
else
    warn "requirements.txt não encontrado — pulando instalação de dependências."
fi
echo

# ---------------------------------------------------------------------------
# 5. Diretórios de apoio
# ---------------------------------------------------------------------------
info "Criando diretórios de apoio..."
mkdir -p "$SCRIPT_DIR"/{logs,reports,data,config,wordlists}
ok "Diretórios prontos: logs/ reports/ data/ config/ wordlists/"
echo

# ---------------------------------------------------------------------------
# 6. Permissão de execução e atalho opcional
# ---------------------------------------------------------------------------
chmod +x "$SCRIPT_DIR/cli.py" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/uninstall.sh" 2>/dev/null || true

cat > "$SCRIPT_DIR/pablocybersec" <<EOF
#!/usr/bin/env bash
# Wrapper gerado pelo install.sh — executa a PABLOCYBERSEC V5 usando o venv do projeto.
exec "$VENV_PY" "$SCRIPT_DIR/cli.py" "\$@"
EOF
chmod +x "$SCRIPT_DIR/pablocybersec"
ok "Script de inicialização criado: $SCRIPT_DIR/pablocybersec"

read -r -p "Deseja criar um atalho 'pablocybersec' em ~/.local/bin (sem usar sudo)? [s/N] " create_shortcut
if [[ "$create_shortcut" =~ ^[sS]$ ]]; then
    mkdir -p "$HOME/.local/bin"
    ln -sf "$SCRIPT_DIR/pablocybersec" "$HOME/.local/bin/pablocybersec"
    ok "Atalho criado em ~/.local/bin/pablocybersec"
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        warn "~/.local/bin não está no seu PATH. Adicione ao seu shell rc, por exemplo:"
        warn "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
    fi
fi
echo

echo "=================================================="
ok "Instalação concluída."
echo "=================================================="
echo
echo "Para iniciar a PABLOCYBERSEC V5:"
echo "  ./pablocybersec"
echo "ou, diretamente:"
echo "  $VENV_PY cli.py"
echo
echo "Para verificar dependências e funcionamento básico, use a opção [11]"
echo "do menu principal após iniciar a ferramenta."
echo
warn "Limitações conhecidas:"
warn "  - Captura de tráfego ao vivo (PC PacketLab) e algumas verificações de"
warn "    PC LinuxEnum podem exigir privilégios adicionais (ver README.md)."
warn "  - Scapy é opcional; sem ele, PC PacketLab usa um modo de leitura básico."
