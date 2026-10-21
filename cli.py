#!/usr/bin/env python3
"""
PABLOCYBERSEC V5 — ULTIMATE LINUX CTF FRAMEWORK
Ponto de entrada principal.

Uso:
    python3 cli.py

Desenvolvido por PabloCyberSec.
"""

from __future__ import annotations

import importlib
import sys
import traceback
from dataclasses import dataclass

from core.config import Settings, ensure_directories, is_root
from core.logger import get_logger
from core.report import ReportManager
from core.ui import UI

log = get_logger("cli")

MIN_PYTHON = (3, 10)


@dataclass
class ModuleEntry:
    key: str
    label: str
    module_path: str  # ex: "modules.recon.menu"
    description: str


MODULES: list[ModuleEntry] = [
    ModuleEntry("01", "Reconhecimento de redes (PC Recon)", "modules.recon.menu",
                "Descoberta de hosts, varredura de portas TCP, banners e DNS."),
    ModuleEntry("02", "HashLab", "modules.hashlab.menu",
                "Identificação, cálculo, comparação e teste de hashes em wordlists."),
    ModuleEntry("03", "CipherLab", "modules.cipherlab.menu",
                "Codificação/decodificação e criptoanálise assistida para CTF."),
    ModuleEntry("04", "NetCore", "modules.netcore.menu",
                "Cliente/servidor TCP, testes de conectividade e transferência de arquivos."),
    ModuleEntry("05", "WebHunter", "modules.webhunter.menu",
                "Inspeção de cabeçalhos HTTP, TLS, cookies e enumeração de diretórios."),
    ModuleEntry("06", "VulnScope", "modules.vulnscope.menu",
                "Correlação de serviços/versões com referências de vulnerabilidades (hipóteses)."),
    ModuleEntry("07", "LinuxEnum", "modules.linuxenum.menu",
                "Enumeração local somente leitura para desafios de privilege escalation."),
    ModuleEntry("08", "Forensics", "modules.forensics.menu",
                "Identificação de assinatura de arquivo, metadados, strings e hex dump."),
    ModuleEntry("09", "PacketLab", "modules.packetlab.menu",
                "Análise de capturas PCAP (integração opcional com Scapy)."),
    ModuleEntry("10", "FlagHunter", "modules.flaghunter.menu",
                "Assistente de organização e detecção de padrões de flag para CTF."),
]

MODULE_INDEX = {m.key: m for m in MODULES}


def check_python_version(ui: UI) -> bool:
    if sys.version_info < MIN_PYTHON:
        ui.error(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ é necessário. "
            f"Versão detectada: {sys.version_info.major}.{sys.version_info.minor}"
        )
        return False
    return True


def check_dependencies(ui: UI) -> None:
    ui.header("Verificação de dependências")
    ui.info(f"Python: {sys.version.split()[0]}")
    ui.info(f"Executando como root: {'sim' if is_root() else 'não'}")

    optional_deps = {
        "scapy": "necessário para PC PacketLab (análise completa de PCAP)",
    }
    for dep, purpose in optional_deps.items():
        try:
            importlib.import_module(dep)
            ui.success(f"{dep}: disponível — {purpose}")
        except ImportError:
            ui.warn(f"{dep}: NÃO disponível — {purpose}. Funcionalidade terá fallback limitado.")

    system_tools = ["ss", "ip", "sudo", "crontab", "ps", "uname"]
    import shutil as _shutil
    for tool in system_tools:
        path = _shutil.which(tool)
        if path:
            ui.success(f"{tool}: encontrado em {path}")
        else:
            ui.warn(f"{tool}: não encontrado no PATH — algumas funções do PC LinuxEnum serão limitadas.")

    ui.info("Nenhuma dependência listada acima é estritamente obrigatória para iniciar a ferramenta;")
    ui.info("elas apenas habilitam funcionalidades específicas de módulos individuais.")


def show_settings(ui: UI, settings: Settings) -> None:
    ui.header("Configurações atuais")
    rows = [
        ["max_concurrent_connections", str(settings.max_concurrent_connections)],
        ["default_timeout_seconds", str(settings.default_timeout_seconds)],
        ["max_ports_per_scan", str(settings.max_ports_per_scan)],
        ["rate_limit_requests_per_second", str(settings.rate_limit_requests_per_second)],
        ["http_request_timeout", str(settings.http_request_timeout)],
        ["hash_wordlist_max_lines", str(settings.hash_wordlist_max_lines)],
        ["log_level", settings.log_level],
        ["redact_sensitive_values", str(settings.redact_sensitive_values)],
        ["color_output", str(settings.color_output)],
        ["require_explicit_target_for_active_modules", str(settings.require_explicit_target_for_active_modules)],
    ]
    ui.table(["PARÂMETRO", "VALOR"], rows)
    print()
    if ui.confirm("Deseja editar algum parâmetro numérico agora?", default=False):
        _edit_settings(ui, settings)


def _edit_settings(ui: UI, settings: Settings) -> None:
    editable_numeric = [
        "max_concurrent_connections", "default_timeout_seconds", "max_ports_per_scan",
        "rate_limit_requests_per_second", "http_request_timeout", "hash_wordlist_max_lines",
    ]
    ui.info("Parâmetros editáveis: " + ", ".join(editable_numeric))
    field_name = ui.prompt("Nome do parâmetro a editar")
    if field_name not in editable_numeric:
        ui.error("Parâmetro inválido ou não editável por aqui.")
        return
    new_value_raw = ui.prompt("Novo valor")
    try:
        new_value = float(new_value_raw) if "." in new_value_raw else int(new_value_raw)
    except ValueError:
        ui.error("Valor inválido.")
        return
    setattr(settings, field_name, new_value)
    settings.save()
    ui.success(f"'{field_name}' atualizado para {new_value} e salvo em config/settings.json.")


def show_history(ui: UI, reporter: ReportManager) -> None:
    ui.header("Histórico de relatórios")
    entries = reporter.list_history(limit=30)
    if not entries:
        ui.info("Nenhum relatório salvo ainda.")
        return
    rows = [[e["id"], e["module"], e["title"], e["generated_at"][:19]] for e in entries]
    ui.table(["ID", "MÓDULO", "TÍTULO", "DATA/HORA (UTC)"], rows)

    if ui.confirm("Deseja visualizar algum relatório pelo ID?", default=False):
        report_id = ui.prompt("ID do relatório")
        data = reporter.load(report_id)
        if data is None:
            ui.error("Relatório não encontrado.")
            return
        import json
        print(json.dumps(data, indent=2, ensure_ascii=False)[:4000])


def show_help(ui: UI) -> None:
    ui.header("Ajuda — PABLOCYBERSEC V5")
    print(
        "PABLOCYBERSEC V5 é um framework modular de cibersegurança para Linux,\n"
        "voltado a CTFs, laboratórios educacionais, TryHackMe e Hack The Box.\n\n"
        "Navegação:\n"
        "  - Digite o número entre colchetes para entrar em um módulo.\n"
        "  - Dentro de cada módulo, '0' ou ENTER volta ao menu anterior.\n"
        "  - Ctrl+C a qualquer momento retorna com segurança ao menu principal.\n\n"
        "Módulos ativos (que fazem conexões de rede reais) sempre pedem\n"
        "confirmação explícita de autorização antes de testar um alvo.\n\n"
        "Documentação completa: consulte README.md no repositório.\n"
    )
    ui.info("Módulos disponíveis:")
    for m in MODULES:
        print(f"  [{m.key}] {m.label} — {m.description}")


def run_module(ui: UI, settings: Settings, reporter: ReportManager, entry: ModuleEntry) -> None:
    try:
        module = importlib.import_module(entry.module_path)
    except ImportError as exc:
        ui.error(f"Falha ao carregar o módulo '{entry.label}': {exc}")
        log.exception(f"Falha ao importar {entry.module_path}")
        return

    if not hasattr(module, "run_interactive"):
        ui.error(f"Módulo '{entry.label}' não implementa run_interactive(). Reporte este bug.")
        return

    try:
        module.run_interactive(ui, settings, reporter)
    except KeyboardInterrupt:
        ui.warn("\nOperação interrompida. Retornando ao menu principal.")
    except Exception as exc:  # nunca deixar um módulo derrubar o framework inteiro
        ui.error(f"Erro inesperado no módulo '{entry.label}': {exc}")
        log.error(f"Erro não tratado em {entry.module_path}: {exc}\n{traceback.format_exc()}")
        ui.info("O erro foi registrado em logs/pablocybersec.log. Retornando ao menu principal.")


def main() -> int:
    ensure_directories()
    settings = Settings.load()
    ui = UI(color_enabled=settings.color_output)

    if not check_python_version(ui):
        return 1

    reporter = ReportManager()

    if settings.banner_enabled:
        ui.banner()

    log.info("PABLOCYBERSEC V5 iniciado.")

    top_level_options = [(m.key, m.label) for m in MODULES] + [
        ("11", "Verificar dependências"),
        ("12", "Configurações"),
        ("13", "Histórico e relatórios"),
        ("14", "Ajuda"),
        ("00", "Sair"),
    ]

    while True:
        try:
            ui.menu("MENU PRINCIPAL", top_level_options)
            choice = ui.prompt("Selecione uma opção")
        except KeyboardInterrupt:
            print()
            choice = "00"

        if choice == "00" or choice == "":
            if choice == "":
                continue
            ui.info("Encerrando PABLOCYBERSEC V5. Até a próxima!")
            log.info("PABLOCYBERSEC V5 encerrado pelo usuário.")
            return 0
        elif choice in MODULE_INDEX:
            run_module(ui, settings, reporter, MODULE_INDEX[choice])
        elif choice == "11":
            check_dependencies(ui)
        elif choice == "12":
            show_settings(ui, settings)
        elif choice == "13":
            show_history(ui, reporter)
        elif choice == "14":
            show_help(ui)
        else:
            ui.error("Opção inválida. Tente novamente.")


if __name__ == "__main__":
    sys.exit(main())
