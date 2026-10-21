"""
modules/packetlab/menu.py

Integração do PC PacketLab com o menu principal.
"""

from __future__ import annotations

from pathlib import Path

from core.config import Settings
from core.logger import get_logger
from core.report import ReportManager
from core.ui import UI

from . import engine

log = get_logger("packetlab")

_SUBMENU = [
    ("1", "Analisar arquivo PCAP (requer Scapy)"),
    ("2", "Ler cabeçalho PCAP sem dependências externas (fallback)"),
    ("3", "Verificar privilégios para captura ao vivo (não captura nada)"),
    ("0", "Voltar ao menu principal"),
]


def run_interactive(ui: UI, settings: Settings, reporter: ReportManager) -> None:
    ui.header("PC PacketLab — Análise de Tráfego e Protocolos")
    if engine.check_scapy_available():
        ui.success("Scapy detectado — análise completa de PCAP disponível.")
    else:
        ui.warn(
            "Scapy NÃO está instalado neste ambiente. A opção 1 ficará indisponível; "
            "use a opção 2 para leitura básica de cabeçalho PCAP, ou instale com "
            "'pip install scapy'."
        )

    while True:
        ui.menu("PC PacketLab", _SUBMENU)
        choice = ui.prompt("Escolha uma opção")
        if choice in ("0", ""):
            return
        try:
            if choice == "1":
                _analyze(ui, reporter)
            elif choice == "2":
                _fallback_header(ui)
            elif choice == "3":
                _check_privileges(ui)
            else:
                ui.error("Opção inválida.")
        except (OSError, ValueError, RuntimeError) as exc:
            ui.error(f"Erro: {exc}")


def _analyze(ui: UI, reporter: ReportManager) -> None:
    if not engine.check_scapy_available():
        ui.error("Scapy não está instalado. Instale com 'pip install scapy' para usar esta opção.")
        return
    path_str = ui.prompt("Caminho do arquivo PCAP/PCAPNG")
    path = Path(path_str).expanduser()
    if not path.is_file():
        ui.error("Arquivo não encontrado.")
        return

    ui.info("Analisando captura (isso pode levar alguns segundos para arquivos grandes)...")
    analysis = engine.analyze_pcap(path)

    ui.header("Resumo da captura")
    ui.info(f"Total de pacotes: {analysis.total_packets}")
    ui.info("Contagem por protocolo:")
    for proto, count in sorted(analysis.protocol_counts.items(), key=lambda kv: kv[1], reverse=True):
        print(f"  {proto}: {count}")

    if analysis.top_talkers:
        ui.info("Top talkers (IP mais ativo):")
        for ip, count in analysis.top_talkers:
            print(f"  {ip}: {count} pacote(s)")

    if analysis.dns_queries:
        ui.info(f"Consultas DNS únicas ({len(analysis.dns_queries)}):")
        for q in analysis.dns_queries[:20]:
            print(f"  {q}")

    if analysis.http_hosts:
        ui.info(f"Hosts HTTP observados ({len(analysis.http_hosts)}):")
        for h in analysis.http_hosts[:20]:
            print(f"  {h}")

    if ui.confirm("Salvar relatório?", default=True):
        from dataclasses import asdict
        reporter.save("packetlab", f"Análise de {path.name}", asdict(analysis))


def _fallback_header(ui: UI) -> None:
    path_str = ui.prompt("Caminho do arquivo PCAP")
    path = Path(path_str).expanduser()
    if not path.is_file():
        ui.error("Arquivo não encontrado.")
        return
    info = engine.read_pcap_header_without_scapy(path)
    ui.header("Cabeçalho PCAP")
    for key, value in info.items():
        ui.info(f"{key}: {value}")


def _check_privileges(ui: UI) -> None:
    ok, message = engine.check_raw_capture_privileges()
    (ui.success if ok else ui.warn)(message)
