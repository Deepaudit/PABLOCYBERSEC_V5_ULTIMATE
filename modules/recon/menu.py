"""
modules/recon/menu.py

Integração do PC Recon com o menu principal da PABLOCYBERSEC V5.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict

from core.config import Settings
from core.logger import get_logger
from core.report import ReportManager
from core.ui import UI
from core.utils import ValidationError, parse_port_spec, validate_target

from .scanner import DEFAULT_TOP_PORTS, run_recon

log = get_logger("recon")


def run_interactive(ui: UI, settings: Settings, reporter: ReportManager) -> None:
    ui.header("PC Recon — Reconhecimento e Enumeração de Redes")
    ui.warn("Use apenas contra alvos que você tem autorização explícita para testar.")

    target_raw = ui.prompt("Alvo (IP ou hostname)")
    try:
        target = validate_target(target_raw)
    except ValidationError as exc:
        ui.error(str(exc))
        return

    if not ui.confirm(f"Confirma que você está autorizado a varrer '{target}'?", default=False):
        ui.warn("Operação cancelada pelo usuário.")
        return

    port_spec = ui.prompt(
        "Portas (ex: 1-1024, 22,80,443) [ENTER = top portas conhecidas]"
    )
    try:
        ports = parse_port_spec(port_spec) if port_spec else list(DEFAULT_TOP_PORTS)
    except ValidationError as exc:
        ui.error(str(exc))
        return

    if len(ports) > settings.max_ports_per_scan:
        ui.warn(
            f"Número de portas ({len(ports)}) excede o limite configurado "
            f"({settings.max_ports_per_scan}). Ajustando para o limite."
        )
        ports = ports[: settings.max_ports_per_scan]

    banners_raw = ui.prompt("Capturar banners? [S/n]") or "s"
    grab_banners = banners_raw.lower() in ("s", "sim", "y", "yes")

    ui.info(
        f"Varrendo {len(ports)} porta(s) em {target} "
        f"(timeout={settings.default_timeout_seconds}s, "
        f"concorrência={settings.max_concurrent_connections})..."
    )
    log.info(f"Iniciando varredura de recon em alvo={target} portas={len(ports)}")

    try:
        result = asyncio.run(
            run_recon(
                target,
                ports=ports,
                timeout=settings.default_timeout_seconds,
                concurrency=settings.max_concurrent_connections,
                grab_banners=grab_banners,
            )
        )
    except KeyboardInterrupt:
        ui.warn("Varredura interrompida pelo usuário.")
        return
    except Exception as exc:  # defesa: nunca deixar o framework cair por um módulo
        ui.error(f"Erro inesperado durante a varredura: {exc}")
        log.exception("Erro no PC Recon")
        return

    _print_result(ui, result)

    if ui.confirm("Salvar relatório desta varredura?", default=True):
        path = reporter.save("recon", f"Recon de {target}", asdict(result))
        ui.success(f"Relatório salvo em: {path}")


def _print_result(ui: UI, result) -> None:
    ui.header(f"Resultado — {result.target}")
    if result.errors and not result.resolved_ip:
        for err in result.errors:
            ui.error(err)
        return

    ui.info(f"IP resolvido: {result.resolved_ip}")
    if result.alive is not None:
        status = "provavelmente ativo" if result.alive else "sem resposta nas sondas"
        (ui.success if result.alive else ui.warn)(f"Status do host: {status}")

    if result.dns_records:
        for rtype, values in result.dns_records.items():
            if values:
                ui.info(f"{rtype}: {', '.join(values)}")

    open_ports = [p for p in result.ports if p.state == "open"]
    if not open_ports:
        ui.warn("Nenhuma porta aberta encontrada na faixa varrida.")
    else:
        rows = []
        for p in open_ports:
            banner = (p.banner or "").replace("\n", " ").replace("\r", "")[:40]
            rows.append([str(p.port), p.service_guess or "?", f"{p.latency_ms or '-'}", banner])
        ui.table(["PORTA", "SERVIÇO", "LATÊNCIA(ms)", "BANNER"], rows)

    for err in result.errors:
        ui.warn(err)

    ui.info(f"Duração da varredura: {result.scan_duration_seconds}s")
