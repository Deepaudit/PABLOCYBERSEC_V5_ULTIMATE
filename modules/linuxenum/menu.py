"""
modules/linuxenum/menu.py

Integração do PC LinuxEnum com o menu principal.
"""

from __future__ import annotations

from dataclasses import asdict

from core.config import Settings
from core.logger import get_logger
from core.report import ReportManager
from core.ui import UI

from . import engine

log = get_logger("linuxenum")


def run_interactive(ui: UI, settings: Settings, reporter: ReportManager) -> None:
    ui.header("PC LinuxEnum — Enumeração e Auditoria Local (somente leitura)")
    ui.info("Este módulo não modifica permissões, instala persistência ou altera o sistema.")

    profile = ui.prompt("Perfil de enumeração: básico (b) ou completo (c)? [b/c]") or "b"
    profile_key = "completo" if profile.lower().startswith("c") else "basico"

    ui.info("Coletando informações locais...")
    try:
        report = engine.run_full_enum(profile=profile_key)
    except Exception as exc:
        ui.error(f"Erro durante a enumeração: {exc}")
        log.exception("Erro no PC LinuxEnum")
        return

    _print_report(ui, report)

    if ui.confirm("Salvar relatório?", default=True):
        payload = asdict(report)
        reporter.save("linuxenum", f"Enumeração Linux ({profile_key})", payload)


def _print_report(ui: UI, report) -> None:
    ui.header("Usuário atual")
    u = report.current_user
    ui.info(f"{u.username} (uid={u.uid}, gid={u.gid}) shell={u.shell}")
    if u.groups:
        ui.info("Grupos: " + ", ".join(u.groups))

    ui.header("Sudo")
    if report.sudo_info and report.sudo_info.entries:
        for entry in report.sudo_info.entries:
            print(f"  {entry}")
        if report.sudo_info.can_run_as_root_without_password:
            ui.warn("Encontrada regra NOPASSWD — investigar possível escalonamento.")
    else:
        ui.info("Nenhuma permissão sudo detectável sem senha interativa (ou 'sudo' indisponível).")

    ui.header("Arquivos com permissões especiais (SUID/SGID/world-writable)")
    if report.special_permission_files:
        rows = []
        for f in report.special_permission_files[:40]:
            flags = []
            if f.is_suid:
                flags.append("SUID")
            if f.is_sgid:
                flags.append("SGID")
            if f.is_world_writable:
                flags.append("WORLD-WRITABLE")
            if f.known_gtfobins_hint:
                flags.append("GTFOBINS?")
            rows.append([f.path, f.permissions, "/".join(flags)])
        ui.table(["CAMINHO", "PERMISSÕES", "FLAGS"], rows)
        if len(report.special_permission_files) > 40:
            ui.info(f"... e mais {len(report.special_permission_files) - 40} resultado(s).")
    else:
        ui.info("Nenhum arquivo com permissões especiais encontrado nos diretórios verificados.")

    if report.writable_sensitive_paths:
        ui.warn("Caminhos sensíveis graváveis pelo usuário atual: " + ", ".join(report.writable_sensitive_paths))

    if report.cron_jobs:
        ui.header("Tarefas agendadas (cron)")
        for job in report.cron_jobs[:20]:
            print(f"  {job}")

    if report.listening_ports:
        ui.header("Portas em escuta")
        for line in report.listening_ports[:20]:
            print(f"  {line}")

    if report.network_interfaces:
        ui.header("Interfaces de rede")
        for line in report.network_interfaces[:20]:
            print(f"  {line}")

    if report.kernel_info:
        ui.header("Kernel / Sistema")
        ui.info(report.kernel_info)

    if report.notes:
        ui.header("Observações para investigação manual")
        for note in report.notes:
            ui.warn(note)
