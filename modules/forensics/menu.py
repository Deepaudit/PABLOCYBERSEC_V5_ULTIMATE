"""
modules/forensics/menu.py

Integração do PC Forensics com o menu principal.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from core.config import Settings
from core.logger import get_logger
from core.report import ReportManager
from core.ui import UI

from . import engine

log = get_logger("forensics")

_SUBMENU = [
    ("1", "Identificar tipo real do arquivo (assinatura/magic bytes)"),
    ("2", "Calcular hashes e metadados"),
    ("3", "Extrair strings imprimíveis"),
    ("4", "Buscar padrão (regex) nas strings extraídas"),
    ("5", "Visualizar dump hexadecimal de uma seção"),
    ("0", "Voltar ao menu principal"),
]


def run_interactive(ui: UI, settings: Settings, reporter: ReportManager) -> None:
    ui.header("PC Forensics — Análise Forense Digital")
    path_str = ui.prompt("Caminho do arquivo de evidência")
    if not path_str:
        return
    path = Path(path_str).expanduser()
    if not path.is_file():
        ui.error("Arquivo não encontrado.")
        return

    log.info(f"Análise forense iniciada em: {path}")
    ui.info("O arquivo original NÃO será modificado por este módulo (somente leitura).")

    cached_strings: list[str] | None = None

    while True:
        ui.menu(f"PC Forensics — evidência: {path.name}", _SUBMENU)
        choice = ui.prompt("Escolha uma opção")
        if choice in ("0", ""):
            return
        try:
            if choice == "1":
                _signature(ui, path, reporter)
            elif choice == "2":
                _metadata(ui, path, reporter)
            elif choice == "3":
                cached_strings = _strings(ui, path, reporter)
            elif choice == "4":
                cached_strings = _search(ui, path, cached_strings)
            elif choice == "5":
                _hexdump(ui, path)
            else:
                ui.error("Opção inválida.")
        except (OSError, ValueError) as exc:
            ui.error(f"Erro: {exc}")


def _signature(ui: UI, path: Path, reporter: ReportManager) -> None:
    result = engine.identify_signature(path)
    ui.header("Identificação por assinatura")
    ui.info(f"Extensão declarada: .{result.extension_claimed}")
    ui.info(f"Tipo detectado pela assinatura: {result.detected_type or 'desconhecido'}")
    if result.mime_guess:
        ui.info(f"MIME estimado: {result.mime_guess}")
    ui.info(f"Primeiros bytes (hex): {result.first_bytes_hex}")
    if result.mismatch_warning:
        ui.warn(result.mismatch_warning)
    if ui.confirm("Salvar no histórico?", default=False):
        reporter.save("forensics", f"Assinatura de {path.name}", asdict(result))


def _metadata(ui: UI, path: Path, reporter: ReportManager) -> None:
    result = engine.compute_metadata(path)
    ui.header("Metadados")
    ui.info(f"Tamanho: {result.size_bytes} bytes")
    ui.info(f"MD5:    {result.md5}")
    ui.info(f"SHA256: {result.sha256}")
    if result.is_zip_based:
        ui.success(f"Arquivo baseado em ZIP com {len(result.zip_contents)} entrada(s) listada(s):")
        for name in result.zip_contents[:20]:
            print(f"  {name}")
    for note in result.notes:
        ui.info(note)
    if ui.confirm("Salvar relatório?", default=True):
        reporter.save("forensics", f"Metadados de {path.name}", asdict(result))


def _strings(ui: UI, path: Path, reporter: ReportManager) -> list[str]:
    min_len_raw = ui.prompt("Comprimento mínimo das strings [ENTER = 4]") or "4"
    try:
        min_len = int(min_len_raw)
    except ValueError:
        ui.error("Valor inválido, usando 4.")
        min_len = 4

    result = engine.extract_strings(path, min_length=min_len)
    ui.success(f"{result.total_found} string(s) encontradas" + (" (truncado)" if result.truncated else ""))
    for s in result.strings[:30]:
        print(f"  {s}")
    if result.total_found > 30:
        ui.info(f"... e mais {result.total_found - 30} (use a busca por padrão para filtrar).")

    if ui.confirm("Salvar lista completa no histórico?", default=False):
        reporter.save("forensics", f"Strings de {path.name}", {"total": result.total_found, "strings": result.strings})
    return result.strings


def _search(ui: UI, path: Path, cached_strings: list[str] | None) -> list[str]:
    if cached_strings is None:
        ui.info("Extraindo strings primeiro (ainda não haviam sido extraídas nesta sessão)...")
        cached_strings = engine.extract_strings(path).strings

    pattern = ui.prompt("Padrão regex a buscar (ex: flag\\{.*\\})")
    if not pattern:
        return cached_strings
    matches = engine.search_pattern_in_strings(cached_strings, pattern)
    if matches:
        ui.success(f"{len(matches)} correspondência(s):")
        for m in matches[:30]:
            print(f"  {m}")
    else:
        ui.warn("Nenhuma correspondência encontrada.")
    return cached_strings


def _hexdump(ui: UI, path: Path) -> None:
    offset_raw = ui.prompt("Offset inicial (em bytes) [ENTER = 0]") or "0"
    length_raw = ui.prompt("Quantidade de bytes a exibir [ENTER = 256]") or "256"
    try:
        offset = int(offset_raw)
        length = int(length_raw)
    except ValueError:
        ui.error("Valores inválidos.")
        return
    print(engine.hex_dump(path, offset=offset, length=length))
