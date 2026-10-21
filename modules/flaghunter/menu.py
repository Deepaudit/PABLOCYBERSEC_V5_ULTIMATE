"""
modules/flaghunter/menu.py

Integração do PC FlagHunter com o menu principal.
"""

from __future__ import annotations

from core.config import DATA_DIR, Settings
from core.logger import get_logger
from core.report import ReportManager
from core.ui import UI

from . import engine

log = get_logger("flaghunter")

_SUBMENU = [
    ("1", "Analisar texto em busca de candidatos a flag"),
    ("2", "Adicionar hipótese ao caderno do caso atual"),
    ("3", "Adicionar evidência manual ao caderno"),
    ("4", "Confirmar flag manualmente (requer evidência)"),
    ("5", "Ver resumo do caderno atual"),
    ("6", "Trocar/criar caderno de caso"),
    ("0", "Voltar ao menu principal"),
]


def run_interactive(ui: UI, settings: Settings, reporter: ReportManager) -> None:
    ui.header("PC FlagHunter — Assistente de Resolução de CTF")
    manager = engine.NotebookManager(DATA_DIR)

    existing = manager.list_notebooks()
    if existing:
        ui.info("Cadernos existentes: " + ", ".join(existing))
    case_name = ui.prompt("Nome do caso/desafio [ENTER = 'default']") or "default"
    notebook = manager.create_or_load(case_name)
    ui.success(f"Caderno '{notebook.name}' carregado ({len(notebook.candidates)} candidato(s) registrados).")

    while True:
        ui.menu(f"PC FlagHunter — caso: {notebook.name}", _SUBMENU)
        choice = ui.prompt("Escolha uma opção")
        if choice in ("0", ""):
            manager.save(notebook)
            return
        if choice == "1":
            _analyze(ui, manager, notebook)
        elif choice == "2":
            _hypothesis(ui, manager, notebook)
        elif choice == "3":
            _evidence(ui, manager, notebook)
        elif choice == "4":
            _confirm(ui, manager, notebook)
        elif choice == "5":
            _summary(ui, notebook)
        elif choice == "6":
            case_name = ui.prompt("Nome do novo caderno")
            if case_name:
                manager.save(notebook)
                notebook = manager.create_or_load(case_name)
                ui.success(f"Caderno '{notebook.name}' carregado.")
        else:
            ui.error("Opção inválida.")


def _analyze(ui: UI, manager: engine.NotebookManager, notebook) -> None:
    text = ui.prompt("Cole o texto a analisar (saída de outro módulo, arquivo, etc.)")
    if not text:
        return
    source = ui.prompt("Rótulo da fonte (ex: 'strings do forensics', 'banner do recon')") or "entrada manual"

    candidates = engine.detect_flag_candidates(text, source_label=source)
    if candidates:
        ui.success(f"{len(candidates)} candidato(s) a flag encontrados:")
        for c in candidates:
            print(f"  [{c.pattern_name}] {c.value}  (fonte: {c.source_label})")
            notebook.candidates.append(c)
    else:
        ui.warn("Nenhum padrão de flag conhecido encontrado no texto.")

    clues = engine.detect_encoding_clues(text)
    for clue in clues:
        ui.info("Pista: " + clue)

    engine.add_evidence(notebook, "flaghunter", f"Análise de texto (fonte: {source})", {"text_preview": text[:300]})
    manager.save(notebook)


def _hypothesis(ui: UI, manager: engine.NotebookManager, notebook) -> None:
    text = ui.prompt("Descreva a hipótese")
    if not text:
        return
    tags_raw = ui.prompt("Tags (separadas por vírgula, opcional)")
    tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []
    engine.add_hypothesis(notebook, text, tags)
    manager.save(notebook)
    ui.success("Hipótese registrada.")


def _evidence(ui: UI, manager: engine.NotebookManager, notebook) -> None:
    module = ui.prompt("Módulo de origem da evidência (ex: recon, hashlab, manual)") or "manual"
    description = ui.prompt("Descrição da evidência")
    engine.add_evidence(notebook, module, description, {})
    manager.save(notebook)
    ui.success("Evidência registrada.")


def _confirm(ui: UI, manager: engine.NotebookManager, notebook) -> None:
    ui.warn(
        "A confirmação de flag é sempre manual — a plataforma não declara "
        "um desafio resolvido por conta própria."
    )
    flag_value = ui.prompt("Valor exato da flag confirmada")
    if not flag_value:
        return
    evidence = ui.prompt("Como você confirmou esta flag (ex: aceita pela plataforma X)?")
    if not evidence:
        ui.error("É necessário descrever a evidência da confirmação.")
        return
    engine.confirm_flag(notebook, flag_value, evidence)
    manager.save(notebook)
    ui.success(f"Flag '{flag_value}' marcada como confirmada no caderno '{notebook.name}'.")


def _summary(ui: UI, notebook) -> None:
    ui.header(f"Resumo do caderno: {notebook.name}")
    ui.info(f"Criado em: {notebook.created_at}")
    ui.info(f"Resolvido: {'Sim' if notebook.resolved else 'Não'}")
    if notebook.confirmed_flag:
        ui.success(f"Flag confirmada: {notebook.confirmed_flag}")

    if notebook.candidates:
        ui.info(f"Candidatos a flag registrados ({len(notebook.candidates)}):")
        for c in notebook.candidates[-20:]:
            print(f"  [{c.pattern_name}] {c.value} (fonte: {c.source_label})")

    if notebook.hypotheses:
        ui.info(f"Hipóteses registradas ({len(notebook.hypotheses)}):")
        for h in notebook.hypotheses[-10:]:
            tag_str = f" [{', '.join(h.tags)}]" if h.tags else ""
            print(f"  - {h.text}{tag_str}")

    if notebook.evidence_log:
        ui.info(f"Entradas no log de evidências: {len(notebook.evidence_log)}")
