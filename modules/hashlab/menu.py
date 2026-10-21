"""
modules/hashlab/menu.py

Integração do PC HashLab com o menu principal.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from core.config import Settings, WORDLIST_DIR
from core.logger import get_logger
from core.report import ReportManager
from core.ui import UI
from core.utils import ValidationError, safe_path

from .engine import (
    SUPPORTED_ALGORITHMS,
    compute_file_hash,
    compute_hash,
    crack_with_wordlist,
    identify_hash,
    verify_file_integrity,
)

log = get_logger("hashlab")

_SUBMENU = [
    ("1", "Identificar formato de hash (heurística)"),
    ("2", "Calcular hash de um texto"),
    ("3", "Calcular hash de um arquivo"),
    ("4", "Comparar dois hashes"),
    ("5", "Verificar integridade de arquivo"),
    ("6", "Testar senha em wordlist (hash cracking assistido)"),
    ("0", "Voltar ao menu principal"),
]


def run_interactive(ui: UI, settings: Settings, reporter: ReportManager) -> None:
    while True:
        ui.menu("PC HashLab — Laboratório de Hashes", _SUBMENU)
        choice = ui.prompt("Escolha uma opção")
        if choice == "0" or choice == "":
            return
        elif choice == "1":
            _identify(ui)
        elif choice == "2":
            _hash_text(ui, reporter)
        elif choice == "3":
            _hash_file(ui, reporter)
        elif choice == "4":
            _compare(ui)
        elif choice == "5":
            _verify_integrity(ui)
        elif choice == "6":
            _crack(ui, settings, reporter)
        else:
            ui.error("Opção inválida.")


def _pick_algorithm(ui: UI, default: str = "sha256") -> str | None:
    ui.info("Algoritmos suportados: " + ", ".join(sorted(SUPPORTED_ALGORITHMS)))
    algo = ui.prompt(f"Algoritmo [ENTER = {default}]") or default
    algo = algo.lower()
    if algo not in SUPPORTED_ALGORITHMS:
        ui.error(f"Algoritmo não suportado: {algo}")
        return None
    return algo


def _identify(ui: UI) -> None:
    value = ui.prompt("Cole o hash a identificar")
    if not value:
        return
    result = identify_hash(value)
    ui.header("Resultado da identificação")
    ui.info(f"Comprimento: {result.length} caracteres | Hexadecimal: {result.is_hex}")
    if result.candidates:
        ui.success("Candidatos prováveis: " + ", ".join(result.candidates))
    else:
        ui.warn("Nenhum candidato identificado com confiança.")
    if result.note:
        ui.warn(result.note)
    ui.warn(
        "Lembrete: isto é uma heurística baseada em formato, não uma confirmação "
        "do algoritmo real usado para gerar o hash."
    )


def _hash_text(ui: UI, reporter: ReportManager) -> None:
    text = ui.prompt("Texto a ser hasheado")
    algo = _pick_algorithm(ui)
    if algo is None:
        return
    digest = compute_hash(text.encode("utf-8"), algo)
    ui.success(f"{algo}: {digest}")
    if ui.confirm("Salvar no histórico?", default=False):
        reporter.save("hashlab", f"Hash de texto ({algo})", {"algorithm": algo, "hash": digest})


def _hash_file(ui: UI, reporter: ReportManager) -> None:
    path_str = ui.prompt("Caminho do arquivo")
    algo = _pick_algorithm(ui)
    if algo is None:
        return
    path = Path(path_str).expanduser()
    if not path.is_file():
        ui.error("Arquivo não encontrado.")
        return
    try:
        digest = compute_file_hash(path, algo)
    except OSError as exc:
        ui.error(f"Erro ao ler arquivo: {exc}")
        return
    ui.success(f"{algo}: {digest}")
    if ui.confirm("Salvar no histórico?", default=False):
        reporter.save(
            "hashlab",
            f"Hash de arquivo ({path.name})",
            {"file": str(path), "algorithm": algo, "hash": digest},
        )


def _compare(ui: UI) -> None:
    a = ui.prompt("Hash A")
    b = ui.prompt("Hash B")
    if a.strip().lower() == b.strip().lower():
        ui.success("Os hashes são idênticos.")
    else:
        ui.warn("Os hashes são diferentes.")


def _verify_integrity(ui: UI) -> None:
    path_str = ui.prompt("Caminho do arquivo")
    expected = ui.prompt("Hash esperado")
    algo = _pick_algorithm(ui)
    if algo is None:
        return
    path = Path(path_str).expanduser()
    if not path.is_file():
        ui.error("Arquivo não encontrado.")
        return
    ok = verify_file_integrity(path, expected, algo)
    (ui.success if ok else ui.error)(
        "Integridade OK — hash confere." if ok else "Integridade FALHOU — hash não confere."
    )


def _crack(ui: UI, settings: Settings, reporter: ReportManager) -> None:
    ui.warn(
        "Use apenas com hashes/credenciais de teste obtidos legitimamente "
        "(seus próprios desafios de CTF ou laboratórios autorizados)."
    )
    target_hash = ui.prompt("Hash alvo")
    algo = _pick_algorithm(ui)
    if algo is None:
        return

    wordlist_str = ui.prompt(
        f"Caminho da wordlist (relativo a {WORDLIST_DIR} ou absoluto)"
    )
    wordlist_path = Path(wordlist_str).expanduser()
    if not wordlist_path.is_absolute():
        try:
            wordlist_path = safe_path(wordlist_str, WORDLIST_DIR)
        except ValidationError as exc:
            ui.error(str(exc))
            return

    if not wordlist_path.is_file():
        ui.error("Wordlist não encontrada.")
        return

    ui.info("Processando wordlist... isso pode levar algum tempo dependendo do tamanho.")

    def _progress(n: int) -> None:
        ui.info(f"  ... {n} tentativas processadas")

    try:
        result = crack_with_wordlist(
            target_hash,
            algo,
            wordlist_path,
            max_lines=settings.hash_wordlist_max_lines,
            progress_callback=_progress,
            progress_interval=settings.hash_progress_interval,
        )
    except (OSError, ValueError) as exc:
        ui.error(f"Erro durante o processamento: {exc}")
        return

    if result.found:
        ui.success(f"Correspondência encontrada após {result.attempts} tentativa(s).")
        ui.success(f"Texto plano candidato: {result.plaintext!r}")
    else:
        ui.warn(
            f"Nenhuma correspondência encontrada em {result.attempts} linha(s) "
            f"({result.duration_seconds}s). Isso NÃO prova que o hash é 'inquebrável' "
            "— apenas que a senha não estava nesta wordlist."
        )
        if result.truncated:
            ui.warn(
                f"A wordlist foi truncada em {settings.hash_wordlist_max_lines} linhas "
                "pelo limite configurado."
            )

    if ui.confirm("Salvar relatório desta tentativa?", default=True):
        reporter.save(
            "hashlab",
            "Tentativa de cracking com wordlist",
            {"algorithm": algo, "wordlist": str(wordlist_path), **asdict(result)},
        )
