"""
modules/flaghunter/engine.py

PC FlagHunter — assistente integrado de resolução de CTF.

Este módulo NUNCA inventa flags. Ele apenas:
  (a) detecta padrões de formato de flag CONHECIDOS em texto já fornecido
      pelo usuário ou coletado por outros módulos,
  (b) organiza hipóteses e evidências em um caderno de anotações
      (notebook) por "caso"/desafio, e
  (c) gera relatórios reproduzíveis — cada flag reportada carrega a
      evidência (texto de origem e módulo) que a originou.

Uma "flag" aqui só é considerada ENCONTRADA se corresponder, de forma
verificável, a um padrão de formato presente no texto de entrada.
Nenhum valor é gerado ou completado por adivinhação.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Padrões comuns de formato de flag usados por plataformas de CTF.
# Plataformas reais costumam anunciar o formato esperado (ex.: no enunciado).
FLAG_PATTERNS: dict[str, str] = {
    "generico_chaves": r"[A-Za-z0-9_]{2,20}\{[^{}\s]{3,200}\}",
    "flag_explicito": r"(?i)flag\{[^{}\s]{1,200}\}",
    "ctf_explicito": r"(?i)ctf\{[^{}\s]{1,200}\}",
    "htb_explicito": r"(?i)htb\{[^{}\s]{1,200}\}",
    "thm_explicito": r"(?i)thm\{[^{}\s]{1,200}\}",
    "picoctf_explicito": r"(?i)picoCTF\{[^{}\s]{1,200}\}",
}

_COMPILED_PATTERNS = {name: re.compile(pattern) for name, pattern in FLAG_PATTERNS.items()}


@dataclass
class FlagCandidate:
    value: str
    pattern_name: str
    source_label: str
    verified_format: bool = True


@dataclass
class Hypothesis:
    text: str
    created_at: str
    tags: list[str] = field(default_factory=list)


@dataclass
class CaseNotebook:
    name: str
    created_at: str
    candidates: list[FlagCandidate] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    evidence_log: list[dict] = field(default_factory=list)
    resolved: bool = False
    confirmed_flag: str | None = None


def detect_flag_candidates(text: str, source_label: str = "entrada manual") -> list[FlagCandidate]:
    """Procura padrões de flag conhecidos em um texto. Não inventa nada fora do texto."""
    found: list[FlagCandidate] = []
    seen_values: set[str] = set()

    # Prioriza padrões explícitos (flag{}, ctf{}, etc.) sobre o genérico.
    priority_order = [n for n in FLAG_PATTERNS if n != "generico_chaves"] + ["generico_chaves"]

    for name in priority_order:
        regex = _COMPILED_PATTERNS[name]
        for match in regex.finditer(text):
            value = match.group(0)
            if value in seen_values:
                continue
            seen_values.add(value)
            found.append(FlagCandidate(value=value, pattern_name=name, source_label=source_label))
    return found


def detect_encoding_clues(text: str) -> list[str]:
    """Reaproveita heurísticas simples para apontar pistas de codificação no texto (sem decodificar automaticamente)."""
    clues = []
    stripped = text.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", stripped) and len(stripped) % 2 == 0 and stripped:
        clues.append("Parece hexadecimal — considere decodificar no PC CipherLab.")
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", stripped) and len(stripped) % 4 == 0 and stripped:
        clues.append("Parece Base64 — considere decodificar no PC CipherLab.")
    if re.fullmatch(r"[01\s]+", stripped) and stripped:
        clues.append("Parece binário — considere decodificar no PC CipherLab.")
    if "%" in text and re.search(r"%[0-9a-fA-F]{2}", text):
        clues.append("Contém sequências de URL encoding.")
    return clues


class NotebookManager:
    """Gerencia cadernos de anotações (notebooks) de casos de CTF em disco, em data/flaghunter/."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir / "flaghunter"
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, name: str) -> Path:
        safe_name = re.sub(r"[^A-Za-z0-9_-]", "_", name)
        return self.data_dir / f"{safe_name}.json"

    def create_or_load(self, name: str) -> CaseNotebook:
        path = self._path_for(name)
        if path.exists():
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return CaseNotebook(
                name=data["name"],
                created_at=data["created_at"],
                candidates=[FlagCandidate(**c) for c in data.get("candidates", [])],
                hypotheses=[Hypothesis(**h) for h in data.get("hypotheses", [])],
                evidence_log=data.get("evidence_log", []),
                resolved=data.get("resolved", False),
                confirmed_flag=data.get("confirmed_flag"),
            )
        notebook = CaseNotebook(name=name, created_at=datetime.now(timezone.utc).isoformat())
        self.save(notebook)
        return notebook

    def save(self, notebook: CaseNotebook) -> Path:
        path = self._path_for(notebook.name)
        payload = {
            "name": notebook.name,
            "created_at": notebook.created_at,
            "candidates": [c.__dict__ for c in notebook.candidates],
            "hypotheses": [h.__dict__ for h in notebook.hypotheses],
            "evidence_log": notebook.evidence_log,
            "resolved": notebook.resolved,
            "confirmed_flag": notebook.confirmed_flag,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        return path

    def list_notebooks(self) -> list[str]:
        return sorted(p.stem for p in self.data_dir.glob("*.json"))


def add_evidence(notebook: CaseNotebook, module: str, description: str, data: dict) -> None:
    notebook.evidence_log.append(
        {
            "module": module,
            "description": description,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


def add_hypothesis(notebook: CaseNotebook, text: str, tags: list[str] | None = None) -> None:
    notebook.hypotheses.append(
        Hypothesis(text=text, created_at=datetime.now(timezone.utc).isoformat(), tags=tags or [])
    )


def confirm_flag(notebook: CaseNotebook, flag_value: str, evidence_description: str) -> None:
    """
    Marca uma flag como confirmada MANUALMENTE pelo usuário, exigindo uma
    descrição da evidência. O módulo nunca faz essa confirmação sozinho.
    """
    notebook.confirmed_flag = flag_value
    notebook.resolved = True
    add_evidence(notebook, "flaghunter", f"Flag confirmada manualmente: {evidence_description}", {"flag": flag_value})
