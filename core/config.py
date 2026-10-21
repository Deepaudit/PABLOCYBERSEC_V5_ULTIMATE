"""
core/config.py

Configuração central da PABLOCYBERSEC V5.
Carrega config/settings.json (se existir) e aplica valores padrão seguros.
Nenhum valor aqui habilita comportamento destrutivo por padrão.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "settings.json"
LOG_DIR = PROJECT_ROOT / "logs"
REPORT_DIR = PROJECT_ROOT / "reports"
DATA_DIR = PROJECT_ROOT / "data"
WORDLIST_DIR = PROJECT_ROOT / "wordlists"


@dataclass
class Settings:
    """
    Configurações globais da plataforma.

    Os limites abaixo existem para manter o framework dentro do escopo de
    laboratórios autorizados e CTFs. Eles são conservadores por padrão e
    podem ser ajustados pelo usuário em config/settings.json, mas a
    plataforma nunca os ignora silenciosamente.
    """

    # Rede / varredura
    max_concurrent_connections: int = 100
    default_timeout_seconds: float = 2.0
    max_ports_per_scan: int = 65535
    rate_limit_requests_per_second: float = 20.0

    # HTTP / WebHunter
    http_user_agent: str = "PABLOCYBERSEC-V5/WebHunter (lab-use-only)"
    http_max_redirects: int = 5
    http_request_timeout: float = 5.0

    # HashLab
    hash_wordlist_max_lines: int = 2_000_000
    hash_progress_interval: int = 50_000

    # Logging
    log_level: str = "INFO"
    redact_sensitive_values: bool = True

    # Interface
    color_output: bool = True
    banner_enabled: bool = True

    # Segurança operacional
    require_explicit_target_for_active_modules: bool = True
    confirm_destructive_actions: bool = True

    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path = DEFAULT_CONFIG_PATH) -> "Settings":
        data: dict[str, Any] = {}
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except (json.JSONDecodeError, OSError):
                # Config inválida não deve derrubar a ferramenta: cai para padrões.
                data = {}
        known_fields = {f for f in cls.__dataclass_fields__.keys() if f != "extra"}
        known = {k: v for k, v in data.items() if k in known_fields}
        extra = {k: v for k, v in data.items() if k not in known_fields}
        return cls(**known, extra=extra)

    def save(self, path: Path = DEFAULT_CONFIG_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(self)
        extra = payload.pop("extra", {})
        payload.update(extra)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)


def ensure_directories() -> None:
    """Garante que os diretórios de apoio existam. Não cria nada fora do projeto."""
    for directory in (LOG_DIR, REPORT_DIR, DATA_DIR, WORDLIST_DIR, DEFAULT_CONFIG_PATH.parent):
        directory.mkdir(parents=True, exist_ok=True)


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False  # plataformas sem geteuid (não-POSIX)
