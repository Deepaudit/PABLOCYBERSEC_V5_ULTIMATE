"""
core/logger.py

Logging centralizado. Por padrão, redige valores sensíveis comuns
(senhas, tokens, chaves, hashes completos de credenciais) antes de
gravar em disco, quando settings.redact_sensitive_values=True.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from core.config import LOG_DIR, Settings

_SENSITIVE_PATTERNS = [
    re.compile(r"(password\s*[:=]\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(passwd\s*[:=]\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(token\s*[:=]\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(secret\s*[:=]\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(api[_-]?key\s*[:=]\s*)(\S+)", re.IGNORECASE),
]


class RedactingFilter(logging.Filter):
    """Substitui valores após padrões sensíveis conhecidos por [REDACTED]."""

    def __init__(self, enabled: bool = True) -> None:
        super().__init__()
        self.enabled = enabled

    def filter(self, record: logging.LogRecord) -> bool:
        if self.enabled and isinstance(record.msg, str):
            msg = record.msg
            for pattern in _SENSITIVE_PATTERNS:
                msg = pattern.sub(r"\1[REDACTED]", msg)
            record.msg = msg
        return True


_LOGGER_CACHE: dict[str, logging.Logger] = {}


def get_logger(name: str, settings: Settings | None = None) -> logging.Logger:
    """Retorna um logger configurado, criando-o na primeira chamada."""
    if name in _LOGGER_CACHE:
        return _LOGGER_CACHE[name]

    settings = settings or Settings.load()
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(f"pablocybersec.{name}")
    logger.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))
    logger.propagate = False

    if not logger.handlers:
        file_handler = logging.FileHandler(LOG_DIR / "pablocybersec.log", encoding="utf-8")
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(RedactingFilter(settings.redact_sensitive_values))
        logger.addHandler(file_handler)

    _LOGGER_CACHE[name] = logger
    return logger
