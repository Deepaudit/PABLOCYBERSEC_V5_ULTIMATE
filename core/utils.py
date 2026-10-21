"""
core/utils.py

Utilidades compartilhadas entre módulos: validação de alvos, proteção
contra path traversal, parsing de faixas de portas e helpers gerais.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


class ValidationError(ValueError):
    """Erro de validação de entrada do usuário."""


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_hostname(value: str) -> bool:
    return bool(_HOSTNAME_RE.match(value))


def validate_target(target: str) -> str:
    """
    Valida que 'target' é um IP ou hostname plausível.
    Não resolve automaticamente nem assume autorização — isso é
    responsabilidade do usuário/módulo chamador, que deve exigir
    confirmação explícita de escopo antes de testes ativos.
    """
    target = target.strip()
    if not target:
        raise ValidationError("Alvo vazio.")
    if is_valid_ip(target) or is_valid_hostname(target):
        return target
    raise ValidationError(f"Alvo inválido: {target!r}")


def resolve_host(target: str, timeout: float = 3.0) -> str | None:
    """Resolve hostname para IP. Retorna None em caso de falha, sem lançar exceção."""
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(target)
    except socket.error:
        return None


def parse_port_spec(spec: str) -> list[int]:
    """
    Converte uma especificação de portas em lista de inteiros únicos e ordenados.
    Aceita formatos como: "22,80,443", "1-1024", "22,80,1000-1010".
    """
    ports: set[int] = set()
    spec = spec.strip()
    if not spec:
        raise ValidationError("Especificação de portas vazia.")

    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_str, end_str = chunk.split("-", 1)
            try:
                start, end = int(start_str), int(end_str)
            except ValueError as exc:
                raise ValidationError(f"Intervalo de portas inválido: {chunk!r}") from exc
            if not (0 < start <= 65535 and 0 < end <= 65535 and start <= end):
                raise ValidationError(f"Intervalo de portas fora da faixa: {chunk!r}")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError as exc:
                raise ValidationError(f"Porta inválida: {chunk!r}") from exc
            if not (0 < port <= 65535):
                raise ValidationError(f"Porta fora da faixa: {chunk!r}")
            ports.add(port)
    return sorted(ports)


def safe_path(user_path: str, base_dir: Path) -> Path:
    """
    Resolve 'user_path' relativo a base_dir e garante que o resultado
    final permaneça dentro de base_dir, prevenindo path traversal
    (ex.: "../../etc/passwd").
    """
    base = base_dir.resolve()
    candidate = (base / user_path).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValidationError(
            f"Caminho fora do diretório permitido: {user_path!r}"
        ) from exc
    return candidate


def human_bytes(size: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}PB"
