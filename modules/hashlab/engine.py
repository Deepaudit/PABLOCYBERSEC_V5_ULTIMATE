"""
modules/hashlab/engine.py

PC HashLab — laboratório de hashes.

IMPORTANTE (honestidade técnica): hashes criptográficos não são
"decodificados". Um hash é o resultado de uma função unidirecional.
A única forma de "recuperar" o valor original é:
  (a) encontrar uma entrada (ex.: em uma wordlist) cujo hash coincida, ou
  (b) explorar fraquezas específicas do algoritmo (não implementado aqui
      para algoritmos modernos como SHA-256, que não possuem quebra prática).
Este módulo deixa isso explícito em toda saída relevante.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

SUPPORTED_ALGORITHMS: dict[str, str] = {
    "md5": "MD5 (128 bits) — quebrado para fins criptográficos, ainda usado em checksums",
    "sha1": "SHA-1 (160 bits) — quebrado para colisões, evitar em novos sistemas",
    "sha224": "SHA-224",
    "sha256": "SHA-256 — padrão atual recomendado",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha3_224": "SHA3-224",
    "sha3_256": "SHA3-256",
    "sha3_384": "SHA3-384",
    "sha3_512": "SHA3-512",
    "blake2b": "BLAKE2b",
    "blake2s": "BLAKE2s",
}

# Comprimentos hexadecimais característicos para identificação heurística.
_HEX_LENGTH_CANDIDATES: dict[int, list[str]] = {
    32: ["md5", "ntlm (heurística: mesmo tamanho do md5)"],
    40: ["sha1"],
    56: ["sha224", "sha3_224"],
    64: ["sha256", "sha3_256", "blake2s"],
    96: ["sha384", "sha3_384"],
    128: ["sha512", "sha3_512", "blake2b"],
}


@dataclass
class HashIdentification:
    value: str
    length: int
    is_hex: bool
    candidates: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class CrackAttemptResult:
    found: bool
    plaintext: str | None
    attempts: int
    lines_processed: int
    duration_seconds: float
    truncated: bool = False


def compute_hash(data: bytes, algorithm: str) -> str:
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algoritmo não suportado: {algorithm}")
    h = hashlib.new(algorithm.replace("_", "_") if "_" in algorithm else algorithm)
    h.update(data)
    return h.hexdigest()


def compute_file_hash(path: Path, algorithm: str, chunk_size: int = 1024 * 1024) -> str:
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algoritmo não suportado: {algorithm}")
    h = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        while chunk := fh.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def identify_hash(value: str) -> HashIdentification:
    """Identificação heurística do(s) algoritmo(s) possível(is), por comprimento e alfabeto."""
    value = value.strip()
    is_hex = all(c in "0123456789abcdefABCDEF" for c in value) and len(value) > 0
    candidates: list[str] = []

    if is_hex:
        candidates = list(_HEX_LENGTH_CANDIDATES.get(len(value), []))

    note = ""
    if not candidates:
        if value.startswith("$1$"):
            candidates = ["md5crypt (formato /etc/shadow)"]
        elif value.startswith("$2a$") or value.startswith("$2b$") or value.startswith("$2y$"):
            candidates = ["bcrypt"]
        elif value.startswith("$6$"):
            candidates = ["sha512crypt (formato /etc/shadow)"]
        elif value.startswith("$y$") or value.startswith("$7$"):
            candidates = ["yescrypt (formato /etc/shadow moderno)"]
        else:
            note = (
                "Não foi possível identificar o formato com confiança apenas pelo "
                "comprimento/alfabeto. Múltiplos algoritmos compartilham o mesmo "
                "tamanho de saída — trate como hipótese, não confirmação."
            )
    else:
        note = (
            "Múltiplos algoritmos podem compartilhar este comprimento de saída. "
            "A identificação por comprimento é uma heurística, não uma prova."
        )

    return HashIdentification(
        value=value, length=len(value), is_hex=is_hex, candidates=candidates, note=note
    )


def compare_hashes(hash_a: str, hash_b: str) -> bool:
    """Comparação de hashes em tempo constante (evita timing side-channel básico)."""
    return hmac.compare_digest(hash_a.strip().lower(), hash_b.strip().lower())


def verify_file_integrity(path: Path, expected_hash: str, algorithm: str) -> bool:
    computed = compute_file_hash(path, algorithm)
    return compare_hashes(computed, expected_hash)


def crack_with_wordlist(
    target_hash: str,
    algorithm: str,
    wordlist_path: Path,
    max_lines: int = 2_000_000,
    progress_callback: Callable[[int], None] | None = None,
    progress_interval: int = 50_000,
) -> CrackAttemptResult:
    """
    Testa cada linha da wordlist contra o hash alvo.

    Isto NÃO é "quebra de criptografia": é busca por correspondência em
    um dicionário de candidatos. Só encontra a senha se ela estiver,
    literalmente, na wordlist fornecida (ou for derivável por regras
    simples não implementadas aqui).
    """
    import time

    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algoritmo não suportado: {algorithm}")

    target_hash_norm = target_hash.strip().lower()
    start = time.monotonic()
    attempts = 0
    truncated = False

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
        for line_number, raw_line in enumerate(fh, start=1):
            if line_number > max_lines:
                truncated = True
                break
            candidate = raw_line.rstrip("\n\r")
            if not candidate:
                continue
            attempts += 1
            candidate_hash = compute_hash(candidate.encode("utf-8"), algorithm)
            if compare_hashes(candidate_hash, target_hash_norm):
                return CrackAttemptResult(
                    found=True,
                    plaintext=candidate,
                    attempts=attempts,
                    lines_processed=line_number,
                    duration_seconds=round(time.monotonic() - start, 3),
                    truncated=truncated,
                )
            if progress_callback and attempts % progress_interval == 0:
                progress_callback(attempts)

    return CrackAttemptResult(
        found=False,
        plaintext=None,
        attempts=attempts,
        lines_processed=min(attempts, max_lines),
        duration_seconds=round(time.monotonic() - start, 3),
        truncated=truncated,
    )


def iter_batch_hashes(values: Iterator[str], algorithm: str) -> Iterator[tuple[str, str]]:
    """Gera (entrada, hash) para processamento em lote."""
    for value in values:
        yield value, compute_hash(value.encode("utf-8"), algorithm)
