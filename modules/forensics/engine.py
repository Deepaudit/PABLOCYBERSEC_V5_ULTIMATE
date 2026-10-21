"""
modules/forensics/engine.py

PC Forensics — laboratório de análise forense digital.

Princípio central: PRESERVAR o arquivo original. Nenhuma função aqui
abre um arquivo em modo de escrita ou o modifica; tudo é leitura.
Toda operação relevante deve ser registrada via core.logger pelo
chamador (menu), formando uma trilha simples de auditoria.
"""

from __future__ import annotations

import hashlib
import re
import string
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# Assinaturas de arquivo (magic bytes) mais comuns em desafios de CTF.
FILE_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"\x89PNG\r\n\x1a\n", "PNG", "image/png"),
    (b"\xff\xd8\xff", "JPEG", "image/jpeg"),
    (b"GIF87a", "GIF", "image/gif"),
    (b"GIF89a", "GIF", "image/gif"),
    (b"%PDF-", "PDF", "application/pdf"),
    (b"PK\x03\x04", "ZIP/Office/APK/JAR", "application/zip"),
    (b"Rar!\x1a\x07\x00", "RAR", "application/x-rar-compressed"),
    (b"\x1f\x8b\x08", "GZIP", "application/gzip"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip", "application/x-7z-compressed"),
    (b"BM", "BMP", "image/bmp"),
    (b"\x7fELF", "ELF (executável Linux)", "application/x-elf"),
    (b"MZ", "PE (executável Windows)", "application/x-msdownload"),
    (b"\x00\x00\x00\x18ftyp", "MP4", "video/mp4"),
    (b"ID3", "MP3", "audio/mpeg"),
    (b"OggS", "OGG", "audio/ogg"),
    (b"\x52\x49\x46\x46", "WAV/AVI (RIFF)", "application/octet-stream"),
    (b"<?xml", "XML", "application/xml"),
    (b"{", "Possível JSON", "application/json"),
]


@dataclass
class FileSignatureResult:
    detected_type: str | None
    mime_guess: str | None
    extension_claimed: str
    mismatch_warning: str | None
    first_bytes_hex: str


@dataclass
class StringsResult:
    total_found: int
    strings: list[str] = field(default_factory=list)
    truncated: bool = False


@dataclass
class MetadataResult:
    size_bytes: int
    md5: str
    sha256: str
    is_zip_based: bool
    zip_contents: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def identify_signature(path: Path) -> FileSignatureResult:
    """Identifica o tipo real do arquivo por assinatura (magic bytes), ignorando a extensão."""
    with open(path, "rb") as fh:
        header = fh.read(32)

    detected = None
    mime = None
    for signature, label, mime_type in FILE_SIGNATURES:
        if header.startswith(signature):
            detected = label
            mime = mime_type
            break

    extension = path.suffix.lstrip(".").lower()
    mismatch = None
    if detected and extension:
        plausible_exts = {
            "PNG": {"png"}, "JPEG": {"jpg", "jpeg"}, "GIF": {"gif"},
            "PDF": {"pdf"}, "ZIP/Office/APK/JAR": {"zip", "docx", "xlsx", "pptx", "apk", "jar"},
            "RAR": {"rar"}, "GZIP": {"gz", "tgz"}, "7-Zip": {"7z"}, "BMP": {"bmp"},
            "ELF (executável Linux)": {"elf", "", "bin", "out"},
            "PE (executável Windows)": {"exe", "dll"},
            "MP4": {"mp4"}, "MP3": {"mp3"}, "OGG": {"ogg"}, "XML": {"xml"}, "Possível JSON": {"json"},
        }.get(detected, set())
        if plausible_exts and extension not in plausible_exts:
            mismatch = (
                f"A extensão '.{extension}' não é compatível com o tipo detectado "
                f"({detected}) — possível arquivo renomeado (técnica comum em CTF)."
            )

    return FileSignatureResult(
        detected_type=detected,
        mime_guess=mime,
        extension_claimed=extension or "(sem extensão)",
        mismatch_warning=mismatch,
        first_bytes_hex=header[:16].hex(),
    )


def compute_metadata(path: Path) -> MetadataResult:
    """Calcula hashes e metadados básicos, preservando o arquivo original (somente leitura)."""
    size = path.stat().st_size
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1024 * 1024):
            md5.update(chunk)
            sha256.update(chunk)

    is_zip = zipfile.is_zipfile(path)
    contents: list[str] = []
    notes: list[str] = []
    if is_zip:
        try:
            with zipfile.ZipFile(path) as zf:
                contents = zf.namelist()[:100]
                if len(zf.namelist()) > 100:
                    notes.append(f"Arquivo ZIP contém {len(zf.namelist())} entradas (mostrando 100).")
        except zipfile.BadZipFile:
            notes.append("Arquivo parece ZIP pela assinatura, mas está corrompido ou mal formado.")

    return MetadataResult(
        size_bytes=size, md5=md5.hexdigest(), sha256=sha256.hexdigest(),
        is_zip_based=is_zip, zip_contents=contents, notes=notes,
    )


def extract_strings(
    path: Path, min_length: int = 4, max_results: int = 5000, encoding: str = "ascii"
) -> StringsResult:
    """
    Extrai sequências de caracteres imprimíveis, similar ao utilitário 'strings'.
    Lê o arquivo inteiro em memória — para arquivos muito grandes, prefira
    um min_length maior ou processe em um laboratório com mais memória.
    """
    printable_bytes = set(string.printable.encode())
    found: list[str] = []
    current: list[int] = []
    truncated = False

    with open(path, "rb") as fh:
        data = fh.read()

    for byte in data:
        if byte in printable_bytes and byte not in (9, 10, 11, 12, 13):
            current.append(byte)
        else:
            if len(current) >= min_length:
                found.append(bytes(current).decode(encoding, errors="ignore"))
                if len(found) >= max_results:
                    truncated = True
                    break
            current = []
    if not truncated and len(current) >= min_length:
        found.append(bytes(current).decode(encoding, errors="ignore"))

    return StringsResult(total_found=len(found), strings=found, truncated=truncated)


def hex_dump(path: Path, offset: int = 0, length: int = 256) -> str:
    """Gera uma representação hexadecimal estilo 'xxd' de uma seção do arquivo."""
    with open(path, "rb") as fh:
        fh.seek(offset)
        data = fh.read(length)

    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset + i:08x}  {hex_part:<48}  {ascii_part}")
    return "\n".join(lines)


def search_pattern_in_strings(strings_list: list[str], pattern: str) -> list[str]:
    """Busca um padrão (regex) nas strings extraídas — útil para localizar flags."""
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Expressão regular inválida: {exc}") from exc
    return [s for s in strings_list if regex.search(s)]
