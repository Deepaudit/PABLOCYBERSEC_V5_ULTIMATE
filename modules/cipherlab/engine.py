"""
modules/cipherlab/engine.py

PC CipherLab — laboratório de codificação, decodificação e análise
criptográfica para CTF. Cobre as classes de problema mais comuns em
desafios de "crypto" e "misc": codificações reversíveis (Base64/32,
hex, URL encoding), cifras clássicas (César, ROT13, Vigenère, XOR)
e análise de frequência para apoiar criptoanálise manual.
"""

from __future__ import annotations

import base64
import binascii
import re
import string
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field

ENGLISH_FREQ_ORDER = "etaoinshrdlcumwfgypbvkjxqz"


# ---------------------------------------------------------------------------
# Codificações reversíveis
# ---------------------------------------------------------------------------

def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64_decode(text: str) -> bytes:
    padded = text.strip()
    padded += "=" * (-len(padded) % 4)
    return base64.b64decode(padded)


def b32_encode(data: bytes) -> str:
    return base64.b32encode(data).decode()


def b32_decode(text: str) -> bytes:
    padded = text.strip().upper()
    padded += "=" * (-len(padded) % 8)
    return base64.b32decode(padded)


def hex_encode(data: bytes) -> str:
    return data.hex()


def hex_decode(text: str) -> bytes:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(cleaned) % 2 != 0:
        raise ValueError("Comprimento hexadecimal ímpar após limpeza.")
    return bytes.fromhex(cleaned)


def url_encode(text: str) -> str:
    return urllib.parse.quote(text, safe="")


def url_decode(text: str) -> str:
    return urllib.parse.unquote(text)


def binary_encode(data: bytes) -> str:
    return " ".join(f"{byte:08b}" for byte in data)


def binary_decode(text: str) -> bytes:
    cleaned = re.sub(r"[^01]", "", text)
    if len(cleaned) % 8 != 0:
        raise ValueError("Comprimento binário não é múltiplo de 8 bits.")
    return bytes(int(cleaned[i : i + 8], 2) for i in range(0, len(cleaned), 8))


# ---------------------------------------------------------------------------
# Cifras clássicas
# ---------------------------------------------------------------------------

def rot13(text: str) -> str:
    return text.translate(
        str.maketrans(
            string.ascii_lowercase + string.ascii_uppercase,
            string.ascii_lowercase[13:] + string.ascii_lowercase[:13]
            + string.ascii_uppercase[13:] + string.ascii_uppercase[:13],
        )
    )


def caesar_shift(text: str, shift: int) -> str:
    """Cifra de César. shift negativo decifra."""
    result = []
    for ch in text:
        if ch.isupper():
            result.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        elif ch.islower():
            result.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        else:
            result.append(ch)
    return "".join(result)


def caesar_bruteforce(text: str) -> list[tuple[int, str]]:
    """Retorna as 26 possibilidades de deslocamento para análise manual."""
    return [(shift, caesar_shift(text, shift)) for shift in range(26)]


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    if not key or not key.isalpha():
        raise ValueError("A chave da cifra de Vigenère deve conter apenas letras.")
    key = key.lower()
    result = []
    key_index = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[key_index % len(key)]) - 97
            if decrypt:
                shift = -shift
            base = 65 if ch.isupper() else 97
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            key_index += 1
        else:
            result.append(ch)
    return "".join(result)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("A chave XOR não pode ser vazia.")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_single_byte_bruteforce(data: bytes, top: int = 5) -> list[tuple[int, bytes, float]]:
    """
    Tenta todas as 256 chaves XOR de um byte e pontua o resultado por
    plausibilidade de texto (proporção de caracteres imprimíveis/ASCII
    comuns). Útil para desafios clássicos de CTF com XOR de byte único.
    """
    scored = []
    for key_byte in range(256):
        candidate = xor_bytes(data, bytes([key_byte]))
        score = _printable_score(candidate)
        scored.append((key_byte, candidate, score))
    scored.sort(key=lambda item: item[2], reverse=True)
    return scored[:top]


def _printable_score(data: bytes) -> float:
    """
    Heurística de plausibilidade de texto. Favorece bytes imprimíveis,
    letras, espaços (muito comuns em texto em inglês/português) e
    chaves de desafio comuns em CTF ('flag{', 'CTF{'). É uma heurística
    aproximada, não uma prova — por isso o chamador sempre recebe o top-N
    e não apenas o "vencedor".
    """
    if not data:
        return 0.0
    length = len(data)
    printable = sum(1 for b in data if 32 <= b < 127)
    alpha = sum(1 for b in data if chr(b).isalpha())
    spaces = sum(1 for b in data if b == 32)
    score = (printable / length) * 0.5 + (alpha / length) * 0.3 + (spaces / length) * 0.2
    lowered = data.lower()
    if b"flag{" in lowered or b"ctf{" in lowered or b"flag:" in lowered:
        score += 0.5
    return score


# ---------------------------------------------------------------------------
# Análise de frequência / detecção de formato
# ---------------------------------------------------------------------------

@dataclass
class FrequencyAnalysis:
    letter_counts: dict[str, int]
    total_letters: int
    sorted_letters: list[str] = field(default_factory=list)
    likely_shift_guess: int | None = None


def frequency_analysis(text: str) -> FrequencyAnalysis:
    letters = [c.lower() for c in text if c.isalpha()]
    counts = Counter(letters)
    total = len(letters)
    sorted_letters = [item[0] for item in counts.most_common()]

    guess = None
    if sorted_letters and total > 20:
        # Heurística simples: compara a letra mais comum do texto com "e"
        # (a letra mais comum em inglês) para estimar deslocamento de César.
        most_common = sorted_letters[0]
        guess = (ord(most_common) - ord("e")) % 26

    return FrequencyAnalysis(
        letter_counts=dict(counts),
        total_letters=total,
        sorted_letters=sorted_letters,
        likely_shift_guess=guess,
    )


@dataclass
class FormatGuess:
    label: str
    confidence: str  # "alta", "média", "baixa"
    reason: str


def guess_encoding(text: str) -> list[FormatGuess]:
    """Heurísticas de detecção de formato comuns em desafios de CTF."""
    text = text.strip()
    guesses: list[FormatGuess] = []

    if re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) % 2 == 0 and len(text) > 0:
        guesses.append(FormatGuess("Hexadecimal", "alta", "Apenas dígitos hexadecimais, comprimento par."))

    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text) and len(text) % 4 == 0 and len(text) > 0:
        guesses.append(FormatGuess("Base64", "média", "Alfabeto e padding compatíveis com Base64."))

    if re.fullmatch(r"[A-Z2-7]+={0,6}", text) and len(text) > 0:
        guesses.append(FormatGuess("Base32", "média", "Alfabeto compatível com Base32 (A-Z, 2-7)."))

    if re.fullmatch(r"[01\s]+", text) and len(text.replace(" ", "")) % 8 == 0 and text.strip():
        guesses.append(FormatGuess("Binário", "alta", "Apenas 0s e 1s, múltiplo de 8 bits."))

    if "%" in text and re.search(r"%[0-9a-fA-F]{2}", text):
        guesses.append(FormatGuess("URL Encoding", "alta", "Sequências %XX presentes."))

    if re.fullmatch(r"[A-Za-z\s.,!?'\"-]+", text) and any(c.isalpha() for c in text):
        guesses.append(FormatGuess("Texto simples / cifra de substituição", "baixa",
                                    "Apenas letras e pontuação — pode ser texto plano, ROT13 ou César."))

    if not guesses:
        guesses.append(FormatGuess("Desconhecido", "baixa", "Nenhum padrão conhecido identificado."))

    return guesses
