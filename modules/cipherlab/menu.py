"""
modules/cipherlab/menu.py

Integração do PC CipherLab com o menu principal.
"""

from __future__ import annotations

import binascii

from core.config import Settings
from core.logger import get_logger
from core.report import ReportManager
from core.ui import UI

from . import engine

log = get_logger("cipherlab")

_SUBMENU = [
    ("1", "Base64 (codificar/decodificar)"),
    ("2", "Base32 (codificar/decodificar)"),
    ("3", "Hexadecimal (codificar/decodificar)"),
    ("4", "URL Encoding (codificar/decodificar)"),
    ("5", "Binário (codificar/decodificar)"),
    ("6", "ROT13"),
    ("7", "Cifra de César (deslocamento ou força bruta)"),
    ("8", "Cifra de Vigenère"),
    ("9", "XOR (chave conhecida ou força bruta de byte único)"),
    ("10", "Análise de frequência de letras"),
    ("11", "Detectar formato de um texto desconhecido"),
    ("0", "Voltar ao menu principal"),
]


def run_interactive(ui: UI, settings: Settings, reporter: ReportManager) -> None:
    while True:
        ui.menu("PC CipherLab — Codificação, Decodificação e Criptoanálise", _SUBMENU)
        choice = ui.prompt("Escolha uma opção")
        if choice in ("0", ""):
            return
        handler = {
            "1": lambda: _codec_bytes(ui, "Base64", engine.b64_encode, engine.b64_decode),
            "2": lambda: _codec_bytes(ui, "Base32", engine.b32_encode, engine.b32_decode),
            "3": lambda: _codec_bytes(ui, "Hexadecimal", engine.hex_encode, engine.hex_decode),
            "4": lambda: _codec_text(ui, "URL Encoding", engine.url_encode, engine.url_decode),
            "5": lambda: _codec_bytes(ui, "Binário", engine.binary_encode, engine.binary_decode),
            "6": lambda: _rot13(ui),
            "7": lambda: _caesar(ui),
            "8": lambda: _vigenere(ui),
            "9": lambda: _xor(ui),
            "10": lambda: _frequency(ui),
            "11": lambda: _detect(ui),
        }.get(choice)
        if handler:
            try:
                handler()
            except (ValueError, binascii.Error) as exc:
                ui.error(f"Erro: {exc}")
        else:
            ui.error("Opção inválida.")


def _direction(ui: UI) -> str:
    return (ui.prompt("Codificar (c) ou decodificar (d)? [c/d]") or "c").lower()


def _codec_bytes(ui: UI, name: str, encoder, decoder) -> None:
    ui.header(name)
    if _direction(ui).startswith("d"):
        text = ui.prompt("Texto codificado")
        raw = decoder(text)
        try:
            ui.success("Resultado: " + raw.decode("utf-8"))
        except UnicodeDecodeError:
            ui.success("Resultado (bytes, não é UTF-8 válido): " + repr(raw))
    else:
        text = ui.prompt("Texto a codificar")
        ui.success("Resultado: " + encoder(text.encode("utf-8")))


def _codec_text(ui: UI, name: str, encoder, decoder) -> None:
    ui.header(name)
    if _direction(ui).startswith("d"):
        text = ui.prompt("Texto codificado")
        ui.success("Resultado: " + decoder(text))
    else:
        text = ui.prompt("Texto a codificar")
        ui.success("Resultado: " + encoder(text))


def _rot13(ui: UI) -> None:
    ui.header("ROT13 (operação é sua própria inversa)")
    text = ui.prompt("Texto")
    ui.success("Resultado: " + engine.rot13(text))


def _caesar(ui: UI) -> None:
    ui.header("Cifra de César")
    text = ui.prompt("Texto")
    mode = ui.prompt("Deslocamento específico (n) ou forçar todas as 26 opções (todas)? [n/todas]")
    if mode.strip().lower() in ("todas", "all", "a"):
        for shift, candidate in engine.caesar_bruteforce(text):
            print(f"  [{shift:2d}] {candidate}")
    else:
        try:
            shift = int(mode)
        except ValueError:
            ui.error("Deslocamento inválido.")
            return
        ui.success("Resultado: " + engine.caesar_shift(text, shift))


def _vigenere(ui: UI) -> None:
    ui.header("Cifra de Vigenère")
    text = ui.prompt("Texto")
    key = ui.prompt("Chave (apenas letras)")
    mode = (ui.prompt("Cifrar (c) ou decifrar (d)? [c/d]") or "c").lower()
    result = engine.vigenere(text, key, decrypt=mode.startswith("d"))
    ui.success("Resultado: " + result)


def _xor(ui: UI) -> None:
    ui.header("XOR")
    mode = ui.prompt("Chave conhecida (k) ou força bruta de 1 byte (b)? [k/b]").lower()
    text_hex = ui.prompt("Dados em hexadecimal (ex: 48656c6c6f)")
    try:
        data = engine.hex_decode(text_hex)
    except ValueError as exc:
        ui.error(f"Entrada hexadecimal inválida: {exc}")
        return

    if mode.startswith("b"):
        ui.info("Testando as 256 chaves de 1 byte e ordenando por plausibilidade de texto...")
        for key_byte, candidate, score in engine.xor_single_byte_bruteforce(data):
            printable = candidate.decode("latin-1")
            print(f"  chave=0x{key_byte:02x} score={score:.2f} -> {printable!r}")
    else:
        key_hex = ui.prompt("Chave em hexadecimal")
        try:
            key = engine.hex_decode(key_hex)
        except ValueError as exc:
            ui.error(f"Chave hexadecimal inválida: {exc}")
            return
        result = engine.xor_bytes(data, key)
        ui.success("Resultado (hex): " + result.hex())
        try:
            ui.success("Resultado (texto): " + result.decode("utf-8"))
        except UnicodeDecodeError:
            ui.warn("Resultado não é UTF-8 válido; apenas a forma hexadecimal é exibida.")


def _frequency(ui: UI) -> None:
    ui.header("Análise de frequência de letras")
    text = ui.prompt("Texto")
    analysis = engine.frequency_analysis(text)
    if analysis.total_letters == 0:
        ui.warn("Nenhuma letra encontrada no texto.")
        return
    ui.info(f"Total de letras: {analysis.total_letters}")
    ui.info("Ordem de frequência (mais → menos comum): " + "".join(analysis.sorted_letters))
    ui.info(f"Referência (inglês): {engine.ENGLISH_FREQ_ORDER}")
    if analysis.likely_shift_guess is not None:
        ui.warn(
            f"Hipótese de deslocamento de César (baseada na letra mais comum): "
            f"{analysis.likely_shift_guess} — trate como ponto de partida, não certeza."
        )


def _detect(ui: UI) -> None:
    ui.header("Detecção heurística de formato")
    text = ui.prompt("Texto desconhecido")
    guesses = engine.guess_encoding(text)
    for g in guesses:
        ui.info(f"[{g.confidence.upper()}] {g.label} — {g.reason}")
