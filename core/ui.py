"""
core/ui.py

Camada de interface de terminal: cores, banners ASCII originais,
menus, prompts validados e mensagens de status consistentes.
Funciona em terminais comuns (sem dependências externas); degrada
graciosamente se o terminal não suportar cores ANSI.
"""

from __future__ import annotations

import os
import shutil
import sys


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_CYAN = "\033[96m"


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("PABLOCYBERSEC_NO_COLOR"):
        return False
    return sys.stdout.isatty()


class UI:
    def __init__(self, color_enabled: bool = True) -> None:
        self.color_enabled = color_enabled and _supports_color()

    def c(self, text: str, color: str) -> str:
        if not self.color_enabled:
            return text
        return f"{color}{text}{Colors.RESET}"

    def banner(self) -> None:
        width = min(shutil.get_terminal_size(fallback=(80, 24)).columns, 70)
        title = "PABLOCYBERSEC V5"
        subtitle = "ULTIMATE LINUX CTF FRAMEWORK"
        tags = "RECON  •  HASH  •  CIPHER  •  WEB  •  FORENSICS"
        slogan = "ONE FRAMEWORK. MULTIPLE CAPABILITIES."

        art = r"""
  ____   _    ____  _     ___     ______ _____ ____  _____ ______ ____
 |  _ \ / \  | __ )| |   / _ \   / / ___|_   _| __ )| ____|  _ \/ ___|
 | |_) / _ \ |  _ \| |  | | | | / / |     | | |  _ \|  _| | |_) \___ \
 |  __/ ___ \| |_) | |__| |_| |/ /| |___  | | | |_) | |___|  _ < ___) |
 |_| /_/   \_\____/|_____\___/_/  \____|  |_| |____/|_____|_| \_\____/
"""
        print(self.c(art, Colors.BRIGHT_CYAN))
        print(self.c("=" * width, Colors.CYAN))
        print(self.c(subtitle.center(width), Colors.BOLD))
        print(self.c(tags.center(width), Colors.YELLOW))
        print(self.c(slogan.center(width), Colors.DIM))
        print(self.c("=" * width, Colors.CYAN))
        print(self.c("Desenvolvido por PabloCyberSec — uso educacional e autorizado".center(width), Colors.DIM))
        print()

    def header(self, text: str) -> None:
        print()
        print(self.c(f"── {text} ", Colors.BOLD) + self.c("─" * max(0, 60 - len(text)), Colors.DIM))

    def info(self, text: str) -> None:
        print(self.c("[*] ", Colors.CYAN) + text)

    def success(self, text: str) -> None:
        print(self.c("[+] ", Colors.BRIGHT_GREEN) + text)

    def warn(self, text: str) -> None:
        print(self.c("[!] ", Colors.BRIGHT_YELLOW) + text)

    def error(self, text: str) -> None:
        print(self.c("[x] ", Colors.BRIGHT_RED) + text)

    def menu(self, title: str, options: list[tuple[str, str]]) -> None:
        self.header(title)
        for key, label in options:
            print(f"  {self.c(f'[{key}]', Colors.BRIGHT_CYAN)} {label}")
        print()

    def prompt(self, text: str) -> str:
        try:
            return input(self.c(f"{text} > ", Colors.BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return ""

    def confirm(self, text: str, default: bool = False) -> bool:
        suffix = "[S/n]" if default else "[s/N]"
        answer = self.prompt(f"{text} {suffix}").lower()
        if not answer:
            return default
        return answer in ("s", "sim", "y", "yes")

    def table(self, headers: list[str], rows: list[list[str]]) -> None:
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))
        line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
        print(self.c(line, Colors.BOLD))
        print(self.c("  ".join("-" * w for w in widths), Colors.DIM))
        for row in rows:
            print("  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))
