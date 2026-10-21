"""
modules/webhunter/menu.py

Integração do PC WebHunter com o menu principal.
"""

from __future__ import annotations

from dataclasses import asdict
from urllib.parse import urlparse

from core.config import Settings
from core.logger import get_logger
from core.report import ReportManager
from core.ui import UI

from . import engine

log = get_logger("webhunter")

_SUBMENU = [
    ("1", "Inspecionar cabeçalhos HTTP, cookies e redirecionamentos"),
    ("2", "Inspecionar certificado TLS"),
    ("3", "Detectar tecnologias e cabeçalhos de segurança ausentes"),
    ("4", "Enumerar diretórios/caminhos comuns"),
    ("0", "Voltar ao menu principal"),
]


def run_interactive(ui: UI, settings: Settings, reporter: ReportManager) -> None:
    ui.header("PC WebHunter — Análise de Aplicações Web")
    ui.warn("Testes ativos exigem alvo explícito e autorização para o teste.")

    target_raw = ui.prompt("URL ou host alvo (ex: https://exemplo.com)")
    if not target_raw:
        return
    url = engine.normalize_url(target_raw)

    if not ui.confirm(f"Confirma autorização para testar '{url}'?", default=False):
        ui.warn("Operação cancelada pelo usuário.")
        return

    while True:
        ui.menu(f"PC WebHunter — alvo: {url}", _SUBMENU)
        choice = ui.prompt("Escolha uma opção")
        if choice in ("0", ""):
            return
        try:
            if choice == "1":
                _headers(ui, settings, reporter, url)
            elif choice == "2":
                _tls(ui, settings, reporter, url)
            elif choice == "3":
                _tech(ui, settings, url)
            elif choice == "4":
                _enumerate(ui, settings, reporter, url)
            else:
                ui.error("Opção inválida.")
        except Exception as exc:
            ui.error(f"Erro inesperado: {exc}")
            log.exception("Erro no PC WebHunter")


def _headers(ui: UI, settings: Settings, reporter: ReportManager, url: str) -> None:
    result = engine.probe_url(
        url,
        timeout=settings.http_request_timeout,
        max_redirects=settings.http_max_redirects,
        user_agent=settings.http_user_agent,
    )
    if result.error:
        ui.error(f"Falha na requisição: {result.error}")
        return

    ui.header("Resultado")
    ui.info(f"Status: {result.status_code}")
    if result.redirect_chain:
        ui.info("Cadeia de redirecionamento:")
        for step in result.redirect_chain:
            print(f"  -> {step}")
        ui.info(f"URL final: {result.final_url}")

    ui.info("Cabeçalhos:")
    for key, value in result.headers.items():
        print(f"  {key}: {value}")

    if result.cookies:
        ui.info("Cookies definidos:")
        for cookie in result.cookies:
            print(f"  {cookie}")

    missing = engine.analyze_security_headers(result.headers)
    if missing:
        ui.warn("Cabeçalhos de segurança ausentes:")
        for item in missing:
            print(f"  - {item}")
    else:
        ui.success("Todos os cabeçalhos de segurança recomendados estão presentes.")

    if ui.confirm("Salvar relatório?", default=True):
        reporter.save("webhunter", f"Inspeção HTTP de {url}", asdict(result))


def _tls(ui: UI, settings: Settings, reporter: ReportManager, url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        ui.warn("O alvo não usa HTTPS; não há certificado TLS para inspecionar.")
        return
    host = parsed.hostname
    port = parsed.port or 443
    info = engine.inspect_tls(host, port, timeout=settings.http_request_timeout)
    if info.error:
        ui.error(f"Falha ao obter certificado: {info.error}")
        return

    ui.header("Certificado TLS")
    ui.info(f"Versão TLS: {info.version}")
    ui.info(f"Válido de {info.not_before} até {info.not_after}")
    if info.subject:
        ui.info(f"Subject: {info.subject}")
    if info.issuer:
        ui.info(f"Issuer: {info.issuer}")

    if ui.confirm("Salvar relatório?", default=False):
        reporter.save("webhunter", f"TLS de {host}:{port}", asdict(info))


def _tech(ui: UI, settings: Settings, url: str) -> None:
    result = engine.probe_url(
        url, timeout=settings.http_request_timeout, max_redirects=settings.http_max_redirects,
        user_agent=settings.http_user_agent,
    )
    if result.error:
        ui.error(f"Falha na requisição: {result.error}")
        return
    techs = engine.detect_technologies(result.headers, result.body_preview)
    if techs:
        ui.success("Tecnologias identificadas por evidências observáveis: " + ", ".join(techs))
    else:
        ui.warn("Nenhuma tecnologia identificada com as assinaturas conhecidas.")
    ui.warn("Isto é uma identificação por evidência, não uma confirmação de versão exata.")


def _enumerate(ui: UI, settings: Settings, reporter: ReportManager, url: str) -> None:
    custom = ui.prompt(
        "Caminho para lista personalizada (ENTER = usar lista padrão embutida)"
    )
    paths = None
    if custom:
        try:
            with open(custom, "r", encoding="utf-8") as fh:
                paths = [line.strip() for line in fh if line.strip()]
        except OSError as exc:
            ui.error(f"Erro ao ler lista: {exc}")
            return

    rate_raw = ui.prompt(
        f"Atraso entre requisições em segundos [ENTER = {1/settings.rate_limit_requests_per_second:.2f}]"
    )
    delay = float(rate_raw) if rate_raw else 1 / settings.rate_limit_requests_per_second

    ui.info(f"Enumerando {len(paths) if paths else len(engine.DEFAULT_PATHS)} caminho(s)...")
    findings = engine.enumerate_paths(
        url, paths=paths, timeout=settings.http_request_timeout, delay_between_requests=delay,
        user_agent=settings.http_user_agent,
    )

    if not findings:
        ui.warn("Nenhum caminho retornou status diferente de 404.")
    else:
        rows = [[f.path, str(f.status_code), str(f.length)] for f in findings]
        ui.table(["CAMINHO", "STATUS", "TAMANHO(bytes)"], rows)

    if ui.confirm("Salvar relatório?", default=True):
        reporter.save(
            "webhunter",
            f"Enumeração de diretórios em {url}",
            {"url": url, "findings": [asdict(f) for f in findings]},
        )
