"""
modules/vulnscope/menu.py

Integração do PC VulnScope com o menu principal.
"""

from __future__ import annotations

from dataclasses import asdict

from core.config import Settings
from core.logger import get_logger
from core.report import ReportManager
from core.ui import UI

from .cve_reference import CVE_REFERENCE_DB
from .engine import correlate_service, summarize_findings

log = get_logger("vulnscope")


def run_interactive(ui: UI, settings: Settings, reporter: ReportManager) -> None:
    ui.header("PC VulnScope — Correlação de Vulnerabilidades (Hipóteses)")
    ui.warn(
        "Resultados aqui são HIPÓTESES baseadas em versão relatada, não confirmações. "
        "Use apenas em sistemas que você tem autorização para avaliar."
    )
    ui.info("Serviços conhecidos na base local: " + ", ".join(sorted(CVE_REFERENCE_DB.keys())))

    service = ui.prompt("Nome do serviço (ex: openssh, apache, openssl)")
    if not service:
        return
    version = ui.prompt("Versão observada (ex: 2.4.49, ou o banner completo)")
    raw_banner = ui.prompt("Banner bruto (opcional, para registro de evidência)")

    findings = correlate_service(service, version, raw_banner)

    if not findings:
        ui.warn(
            f"Nenhuma correspondência na base local de referência para '{service}' "
            f"versão '{version}'. Isso NÃO significa que o serviço é seguro — "
            "apenas que não há entrada correspondente nesta base local e limitada."
        )
        return

    ui.header(f"Hipóteses encontradas ({len(findings)})")
    for finding in findings:
        ui.warn(f"[{finding.severity_estimate.upper()}] {finding.cve_id} — {finding.description}")
        ui.info(f"  Confiança: {finding.confidence.value}")
        ui.info(f"  Evidência: {finding.evidence}")
        ui.info(f"  Recomendação: {finding.recommendation}")
        print()

    summary = summarize_findings(findings)
    ui.info("Resumo por criticidade estimada: " + ", ".join(f"{k}={v}" for k, v in summary.items() if v))

    if ui.confirm("Salvar relatório?", default=True):
        reporter.save(
            "vulnscope",
            f"Correlação de {service} {version}",
            {
                "service": service,
                "version": version,
                "findings": [
                    {**asdict(f), "confidence": f.confidence.value} for f in findings
                ],
                "summary": summary,
            },
        )
