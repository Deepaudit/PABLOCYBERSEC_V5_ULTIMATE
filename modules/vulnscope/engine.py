"""
modules/vulnscope/engine.py

PC VulnScope — avaliação de segurança para laboratórios e sistemas
autorizados.

HONESTIDADE TÉCNICA (obrigatória para este módulo):
- Identificar que um serviço roda uma versão "potencialmente afetada"
  por um CVE conhecido NÃO é o mesmo que confirmar que o alvo é
  explorável. Faltam, no mínimo: confirmação da versão exata, do
  contexto de configuração, de patches de distribuição aplicados
  (muitas distros fazem backport de correções sem mudar o número de
  versão) e, idealmente, validação ativa controlada.
- Este módulo distingue três níveis: DESCOBERTA (um fato observado,
  ex.: "banner reporta OpenSSH 7.2"), HIPÓTESE (uma vulnerabilidade
  possivelmente aplicável com base nessa descoberta) e CONFIRMAÇÃO
  (verificação ativa, que este módulo não realiza automaticamente).
- A base de referências abaixo é um conjunto pequeno e ilustrativo de
  CVEs amplamente conhecidos, mantido localmente. NÃO é um substituto
  para consultar fontes oficiais (NVD, MITRE, fornecedor do software)
  antes de qualquer decisão real.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from .cve_reference import CVE_REFERENCE_DB


class ConfidenceLevel(str, Enum):
    DISCOVERY = "descoberta"
    HYPOTHESIS = "hipótese"
    CONFIRMED = "confirmado"


@dataclass
class VulnFinding:
    service: str
    version_observed: str
    cve_id: str
    description: str
    severity_estimate: str  # "crítica", "alta", "média", "baixa"
    confidence: ConfidenceLevel
    evidence: str
    recommendation: str


@dataclass
class ServiceBanner:
    service: str
    version: str | None
    raw_banner: str


_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def parse_version(version_str: str) -> tuple[int, ...] | None:
    match = _VERSION_RE.search(version_str)
    if not match:
        return None
    parts = [int(g) for g in match.groups() if g is not None]
    return tuple(parts)


def version_in_range(version: tuple[int, ...], min_v: tuple[int, ...] | None, max_v: tuple[int, ...] | None) -> bool:
    if min_v and version < min_v:
        return False
    if max_v and version > max_v:
        return False
    return True


def correlate_service(service: str, version_str: str, raw_banner: str = "") -> list[VulnFinding]:
    """
    Correlaciona um serviço+versão observados com a base local de
    referências. Retorna hipóteses, nunca confirmações automáticas.
    """
    findings: list[VulnFinding] = []
    service_key = service.lower().strip()
    entries = CVE_REFERENCE_DB.get(service_key, [])

    parsed_version = parse_version(version_str)

    for entry in entries:
        applies = True
        if parsed_version and (entry.get("min_version") or entry.get("max_version")):
            applies = version_in_range(
                parsed_version,
                tuple(entry["min_version"]) if entry.get("min_version") else None,
                tuple(entry["max_version"]) if entry.get("max_version") else None,
            )
        if not applies:
            continue

        findings.append(
            VulnFinding(
                service=service,
                version_observed=version_str,
                cve_id=entry["cve_id"],
                description=entry["description"],
                severity_estimate=entry["severity"],
                confidence=ConfidenceLevel.HYPOTHESIS,
                evidence=f"Banner/versão observado: {raw_banner or version_str!r}",
                recommendation=entry["recommendation"],
            )
        )
    return findings


def summarize_findings(findings: list[VulnFinding]) -> dict[str, int]:
    summary = {"crítica": 0, "alta": 0, "média": 0, "baixa": 0}
    for finding in findings:
        summary[finding.severity_estimate] = summary.get(finding.severity_estimate, 0) + 1
    return summary
