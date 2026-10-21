"""
modules/packetlab/engine.py

PC PacketLab — ferramentas educacionais de análise de tráfego e protocolos.

Recursos SEM privilégios especiais:
  - Leitura de arquivos PCAP/PCAPNG já capturados (não requer root).
  - Filtragem e identificação de protocolos a partir do arquivo.
  - Estatísticas básicas (contagem por protocolo, top talkers).

Recursos que EXIGEM privilégios especiais (não executados por padrão):
  - Captura de tráfego ao vivo (requer CAP_NET_RAW / root). Esta
    funcionalidade é exposta separadamente e sempre avisa sobre o
    requisito de privilégio antes de tentar.

Integração com Scapy é OPCIONAL: o módulo verifica a disponibilidade
da biblioteca antes de usá-la e informa claramente quando não está
instalada, em vez de falhar silenciosamente ou fingir suporte.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from pathlib import Path

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR  # type: ignore

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class PacketSummary:
    index: int
    timestamp: float | None
    src: str | None
    dst: str | None
    protocol: str
    length: int
    info: str = ""


@dataclass
class PcapAnalysis:
    total_packets: int
    protocol_counts: dict[str, int] = field(default_factory=dict)
    top_talkers: list[tuple[str, int]] = field(default_factory=list)
    dns_queries: list[str] = field(default_factory=list)
    http_hosts: list[str] = field(default_factory=list)
    packets_preview: list[PacketSummary] = field(default_factory=list)
    engine_used: str = "scapy"


def check_scapy_available() -> bool:
    return SCAPY_AVAILABLE


def check_raw_capture_privileges() -> tuple[bool, str]:
    """
    Verifica (sem capturar nada) se o processo atual provavelmente teria
    permissão para captura de tráfego ao vivo. Não realiza a captura.
    """
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if is_root:
        return True, "Executando como root — captura ao vivo provavelmente permitida."
    return False, (
        "Não está executando como root. Captura de tráfego ao vivo normalmente exige "
        "privilégios elevados (root ou CAP_NET_RAW). Considere usar "
        "'sudo setcap cap_net_raw+ep <python>' em vez de rodar tudo como root, "
        "ou usar arquivos PCAP já capturados com este módulo."
    )


def analyze_pcap(path: Path, max_preview: int = 50, top_n_talkers: int = 10) -> PcapAnalysis:
    """Analisa um arquivo PCAP/PCAPNG já capturado, usando Scapy se disponível."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError(
            "A biblioteca 'scapy' não está instalada neste ambiente. "
            "Instale com 'pip install scapy' (ou 'pip install scapy --break-system-packages') "
            "para habilitar a análise de PCAP."
        )

    packets = rdpcap(str(path))
    protocol_counts: dict[str, int] = {}
    talker_counts: dict[str, int] = {}
    dns_queries: list[str] = []
    http_hosts: list[str] = []
    preview: list[PacketSummary] = []

    for idx, pkt in enumerate(packets):
        proto = "OUTRO"
        src = dst = None
        info = ""

        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            talker_counts[src] = talker_counts.get(src, 0) + 1
            talker_counts[dst] = talker_counts.get(dst, 0) + 1

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            proto = "DNS"
            try:
                query_name = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                dns_queries.append(query_name)
                info = f"consulta: {query_name}"
            except Exception:
                pass
        elif pkt.haslayer(TCP):
            proto = "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            info = f"{sport} -> {dport}"
            if dport in (80, 8080) or sport in (80, 8080):
                proto = "HTTP (provável)"
                try:
                    payload = bytes(pkt[TCP].payload)
                    if b"Host:" in payload:
                        for line in payload.split(b"\r\n"):
                            if line.startswith(b"Host:"):
                                host = line.split(b":", 1)[1].strip().decode(errors="ignore")
                                http_hosts.append(host)
                                break
                except Exception:
                    pass
        elif pkt.haslayer(UDP):
            proto = "UDP"
            info = f"{pkt[UDP].sport} -> {pkt[UDP].dport}"

        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

        if idx < max_preview:
            preview.append(
                PacketSummary(
                    index=idx,
                    timestamp=float(pkt.time) if hasattr(pkt, "time") else None,
                    src=src, dst=dst, protocol=proto, length=len(pkt), info=info,
                )
            )

    top_talkers = sorted(talker_counts.items(), key=lambda kv: kv[1], reverse=True)[:top_n_talkers]

    return PcapAnalysis(
        total_packets=len(packets),
        protocol_counts=protocol_counts,
        top_talkers=top_talkers,
        dns_queries=sorted(set(dns_queries)),
        http_hosts=sorted(set(http_hosts)),
        packets_preview=preview,
    )


def read_pcap_header_without_scapy(path: Path) -> dict:
    """
    Fallback sem dependências externas: lê apenas o cabeçalho global do
    arquivo PCAP clássico (não PCAPNG) para confirmar formato e contagem
    aproximada, quando Scapy não está disponível.
    """
    with open(path, "rb") as fh:
        header = fh.read(24)
    if len(header) < 24:
        raise ValueError("Arquivo muito pequeno para ser um PCAP válido.")

    magic = header[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        byte_order = "<"
        magic_label = "PCAP clássico (little-endian)"
    elif magic == b"\xa1\xb2\xc3\xd4":
        byte_order = ">"
        magic_label = "PCAP clássico (big-endian)"
    elif magic == b"\x0a\x0d\x0d\x0a":
        return {"format": "PCAPNG", "note": "Leitura detalhada de PCAPNG requer Scapy."}
    else:
        raise ValueError("Assinatura de arquivo não reconhecida como PCAP/PCAPNG.")

    version_major, version_minor = struct.unpack(byte_order + "HH", header[4:8])
    snaplen = struct.unpack(byte_order + "I", header[16:20])[0]
    link_type = struct.unpack(byte_order + "I", header[20:24])[0]

    return {
        "format": magic_label,
        "version": f"{version_major}.{version_minor}",
        "snaplen": snaplen,
        "link_type": link_type,
    }
