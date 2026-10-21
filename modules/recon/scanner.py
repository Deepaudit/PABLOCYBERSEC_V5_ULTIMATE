"""
modules/recon/scanner.py

PC Recon — motor de reconhecimento e enumeração de redes.

Inspirado nas funcionalidades essenciais de ferramentas como o Nmap
(descoberta de hosts, varredura de portas TCP, banner grabbing),
mas é uma implementação própria, mais simples e sem qualquer código
proprietário copiado. Não deve ser tratado como equivalente completo
a ferramentas consolidadas — não há, por exemplo, fingerprinting de
SO, varredura SYN "stealth", nem decodificação de scripts NSE.

Todas as operações de rede aqui são ativas (abrem conexões reais).
Use apenas contra alvos que você tem autorização explícita para testar.
"""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass, field

# Serviços comuns conhecidos por porta — apenas um mapeamento de referência,
# não uma identificação de versão real do serviço.
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "smtp-submission", 631: "ipp",
    873: "rsync", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2375: "docker", 27017: "mongodb",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
}

DEFAULT_TOP_PORTS = sorted(COMMON_SERVICES.keys())


@dataclass
class PortResult:
    port: int
    state: str  # "open", "closed", "filtered"
    service_guess: str | None = None
    banner: str | None = None
    latency_ms: float | None = None


@dataclass
class HostResult:
    target: str
    resolved_ip: str | None = None
    alive: bool | None = None
    ports: list[PortResult] = field(default_factory=list)
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    scan_duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)


def resolve_dns(target: str) -> dict[str, list[str]]:
    """Resolução DNS básica (A/AAAA e reverso), sem dependências externas."""
    records: dict[str, list[str]] = {"A": [], "AAAA": [], "PTR": []}
    try:
        infos = socket.getaddrinfo(target, None)
        for family, _, _, _, sockaddr in infos:
            addr = sockaddr[0]
            if family == socket.AF_INET and addr not in records["A"]:
                records["A"].append(addr)
            elif family == socket.AF_INET6 and addr not in records["AAAA"]:
                records["AAAA"].append(addr)
    except socket.gaierror:
        pass

    for ip in records["A"] + records["AAAA"]:
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            if host not in records["PTR"]:
                records["PTR"].append(host)
        except (socket.herror, socket.gaierror):
            continue
    return records


async def _tcp_connect_probe(
    ip: str, port: int, timeout: float
) -> tuple[str, float | None]:
    """Tenta estabelecer conexão TCP. Retorna (estado, latência_ms)."""
    start = time.monotonic()
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        latency = (time.monotonic() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return "open", latency
    except asyncio.TimeoutError:
        return "filtered", None
    except ConnectionRefusedError:
        return "closed", None
    except OSError:
        return "filtered", None


async def _grab_banner(ip: str, port: int, timeout: float) -> str | None:
    """
    Tenta capturar um banner simples. Para serviços que não enviam banner
    espontaneamente (ex.: HTTP), envia uma requisição mínima e inofensiva.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError):
        return None

    try:
        probe_sent = False
        if port in (80, 8080, 8000, 8888):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            await writer.drain()
            probe_sent = True

        try:
            data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""

        if not data and not probe_sent:
            return None

        banner = data.decode(errors="replace").strip()
        return banner[:200] if banner else None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def scan_ports(
    ip: str,
    ports: list[int],
    timeout: float = 2.0,
    concurrency: int = 100,
    grab_banners: bool = True,
) -> list[PortResult]:
    """Varre uma lista de portas TCP com controle de concorrência via semáforo."""
    semaphore = asyncio.Semaphore(max(1, concurrency))
    results: list[PortResult] = []

    async def worker(port: int) -> None:
        async with semaphore:
            state, latency = await _tcp_connect_probe(ip, port, timeout)
            banner = None
            if state == "open" and grab_banners:
                banner = await _grab_banner(ip, port, timeout)
            results.append(
                PortResult(
                    port=port,
                    state=state,
                    service_guess=COMMON_SERVICES.get(port),
                    banner=banner,
                    latency_ms=round(latency, 2) if latency else None,
                )
            )

    await asyncio.gather(*(worker(p) for p in ports))
    results.sort(key=lambda r: r.port)
    return results


async def host_is_alive(ip: str, timeout: float = 1.5) -> bool:
    """
    Heurística de "host vivo" sem privilégios root (sem ICMP cru):
    tenta conectar a um pequeno conjunto de portas comumente abertas.
    Não é equivalente a um ping ICMP real e pode gerar falsos negativos
    em hosts com firewall restritivo que não respondem a nada.
    """
    probe_ports = [80, 443, 22, 445, 3389]
    for port in probe_ports:
        state, _ = await _tcp_connect_probe(ip, port, timeout)
        if state in ("open", "closed"):
            # "closed" ainda significa que o host respondeu (RST) -> está vivo.
            return True
    return False


async def run_recon(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 2.0,
    concurrency: int = 100,
    grab_banners: bool = True,
    resolve_dns_records: bool = True,
    check_alive: bool = True,
) -> HostResult:
    """Fluxo completo do PC Recon para um único alvo."""
    start = time.monotonic()
    result = HostResult(target=target)
    ports = ports or DEFAULT_TOP_PORTS

    try:
        resolved = socket.gethostbyname(target)
        result.resolved_ip = resolved
    except socket.gaierror as exc:
        result.errors.append(f"Falha ao resolver host: {exc}")
        result.scan_duration_seconds = time.monotonic() - start
        return result

    if resolve_dns_records:
        result.dns_records = resolve_dns(target)

    if check_alive:
        result.alive = await host_is_alive(result.resolved_ip, timeout=min(timeout, 1.5))
        if not result.alive:
            result.errors.append(
                "Host não respondeu às sondas de disponibilidade "
                "(pode estar protegido por firewall ou realmente inativo)."
            )

    result.ports = await scan_ports(
        result.resolved_ip,
        ports,
        timeout=timeout,
        concurrency=concurrency,
        grab_banners=grab_banners,
    )
    result.scan_duration_seconds = round(time.monotonic() - start, 2)
    return result
