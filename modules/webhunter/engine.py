"""
modules/webhunter/engine.py

PC WebHunter — análise de aplicações web em ambientes autorizados.

Usa a biblioteca padrão (urllib) para evitar dependências externas
obrigatórias; se 'requests' estiver disponível, não é necessário —
a implementação já cobre cabeçalhos, métodos, cookies, redirecionamentos,
TLS básico e varredura de diretórios com lista de caminhos.

Todas as funções aqui fazem requisições ATIVAS contra o alvo. O
chamador (menu/CLI) é responsável por exigir confirmação explícita
de escopo antes de qualquer varredura.
"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.client import HTTPResponse
from urllib.parse import urljoin, urlparse

DEFAULT_PATHS = [
    "admin", "login", "robots.txt", ".git/HEAD", ".env", "backup",
    "config", "api", "uploads", "test", "dev", "staging", "swagger.json",
    "wp-admin", "phpmyadmin", ".well-known/security.txt", "sitemap.xml",
]

TECH_SIGNATURES: dict[str, list[str]] = {
    "WordPress": ["wp-content", "wp-includes", "/wp-json/"],
    "PHP": ["X-Powered-By: PHP", ".php"],
    "Nginx": ["Server: nginx"],
    "Apache": ["Server: Apache"],
    "Express/Node.js": ["X-Powered-By: Express"],
    "Django": ["csrftoken", "django"],
    "Laravel": ["laravel_session", "X-Powered-By: Laravel"],
    "Cloudflare": ["Server: cloudflare", "cf-ray"],
    "jQuery": ["jquery.js", "jquery.min.js"],
    "React": ["__REACT_DEVTOOLS_GLOBAL_HOOK__", "react-dom"],
}


@dataclass
class HttpProbeResult:
    url: str
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    cookies: list[str] = field(default_factory=list)
    body_preview: str = ""
    error: str | None = None
    elapsed_ms: float | None = None


@dataclass
class TlsInfo:
    subject: dict | None = None
    issuer: dict | None = None
    not_before: str | None = None
    not_after: str | None = None
    version: str | None = None
    error: str | None = None


@dataclass
class DirectoryFinding:
    path: str
    status_code: int
    length: int


def probe_url(
    url: str,
    method: str = "GET",
    timeout: float = 5.0,
    max_redirects: int = 5,
    user_agent: str = "PABLOCYBERSEC-V5/WebHunter (lab-use-only)",
) -> HttpProbeResult:
    """Executa uma requisição HTTP e coleta cabeçalhos, cookies e redirecionamentos."""
    result = HttpProbeResult(url=url)
    current_url = url
    redirect_chain: list[str] = []
    start = time.monotonic()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # desabilita redirecionamento automático; tratamos manualmente

    opener = urllib.request.build_opener(NoRedirect)

    for _ in range(max_redirects + 1):
        request = urllib.request.Request(current_url, method=method.upper())
        request.add_header("User-Agent", user_agent)
        try:
            response: HTTPResponse = opener.open(request, timeout=timeout)
            status = response.status
            headers = dict(response.headers.items())
            body = response.read(4096)
        except urllib.error.HTTPError as exc:
            status = exc.code
            headers = dict(exc.headers.items()) if exc.headers else {}
            body = exc.read(4096) if hasattr(exc, "read") else b""
        except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
            result.error = str(exc)
            result.elapsed_ms = round((time.monotonic() - start) * 1000, 2)
            return result

        result.status_code = status
        result.headers = headers
        try:
            result.body_preview = body.decode("utf-8", errors="replace")[:2000]
        except Exception:
            result.body_preview = ""

        cookies = headers.get("Set-Cookie")
        if cookies:
            result.cookies.append(cookies)

        if status in (301, 302, 303, 307, 308) and "Location" in headers:
            next_url = urljoin(current_url, headers["Location"])
            redirect_chain.append(current_url)
            current_url = next_url
            continue
        break

    result.final_url = current_url
    result.redirect_chain = redirect_chain
    result.elapsed_ms = round((time.monotonic() - start) * 1000, 2)
    return result


def inspect_tls(host: str, port: int = 443, timeout: float = 5.0) -> TlsInfo:
    """Coleta informações básicas do certificado TLS apresentado pelo servidor."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
    except (ssl.SSLError, socket.error, socket.timeout) as exc:
        return TlsInfo(error=str(exc))

    def _dict_from_tuple(seq) -> dict:
        out = {}
        for entry in seq or []:
            for key, value in entry:
                out[key] = value
        return out

    return TlsInfo(
        subject=_dict_from_tuple(cert.get("subject")),
        issuer=_dict_from_tuple(cert.get("issuer")),
        not_before=cert.get("notBefore"),
        not_after=cert.get("notAfter"),
        version=version,
    )


def detect_technologies(headers: dict[str, str], body: str) -> list[str]:
    """Identifica tecnologias por evidências observáveis em cabeçalhos e corpo da resposta."""
    found = []
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
    haystacks = [header_blob, body]

    for tech, signatures in TECH_SIGNATURES.items():
        for signature in signatures:
            if any(signature.lower() in h.lower() for h in haystacks):
                found.append(tech)
                break
    return found


def enumerate_paths(
    base_url: str,
    paths: list[str] | None = None,
    timeout: float = 5.0,
    delay_between_requests: float = 0.05,
    user_agent: str = "PABLOCYBERSEC-V5/WebHunter (lab-use-only)",
) -> list[DirectoryFinding]:
    """
    Varredura de caminhos/diretórios com lista personalizável.
    Respeita um atraso mínimo entre requisições (rate limiting simples)
    para não sobrecarregar o alvo.
    """
    paths = paths or DEFAULT_PATHS
    findings: list[DirectoryFinding] = []

    for path in paths:
        target_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        request = urllib.request.Request(target_url, method="GET")
        request.add_header("User-Agent", user_agent)
        try:
            response = urllib.request.urlopen(request, timeout=timeout)
            status = response.status
            length = len(response.read(8192))
        except urllib.error.HTTPError as exc:
            status = exc.code
            length = 0
        except (urllib.error.URLError, socket.timeout, TimeoutError):
            time.sleep(delay_between_requests)
            continue

        if status != 404:
            findings.append(DirectoryFinding(path=path, status_code=status, length=length))
        time.sleep(delay_between_requests)

    return findings


def analyze_security_headers(headers: dict[str, str]) -> list[str]:
    """Verifica a presença de cabeçalhos de segurança comumente recomendados."""
    recommended = {
        "Strict-Transport-Security": "Protege contra downgrade para HTTP (HSTS).",
        "Content-Security-Policy": "Mitiga XSS e injeção de conteúdo.",
        "X-Content-Type-Options": "Evita MIME sniffing (deveria ser 'nosniff').",
        "X-Frame-Options": "Mitiga clickjacking.",
        "Referrer-Policy": "Controla vazamento de dados via cabeçalho Referer.",
    }
    missing = []
    lower_headers = {k.lower() for k in headers}
    for header, description in recommended.items():
        if header.lower() not in lower_headers:
            missing.append(f"{header} ausente — {description}")
    return missing


def normalize_url(target: str) -> str:
    """Garante que a URL tenha esquema; assume https por padrão."""
    parsed = urlparse(target)
    if not parsed.scheme:
        return f"https://{target}"
    return target
