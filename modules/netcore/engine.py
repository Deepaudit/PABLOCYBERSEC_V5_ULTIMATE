"""
modules/netcore/engine.py

PC NetCore — ferramentas próprias de diagnóstico e comunicação de rede,
inspiradas nas funcionalidades úteis do Netcat (cliente/servidor TCP,
transferência de dados, testes de conectividade).

Por design, este módulo NÃO implementa execução remota de comandos
("reverse shell" / "bind shell") por padrão. Ele serve para laboratórios
de transferência de arquivos, testes de conectividade e inspeção de
protocolos simples.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from pathlib import Path

DEFAULT_RECV_BUFFER = 4096
MAX_FILE_TRANSFER_BYTES = 200 * 1024 * 1024  # limite de segurança: 200MB


@dataclass
class ConnectivityResult:
    host: str
    port: int
    reachable: bool
    latency_ms: float | None
    error: str | None = None


def test_connectivity(host: str, port: int, timeout: float = 3.0) -> ConnectivityResult:
    """Testa se uma porta TCP está alcançável, reportando latência de conexão."""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = (time.monotonic() - start) * 1000
            return ConnectivityResult(host=host, port=port, reachable=True, latency_ms=round(latency, 2))
    except (socket.timeout, TimeoutError):
        return ConnectivityResult(host=host, port=port, reachable=False, latency_ms=None, error="timeout")
    except ConnectionRefusedError:
        return ConnectivityResult(host=host, port=port, reachable=False, latency_ms=None, error="conexão recusada")
    except OSError as exc:
        return ConnectivityResult(host=host, port=port, reachable=False, latency_ms=None, error=str(exc))


def start_tcp_listener(
    host: str,
    port: int,
    on_data=None,
    on_connect=None,
    timeout: float | None = None,
) -> None:
    """
    Servidor TCP simples para laboratório. Aceita UMA conexão, recebe dados
    até o cliente fechar ou o timeout expirar, e repassa cada chunk recebido
    para 'on_data' (callback), se fornecido. Bloqueante — pensado para uso
    via CLI/menu interativo, não para produção.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        if timeout:
            server.settimeout(timeout)
        try:
            conn, addr = server.accept()
        except socket.timeout:
            raise TimeoutError(f"Nenhuma conexão recebida em {timeout}s.")

        with conn:
            if on_connect:
                on_connect(addr)
            if timeout:
                conn.settimeout(timeout)
            while True:
                try:
                    data = conn.recv(DEFAULT_RECV_BUFFER)
                except socket.timeout:
                    break
                if not data:
                    break
                if on_data:
                    on_data(data)


def send_tcp_data(host: str, port: int, data: bytes, timeout: float = 5.0) -> bytes:
    """Cliente TCP simples: conecta, envia dados, lê a resposta disponível e fecha."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(data)
        sock.settimeout(timeout)
        chunks = []
        try:
            while True:
                chunk = sock.recv(DEFAULT_RECV_BUFFER)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
        return b"".join(chunks)


@dataclass
class FileTransferResult:
    bytes_transferred: int
    duration_seconds: float
    path: Path | None = None


def send_file(host: str, port: int, file_path: Path, timeout: float = 10.0) -> FileTransferResult:
    """Envia um arquivo via TCP para um listener NetCore em execução."""
    size = file_path.stat().st_size
    if size > MAX_FILE_TRANSFER_BYTES:
        raise ValueError(
            f"Arquivo excede o limite de transferência configurado "
            f"({MAX_FILE_TRANSFER_BYTES // (1024*1024)}MB)."
        )
    start = time.monotonic()
    sent = 0
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with open(file_path, "rb") as fh:
            while chunk := fh.read(DEFAULT_RECV_BUFFER):
                sock.sendall(chunk)
                sent += len(chunk)
    return FileTransferResult(bytes_transferred=sent, duration_seconds=round(time.monotonic() - start, 3))


def receive_file(
    host: str,
    port: int,
    output_path: Path,
    max_bytes: int = MAX_FILE_TRANSFER_BYTES,
    timeout: float = 30.0,
) -> FileTransferResult:
    """Recebe um arquivo via TCP e grava em 'output_path', respeitando um limite de tamanho."""
    start = time.monotonic()
    received = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        server.settimeout(timeout)
        try:
            conn, _addr = server.accept()
        except socket.timeout:
            raise TimeoutError(f"Nenhuma conexão recebida em {timeout}s.")

        with conn, open(output_path, "wb") as out:
            conn.settimeout(timeout)
            while True:
                try:
                    chunk = conn.recv(DEFAULT_RECV_BUFFER)
                except socket.timeout:
                    break
                if not chunk:
                    break
                received += len(chunk)
                if received > max_bytes:
                    raise ValueError(
                        f"Transferência excedeu o limite de {max_bytes // (1024*1024)}MB "
                        "e foi abortada."
                    )
                out.write(chunk)

    return FileTransferResult(
        bytes_transferred=received,
        duration_seconds=round(time.monotonic() - start, 3),
        path=output_path,
    )
