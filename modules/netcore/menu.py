"""
modules/netcore/menu.py

Integração do PC NetCore com o menu principal.
"""

from __future__ import annotations

from pathlib import Path

from core.config import Settings
from core.logger import get_logger
from core.report import ReportManager
from core.ui import UI
from core.utils import ValidationError, validate_target

from . import engine

log = get_logger("netcore")

_SUBMENU = [
    ("1", "Testar conectividade TCP (como 'nc -zv')"),
    ("2", "Iniciar listener TCP (modo escuta, exibe dados recebidos)"),
    ("3", "Enviar dados de texto para host:porta"),
    ("4", "Enviar arquivo para um listener"),
    ("5", "Receber arquivo (modo escuta)"),
    ("0", "Voltar ao menu principal"),
]


def run_interactive(ui: UI, settings: Settings, reporter: ReportManager) -> None:
    while True:
        ui.menu("PC NetCore — Diagnóstico e Comunicação de Rede", _SUBMENU)
        choice = ui.prompt("Escolha uma opção")
        if choice in ("0", ""):
            return
        try:
            if choice == "1":
                _connectivity(ui, settings, reporter)
            elif choice == "2":
                _listener(ui, settings)
            elif choice == "3":
                _send_data(ui, settings)
            elif choice == "4":
                _send_file(ui, settings, reporter)
            elif choice == "5":
                _receive_file(ui, settings, reporter)
            else:
                ui.error("Opção inválida.")
        except (OSError, TimeoutError, ValueError) as exc:
            ui.error(f"Erro: {exc}")
        except KeyboardInterrupt:
            ui.warn("Operação interrompida pelo usuário.")


def _port_input(ui: UI, label: str = "Porta") -> int | None:
    raw = ui.prompt(label)
    try:
        port = int(raw)
    except ValueError:
        ui.error("Porta inválida.")
        return None
    if not (0 < port <= 65535):
        ui.error("Porta fora da faixa válida (1-65535).")
        return None
    return port


def _connectivity(ui: UI, settings: Settings, reporter: ReportManager) -> None:
    host_raw = ui.prompt("Host de destino")
    try:
        host = validate_target(host_raw)
    except ValidationError as exc:
        ui.error(str(exc))
        return
    port = _port_input(ui)
    if port is None:
        return

    result = engine.test_connectivity(host, port, timeout=settings.default_timeout_seconds)
    if result.reachable:
        ui.success(f"{host}:{port} está alcançável (latência: {result.latency_ms}ms)")
    else:
        ui.warn(f"{host}:{port} não está alcançável ({result.error})")

    if ui.confirm("Salvar no histórico?", default=False):
        reporter.save("netcore", f"Teste de conectividade {host}:{port}", result.__dict__)


def _listener(ui: UI, settings: Settings) -> None:
    bind_host = ui.prompt("Endereço para escutar [ENTER = 0.0.0.0]") or "0.0.0.0"
    port = _port_input(ui)
    if port is None:
        return
    timeout_raw = ui.prompt("Timeout em segundos para aceitar conexão [ENTER = 60]") or "60"
    try:
        timeout = float(timeout_raw)
    except ValueError:
        ui.error("Timeout inválido.")
        return

    ui.info(f"Escutando em {bind_host}:{port} (timeout={timeout}s). Aguardando conexão...")
    log.info(f"Listener NetCore iniciado em {bind_host}:{port}")

    def on_connect(addr):
        ui.success(f"Conexão recebida de {addr[0]}:{addr[1]}")

    def on_data(data: bytes):
        try:
            print(data.decode("utf-8", errors="replace"), end="")
        except Exception:
            print(repr(data))

    engine.start_tcp_listener(bind_host, port, on_data=on_data, on_connect=on_connect, timeout=timeout)
    ui.info("Conexão encerrada.")


def _send_data(ui: UI, settings: Settings) -> None:
    host_raw = ui.prompt("Host de destino")
    try:
        host = validate_target(host_raw)
    except ValidationError as exc:
        ui.error(str(exc))
        return
    port = _port_input(ui)
    if port is None:
        return
    text = ui.prompt("Dados a enviar (texto)")
    response = engine.send_tcp_data(host, port, text.encode("utf-8"), timeout=settings.default_timeout_seconds)
    if response:
        ui.success("Resposta recebida:")
        print(response.decode("utf-8", errors="replace"))
    else:
        ui.info("Dados enviados. Nenhuma resposta recebida.")


def _send_file(ui: UI, settings: Settings, reporter: ReportManager) -> None:
    host_raw = ui.prompt("Host do listener de destino")
    try:
        host = validate_target(host_raw)
    except ValidationError as exc:
        ui.error(str(exc))
        return
    port = _port_input(ui)
    if port is None:
        return
    path_str = ui.prompt("Caminho do arquivo a enviar")
    path = Path(path_str).expanduser()
    if not path.is_file():
        ui.error("Arquivo não encontrado.")
        return

    ui.info(f"Enviando '{path.name}' para {host}:{port}...")
    result = engine.send_file(host, port, path, timeout=settings.http_request_timeout)
    ui.success(f"Transferido: {result.bytes_transferred} bytes em {result.duration_seconds}s")
    if ui.confirm("Salvar no histórico?", default=False):
        reporter.save(
            "netcore",
            f"Envio de arquivo {path.name}",
            {"host": host, "port": port, **result.__dict__, "path": str(result.path)},
        )


def _receive_file(ui: UI, settings: Settings, reporter: ReportManager) -> None:
    bind_host = ui.prompt("Endereço para escutar [ENTER = 0.0.0.0]") or "0.0.0.0"
    port = _port_input(ui)
    if port is None:
        return
    out_str = ui.prompt("Caminho de saída para o arquivo recebido")
    output_path = Path(out_str).expanduser()
    if output_path.exists() and not ui.confirm(f"'{output_path}' já existe. Sobrescrever?", default=False):
        ui.warn("Operação cancelada.")
        return

    ui.info(f"Escutando em {bind_host}:{port} para receber arquivo (Ctrl+C para cancelar)...")
    result = engine.receive_file(bind_host, port, output_path, timeout=120.0)
    ui.success(f"Recebido: {result.bytes_transferred} bytes -> {result.path}")
    if ui.confirm("Salvar no histórico?", default=False):
        reporter.save(
            "netcore",
            f"Recebimento de arquivo em {output_path.name}",
            {"host": bind_host, "port": port, **{k: v for k, v in result.__dict__.items() if k != "path"}, "path": str(result.path)},
        )
