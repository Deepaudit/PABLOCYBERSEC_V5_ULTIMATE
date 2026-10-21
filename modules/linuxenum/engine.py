"""
modules/linuxenum/engine.py

PC LinuxEnum — enumeração e auditoria local de Linux.

MODO PADRÃO: SOMENTE LEITURA. Nenhuma função aqui modifica permissões,
instala persistência ou altera configurações do sistema. O módulo lê
arquivos e executa comandos de consulta já presentes no sistema
(ex.: 'ps', 'sudo -l') apenas para leitura de estado.

Direcionado a desafios de privilege escalation em laboratórios
próprios e plataformas de CTF (TryHackMe, HackTheBox) — não a
auditoria não autorizada de sistemas de terceiros.
"""

from __future__ import annotations

import grp
import os
import pwd
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

SENSITIVE_SUID_BINARIES_HINT = {
    "nmap", "vim", "find", "bash", "more", "less", "nano", "cp", "mv",
    "python", "python3", "perl", "ruby", "lua", "awk", "env", "tar",
    "docker", "node",
}


@dataclass
class UserInfo:
    username: str
    uid: int
    gid: int
    home: str
    shell: str
    groups: list[str] = field(default_factory=list)


@dataclass
class SudoInfo:
    raw_output: str
    can_run_as_root_without_password: bool
    entries: list[str] = field(default_factory=list)


@dataclass
class SpecialPermissionFile:
    path: str
    permissions: str
    is_suid: bool
    is_sgid: bool
    is_world_writable: bool
    known_gtfobins_hint: bool = False


@dataclass
class EnumReport:
    current_user: UserInfo | None = None
    all_users: list[UserInfo] = field(default_factory=list)
    sudo_info: SudoInfo | None = None
    special_permission_files: list[SpecialPermissionFile] = field(default_factory=list)
    cron_jobs: list[str] = field(default_factory=list)
    listening_ports: list[str] = field(default_factory=list)
    running_processes: list[str] = field(default_factory=list)
    writable_sensitive_paths: list[str] = field(default_factory=list)
    kernel_info: str = ""
    os_release: str = ""
    network_interfaces: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _run(cmd: list[str], timeout: float = 5.0) -> str:
    """Executa um comando de LEITURA já presente no sistema e retorna sua saída."""
    try:
        completed = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return completed.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def get_current_user() -> UserInfo:
    uid = os.getuid()
    pw = pwd.getpwuid(uid)
    try:
        groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
    except Exception:
        groups = []
    return UserInfo(
        username=pw.pw_name, uid=uid, gid=pw.pw_gid, home=pw.pw_dir, shell=pw.pw_shell, groups=groups
    )


def list_all_users(min_uid: int = 0) -> list[UserInfo]:
    users = []
    for entry in pwd.getpwall():
        if entry.pw_uid >= min_uid:
            try:
                groups = [g.gr_name for g in grp.getgrall() if entry.pw_name in g.gr_mem]
            except Exception:
                groups = []
            users.append(
                UserInfo(
                    username=entry.pw_name, uid=entry.pw_uid, gid=entry.pw_gid,
                    home=entry.pw_dir, shell=entry.pw_shell, groups=groups,
                )
            )
    return users


def check_sudo_permissions() -> SudoInfo:
    """Lê as permissões sudo do usuário atual via 'sudo -l' (leitura, sem executar nada)."""
    output = _run(["sudo", "-n", "-l"])
    no_password_risk = "NOPASSWD" in output
    entries = [line.strip() for line in output.splitlines() if line.strip()]
    return SudoInfo(raw_output=output, can_run_as_root_without_password=no_password_risk, entries=entries)


def find_special_permission_files(search_paths: list[str] | None = None, max_results: int = 200) -> list[SpecialPermissionFile]:
    """
    Procura arquivos com bit SUID/SGID ou permissão de escrita por todos,
    nos caminhos informados (padrão: diretórios comuns de binários).
    Apenas leitura de metadados — nenhum arquivo é modificado.
    """
    search_paths = search_paths or ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"]
    findings: list[SpecialPermissionFile] = []

    for base in search_paths:
        base_path = Path(base)
        if not base_path.is_dir():
            continue
        try:
            entries = list(base_path.iterdir())
        except PermissionError:
            continue
        for entry in entries:
            if len(findings) >= max_results:
                return findings
            try:
                st = entry.stat()
            except (OSError, PermissionError):
                continue
            mode = st.st_mode
            is_suid = bool(mode & stat.S_ISUID)
            is_sgid = bool(mode & stat.S_ISGID)
            is_world_writable = bool(mode & stat.S_IWOTH)
            if is_suid or is_sgid or is_world_writable:
                findings.append(
                    SpecialPermissionFile(
                        path=str(entry),
                        permissions=stat.filemode(mode),
                        is_suid=is_suid,
                        is_sgid=is_sgid,
                        is_world_writable=is_world_writable,
                        known_gtfobins_hint=entry.name in SENSITIVE_SUID_BINARIES_HINT,
                    )
                )
    return findings


def list_cron_jobs() -> list[str]:
    jobs = []
    crontab_out = _run(["crontab", "-l"])
    if crontab_out:
        jobs.extend(f"(usuário) {line}" for line in crontab_out.splitlines() if line.strip() and not line.startswith("#"))

    for system_cron in ("/etc/crontab",):
        path = Path(system_cron)
        if path.is_file():
            try:
                for line in path.read_text(errors="ignore").splitlines():
                    if line.strip() and not line.strip().startswith("#"):
                        jobs.append(f"(sistema:{system_cron}) {line}")
            except (OSError, PermissionError):
                continue

    cron_d = Path("/etc/cron.d")
    if cron_d.is_dir():
        try:
            for file in cron_d.iterdir():
                try:
                    for line in file.read_text(errors="ignore").splitlines():
                        if line.strip() and not line.strip().startswith("#"):
                            jobs.append(f"(sistema:{file}) {line}")
                except (OSError, PermissionError):
                    continue
        except PermissionError:
            pass

    return jobs


def list_listening_ports() -> list[str]:
    """Lista portas em escuta usando 'ss' (preferido) ou 'netstat' como fallback, se disponíveis."""
    output = _run(["ss", "-tulnp"])
    if not output:
        output = _run(["ss", "-tuln"])
    if not output:
        output = _run(["netstat", "-tuln"])
    return [line for line in output.splitlines() if line.strip()]


def list_processes() -> list[str]:
    output = _run(["ps", "-eo", "pid,user,comm", "--no-headers"])
    return [line.strip() for line in output.splitlines() if line.strip()]


def get_kernel_info() -> str:
    return _run(["uname", "-a"])


def get_os_release() -> str:
    path = Path("/etc/os-release")
    if path.is_file():
        try:
            return path.read_text(errors="ignore").strip()
        except (OSError, PermissionError):
            return ""
    return ""


def get_network_interfaces() -> list[str]:
    output = _run(["ip", "addr"])
    if not output:
        output = _run(["ifconfig"])
    return [line for line in output.splitlines() if line.strip()]


def check_writable_sensitive_paths() -> list[str]:
    """Verifica se arquivos sensíveis comuns são graváveis pelo usuário atual."""
    sensitive = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab"]
    writable = []
    for path_str in sensitive:
        path = Path(path_str)
        if path.exists() and os.access(path, os.W_OK):
            writable.append(path_str)
    return writable


def run_full_enum(profile: str = "basico") -> EnumReport:
    """
    Executa o perfil de enumeração escolhido.
    profile='basico'   -> usuário atual, sudo, SUID/SGID em diretórios padrão.
    profile='completo' -> tudo do básico + cron, portas, processos, rede.
    """
    report = EnumReport()
    report.current_user = get_current_user()
    report.sudo_info = check_sudo_permissions()
    report.special_permission_files = find_special_permission_files()
    report.writable_sensitive_paths = check_writable_sensitive_paths()
    report.kernel_info = get_kernel_info()
    report.os_release = get_os_release()

    if profile == "completo":
        report.all_users = list_all_users()
        report.cron_jobs = list_cron_jobs()
        report.listening_ports = list_listening_ports()
        report.running_processes = list_processes()
        report.network_interfaces = get_network_interfaces()

    if report.sudo_info and report.sudo_info.can_run_as_root_without_password:
        report.notes.append(
            "Encontrada entrada NOPASSWD no sudo — investigue manualmente se permite "
            "escalonamento de privilégio (ver GTFOBins para o binário envolvido)."
        )
    for finding in report.special_permission_files:
        if finding.is_suid and finding.known_gtfobins_hint:
            report.notes.append(
                f"Binário SUID '{finding.path}' está na lista de binários "
                "frequentemente listados no GTFOBins — vale investigação manual."
            )

    return report
