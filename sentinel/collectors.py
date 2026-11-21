"""Read-only local fact collection (Tier 1 / DETECT).

All collection happens on the host where the agent runs and is limited to
*reading* files and running a small allowlist of side-effect-free commands.
Nothing here writes to the filesystem, starts/stops services, or opens a
network socket.

Every command is executed without a shell (``subprocess`` with an argv list),
with a timeout and an output cap.  Each step is authorised by the
:class:`~sentinel.scope.ScopeGuard`, so a scope without a ``local_host`` target
cannot collect anything.
"""

from __future__ import annotations

import os
import pwd
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from typing import Any, Iterable

from .model import Evidence, utcnow
from .scope import ScopeGuard

READABLE_FILES = {
    "os_release": "/etc/os-release",
    "passwd": "/etc/passwd",
    "sshd_config": "/etc/ssh/sshd_config",
    "login_defs": "/etc/login.defs",
    "pam_common_password": "/etc/pam.d/common-password",
    "pwquality": "/etc/security/pwquality.conf",
    "sudoers": "/etc/sudoers",
}

PERMISSION_TARGETS = {
    "shadow": "/etc/shadow",
    "passwd": "/etc/passwd",
    "sudoers": "/etc/sudoers",
    "sshd_config": "/etc/ssh/sshd_config",
    "cron_d": "/etc/cron.d",
    "cron_daily": "/etc/cron.daily",
}

SUID_SCAN_ROOTS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin")
CRON_DIRS = ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly")
SYSTEMD_UNIT_DIRS = ("/etc/systemd/system", "/usr/lib/systemd/system")

MAX_OUTPUT_BYTES = 200_000


@dataclass
class CommandResult:
    argv: list[str]
    ok: bool
    exit_code: int | None
    stdout: str
    stderr: str
    truncated: bool = False
    error: str | None = None
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "argv": self.argv,
            "ok": self.ok,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "truncated": self.truncated,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


@dataclass
class LocalFacts:
    host: str
    collected_at: str = field(default_factory=utcnow)
    identity: dict[str, Any] = field(default_factory=dict)
    os: dict[str, Any] = field(default_factory=dict)
    files: dict[str, str | None] = field(default_factory=dict)
    permissions: dict[str, dict[str, Any]] = field(default_factory=dict)
    sudo: CommandResult | None = None
    suid: dict[str, Any] = field(default_factory=dict)
    capabilities: dict[str, Any] = field(default_factory=dict)
    cron: list[dict[str, Any]] = field(default_factory=list)
    path_dirs: list[dict[str, Any]] = field(default_factory=list)
    systemd_units: list[dict[str, Any]] = field(default_factory=list)
    accounts: list[dict[str, Any]] = field(default_factory=list)
    commands: list[CommandResult] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "collected_at": self.collected_at,
            "identity": self.identity,
            "os": self.os,
            "files": self.files,
            "permissions": self.permissions,
            "sudo": self.sudo.to_dict() if self.sudo else None,
            "suid": self.suid,
            "capabilities": self.capabilities,
            "cron": self.cron,
            "path_dirs": self.path_dirs,
            "systemd_units": self.systemd_units,
            "accounts": self.accounts,
            "commands": [c.to_dict() for c in self.commands],
        }


def _run(argv: list[str], timeout: int = 10) -> CommandResult:
    import time

    started = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, shell=False, allowlisted by caller
            argv,
            shell=False,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        out = proc.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")
        err = proc.stderr[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")
        return CommandResult(
            argv=argv,
            ok=proc.returncode == 0,
            exit_code=proc.returncode,
            stdout=out,
            stderr=err,
            truncated=len(proc.stdout) > MAX_OUTPUT_BYTES,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    except FileNotFoundError:
        return CommandResult(argv=argv, ok=False, exit_code=None, stdout="", stderr="", error="command not found",
                             duration_ms=int((time.monotonic() - started) * 1000))
    except subprocess.TimeoutExpired:
        return CommandResult(argv=argv, ok=False, exit_code=None, stdout="", stderr="", error=f"timeout after {timeout}s",
                             duration_ms=int((time.monotonic() - started) * 1000))


def _read_text(path: str, limit: int = 200_000) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
        return None


def _mode_str(st: os.stat_result) -> str:
    return stat.filemode(st.st_mode)


def _perm_info(path: str) -> dict[str, Any]:
    try:
        st = os.lstat(path)
    except OSError as exc:
        return {"path": path, "present": False, "error": str(exc)}
    is_symlink = stat.S_ISLNK(st.st_mode)
    target = os.readlink(path) if is_symlink else None
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = __import__("grp").getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    # A symlink's own mode is always 0777; what matters is the link target and
    # the parent directory.  Masked systemd units point at /dev/null, so treating
    # the link mode as a permission would produce false positives.
    return {
        "path": path,
        "present": True,
        "mode": _mode_str(st),
        "mode_octal": oct(stat.S_IMODE(st.st_mode)),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "owner": owner,
        "group": group,
        "is_symlink": is_symlink,
        "symlink_target": target,
        "other_write": (not is_symlink) and bool(st.st_mode & stat.S_IWOTH),
        "other_read": (not is_symlink) and bool(st.st_mode & stat.S_IROTH),
        "world_writable": (not is_symlink) and bool(st.st_mode & stat.S_IWOTH),
    }


def _parse_passwd(text: str) -> list[dict[str, Any]]:
    accounts = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        try:
            uid = int(parts[2])
        except ValueError:
            continue
        accounts.append({
            "name": parts[0],
            "uid": uid,
            "gid": int(parts[3]) if parts[3].isdigit() else None,
            "shell": parts[6],
            "is_system": uid < 1000 and uid != 0,
            "is_root": uid == 0,
            "login_shell": parts[6] not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", ""),
        })
    return accounts


def _parse_os_release(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for line in text.splitlines():
        if "=" in line and not line.strip().startswith("#"):
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip().strip('"')
    return out


def _scan_suid(guard: ScopeGuard, facts: LocalFacts) -> None:
    roots = [r for r in SUID_SCAN_ROOTS if os.path.isdir(r)]
    if not shutil.which("find") or not roots:
        facts.suid = {"available": False, "reason": "find not available or no scan roots", "paths": []}
        return
    guard.check_local("collect:suid_scan")
    argv = ["find", *roots, "-xdev", "-perm", "-4000", "-type", "f", "-print"]
    res = _run(argv, timeout=20)
    facts.commands.append(res)
    paths = [line.strip() for line in res.stdout.splitlines() if line.strip().startswith("/")]
    facts.suid = {
        "available": res.ok,
        "paths": paths,
        "scanned_roots": roots,
        "error": res.error or (res.stderr.strip() or None),
    }


def _scan_capabilities(guard: ScopeGuard, facts: LocalFacts) -> None:
    if not shutil.which("getcap"):
        facts.capabilities = {"available": False, "reason": "getcap not installed (libcap2-bin)", "entries": []}
        return
    roots = [r for r in SUID_SCAN_ROOTS if os.path.isdir(r)]
    guard.check_local("collect:file_capabilities")
    res = _run(["getcap", "-r", *roots], timeout=20)
    facts.commands.append(res)
    entries = [line.strip() for line in res.stdout.splitlines() if line.strip()]
    facts.capabilities = {"available": res.ok, "entries": entries, "error": res.error or (res.stderr.strip() or None)}


def _collect_cron(guard: ScopeGuard, facts: LocalFacts) -> None:
    guard.check_local("collect:cron_permissions")
    entries: list[dict[str, Any]] = []
    for directory in CRON_DIRS:
        if not os.path.isdir(directory):
            continue
        entries.append(_perm_info(directory))
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            entries.append(_perm_info(os.path.join(directory, name)))
    facts.cron = entries


def _collect_path_dirs(guard: ScopeGuard, facts: LocalFacts) -> None:
    guard.check_local("collect:path_dirs")
    try:
        euid = os.geteuid()
        gids = set(os.getgroups()) | {os.getegid()}
    except AttributeError:
        euid, gids = 0, set()
    dirs = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry or not os.path.isdir(entry):
            continue
        info = _perm_info(entry)
        try:
            st = os.stat(entry)
            info["writable_by_current_user"] = (
                st.st_mode & stat.S_IWOTH
                or (st.st_uid == euid and st.st_mode & stat.S_IWUSR)
                or (st.st_gid in gids and st.st_mode & stat.S_IWGRP)
            )
        except OSError:
            info["writable_by_current_user"] = None
        dirs.append(info)
    facts.path_dirs = dirs


def _collect_systemd(guard: ScopeGuard, facts: LocalFacts) -> None:
    guard.check_local("collect:systemd_units")
    entries = []
    for directory in SYSTEMD_UNIT_DIRS:
        if not os.path.isdir(directory):
            continue
        entries.append(_perm_info(directory))
        try:
            names = [n for n in sorted(os.listdir(directory)) if n.endswith((".service", ".timer"))]
        except OSError:
            continue
        for name in names[:200]:
            entries.append(_perm_info(os.path.join(directory, name)))
    facts.systemd_units = entries


def collect_local_facts(guard: ScopeGuard, host: str | None = None) -> LocalFacts:
    """Collect the fact bundle used by the local analysers."""
    host = host or os.uname().nodename
    facts = LocalFacts(host=host)

    guard.check_local("collect:identity")
    ident = _run(["id"], timeout=5)
    facts.commands.append(ident)
    facts.identity = {
        "user": _safe_user(),
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "group_ids": sorted(set(os.getgroups()) | {os.getegid()}) if hasattr(os, "getegid") else [],
        "id_output": ident.stdout.strip(),
        "id_error": ident.error or (ident.stderr.strip() or None),
    }

    guard.check_local("collect:os_release")
    os_text = _read_text(READABLE_FILES["os_release"]) or ""
    facts.os = _parse_os_release(os_text)
    uname = _run(["uname", "-srm"], timeout=5)
    facts.commands.append(uname)
    facts.os["uname"] = uname.stdout.strip()
    parts = uname.stdout.strip().split()
    if len(parts) >= 3:
        facts.os["kernel_release"] = parts[1]
        facts.os["arch"] = parts[2]

    guard.check_local("collect:config_files")
    for key, path in READABLE_FILES.items():
        facts.files[key] = _read_text(path)
    facts.permissions = {name: _perm_info(path) for name, path in PERMISSION_TARGETS.items()}
    passwd_text = facts.files.get("passwd") or ""
    facts.accounts = _parse_passwd(passwd_text)

    guard.check_local("collect:sudo_policy")
    if shutil.which("sudo"):
        res = _run(["sudo", "-n", "-l"], timeout=10)
        facts.commands.append(res)
        facts.sudo = res
    else:
        facts.sudo = CommandResult(argv=["sudo", "-n", "-l"], ok=False, exit_code=None, stdout="", stderr="",
                                   error="sudo not installed")

    _scan_suid(guard, facts)
    _scan_capabilities(guard, facts)
    _collect_cron(guard, facts)
    _collect_path_dirs(guard, facts)
    _collect_systemd(guard, facts)

    facts.evidence.append(Evidence(
        kind="local_facts",
        asset=host,
        summary="Paquete de hechos locales de solo lectura (identidad, SO, configuracion, permisos)",
        data=facts.to_dict(),
        source="collectors.collect_local_facts",
    ))
    return facts


def _safe_user() -> str | None:
    try:
        return pwd.getpwuid(os.geteuid()).pw_name
    except (KeyError, AttributeError):
        return os.environ.get("USER")


def sshd_effective_config(facts: LocalFacts) -> list[dict[str, Any]]:
    """Flatten sshd_config (with ``Include`` expansion) into ordered directives.

    sshd uses "first obtained value wins" semantics, so the caller must not
    assume the last directive is the effective one.  We keep file/line for
    traceability and let the checks apply first-match semantics.
    """
    directives: list[dict[str, Any]] = []
    root_text = facts.files.get("sshd_config")
    if root_text is None:
        return directives

    def expand(text: str, path: str, depth: int = 0) -> None:
        if depth > 2:
            return
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            key = parts[0]
            value = parts[1].strip() if len(parts) > 1 else ""
            if key.lower() == "include":
                for pattern in value.split():
                    import glob

                    for included in sorted(glob.glob(pattern)):
                        included_text = _read_text(included, limit=100_000) or ""
                        expand(included_text, included, depth + 1)
                continue
            directives.append({"file": path, "line": lineno, "key": key, "value": value})

    expand(root_text, "/etc/ssh/sshd_config")
    return directives


def first_directive(directives: Iterable[dict[str, Any]], key: str) -> dict[str, Any] | None:
    lowered = key.lower()
    for directive in directives:
        if directive["key"].lower() == lowered:
            return directive
    return None
