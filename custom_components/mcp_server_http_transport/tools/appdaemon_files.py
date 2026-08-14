"""Narrow, opt-in access to AppDaemon application files only."""

import hashlib
import json
import os
import re
import shutil
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from homeassistant.core import HomeAssistant

from ..const import DOMAIN
from . import (
    ANNOTATION_DESTRUCTIVE,
    ANNOTATION_IDEMPOTENT,
    ANNOTATION_NON_IDEMPOTENT,
    ANNOTATION_READ_ONLY,
    register_tool,
)

_APPS_ROOT = Path("/addon_configs/a0d7b954_appdaemon/apps")
_BACKUP_DIR_NAME = ".mcp_appdaemon_backups"
_BACKUP_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}-\d+$")
_MAX_FILE_BYTES = 1_048_576
_DEFAULT_MODE = 0o640


def _disabled() -> dict[str, Any]:
    return {"content": [{"type": "text", "text": (
        "AppDaemon file access is disabled. Enable it in the MCP Server integration settings."
    )}]}


def _enabled(hass: HomeAssistant) -> bool:
    return hass.data.get(DOMAIN, {}).get("appdaemon_file_access", False)


def _root() -> Path:
    """Return the fixed production boundary (monkeypatched only by tests)."""
    return _APPS_ROOT


def _error(prefix: str, exc: Exception) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": f"Error {prefix}: {exc}"}]}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_path(filename: str, *, allow_backup: bool = False) -> Path:
    """Resolve a user path under the fixed root without following symlinks."""
    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("Path must not be empty")
    normalized = filename.replace("\\", "/")
    candidate = Path(normalized)
    if candidate.is_absolute() or normalized.startswith("/"):
        raise ValueError("Absolute paths are not allowed")
    if ".." in candidate.parts:
        raise ValueError("Parent directory references ('..') are not allowed")
    root = _root()
    if root.is_symlink():
        raise ValueError("AppDaemon apps root must not be a symlink")
    resolved_root = root.resolve()
    path = root.joinpath(*candidate.parts)
    if not path.resolve(strict=False).is_relative_to(resolved_root):
        raise ValueError("Path resolves outside the AppDaemon apps root")
    # Do not follow even an in-root symlink: an attacker cannot race a checked path
    # into another filesystem location between validation and mutation.
    current = root
    for part in candidate.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Symlink paths are not allowed")
    if not allow_backup and _BACKUP_DIR_NAME in candidate.parts:
        raise ValueError("Backup snapshots are managed; use list/restore AppDaemon backups")
    return path


def _relative(path: Path) -> str:
    return path.relative_to(_root()).as_posix()


def _app_files(root: Path) -> list[Path]:
    """All regular app files, excluding controlled backups and symlinks."""
    if not root.is_dir():
        raise ValueError(f"AppDaemon apps root is unavailable: {root}")
    found: list[Path] = []
    for path in root.rglob("*"):
        if _BACKUP_DIR_NAME in path.relative_to(root).parts:
            continue
        if path.is_symlink():
            continue
        if path.is_file():
            if not path.resolve().is_relative_to(root.resolve()):
                continue
            found.append(path)
    return sorted(found)


def _new_backup(root: Path) -> tuple[Path, list[str]]:
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")
    backup_base = root / _BACKUP_DIR_NAME
    if backup_base.is_symlink() or not backup_base.resolve(strict=False).is_relative_to(root.resolve()):
        raise ValueError("Controlled backup directory is unsafe")
    backup = backup_base / timestamp
    backup.mkdir(parents=True, exist_ok=False)
    files: list[str] = []
    for source in _app_files(root):
        rel = source.relative_to(root)
        target = backup / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target, follow_symlinks=False)
        files.append(rel.as_posix())
    return backup, files


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError("Target directory does not exist or is a symlink")
    tmp = path.with_name(f".{path.name}.mcp_tmp")
    try:
        with tmp.open("wb") as handle:
            handle.write(content)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


@register_tool("list_appdaemon_files", "List regular files under the fixed AppDaemon apps root.",
               {"type": "object", "properties": {}}, ANNOTATION_READ_ONLY)
async def list_appdaemon_files(hass: HomeAssistant, arguments: dict[str, Any]) -> dict[str, Any]:
    if not _enabled(hass): return _disabled()
    try:
        def work():
            return [{"path": _relative(p), "size": p.stat().st_size,
                     "sha256": _sha(p.read_bytes())} for p in _app_files(_root())]
        value = await hass.async_add_executor_job(work)
        return {"content": [{"type": "text", "text": json.dumps(value, indent=2)}]}
    except Exception as exc: return _error("listing AppDaemon files", exc)


@register_tool("get_appdaemon_file", "Read a file relative to the fixed AppDaemon apps root.",
               {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}, ANNOTATION_READ_ONLY)
async def get_appdaemon_file(hass: HomeAssistant, arguments: dict[str, Any]) -> dict[str, Any]:
    if not _enabled(hass): return _disabled()
    try:
        path = _safe_path(arguments["path"])
        def work():
            if not path.is_file() or path.is_symlink(): raise ValueError("File does not exist")
            data = path.read_bytes()
            if len(data) > _MAX_FILE_BYTES: raise ValueError("File is too large (maximum 1 MB)")
            return {"path": _relative(path), "sha256": _sha(data), "content": data.decode("utf-8")}
        value = await hass.async_add_executor_job(work)
        return {"content": [{"type": "text", "text": json.dumps(value)}]}
    except Exception as exc: return _error("reading AppDaemon file", exc)


@register_tool("save_appdaemon_file", "Atomically write an AppDaemon app file after a rollback snapshot.",
               {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}, ANNOTATION_IDEMPOTENT)
async def save_appdaemon_file(hass: HomeAssistant, arguments: dict[str, Any]) -> dict[str, Any]:
    if not _enabled(hass): return _disabled()
    try:
        path = _safe_path(arguments["path"]); content = arguments["content"].encode("utf-8")
        if len(content) > _MAX_FILE_BYTES: raise ValueError("Content is too large (maximum 1 MB)")
        def work():
            before = path.read_bytes() if path.exists() else None
            if path.exists() and (not path.is_file() or path.is_symlink()): raise ValueError("Target is not a regular file")
            backup, _ = _new_backup(_root())
            mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else _DEFAULT_MODE
            _atomic_write(path, content, mode)
            return {"success": True, "path": _relative(path), "backup": _relative(backup), "sha256_before": _sha(before) if before is not None else None, "sha256_after": _sha(content)}
        value = await hass.async_add_executor_job(work)
        return {"content": [{"type": "text", "text": json.dumps(value)}]}
    except Exception as exc: return _error("saving AppDaemon file", exc)


@register_tool("delete_appdaemon_file", "Delete an AppDaemon app file after a rollback snapshot.",
               {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}, ANNOTATION_DESTRUCTIVE)
async def delete_appdaemon_file(hass: HomeAssistant, arguments: dict[str, Any]) -> dict[str, Any]:
    if not _enabled(hass): return _disabled()
    try:
        path = _safe_path(arguments["path"])
        def work():
            if not path.is_file() or path.is_symlink(): raise ValueError("File does not exist")
            before = path.read_bytes(); backup, _ = _new_backup(_root()); path.unlink()
            return {"success": True, "path": _relative(path), "backup": _relative(backup), "sha256_before": _sha(before), "sha256_after": None}
        value = await hass.async_add_executor_job(work)
        return {"content": [{"type": "text", "text": json.dumps(value)}]}
    except Exception as exc: return _error("deleting AppDaemon file", exc)


@register_tool("backup_appdaemon_files", "Create a timestamped snapshot of AppDaemon app files.",
               {"type": "object", "properties": {}}, ANNOTATION_NON_IDEMPOTENT)
async def backup_appdaemon_files(hass: HomeAssistant, arguments: dict[str, Any]) -> dict[str, Any]:
    if not _enabled(hass): return _disabled()
    try:
        backup, files = await hass.async_add_executor_job(_new_backup, _root())
        return {"content": [{"type": "text", "text": json.dumps({"success": True, "backup": _relative(backup), "files": files})}]}
    except Exception as exc: return _error("backing up AppDaemon files", exc)


@register_tool("list_appdaemon_backups", "List controlled AppDaemon rollback snapshots.",
               {"type": "object", "properties": {}}, ANNOTATION_READ_ONLY)
async def list_appdaemon_backups(hass: HomeAssistant, arguments: dict[str, Any]) -> dict[str, Any]:
    if not _enabled(hass): return _disabled()
    try:
        def work():
            base = _root() / _BACKUP_DIR_NAME
            if not base.is_dir(): return []
            return [{"timestamp": p.name, "path": _relative(p), "files": [x.relative_to(p).as_posix() for x in _app_files(p)]}
                    for p in sorted(base.iterdir(), reverse=True) if p.is_dir() and _BACKUP_TS_RE.fullmatch(p.name) and not p.is_symlink()]
        value = await hass.async_add_executor_job(work)
        return {"content": [{"type": "text", "text": json.dumps(value)}]}
    except Exception as exc: return _error("listing AppDaemon backups", exc)


@register_tool("restore_appdaemon_backup", "Restore a snapshot after first snapshotting current app files.",
               {"type": "object", "properties": {"timestamp": {"type": "string"}}, "required": ["timestamp"]}, ANNOTATION_NON_IDEMPOTENT)
async def restore_appdaemon_backup(hass: HomeAssistant, arguments: dict[str, Any]) -> dict[str, Any]:
    if not _enabled(hass): return _disabled()
    try:
        timestamp = arguments["timestamp"]
        if not _BACKUP_TS_RE.fullmatch(timestamp): raise ValueError("Invalid backup timestamp")
        def work():
            root = _root(); source = root / _BACKUP_DIR_NAME / timestamp
            if not source.is_dir() or source.is_symlink() or not source.resolve().is_relative_to((root / _BACKUP_DIR_NAME).resolve()): raise ValueError("Backup does not exist")
            pre, _ = _new_backup(root); restored = []
            for item in _app_files(source):
                rel = item.relative_to(source); target = _safe_path(rel.as_posix())
                _atomic_write(target, item.read_bytes(), stat.S_IMODE(item.stat().st_mode)); restored.append(rel.as_posix())
            return {"success": True, "backup": _relative(source), "pre_restore_backup": _relative(pre), "restored": restored}
        value = await hass.async_add_executor_job(work)
        return {"content": [{"type": "text", "text": json.dumps(value)}]}
    except Exception as exc: return _error("restoring AppDaemon backup", exc)
