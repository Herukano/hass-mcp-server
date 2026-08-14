"""Security and lifecycle tests for bounded AppDaemon file access."""

import json
from hashlib import sha256
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from custom_components.mcp_server_http_transport.const import DOMAIN
from custom_components.mcp_server_http_transport.tools import appdaemon_files as tools


def _hass() -> Mock:
    hass = Mock()
    hass.data = {DOMAIN: {"appdaemon_file_access": True}}

    async def executor(fn, *args):
        return fn(*args)

    hass.async_add_executor_job = AsyncMock(side_effect=executor)
    return hass


def _payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


@pytest.fixture
def apps_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "addon_configs" / "a0d7b954_appdaemon" / "apps"
    root.mkdir(parents=True)
    monkeypatch.setattr(tools, "_APPS_ROOT", root)
    return root


@pytest.mark.asyncio
async def test_read_nested_file_and_sha(apps_root: Path):
    file = apps_root / "predictors" / "solar.py"
    file.parent.mkdir()
    file.write_text("class Solar: pass\n")
    result = _payload(await tools.get_appdaemon_file(_hass(), {"path": "predictors/solar.py"}))
    assert result["path"] == "predictors/solar.py"
    assert result["content"] == "class Solar: pass\n"
    assert result["sha256"] == sha256(b"class Solar: pass\n").hexdigest()


@pytest.mark.asyncio
async def test_save_is_atomic_preserves_mode_and_creates_backup(apps_root: Path):
    file = apps_root / "solar.py"
    file.write_text("old\n")
    file.chmod(0o600)
    result = _payload(
        await tools.save_appdaemon_file(_hass(), {"path": "solar.py", "content": "new\n"})
    )
    assert result["success"]
    assert result["sha256_before"] == sha256(b"old\n").hexdigest()
    assert result["sha256_after"] == sha256(b"new\n").hexdigest()
    assert file.read_text() == "new\n" and (file.stat().st_mode & 0o777) == 0o600
    assert (apps_root / result["backup"] / "solar.py").read_text() == "old\n"


@pytest.mark.asyncio
async def test_delete_creates_backup_and_reports_hash(apps_root: Path):
    file = apps_root / "solar.py"
    file.write_text("delete me\n")
    result = _payload(await tools.delete_appdaemon_file(_hass(), {"path": "solar.py"}))
    assert result["success"]
    assert result["sha256_before"] == sha256(b"delete me\n").hexdigest()
    assert result["sha256_after"] is None
    assert not file.exists()
    assert (apps_root / result["backup"] / "solar.py").read_text() == "delete me\n"


@pytest.mark.asyncio
async def test_restore_creates_pre_restore_backup(apps_root: Path):
    file = apps_root / "solar.py"
    file.write_text("original\n")
    backup = _payload(await tools.backup_appdaemon_files(_hass(), {}))["backup"].split("/")[-1]
    file.write_text("changed\n")
    result = _payload(await tools.restore_appdaemon_backup(_hass(), {"timestamp": backup}))
    assert result["success"] and file.read_text() == "original\n"
    assert (apps_root / result["pre_restore_backup"] / "solar.py").read_text() == "changed\n"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "../config/configuration.yaml",
        "/config/configuration.yaml",
        "/addon_configs/other/apps/x.py",
    ],
)
async def test_rejects_traversal_and_absolute_escapes(apps_root: Path, path: str):
    text = (await tools.get_appdaemon_file(_hass(), {"path": path}))["content"][0]["text"]
    assert "Error reading AppDaemon file" in text
    assert not (apps_root.parent.parent / "config").exists()


@pytest.mark.asyncio
async def test_rejects_symlink_escape_and_cannot_touch_config(apps_root: Path, tmp_path: Path):
    outside = tmp_path / "config"
    outside.mkdir()
    victim = outside / "configuration.yaml"
    victim.write_text("safe\n")
    (apps_root / "escape").symlink_to(outside, target_is_directory=True)
    text = (
        await tools.save_appdaemon_file(
            _hass(), {"path": "escape/configuration.yaml", "content": "bad\n"}
        )
    )["content"][0]["text"]
    assert "Error saving AppDaemon file" in text and victim.read_text() == "safe\n"


@pytest.mark.asyncio
async def test_list_backups_and_regular_files_do_not_expose_snapshots(apps_root: Path):
    (apps_root / "solar.py").write_text("x\n")
    await tools.backup_appdaemon_files(_hass(), {})
    files = _payload(await tools.list_appdaemon_files(_hass(), {}))
    backups = _payload(await tools.list_appdaemon_backups(_hass(), {}))
    assert [item["path"] for item in files] == ["solar.py"]
    assert len(backups) == 1 and backups[0]["files"] == ["solar.py"]
