"""Veyra Audit — статический аудит AI-агентов, скиллов и MCP-конфигов.

Сканирование полностью статическое: код не исполняется, сетевые запросы
из самого сканера не делаются. Загруженный архив живёт во временной папке
и удаляется сразу после разбора.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from pathlib import Path

VEYRA_SRC = os.environ.get("VEYRA_SRC", "/home/ubuntu/veyra/src")
WORK_ROOT = Path(os.environ.get("AUDIT_WORK_ROOT", "/tmp/veyra-audit"))

MAX_UPLOAD = 8 * 1024 * 1024      # 8 МБ архив
MAX_UNPACKED = 48 * 1024 * 1024   # 48 МБ распакованного
MAX_ENTRIES = 3000
SCAN_TIMEOUT = 180

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
TEXT_EXT = {
    ".md", ".txt", ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml",
    ".sh", ".bash", ".zsh", ".html", ".css", ".sql", ".env", ".ini", ".cfg",
}


class ScanError(Exception):
    pass


def _safe_extract(zf: zipfile.ZipFile, dest: Path) -> int:
    total = 0
    entries = 0
    for info in zf.infolist():
        entries += 1
        if entries > MAX_ENTRIES:
            raise ScanError(f"слишком много файлов в архиве (>{MAX_ENTRIES})")
        name = info.filename
        if name.startswith("/") or ".." in Path(name).parts:
            raise ScanError("небезопасный путь внутри архива")
        target = (dest / name).resolve()
        if not str(target).startswith(str(dest.resolve())):
            raise ScanError("небезопасный путь внутри архива")
        mode = info.external_attr >> 16
        if (mode & 0o170000) == 0o120000:   # symlink
            continue
        total += info.file_size
        if total > MAX_UNPACKED:
            raise ScanError("архив распаковывается больше допустимого")
    zf.extractall(dest)
    return total


def _prepare_tree(root: Path) -> None:
    """Убираем мусор, чтобы отчёт не тонул в чужих зависимостях."""
    for p in list(root.rglob("*")):
        if p.is_dir() and p.name in SKIP_DIRS:
            shutil.rmtree(p, ignore_errors=True)


def _find_agent_roots(root: Path) -> list[str]:
    """Что вообще похоже на агентские артефакты."""
    hits = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        low = p.name.lower()
        if low in {"skill.md", "agents.md", "claude.md"} or "mcp" in low and p.suffix in {".json", ".yaml", ".yml", ".toml"}:
            hits.append(str(p.relative_to(root)))
    return hits[:50]


def _strip_paths(data: dict, root: Path) -> dict:
    def rel(v: str) -> str:
        try:
            return str(Path(v).resolve().relative_to(root))
        except Exception:
            return Path(v).name
    for f in data.get("findings", []):
        if isinstance(f.get("file"), str):
            f["file"] = rel(f["file"])
    for path in data.get("attack_paths", []) or []:
        for node in path.get("nodes", []) or []:
            if isinstance(node, dict) and isinstance(node.get("file"), str):
                node["file"] = rel(node["file"])
    return data


def run_scan(archive: bytes, filename: str = "upload.zip") -> dict:
    if len(archive) > MAX_UPLOAD:
        raise ScanError("файл больше 8 МБ")
    if not zipfile.is_zipfile(__import__("io").BytesIO(archive)):
        raise ScanError("нужен .zip с исходниками агента")

    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    scan_id = uuid.uuid4().hex[:12]
    work = Path(tempfile.mkdtemp(prefix=f"{scan_id}-", dir=WORK_ROOT))
    started = time.time()
    try:
        with zipfile.ZipFile(__import__("io").BytesIO(archive)) as zf:
            _safe_extract(zf, work)
        _prepare_tree(work)
        roots = _find_agent_roots(work)

        env = dict(os.environ)
        if VEYRA_SRC and Path(VEYRA_SRC).is_dir():
            env["PYTHONPATH"] = VEYRA_SRC
        proc = subprocess.run(
            [sys.executable, "-m", "veyra.cli", "scan", str(work), "--format", "json"],
            capture_output=True, text=True, timeout=SCAN_TIMEOUT, env=env,
        )
        if proc.returncode not in (0, 1):
            raise ScanError(f"сканер завершился с кодом {proc.returncode}: {proc.stderr[-300:]}")
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            raise ScanError("сканер вернул не JSON — проверь версию Veyra")

        data = _strip_paths(data, work)
        data["scan_id"] = scan_id
        data["source_name"] = filename
        data["elapsed_ms"] = int((time.time() - started) * 1000)
        data["agent_roots"] = roots
        data["counts"] = {k: len([f for f in data.get("findings", []) if f.get("severity") == k.upper()])
                          for k in ("critical", "high", "medium", "low")}
        return data
    finally:
        shutil.rmtree(work, ignore_errors=True)


def cleanup_old(storage: Path, ttl_hours: int = 24) -> None:
    if not storage.exists():
        return
    cutoff = time.time() - ttl_hours * 3600
    for p in storage.glob("*.json"):
        try:
            if p.stat().st_mtime < cutoff:
                p.unlink()
        except OSError:
            pass
