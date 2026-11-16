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

from .report import is_doc

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


# те же веса, что в Veyra (src/veyra/models.py): сумма с потолком 100
WEIGHTS = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 0}


def _score(findings: list[dict]) -> tuple[int, int]:
    """Возвращает (score с потолком, сырую сумму весов)."""
    raw = sum(WEIGHTS.get((f.get("severity") or "").upper(), 0)
              for f in findings if not f.get("suppressed"))
    return min(raw, 100), raw


SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _max_risk(findings: list[dict]) -> str:
    """Риск по самой тяжёлой находке, а не по сумме весов.

    Сумма весов — это объём шума: двадцать MEDIUM («HTTP-вызов в скрипте»)
    дают 100/100, хотя критичного там нет. Уровень риска должен отвечать на
    вопрос «насколько плохо», а не «сколько нашлось».
    """
    best = "SAFE"
    for f in findings:
        sev = (f.get("severity") or "").upper()
        if SEV_RANK.get(sev, 0) > SEV_RANK.get(best, 0):
            best = sev
    return best if best != "INFO" else "LOW"


def _risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    if score >= 5:
        return "LOW"
    return "SAFE"


def _safe_extract(zf: zipfile.ZipFile, dest: Path) -> int:
    total = 0
    entries = 0
    for info in zf.infolist():
        entries += 1
        if entries > MAX_ENTRIES:
            raise ScanError(f"too many files in the archive (>{MAX_ENTRIES})")
        name = info.filename
        if name.startswith("/") or ".." in Path(name).parts:
            raise ScanError("unsafe path inside the archive")
        target = (dest / name).resolve()
        if not str(target).startswith(str(dest.resolve())):
            raise ScanError("unsafe path inside the archive")
        mode = info.external_attr >> 16
        if (mode & 0o170000) == 0o120000:   # symlink
            continue
        total += info.file_size
        if total > MAX_UNPACKED:
            raise ScanError("archive unpacks larger than allowed")
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
        raise ScanError("file is larger than 8 MB")
    if not zipfile.is_zipfile(__import__("io").BytesIO(archive)):
        raise ScanError("a .zip with the agent sources is required")

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
        # Veyra: 0 = чисто, 1 = находки >= порога, 2 = есть CRITICAL.
        # Это коды вердикта, а не сбоя — JSON на stdout есть во всех трёх случаях.
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            raise ScanError(
                f"scanner exited with code {proc.returncode}: {proc.stderr[-300:] or 'empty output'}"
            )

        data = _strip_paths(data, work)
        data["scan_id"] = scan_id
        data["source_name"] = filename
        data["elapsed_ms"] = int((time.time() - started) * 1000)
        data["agent_roots"] = roots
        data["counts"] = {k: len([f for f in data.get("findings", []) if f.get("severity") == k.upper()])
                          for k in ("critical", "high", "medium", "low")}
        # Отделяем находки в документации от находок в коде и конфигах:
        # пример команды в README — не то же самое, что исполняемый скрипт.
        findings = data.get("findings", [])
        docs = [f for f in findings if is_doc(f)]
        code = [f for f in findings if not is_doc(f)]
        data["doc_findings"] = len(docs)
        data["code_findings"] = len(code)

        # Оценку считаем отдельно по коду и отдельно по документации:
        # пример команды в README не должен переводить проект в CRITICAL.
        data["score_code"], data["weight_code"] = _score(code)
        data["score_all"], data["weight_all"] = _score(findings)
        data["risk_code"] = _max_risk(code)
        data["risk_all"] = _max_risk(findings)
        data["bucket_code"] = _risk_level(data["score_code"])
        data["bucket_all"] = _risk_level(data["score_all"])
        data["capped_code"] = data["weight_code"] >= 100
        data["capped_all"] = data["weight_all"] >= 100
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
