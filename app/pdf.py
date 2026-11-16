"""Render an HTML report to PDF with headless Chromium."""
from __future__ import annotations

import glob
import os
import subprocess
import tempfile
from pathlib import Path

CANDIDATES = [
    os.environ.get("CHROME_BIN", ""),
    *glob.glob(str(Path.home() / ".cache/ms-playwright/chromium-*/chrome-linux*/chrome")),
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
]


def chrome_bin() -> str:
    for c in CANDIDATES:
        if c and Path(c).exists():
            return c
    raise RuntimeError("Chromium binary not found; set CHROME_BIN")


def html_to_pdf(html: str, out: Path, timeout: int = 90) -> Path:
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as f:
        f.write(html)
        tmp = f.name
    try:
        proc = subprocess.run(
            [chrome_bin(), "--headless=new", "--no-sandbox", "--disable-gpu",
             "--disable-dev-shm-usage", "--no-pdf-header-footer",
             f"--print-to-pdf={out}", f"file://{tmp}"],
            capture_output=True, text=True, timeout=timeout,
        )
        if not out.exists() or out.stat().st_size < 1000:
            raise RuntimeError(f"PDF generation failed: {proc.stderr[-300:]}")
        return out
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
