"""Veyra Audit — веб-сервис: лендинг + загрузка архива + отчёт."""
from __future__ import annotations

import json
import os
import time
from collections import defaultdict, deque
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, send_file, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from .report import group_findings, split_docs, to_markdown
from .scanner import ScanError, cleanup_old, run_scan

BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE = Path(os.environ.get("AUDIT_STORAGE", BASE_DIR / "storage"))
STORAGE.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))
app.config["MAX_CONTENT_LENGTH"] = 9 * 1024 * 1024
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

HITS: dict[str, deque] = defaultdict(deque)
LIMIT_PER_HOUR = int(os.environ.get("AUDIT_RATE_LIMIT", "6"))


def _rate_ok(ip: str) -> bool:
    now = time.time()
    q = HITS[ip]
    while q and now - q[0] > 3600:
        q.popleft()
    if len(q) >= LIMIT_PER_HOUR:
        return False
    q.append(now)
    return True


def _load(scan_id: str) -> dict:
    if not scan_id.isalnum():
        abort(404)
    p = STORAGE / f"{scan_id}.json"
    if not p.exists():
        abort(404)
    return json.loads(p.read_text())


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/scan")
def scan():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()
    if not _rate_ok(ip):
        return render_template("index.html", error="Слишком много сканов с этого адреса. Попробуй через час."), 429

    f = request.files.get("archive")
    if not f or not f.filename:
        return render_template("index.html", error="Прикрепи .zip с исходниками агента."), 400

    data = f.read()
    try:
        result = run_scan(data, f.filename)
    except ScanError as e:
        return render_template("index.html", error=str(e)), 400
    except Exception as e:  # noqa: BLE001
        return render_template("index.html", error=f"Внутренняя ошибка сканера: {e.__class__.__name__}"), 500

    cleanup_old(STORAGE)
    (STORAGE / f"{result['scan_id']}.json").write_text(json.dumps(result, ensure_ascii=False))
    return redirect(url_for("report", scan_id=result["scan_id"]))


@app.get("/r/<scan_id>")
def report(scan_id: str):
    d = _load(scan_id)
    include_docs = request.args.get("docs") == "1"
    code, docs = split_docs(d.get("findings", []))
    for f in code:
        f["_doc"] = False
    for f in docs:
        f["_doc"] = True
    shown = d.get("findings", []) if include_docs else code
    groups = group_findings(shown)
    counts = {s: len(groups.get(s, [])) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    return render_template(
        "report.html", d=d, groups=groups, counts=counts, shown_count=len(shown),
        docs_count=len(docs), include_docs=include_docs,
        score=(d.get("score_all", 0) if include_docs else d.get("score_code", 0)),
        risk=(d.get("risk_all", "—") if include_docs else d.get("risk_code", "—")),
        raw=(d.get("weight_all", 0) if include_docs else d.get("weight_code", 0)),
        bucket=(d.get("bucket_all", "—") if include_docs else d.get("bucket_code", "—")),
        policy=("FAIL" if (counts["CRITICAL"] or counts["HIGH"]) else "PASS"),
        order=["CRITICAL", "HIGH", "MEDIUM", "LOW"])


@app.get("/r/<scan_id>.md")
def report_md(scan_id: str):
    d = _load(scan_id)
    p = STORAGE / f"{scan_id}.md"
    p.write_text(to_markdown(d, include_docs=request.args.get("docs") == "1"))
    return send_file(p, as_attachment=True, download_name=f"veyra-audit-{scan_id}.md", mimetype="text/markdown")


@app.get("/r/<scan_id>.json")
def report_json(scan_id: str):
    p = STORAGE / f"{scan_id}.json"
    _load(scan_id)
    return send_file(p, as_attachment=True, download_name=f"veyra-audit-{scan_id}.json", mimetype="application/json")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8090")))
