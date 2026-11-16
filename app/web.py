"""Veyra Audit — web service: landing, upload, gated report, PDF export."""
from __future__ import annotations

import json
import os
import time
from collections import defaultdict, deque
from pathlib import Path

from flask import (Flask, abort, redirect, render_template, request,
                   send_file, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix

from .i18n import get_lang, t
from .pdf import html_to_pdf
from .report import group_findings, split_docs, to_markdown
from .scanner import ScanError, cleanup_old, run_scan

BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE = Path(os.environ.get("AUDIT_STORAGE", BASE_DIR / "storage"))
STORAGE.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))
app.config["MAX_CONTENT_LENGTH"] = 9 * 1024 * 1024
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

FREE_PREVIEW = int(os.environ.get("AUDIT_FREE_FINDINGS", "3"))
UNLOCK_CODES = {c.strip() for c in os.environ.get("UNLOCK_CODES", "VEYRA-PRO").split(",") if c.strip()}
INDEX_FILE = STORAGE / "index.json"
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


@app.context_processor
def inject_i18n():
    lang = get_lang()
    return {"lang": lang, "t": lambda key, **kw: t(key, lang, **kw)}


@app.after_request
def remember_lang(resp):
    q = (request.args.get("lang") or "").lower()
    if q in ("en", "ru"):
        resp.set_cookie("lang", q, max_age=31536000, samesite="Lax")
    return resp


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


def _index() -> dict:
    if INDEX_FILE.exists():
        try:
            return json.loads(INDEX_FILE.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def _index_put(bundle_hash: str, scan_id: str) -> None:
    idx = _index()
    cutoff = time.time() - 30 * 86400
    idx = {k: v for k, v in idx.items() if isinstance(v, dict) and v.get("ts", 0) > cutoff}
    idx[bundle_hash] = {"scan_id": scan_id, "ts": time.time()}
    INDEX_FILE.write_text(json.dumps(idx))


def _unlocked(scan_id: str) -> bool:
    if request.args.get("code") in UNLOCK_CODES:
        return True
    return request.cookies.get(f"u_{scan_id}") == "1"


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/scan")
def scan():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()
    lang = get_lang()
    if not _rate_ok(ip):
        return render_template("index.html", error=t("err.rate", lang)), 429

    f = request.files.get("archive")
    if not f or not f.filename:
        return render_template("index.html", error=t("err.no_file", lang)), 400

    data = f.read()
    try:
        result = run_scan(data, f.filename)
    except ScanError as e:
        return render_template("index.html", error=str(e)), 400
    except Exception as e:  # noqa: BLE001
        return render_template("index.html", error=f"Internal scanner error: {e.__class__.__name__}"), 500

    # одна бесплатная проверка на бандл: повторный скан ведёт к первому отчёту
    idx = _index()
    prev = idx.get(result["bundle_hash"])
    if prev and (STORAGE / f"{prev['scan_id']}.json").exists():
        return redirect(url_for("report", scan_id=prev["scan_id"], already=1))

    cleanup_old(STORAGE)
    (STORAGE / f"{result['scan_id']}.json").write_text(json.dumps(result, ensure_ascii=False))
    _index_put(result["bundle_hash"], result["scan_id"])
    return redirect(url_for("report", scan_id=result["scan_id"]))


@app.get("/r/<scan_id>")
def report(scan_id: str):
    d = _load(scan_id)
    include_docs = request.args.get("docs") == "1"
    unlocked = _unlocked(scan_id)
    code, docs = split_docs(d.get("findings", []))
    for f in code:
        f["_doc"] = False
    for f in docs:
        f["_doc"] = True

    full = d.get("findings", []) if include_docs else code
    full_sorted = sorted(full, key=lambda f: SEV_ORDER.index((f.get("severity") or "LOW").upper())
                         if (f.get("severity") or "LOW").upper() in SEV_ORDER else 9)
    shown = full_sorted if unlocked else full_sorted[:FREE_PREVIEW]

    groups = group_findings(shown)
    counts = {s: len([f for f in full if (f.get("severity") or "").upper() == s]) for s in SEV_ORDER}
    return render_template(
        "report.html", d=d, groups=groups, counts=counts,
        shown_count=len(shown), total_count=len(full), locked_count=max(0, len(full) - len(shown)),
        docs_count=len(docs), include_docs=include_docs, unlocked=unlocked, free_n=FREE_PREVIEW,
        score=(d.get("score_all", 0) if include_docs else d.get("score_code", 0)),
        risk=(d.get("risk_all", "—") if include_docs else d.get("risk_code", "—")),
        raw=(d.get("weight_all", 0) if include_docs else d.get("weight_code", 0)),
        bucket=(d.get("bucket_all", "—") if include_docs else d.get("bucket_code", "—")),
        policy=("FAIL" if (counts["CRITICAL"] or counts["HIGH"]) else "PASS"),
        order=SEV_ORDER)


@app.post("/r/<scan_id>/unlock")
def unlock(scan_id: str):
    _load(scan_id)
    code = (request.form.get("code") or "").strip()
    if code not in UNLOCK_CODES:
        return render_template("report.html", **_report_ctx(scan_id, unlock_error=True)), 403
    resp = redirect(url_for("report", scan_id=scan_id))
    resp.set_cookie(f"u_{scan_id}", "1", max_age=7 * 86400, httponly=True, samesite="Lax")
    return resp


def _report_ctx(scan_id: str, unlock_error: bool = False) -> dict:
    d = _load(scan_id)
    include_docs = request.args.get("docs") == "1"
    code, docs = split_docs(d.get("findings", []))
    for f in code:
        f["_doc"] = False
    for f in docs:
        f["_doc"] = True
    full = d.get("findings", []) if include_docs else code
    full_sorted = sorted(full, key=lambda f: SEV_ORDER.index((f.get("severity") or "LOW").upper())
                         if (f.get("severity") or "LOW").upper() in SEV_ORDER else 9)
    shown = full_sorted[:FREE_PREVIEW]
    groups = group_findings(shown)
    counts = {s: len([f for f in full if (f.get("severity") or "").upper() == s]) for s in SEV_ORDER}
    return dict(d=d, groups=groups, counts=counts, shown_count=len(shown), total_count=len(full),
                locked_count=max(0, len(full) - len(shown)), docs_count=len(docs),
                include_docs=include_docs, unlocked=False, free_n=FREE_PREVIEW,
                score=(d.get("score_all", 0) if include_docs else d.get("score_code", 0)),
                risk=(d.get("risk_all", "—") if include_docs else d.get("risk_code", "—")),
                raw=(d.get("weight_all", 0) if include_docs else d.get("weight_code", 0)),
                bucket=(d.get("bucket_all", "—") if include_docs else d.get("bucket_code", "—")),
                policy=("FAIL" if (counts["CRITICAL"] or counts["HIGH"]) else "PASS"),
                order=SEV_ORDER, unlock_error=unlock_error)


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


@app.get("/r/<scan_id>.pdf")
def report_pdf(scan_id: str):
    d = _load(scan_id)
    unlocked = _unlocked(scan_id)
    include_docs = request.args.get("docs") == "1"
    code, docs = split_docs(d.get("findings", []))
    full = d.get("findings", []) if include_docs else code
    full_sorted = sorted(full, key=lambda f: SEV_ORDER.index((f.get("severity") or "LOW").upper())
                         if (f.get("severity") or "LOW").upper() in SEV_ORDER else 9)
    shown = full_sorted if unlocked else full_sorted[:FREE_PREVIEW]
    groups = group_findings(shown)
    counts = {s: len([f for f in full if (f.get("severity") or "").upper() == s]) for s in SEV_ORDER}
    lang = get_lang()
    html = render_template(
        "report_pdf.html", d=d, groups=groups, counts=counts, order=SEV_ORDER,
        shown_count=len(shown), total_count=len(full), locked_count=max(0, len(full) - len(shown)),
        unlocked=unlocked, free_n=FREE_PREVIEW, include_docs=include_docs, lang=lang,
        score=(d.get("score_all", 0) if include_docs else d.get("score_code", 0)),
        risk=(d.get("risk_all", "—") if include_docs else d.get("risk_code", "—")),
        t=lambda key, **kw: t(key, lang, **kw))
    suffix = "full" if unlocked else "preview"
    p = STORAGE / f"{scan_id}-{suffix}.pdf"
    if not p.exists() or p.stat().st_mtime < (STORAGE / f"{scan_id}.json").stat().st_mtime:
        html_to_pdf(html, p)
    return send_file(p, as_attachment=True, download_name=f"veyra-audit-{scan_id}.pdf", mimetype="application/pdf")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8090")))
