"""Veyra Audit — Markdown rendering and shared finding helpers (English)."""
from __future__ import annotations

from datetime import datetime, timezone

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_LABEL = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "⚪ LOW",
}
RISK_TEXT = {
    "SAFE": "No findings. This means “no known issues found”, not a guarantee of safety.",
    "UNKNOWN": "No findings, but coverage is incomplete: part of the tree was not read, so no verdict is given.",
    "CRITICAL": "Critical risk: the agent cannot be trusted in its current state.",
    "HIGH": "High risk: findings must be closed before the agent gets access.",
    "MEDIUM": "Medium risk: fixes are needed, but nothing blocking.",
    "LOW": "Low risk: no serious issues, some remarks.",
}
DOC_EXT = (".md", ".txt", ".rst")


def _dt() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _paths_in(text: str) -> list[str]:
    import re
    return re.findall(r"[\w./-]+\.(?:md|txt|rst|py|js|mjs|ts|json|ya?ml|toml|sh|html|css)", text.lower())


def is_doc(f: dict) -> bool:
    """Is the finding about documentation?

    Direct extension check plus correlated findings: AS-CHAIN-* arrive with
    file="<correlated>" and list their sources in evidence/matched_text.
    If every source is markdown, the chain is documentation too.
    """
    path = str(f.get("file", "")).lower()
    name = path.rsplit("/", 1)[-1]
    # SKILL.md / AGENTS.md / CLAUDE.md are instructions the agent follows —
    # they are in scope, unlike README and prose docs.
    if name in {"skill.md", "agents.md", "claude.md", "agent.md"}:
        return False
    if "/skills/" in f"/{path}" and path.endswith(DOC_EXT):
        return False
    if path.endswith(DOC_EXT):
        return True
    if path.startswith("<"):
        blob = f"{f.get('evidence', '')} {f.get('matched_text', '')}"
        paths = _paths_in(blob)
        if paths:
            return all(p.endswith(DOC_EXT) for p in paths)
    return False


def split_docs(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    docs = [f for f in findings if is_doc(f)]
    code = [f for f in findings if not is_doc(f)]
    return code, docs


def group_findings(findings: list[dict]) -> dict[str, list[dict]]:
    out = {s: [] for s in SEV_ORDER}
    for f in findings:
        sev = (f.get("severity") or "LOW").upper()
        out.setdefault(sev, []).append(f)
    for sev in out:
        out[sev].sort(key=lambda f: (f.get("file") or "", f.get("line") or 0))
    return out


def _counts(items: list[dict]) -> dict[str, int]:
    c = {s.lower(): 0 for s in SEV_ORDER}
    for f in items:
        sev = (f.get("severity") or "LOW").lower()
        c[sev] = c.get(sev, 0) + 1
    return c


def to_markdown(d: dict, include_docs: bool = False) -> str:
    all_findings = d.get("findings", [])
    code, docs = split_docs(all_findings)
    shown = all_findings if include_docs else code
    counts = _counts(shown)
    groups = group_findings(shown)
    total = len(shown)
    score = d.get("score_all" if include_docs else "score_code", d.get("score", 0))
    risk = d.get("risk_all" if include_docs else "risk_code", d.get("risk_level", "—"))
    raw = d.get("weight_all" if include_docs else "weight_code", 0)

    lines = []
    lines.append(f"# Veyra Audit — {d.get('source_name', 'archive')}")
    lines.append("")
    lines.append(f"- **Scan ID:** `{d.get('scan_id', '—')}`")
    lines.append(f"- **Date:** {_dt()}")
    lines.append(f"- **Agent artifacts found:** {len(d.get('agent_roots') or [])}")
    lines.append(f"- **Scan time:** {d.get('elapsed_ms', 0)} ms")
    lines.append(f"- **Scoring mode:** {'code + documentation' if include_docs else 'code and configs only'}")
    lines.append("")
    lines.append(f"## Result: risk **{risk}** · finding volume {score}/100")
    bucket = d.get("bucket_all" if include_docs else "bucket_code")
    if bucket and bucket != risk:
        lines.append("")
        lines.append(f"> The weight sum lands in {bucket}: that is volume, not severity. "
                     "The risk level is set by the most severe finding.")
    if raw >= 100:
        lines.append("")
        lines.append(f"> Volume scale is capped: raw weight sum is {raw}.")
    lines.append("")
    lines.append(RISK_TEXT.get(risk, "The higher — the worse."))
    lines.append("")
    lines.append("| Severity | Findings |")
    lines.append("|---|---|")
    for sev in SEV_ORDER:
        lines.append(f"| {sev} | {counts.get(sev.lower(), 0)} |")
    lines.append(f"| **Total** | **{total}** |")
    lines.append("")
    if not include_docs and docs:
        lines.append(f"_Documentation: {len(docs)} findings are out of scope — see the last section._")
        lines.append("")

    if d.get("agent_roots"):
        lines.append("## What was checked")
        for r in d["agent_roots"][:20]:
            lines.append(f"- `{r}`")
        if len(d["agent_roots"]) > 20:
            lines.append(f"- … and {len(d['agent_roots']) - 20} more")
        lines.append("")

    for sev in SEV_ORDER:
        items = groups.get(sev) or []
        if not items:
            continue
        lines.append(f"## {SEV_LABEL[sev]} — {len(items)}")
        lines.append("")
        for f in items[:60]:
            loc = f"{f.get('file', '?')}:{f.get('line', '?')}"
            lines.append(f"### {f.get('rule_id', '')} · {f.get('title', '')}")
            lines.append(f"- **Where:** `{loc}`")
            lines.append(f"- **Confidence:** {f.get('confidence', '—')}")
            if f.get("evidence"):
                lines.append(f"- **What it sees:** {f['evidence']}")
            if f.get("matched_text"):
                snippet = str(f["matched_text"]).replace("\n", " ")[:220]
                lines.append(f"- **Snippet:** `{snippet}`")
            if f.get("cwe"):
                lines.append(f"- **CWE:** {', '.join(f['cwe']) if isinstance(f['cwe'], list) else f['cwe']}")
            if f.get("mitre"):
                m = ", ".join(x.get("id", "") for x in f["mitre"] if isinstance(x, dict))
                if m:
                    lines.append(f"- **MITRE ATT&CK:** {m}")
            if f.get("remediation"):
                lines.append(f"- **How to fix:** {f['remediation']}")
            lines.append("")
        if len(items) > 60:
            lines.append(f"_…and {len(items) - 60} more findings of this level in the full JSON._")
            lines.append("")

    if not include_docs and docs:
        doc_counts = _counts(docs)
        lines.append("## Documentation — out of scope")
        lines.append("")
        lines.append("Command examples and prose in markdown: these are instructions for a human, "
                     "not executable code. Review them by eye.")
        lines.append("")
        lines.append("| Severity | Findings |")
        lines.append("|---|---|")
        for sev in SEV_ORDER:
            lines.append(f"| {sev} | {doc_counts.get(sev.lower(), 0)} |")
        lines.append("")
        for f in docs[:20]:
            lines.append(f"- `{f.get('file')}:{f.get('line')}` — {f.get('rule_id')} · {f.get('title')}")
        if len(docs) > 20:
            lines.append(f"- … and {len(docs) - 20} more")
        lines.append("")

    lines.append("---")
    lines.append("Veyra is a deterministic static analyser. No code was executed, "
                 "no network requests were made during the scan. The report is a basis "
                 "for human review, not a final verdict.")
    return "\n".join(lines)
