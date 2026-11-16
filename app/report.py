"""Рендер отчёта Veyra Audit в Markdown (для письма/бота) и подготовка данных для HTML."""
from __future__ import annotations

from datetime import datetime, timezone

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_LABEL = {
    "CRITICAL": "🔴 КРИТИЧНО",
    "HIGH": "🟠 ВЫСОКИЙ",
    "MEDIUM": "🟡 СРЕДНИЙ",
    "LOW": "⚪ НИЗКИЙ",
}
RISK_TEXT = {
    "SAFE": "Находок нет, покрытие полное. Это «не найдено известных проблем», а не гарантия безопасности.",
    "UNKNOWN": "Находок нет, но покрытие неполное: часть файлов не прочитана, поэтому вердикт не выдаётся.",
    "CRITICAL": "Критический риск: агенту нельзя доверять в текущем виде.",
    "HIGH": "Высокий риск: есть находки, которые нужно закрыть до подключения.",
    "MEDIUM": "Средний риск: требуются правки, но блокирующих проблем нет.",
    "LOW": "Низкий риск: серьёзных проблем не видно, есть замечания.",
}


def _dt() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def group_findings(findings: list[dict]) -> dict[str, list[dict]]:
    out = {s: [] for s in SEV_ORDER}
    for f in findings:
        sev = (f.get("severity") or "LOW").upper()
        out.setdefault(sev, []).append(f)
    for sev in out:
        out[sev].sort(key=lambda f: (f.get("file") or "", f.get("line") or 0))
    return out


def to_markdown(d: dict) -> str:
    counts = d.get("counts") or d.get("summary") or {}
    groups = group_findings(d.get("findings", []))
    total = len(d.get("findings", []))
    lines = []
    lines.append(f"# Veyra Audit — {d.get('source_name', 'архив')}")
    lines.append("")
    lines.append(f"- **Scan ID:** `{d.get('scan_id', '—')}`")
    lines.append(f"- **Дата:** {_dt()}")
    lines.append(f"- **Файлов-артефактов найдено:** {len(d.get('agent_roots') or [])}")
    lines.append(f"- **Время скана:** {d.get('elapsed_ms', 0)} мс")
    lines.append("")
    lines.append(f"## Итог: оценка риска {d.get('score', '—')}/100 · **{d.get('risk_level', '—')}**")
    lines.append("")
    lines.append(RISK_TEXT.get(d.get("risk_level", ""), "Чем выше оценка — тем хуже."))
    lines.append("")
    lines.append("| Severity | Находок |")
    lines.append("|---|---|")
    for sev in SEV_ORDER:
        lines.append(f"| {sev} | {counts.get(sev.lower(), 0)} |")
    lines.append(f"| **Всего** | **{total}** |")
    lines.append("")

    if d.get("agent_roots"):
        lines.append("## Что проверялось")
        for r in d["agent_roots"][:20]:
            lines.append(f"- `{r}`")
        if len(d["agent_roots"]) > 20:
            lines.append(f"- … и ещё {len(d['agent_roots']) - 20}")
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
            lines.append(f"- **Где:** `{loc}`")
            lines.append(f"- **Уверенность:** {f.get('confidence', '—')}")
            if f.get("evidence"):
                lines.append(f"- **Что видно:** {f['evidence']}")
            if f.get("matched_text"):
                snippet = str(f["matched_text"]).replace("\n", " ")[:220]
                lines.append(f"- **Фрагмент:** `{snippet}`")
            if f.get("cwe"):
                lines.append(f"- **CWE:** {', '.join(f['cwe']) if isinstance(f['cwe'], list) else f['cwe']}")
            if f.get("mitre"):
                m = ", ".join(x.get("id", "") for x in f["mitre"] if isinstance(x, dict))
                if m:
                    lines.append(f"- **MITRE ATT&CK:** {m}")
            if f.get("remediation"):
                lines.append(f"- **Как исправить:** {f['remediation']}")
            lines.append("")
        if len(items) > 60:
            lines.append(f"_…и ещё {len(items) - 60} находок этого уровня в полном JSON._")
            lines.append("")

    lines.append("---")
    lines.append("Veyra — детерминированный статический анализатор. Код не исполнялся, "
                 "сетевые запросы при сканировании не выполнялись. Отчёт — основание "
                 "для ручной проверки, а не окончательный вердикт.")
    return "\n".join(lines)
