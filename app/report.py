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
    "SAFE": "Находок нет. Это «не найдено известных проблем», а не гарантия безопасности.",
    "UNKNOWN": "Находок нет, но покрытие неполное: часть файлов не прочитана, поэтому вердикт не выдаётся.",
    "CRITICAL": "Критический риск: агенту нельзя доверять в текущем виде.",
    "HIGH": "Высокий риск: есть находки, которые нужно закрыть до подключения.",
    "MEDIUM": "Средний риск: требуются правки, но блокирующих проблем нет.",
    "LOW": "Низкий риск: серьёзных проблем не видно, есть замечания.",
}
DOC_EXT = (".md", ".txt", ".rst")


def _dt() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


_PATH_RE = compiled = None


def _paths_in(text: str) -> list[str]:
    import re
    return re.findall(r"[\w./-]+\.(?:md|txt|rst|py|js|mjs|ts|json|ya?ml|toml|sh|html|css)", text.lower())


def is_doc(f: dict) -> bool:
    """Находка относится к документации?

    Прямая проверка по расширению плюс разбор коррелированных находок:
    AS-CHAIN-* приходят с file="<correlated>", а источник перечислен в
    evidence/matched_text. Если все источники — markdown, это тоже документация.
    """
    path = str(f.get("file", "")).lower()
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
    lines.append(f"# Veyra Audit — {d.get('source_name', 'архив')}")
    lines.append("")
    lines.append(f"- **Scan ID:** `{d.get('scan_id', '—')}`")
    lines.append(f"- **Дата:** {_dt()}")
    lines.append(f"- **Файлов-артефактов найдено:** {len(d.get('agent_roots') or [])}")
    lines.append(f"- **Время скана:** {d.get('elapsed_ms', 0)} мс")
    lines.append(f"- **Режим оценки:** {'код + документация' if include_docs else 'только код и конфиги'}")
    lines.append("")
    lines.append(f"## Итог: уровень риска **{risk}** · объём находок {score}/100")
    bucket = d.get("bucket_all" if include_docs else "bucket_code")
    if bucket and bucket != risk:
        lines.append("")
        lines.append(f"> Сумма весов даёт {bucket}: это объём находок, а не их тяжесть. "
                     f"Уровень риска считается по самой тяжёлой находке.")
    if raw >= 100:
        lines.append("")
        lines.append(f"> Потолок шкалы объёма: сырая сумма весов {raw}.")
    lines.append("")
    lines.append(RISK_TEXT.get(risk, "Чем выше оценка — тем хуже."))
    lines.append("")
    lines.append("| Severity | Находок |")
    lines.append("|---|---|")
    for sev in SEV_ORDER:
        lines.append(f"| {sev} | {counts.get(sev.lower(), 0)} |")
    lines.append(f"| **Всего** | **{total}** |")
    lines.append("")
    if not include_docs and docs:
        lines.append(f"_Документация: {len(docs)} находок не входят в оценку — см. раздел в конце._")
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

    if not include_docs and docs:
        doc_counts = _counts(docs)
        lines.append("## Документация — не входит в оценку")
        lines.append("")
        lines.append("Примеры команд и описания в markdown: это инструкции для человека, "
                     "а не исполняемый код. Проверять их нужно глазами.")
        lines.append("")
        lines.append("| Severity | Находок |")
        lines.append("|---|---|")
        for sev in SEV_ORDER:
            lines.append(f"| {sev} | {doc_counts.get(sev.lower(), 0)} |")
        lines.append("")
        for f in docs[:20]:
            lines.append(f"- `{f.get('file')}:{f.get('line')}` — {f.get('rule_id')} · {f.get('title')}")
        if len(docs) > 20:
            lines.append(f"- … и ещё {len(docs) - 20}")
        lines.append("")

    lines.append("---")
    lines.append("Veyra — детерминированный статический анализатор. Код не исполнялся, "
                 "сетевые запросы при сканировании не выполнялись. Отчёт — основание "
                 "для ручной проверки, а не окончательный вердикт.")
    return "\n".join(lines)
