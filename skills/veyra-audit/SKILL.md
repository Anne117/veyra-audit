---
name: veyra-audit
description: "Use when auditing an AI agent, skill or MCP config for security before connecting it."
version: 1.0.0
author: Anne Arintseva
license: PolyForm-Noncommercial-1.0.0
metadata:
  hermes:
    tags: [security, ai-agents, mcp, skills, audit, static-analysis]
    editorial_name: Veyra Audit
    editorial_description: Static security review for AI agents — finds secrets, exfiltration, dangerous commands and attack chains before an agent gets access.
    requires_tools: [terminal, write_file]
    requires_toolsets: [terminal]
---

# Veyra Audit — security review for AI agents

Use this skill when the user wants to check an AI agent, a third-party skill,
an MCP server config or a prompt bundle **before** giving it access to files,
secrets or the network.

Veyra is a deterministic static analyser: it reads the artifacts, builds a
component graph, applies rules and reports findings with evidence. It never
executes scanned code and never makes network requests during a scan.

## When to use

- "check this skill / MCP server before I install it";
- "is this agent safe to connect to our repo?";
- a vendor ships an agent bundle and you need a written risk summary;
- a repository contains `SKILL.md`, `AGENTS.md`, MCP JSON/YAML configs and
  you want a review that is repeatable and diffable.

Do **not** use it as a substitute for a penetration test or as proof that
something is safe.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install veyra          # engine
# or, for the service + report UI:
git clone https://github.com/Anne117/veyra-audit.git
cd veyra-audit && .venv/bin/pip install -r requirements.txt
```

## Run a scan (CLI)

```bash
veyra scan ./agent-bundle --format json > report.json
veyra scan ./agent-bundle                # human-readable terminal report
veyra scan ./agent-bundle --format html > report.html
```

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default HIGH),
`2` CRITICAL findings. Treat `2` as a verdict, not a crash.

## Run the service

```bash
.venv/bin/gunicorn --workers 1 --threads 4 --timeout 300 \
  --bind 127.0.0.1:8090 app.web:app
# open http://127.0.0.1:8090
```

The web UI accepts a `.zip` up to 8 MB, stores the report for 24 hours and
offers Markdown/JSON export.

## Reading the report

1. **Risk level** comes from the most severe finding. **Volume** is the
   weighted sum capped at 100 — twenty MEDIUM findings saturate it without
   anything being critical.
2. **Documentation is out of scope by default.** Findings in `*.md`, `*.txt`,
   `*.rst` are examples for humans; the UI shows them separately and can
   include them on request (`?docs=1`).
3. For each finding check `file:line`, `evidence`, `confidence`, `CWE`, `MITRE`.
   A finding without a location is a correlation — verify its contributing
   sources in `evidence`.
4. Report what you verified. If coverage was partial, say so instead of
   claiming the bundle is clean.

## Safety rules

- never run the scanned code, not even "just to check";
- do not upload archives with live credentials — rotate anything that leaked
  before scanning;
- the report is evidence for a human decision, not an automated approval;
- the free tier is for personal and noncommercial use; company use requires a
  commercial license ([COMMERCIAL.md](../../COMMERCIAL.md)).

## Output template

When reporting back to the user:

```
Risk: <level> (volume <score>/100)
Scope: <n> code findings, <m> documentation findings (out of scope)

1. [SEVERITY] <rule> — <file>:<line>
   What: <evidence>
   Fix: <remediation>
```

End with an explicit statement of what was **not** checked.
