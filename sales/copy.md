# Outreach copy

## Threads / X — announcement

I've been building AI systems for three years. And the same thing keeps
happening: a team connects a third-party skill or an MCP server because "it's
convenient" — without reading what it actually does.

Then it turns out the skill reads `~/.ssh/id_rsa`, sends it to an external
endpoint, and tells the agent not to mention it.

So I built Veyra Audit — a static security review for agents before they get
access. Drop a zip with skills, prompts and MCP configs, get a report: what the
agent reads, where it sends data, which commands it runs, and how those pieces
chain into an attack path. Risk level, evidence, CWE/MITRE, fix priorities.

No code is executed. No network requests during a scan. Deterministic: same
input, same report.

First scan is free (personal use): <link>

If your agent is already in production and you don't know what's in its skills —
message me, let's look together.

---

## Short version (for comments)

Connecting third-party skills or MCP servers to your agent? I run a static
audit: what it reads, where it sends data, which commands it runs. Report with
evidence and fixes, no code execution. First scan free: <link>

---

## Cold message (chat / email)

Subject: security review for your agent's skills and MCP servers

Hi — I'm an AI engineer (3 years in big tech). I do static security reviews of
AI agents.

If you connect third-party skills or MCP servers, there is a typical risk: the
skill reads sensitive files and sends them out while the agent says nothing.
Code review does not catch it, because it looks like an ordinary instruction in
markdown.

I review an agent archive and return a report: findings by severity,
`file:line`, evidence, CWE/MITRE, fix priorities. No code is executed.

One-off project audit is €490, including a walkthrough and a re-scan after
fixes. Happy to run the first scan for free — just send the archive.

---

## How to talk about price

- €490 — one project, up to 5 archives, 30-minute walkthrough, re-scan.
- €3,900/month — unlimited scans and a CI gate (SARIF for GitHub/GitLab).
- Never compare it to a pentest: different class of work, cheaper and faster,
  and it does not replace a pentest.

## What not to promise

- "we find everything" — no, only known patterns;
- "security guarantee" — no, the report is a basis for human review;
- "replaces a pentest" — no.
