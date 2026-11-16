"""Veyra Audit — Telegram-бот.

Принимает .zip с агентом, запускает тот же сканер, что и сайт, и отдаёт
краткий разбор + полный отчёт файлом. Токен берётся из BOT_TOKEN.
"""
from __future__ import annotations

import io
import json
import os
import time
from pathlib import Path

import requests

from .report import to_markdown
from .scanner import ScanError, cleanup_old, run_scan

BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE = Path(os.environ.get("AUDIT_STORAGE", BASE_DIR / "storage"))
STORAGE.mkdir(parents=True, exist_ok=True)

TOKEN = os.environ.get("BOT_TOKEN", "")
PUBLIC_BASE = os.environ.get("PUBLIC_BASE", "http://51.38.99.122:8090").rstrip("/")
API = f"https://api.telegram.org/bot{TOKEN}"

LIMIT_PER_DAY = int(os.environ.get("BOT_LIMIT_PER_DAY", "3"))
HITS: dict[int, list[float]] = {}

WELCOME = (
    "🐾 Veyra Audit — статическая проверка AI-агентов.\n\n"
    "Пришли .zip со скиллами, промптами и MCP-конфигами — верну отчёт: "
    "что агент читает, куда отправляет данные, какие команды выполняет "
    "и какие цепочки складываются в атаку.\n\n"
    "Код не исполняется, сетевые запросы при скане не делаются.\n\n"
    "Бесплатно: 3 скана в сутки.\n"
    "Разовый аудит проекта — 4 900 ₽, разбор отчёта и повторный скан после правок включены.\n\n"
    "Просто отправь архив файлом."
)


def api(method: str, **kwargs):
    r = requests.post(f"{API}/{method}", timeout=60, **kwargs)
    try:
        return r.json()
    except ValueError:
        return {"ok": False, "description": r.text[:200]}


def send(chat_id: int, text: str, **extra):
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML",
               "disable_web_page_preview": True}
    payload.update(extra)
    return api("sendMessage", json=payload)


def send_doc(chat_id: int, filename: str, content: bytes, caption: str = ""):
    return api("sendDocument", data={"chat_id": chat_id, "caption": caption[:900]},
               files={"document": (filename, content, "text/markdown")})


def allowed(user_id: int) -> bool:
    now = time.time()
    q = [t for t in HITS.get(user_id, []) if now - t < 86400]
    HITS[user_id] = q
    if len(q) >= LIMIT_PER_DAY:
        return False
    q.append(now)
    return True


def summary_text(d: dict) -> str:
    c = d.get("counts", {})
    top = [f for f in d.get("findings", []) if f.get("severity") in ("CRITICAL", "HIGH")][:3]
    lines = [
        f"<b>Отчёт готов</b> · <code>{d['scan_id']}</code>",
        f"Оценка риска: <b>{d.get('score', 0)}/100</b> · <b>{d.get('risk_level')}</b>",
        f"CRITICAL {c.get('critical', 0)} · HIGH {c.get('high', 0)} · "
        f"MEDIUM {c.get('medium', 0)} · LOW {c.get('low', 0)}",
        "",
    ]
    for f in top:
        lines.append(f"• <code>{f.get('rule_id')}</code> {f.get('title')} — "
                     f"{f.get('file')}:{f.get('line')}")
    if top:
        lines.append("")
    lines.append(f"Полная версия: {PUBLIC_BASE}/r/{d['scan_id']}")
    return "\n".join(lines)


def handle_document(msg: dict):
    chat_id = msg["chat"]["id"]
    doc = msg["document"]
    name = doc.get("file_name", "agent.zip")
    if not name.lower().endswith(".zip"):
        send(chat_id, "Нужен .zip с исходниками агента.")
        return
    if doc.get("file_size", 0) > 8 * 1024 * 1024:
        send(chat_id, "Файл больше 8 МБ — пришли архив поменьше.")
        return
    if not allowed(msg["from"]["id"]):
        send(chat_id, "Лимит бесплатных сканов на сегодня исчерпан (3). "
                      "Напиши @annearintseva — обсудим пакет.")
        return

    send(chat_id, "Сканирую… это обычно 10–30 секунд.")
    info = api("getFile", json={"file_id": doc["file_id"]})
    if not info.get("ok"):
        send(chat_id, "Не смогла получить файл из Telegram, попробуй ещё раз.")
        return
    path = info["result"]["file_path"]
    raw = requests.get(f"https://api.telegram.org/file/bot{TOKEN}/{path}", timeout=120)
    if raw.status_code != 200:
        send(chat_id, "Не смогла скачать файл из Telegram.")
        return

    try:
        d = run_scan(raw.content, name)
    except ScanError as e:
        send(chat_id, f"⚠️ {e}")
        return
    except Exception as e:  # noqa: BLE001
        send(chat_id, f"Внутренняя ошибка: {e.__class__.__name__}")
        return

    cleanup_old(STORAGE)
    (STORAGE / f"{d['scan_id']}.json").write_text(json.dumps(d, ensure_ascii=False))
    md = to_markdown(d)
    (STORAGE / f"{d['scan_id']}.md").write_text(md)

    send(chat_id, summary_text(d))
    send_doc(chat_id, f"veyra-audit-{d['scan_id']}.md", md.encode(),
             caption="Полный отчёт в Markdown. JSON пришлю по запросу.")


def main():
    if not TOKEN:
        raise SystemExit("BOT_TOKEN не задан")
    print("Veyra Audit bot started", flush=True)
    offset = 0
    while True:
        try:
            r = requests.get(f"{API}/getUpdates",
                             params={"offset": offset, "timeout": 50,
                                     "allowed_updates": '["message"]'}, timeout=70)
            data = r.json()
            if not data.get("ok"):
                time.sleep(3)
                continue
            for upd in data.get("result", []):
                offset = upd["update_id"] + 1
                msg = upd.get("message") or {}
                if "document" in msg:
                    handle_document(msg)
                elif msg.get("text", "").startswith("/start"):
                    send(msg["chat"]["id"], WELCOME)
                elif msg.get("text", "").startswith("/price"):
                    send(msg["chat"]["id"],
                         "0 ₽ — 3 скана в сутки\n"
                         "4 900 ₽ — разовый аудит проекта (до 5 архивов, разбор, повторный скан)\n"
                         "39 900 ₽/мес — безлимит и гейт в CI\n\n"
                         "Заказ: @annearintseva")
                elif msg.get("text"):
                    send(msg["chat"]["id"], "Пришли .zip с агентом — или /start, чтобы посмотреть возможности.")
        except Exception as e:  # noqa: BLE001
            print("loop error:", e.__class__.__name__, flush=True)
            time.sleep(3)


if __name__ == "__main__":
    main()
