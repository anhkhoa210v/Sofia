"""Discord webhook reporting.

Sends the `domain | cve | evidence` report lines to the configured webhook.
When sending is disabled or fails, the payload is saved to webhook_unsent.json
so no findings are lost.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import List, Optional

import requests

from .logger import get_logger
from .report import ReportBuilder

log = get_logger()

MAX_MESSAGE_LEN = 1900


class DiscordWebhook:
    def __init__(self, url: str, enabled: bool):
        self.url = url
        self.enabled = enabled

    def send(self, target: str, report_lines: List[str],
             fallback_path: str = "webhook_unsent.json") -> bool:
        if not self.enabled or not self.url:
            log.info("webhook disabled - not sending")
            return False
        content = self._chunk(target, report_lines)
        ok = True
        for chunk in content:
            try:
                resp = requests.post(self.url, json={"content": chunk}, timeout=15)
                if resp.status_code not in (200, 204):
                    log.warn(f"webhook status {resp.status_code}: "
                             f"{resp.text[:200]}")
                    ok = False
                else:
                    log.info(f"webhook delivered ({len(chunk)} chars)")
            except requests.exceptions.RequestException as e:
                log.warn(f"webhook send failed: {e}")
                ok = False
        if not ok:
            self._save_fallback(target, report_lines, fallback_path)
        return ok

    def _chunk(self, target: str, lines: List[str]) -> List[str]:
        header = f"**Sofia XXE report** - {target} ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})"
        chunks: List[str] = []
        buf = header
        for line in lines:
            candidate = buf + "\n" + line
            if len(candidate) > MAX_MESSAGE_LEN:
                chunks.append(buf)
                buf = line
            else:
                buf = candidate
        if buf:
            chunks.append(buf)
        return chunks

    def _save_fallback(self, target: str, lines: List[str], path: str):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({
                    "target": target,
                    "webhook": self.url,
                    "unsent_at": datetime.now().isoformat(),
                    "lines": lines,
                }, f, ensure_ascii=False, indent=2)
            log.warn(f"webhook payload saved to {path}")
        except OSError as e:
            log.error(f"cannot save fallback payload: {e}")


def lines_from_result(result) -> List[str]:
    return ReportBuilder.report_lines(result)

