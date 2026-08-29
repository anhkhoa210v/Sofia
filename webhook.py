"""Discord webhook reporting.

Sends the `domain | cve | evidence` report lines to the configured webhook.
When sending is disabled or fails, the payload is queued to webhook_unsent.json
so no findings are lost; queued payloads can be replayed with replay_unsent().

S6 hardening:
  - webhook URL scheme validated (http/https only)
  - send retries with exponential backoff
  - redaction logging only fires when something was actually redacted
  - message length limit is configurable (Discord default 1900)
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

from .logger import get_logger
from .report import ReportBuilder

log = get_logger()

MAX_MESSAGE_LEN = 1900  # Discord limit; override via DiscordWebhook(max_len=...)

# Evidence redaction: report lines may embed exfiltrated file content
# (base64 blobs, DB passwords, API keys). Everything transmitted through the
# webhook is scrubbed; full evidence stays in the local report files.
_B64_RE = re.compile(r"[A-Za-z0-9+/]{64,}={0,2}")
_SECRET_RE = re.compile(
    r"(?i)(['\"]?(?:password|passwd|pwd|dbpassword|db_pass|secret|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|"
    r"token|auth[_-]?key|encryption[_-]?key)['\"]?\s*(?:=>|:|=)\s*)"
    r"([^,;\n]+)"
)
_URL_CRED_RE = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@")


def _redact(text: str) -> tuple:
    """Return (redacted_text, count) where count is the number of patterns
    that actually matched (S6: only log redaction when it happened)."""
    out = text
    count = 0
    new = _URL_CRED_RE.sub(r"\1[REDACTED]@", out)
    if new != out:
        count += 1
        out = new
    new = _SECRET_RE.sub(lambda m: m.group(1) + "[REDACTED]", out)
    if new != out:
        count += 1
        out = new
    new = _B64_RE.sub(lambda m: f"[base64:{len(m.group(0))} chars redacted]",
                      out)
    if new != out:
        count += 1
        out = new
    return out, count


def redact_line(line: str) -> str:
    """Redact exfil evidence from a `domain | cve | evidence` report line."""
    parts = line.split(" | ")
    if len(parts) >= 3:
        return f"{parts[0]} | {parts[1]} | {_redact(' | '.join(parts[2:]))[0]}"
    return _redact(line)[0]


def summary_from_result(result) -> Dict:
    """Build a compact webhook summary block from a ScanResult (S2)."""
    cov = result.coverage
    return {
        "tests_run": len(result.raw_results),
        "tests_planned": result.tests_planned,
        "aborted": result.aborted,
        "aborted_reason": result.aborted_reason,
        "analysis_complete": result.analysis_complete,
        "findings": len(result.findings),
        "oob_hits": (result.oob_summary or {}).get("hits", 0),
        "coverage_tested": sum(c.tested for c in cov),
        "coverage_total": sum(c.total for c in cov),
    }


class DiscordWebhook:
    def __init__(self, url: str, enabled: bool,
                 max_len: int = MAX_MESSAGE_LEN,
                 retries: int = 3, backoff_base: float = 1.0):
        self.url = url or ""
        self.enabled = enabled
        self.max_len = max_len
        self.retries = retries
        self.backoff_base = backoff_base
        self._valid = self._validate_url(self.url)

    @staticmethod
    def _validate_url(url: str) -> bool:
        if not url:
            return False
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)

    # ------------------------------------------------------------------
    def send(self, target: str, report_lines: List[str],
             fallback_path: str = "webhook_unsent.json",
             summary: Optional[Dict] = None) -> bool:
        if not self.enabled or not self.url:
            log.info("webhook disabled - not sending")
            return False
        if not self._valid:
            log.warn("webhook URL rejected - scheme must be http/https; "
                     "payload queued instead")
            self._save_fallback(target, report_lines, fallback_path,
                                summary=summary)
            return False
        redacted = [redact_line(line) for line in report_lines]
        changed = sum(1 for r, o in zip(redacted, report_lines) if r != o)
        if changed:
            log.info(f"webhook: {changed}/{len(redacted)} lines redacted "
                     "before transmission")
        else:
            log.info("webhook: no exfil evidence to redact")
        content = self._chunk(target, redacted, summary=summary)
        ok = True
        for chunk in content:
            if not self._post_with_retry(chunk):
                ok = False
        if not ok:
            log.warn("webhook delivery failed - payload queued for replay")
            self._save_fallback(target, report_lines, fallback_path,
                                summary=summary)
        return ok

    def _post_with_retry(self, chunk: str) -> bool:
        delay = self.backoff_base
        for attempt in range(1, self.retries + 1):
            try:
                resp = requests.post(self.url, json={"content": chunk},
                                     timeout=15)
                if resp.status_code in (200, 204):
                    log.info(f"webhook delivered ({len(chunk)} chars, "
                             f"attempt {attempt})")
                    return True
                log.warn(f"webhook status {resp.status_code} "
                         f"(attempt {attempt}/{self.retries}): "
                         f"{resp.text[:200]}")
            except requests.exceptions.RequestException as e:
                log.warn(f"webhook send failed (attempt {attempt}/"
                         f"{self.retries}): {e}")
            if attempt < self.retries:
                time.sleep(delay)
                delay *= 2
        return False

    # ------------------------------------------------------------------
    @staticmethod
    def _summary_block(summary: Optional[Dict]) -> str:
        if not summary:
            return ""
        parts = []
        if "tests_run" in summary:
            parts.append(f"tests={summary['tests_run']}")
        if "tests_planned" in summary:
            parts.append(f"planned={summary['tests_planned']}")
        if "findings" in summary:
            parts.append(f"findings={summary['findings']}")
        if summary.get("aborted"):
            parts.append("aborted")
            if summary.get("aborted_reason"):
                parts.append(f"reason={summary['aborted_reason']}")
        elif "aborted" in summary:
            parts.append("completed")
        if summary.get("analysis_complete") is False:
            parts.append("analysis=INCOMPLETE")
        if summary.get("oob_hits"):
            parts.append(f"oob_hits={summary['oob_hits']}")
        if summary.get("coverage_total"):
            parts.append(f"coverage={summary['coverage_tested']}/"
                         f"{summary['coverage_total']}")
        if not parts:
            return ""
        return f"**Summary:** {' | '.join(parts)}"

    def _chunk(self, target: str, lines: List[str],
               summary: Optional[Dict] = None) -> List[str]:
        header = (f"**Sofia XXE report** - {target} "
                  f"({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")
        summary_line = self._summary_block(summary)
        buf = header
        if summary_line:
            buf += "\n" + summary_line
        chunks: List[str] = []
        for line in lines:
            candidate = buf + "\n" + line
            if len(candidate) > self.max_len:
                chunks.append(buf)
                buf = line
            else:
                buf = candidate
        if buf:
            chunks.append(buf)
        return chunks

    # ------------------------------------------------------------------
    def _save_fallback(self, target: str, lines: List[str], path: str,
                       summary: Optional[Dict] = None):
        """Append to the unsent queue (S6): preserves earlier undelivered
        payloads instead of overwriting them."""
        if not path:
            return
        payload = {
            "target": target,
            "webhook": self.url,
            "unsent_at": datetime.now().isoformat(),
            "lines": lines,
            "summary": summary,
        }
        try:
            existing: List[Dict] = []
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    existing = data if isinstance(data, list) else [data]
                except (OSError, ValueError):
                    existing = []
            existing.append(payload)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(existing, f, ensure_ascii=False, indent=2)
            log.warn(f"webhook payload queued to {path} "
                     f"({len(existing)} unsent)")
        except OSError as e:
            log.error(f"cannot save fallback payload: {e}")


def replay_unsent(fallback_path: str = "webhook_unsent.json",
                  url: Optional[str] = None) -> int:
    """Retry queued payloads from webhook_unsent.json (S6).

    Returns the number of payloads delivered. Entries that still fail remain
    in the queue; a fully drained queue is removed.
    """
    try:
        with open(fallback_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return 0
    entries = data if isinstance(data, list) else [data]
    remaining: List[Dict] = []
    delivered = 0
    for entry in entries:
        hook_url = entry.get("webhook") or url or ""
        hook = DiscordWebhook(hook_url, bool(hook_url))
        # pass an empty path during replay so failures re-queue only once
        if hook.send(entry.get("target", ""), entry.get("lines", []),
                     fallback_path="", summary=entry.get("summary")):
            delivered += 1
        else:
            remaining.append(entry)
    try:
        if remaining:
            with open(fallback_path, "w", encoding="utf-8") as f:
                json.dump(remaining, f, ensure_ascii=False, indent=2)
        elif os.path.exists(fallback_path):
            os.remove(fallback_path)
    except OSError as e:
        log.error(f"cannot update fallback queue {fallback_path}: {e}")
    return delivered


def lines_from_result(result) -> List[str]:
    return ReportBuilder.report_lines(result)

