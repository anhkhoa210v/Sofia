"""Baseline engine: characterize normal endpoint behavior for comparison.

For each endpoint we capture: status, length, content-type, elapsed, head of
body, a stable digest, and an error signature. Negative controls and payload
tests are compared against this baseline to filter out benign noise.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Optional

from .http import HttpClient
from .logger import get_logger
from .models import Baseline, Classification, Endpoint
from .payloads import get_payload

log = get_logger()

_ERROR_RE = re.compile(
    r"(error|exception|fatal|warning|failed|could not|unable to|parse error|"
    r"DTD|DOCTYPE|entity|libxml|XMLReader|DOMDocument|not well-formed)",
    re.I)


class BaselineEngine:
    def __init__(self, client: HttpClient):
        self.client = client

    def run(self, endpoints: List[Endpoint],
            classifications: Dict[str, Classification]) -> Dict[str, Baseline]:
        out: Dict[str, Baseline] = {}
        for ep in endpoints:
            cls = classifications.get(ep.uid())
            if cls is None:
                continue
            if cls.kind == "none":
                continue
            out[ep.uid()] = self._baseline(ep, cls)
        log.info(f"baseline: profiled {len(out)} endpoints")
        return out

    def _baseline(self, ep: Endpoint, cls: Classification) -> Baseline:
        if cls.kind in ("xml_direct", "soap", "svg", "rss", "parser_chain",
                        "unknown", "docx", "json_to_xml"):
            body = self._sample_body(ep)
            ctype = "application/xml" if cls.kind in ("xml_direct", "soap") \
                else ("image/svg+xml" if cls.kind == "svg" else
                      ("application/rss+xml" if cls.kind == "rss" else
                       ("application/json" if cls.kind == "json_to_xml"
                        else "application/xml")))
            _, xml, _ = get_payload("baseline")
            status, resp, headers, elapsed = self.client.post(
                ep.url, data=xml.encode("utf-8"),
                headers={"Content-Type": ctype},
                allow_redirects=True)
        else:
            status, resp, headers, elapsed = self.client.get(
                ep.url, timeout=min(self.client.cfg.timeout, 10))
        if status == 0:
            return Baseline(ep.uid(), status=0, note="unreachable")
        b = Baseline(
            endpoint_uid=ep.uid(),
            status=status,
            length=len(resp or ""),
            content_type=(headers.get("Content-Type") or ""),
            elapsed=elapsed,
            body_head=(resp or "")[:200],
            digest=self._digest(resp or ""),
        )
        m = _ERROR_RE.search(resp or "")
        if m:
            b.error_signature = m.group(0)
        return b

    def _sample_body(self, ep: Endpoint) -> str:
        status, body, headers, _ = self.client.get(ep.url, timeout=min(self.client.cfg.timeout, 10))
        return body or ""

    @staticmethod
    def _digest(body: str) -> str:
        norm = re.sub(r"\s+", " ", body or "").strip()
        return hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest()[:16]


def baseline_matches(b: Baseline, status: int, length: int, ctype: str,
                     elapsed: float, body: str, tolerance: float = 0.15) -> bool:
    """True when a response looks like the benign baseline."""
    if b.status == 0 or status == 0:
        return False
    if status != b.status:
        return False
    if length and b.length:
        lo = b.length * (1 - tolerance)
        hi = b.length * (1 + tolerance)
        if not (lo <= length <= hi):
            return False
    if ctype and b.content_type:
        if ctype.split(";")[0].strip() != b.content_type.split(";")[0].strip():
            return False
    return True


