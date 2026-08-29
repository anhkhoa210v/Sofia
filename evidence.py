"""Evidence taxonomy.

Maps raw observations to an evidence strength per the taxonomy:
  WEAK   -> Suspected
  MEDIUM -> Probable
  STRONG -> Confirmed
  UNKNOWN-> Insufficient

Strength is derived from:
  - OOB callback with unique canary (hard proof of external entity resolution)
  - file content recovered via exfil or error reflection (decodable base64)
  - clean negative control (no interference / WAF replay)
  - independent retest with a different payload kind
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Dict, List, Optional, Tuple

from .logger import get_logger
from .models import PrimitiveEvidence, RawResult, ScanResult
from .models import link_canary

log = get_logger()

_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_ENV_HINTS = [
    "db", "password", "host", "username", "crypt", "key", "session",
    "cache", "redis", "secret", "MAGE_MODE", "'driver'", "search",
]
_PASSWD_HINT = re.compile(r"root:.*:0:0:", re.M)
# payload kinds that reflect entity/file content into the response
_REFLECT_KINDS = (
    "internal_entity", "file_read_inband", "param_entity_file_read",
    "xinclude_file", "svg_file_read", "soap_file_read",
    "json_xml_chain_file", "docx_file_read",
)
# (marker, file label) pairs for in-band file-read evidence
_FILE_MARKERS = (
    ("root:", "/etc/passwd"),
    ("MAGE_MODE", "env.php"),
    ("'db'", "env.php"),
    ("[fonts]", "win.ini"),
    ("[boot loader]", "boot.ini"),
)


def _canary_for(result: ScanResult, raw: RawResult) -> str:
    return link_canary(result, raw.test_id)


def _oob_exfil_data(oob_hits: List[Dict]) -> Tuple[bool, str]:
    """Extract base64 file data from OOB /x/{cid} hits."""
    for h in oob_hits or []:
        path = h.get("path", "")
        if "/x/" not in path:
            continue
        extra = h.get("extra", "")
        q = h.get("path", "")
        # query data was captured in path only; reconstruct from stored path.
        # Use raw extraction (not parse_qs) so '+' in base64 payloads survives.
        data = ""
        if "?" in q:
            m = re.search(r"[?&]d=([^&]*)", q)
            if m:
                data = m.group(1)
        if data:
            return True, data
    return False, ""


def _decode_base64_maybe(data: str) -> Optional[str]:
    try:
        padded = data + "=" * (-len(data) % 4)
        raw = base64.b64decode(padded, validate=False)
        if not raw:
            return None
        text = raw.decode("utf-8", "replace")
        if text and any(c.isprintable() or c in "\n\r\t" for c in text[:64]):
            return text
    except (binascii.Error, ValueError):
        return None
    return None


def _classify_file_content(text: str) -> Tuple[str, str]:
    """Return (label, snippet)."""
    if "MAGE_MODE" in text or "'db'" in text or "'driver'" in text:
        return "env.php", text
    if _PASSWD_HINT.search(text):
        return "/etc/passwd", text
    if "[fonts]" in text:
        return "win.ini", text
    if "[boot loader]" in text:
        return "boot.ini", text
    return "file", text


class EvidenceClassifier:
    def __init__(self):
        self._oob_all: List[Dict] = []
        self._interference: set = set()

    def classify_all(self, result: ScanResult,
                     oob_all: List[Dict]) -> Dict[str, List[PrimitiveEvidence]]:
        """Return {endpoint_uid: [PrimitiveEvidence,...]}"""
        self._oob_all = oob_all
        # detect interference: negative controls that fired OOB (WAF replay etc.)
        for raw in result.raw_results:
            if raw.payload_kind == "negative_control":
                cid = _canary_for(result, raw)
                if self._hits_for(cid):
                    self._interference.add(raw.endpoint_uid)
        if self._interference:
            log.warn(f"interference detected on: {sorted(self._interference)} "
                     "(negative control fired - results downgraded)")

        out: Dict[str, List[PrimitiveEvidence]] = {}
        by_endpoint: Dict[str, List[RawResult]] = {}
        for raw in result.raw_results:
            if raw.payload_kind in ("baseline", "negative_control"):
                continue
            by_endpoint.setdefault(raw.endpoint_uid, []).append(raw)

        for ep_uid, raws in by_endpoint.items():
            evs: List[PrimitiveEvidence] = []
            for raw in raws:
                ev = self._classify_one(result, raw)
                if ev:
                    evs.append(ev)
            # independent retest: same primitive fired via >=2 payload kinds
            prims = {}
            for ev in evs:
                prims.setdefault(ev.primitive, []).append(ev)
            for prim, lst in prims.items():
                kinds = {e.detail.split("|")[0] for e in lst}
                if len(kinds) >= 2 and prim in ("oob_http", "file_read"):
                    for e in lst:
                        if e.strength == "MEDIUM":
                            e.strength = "STRONG"
                            e.detail += " (independent retest)"
            if ep_uid in self._interference:
                for e in evs:
                    if e.strength in ("MEDIUM", "STRONG"):
                        e.strength = "UNKNOWN"
                        e.detail += " [interference]"
            if evs:
                out[ep_uid] = evs
        return out

    # ------------------------------------------------------------------
    def _hits_for(self, cid: str) -> bool:
        return any(h.get("cid") == cid for h in self._oob_all)

    def _classify_one(self, result: ScanResult, raw: RawResult) -> Optional[PrimitiveEvidence]:
        cid = _canary_for(result, raw)
        hits = [h for h in (raw.oob_hits or []) if h.get("cid") == cid]
        kind = raw.payload_kind

        # 1) exfil with decodable file content -> STRONG file_read
        if kind == "oob_file_exfil" and hits:
            got, data = _oob_exfil_data(hits)
            if got and data:
                text = _decode_base64_maybe(data)
                if text:
                    label, content = _classify_file_content(text)
                    return PrimitiveEvidence(
                        primitive="file_read", strength="STRONG",
                        detail=f"{label}|exfil:{_snippet(content, 240)}",
                        proof=[f"OOB exfil cid={cid} target={raw.payload_kind}",
                               f"decoded: {_snippet(content, 120)}"],
                    )
                return PrimitiveEvidence(
                    primitive="oob_http", strength="MEDIUM",
                    detail=f"{kind}|OOB exfil request without decodable data",
                    proof=[f"cid={cid} path={[h.get('path') for h in hits]}"],
                )

        # 2) any OOB callback -> external entity resolution
        if hits:
            strength = "MEDIUM"
            detail = f"{kind}|OOB callback cid={cid}"
            if any("/dtd/" in h.get("path", "") for h in hits):
                detail += " (DTD fetched)"
            return PrimitiveEvidence(
                primitive="oob_http", strength=strength,
                detail=detail,
                proof=[f"cid={cid} hits={len(hits)}",
                       f"paths={[h.get('path') for h in hits[:4]]}"],
            )

        # 3) error reflection / response embedding
        body = raw.body_snippet or ""
        if body:
            m = _B64_RE.search(body)
            if m:
                text = _decode_base64_maybe(m.group(0))
                if text and ("MAGE_MODE" in text or _PASSWD_HINT.search(text)
                             or "'db'" in text):
                    label, content = _classify_file_content(text)
                    return PrimitiveEvidence(
                        primitive="file_read", strength="MEDIUM",
                        detail=f"{label}|error_reflection:{_snippet(content, 240)}",
                        proof=[f"base64 in response len={len(m.group(0))}"],
                    )
            if re.search(r"SOFIA\[[0-9a-f]{10}\]", body) and "/etc/hostname" in kind:
                pass  # handled below

        # 4) in-band reflection: file content or canary echoed in the response
        if kind in _REFLECT_KINDS and body:
            for marker, label in _FILE_MARKERS:
                if marker in body:
                    return PrimitiveEvidence(
                        primitive="file_read", strength="MEDIUM",
                        detail=f"{kind}|{label} echoed in response:"
                               f"{_snippet(body, 200)}",
                        proof=[f"marker '{marker}' in response body"],
                    )
            if re.search(r"SOFIA\[[0-9a-f]{10}\]", body):
                return PrimitiveEvidence(
                    primitive="entity", strength="MEDIUM",
                    detail=f"{kind}|entity expansion reflected",
                    proof=["SOFIA canary echoed in response"],
                )

        # 5) entity expansion timing anomaly
        if kind == "entity_expansion" and raw.elapsed > 5.0:
            return PrimitiveEvidence(
                primitive="resource_limit", strength="WEAK",
                detail=f"entity_expansion|elapsed={raw.elapsed:.1f}s",
                proof=[f"response time {raw.elapsed:.2f}s"],
            )

        # 6) error-based: parser error signature changed
        if kind == "error_based" and raw.status in (400, 500) and raw.body_snippet:
            if "entity" in raw.body_snippet.lower() or "doctype" in raw.body_snippet.lower():
                return PrimitiveEvidence(
                    primitive="error_reflection", strength="WEAK",
                    detail=f"error_based|parser surfaced DTD-related error",
                    proof=[_snippet(raw.body_snippet, 160)],
                )
        return None


def _snippet(text: str, limit: int) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."




