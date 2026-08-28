"""Response/OOB/async analysis: turns evidence into findings."""

from __future__ import annotations

from typing import Dict, List

from .logger import get_logger
from .models import (CveCandidate, Finding, PrimitiveEvidence, ScanResult,
                     new_id)

log = get_logger()

_PRIMITIVE_TITLES = {
    "file_read": "XXE arbitrary file read",
    "oob_http": "XXE out-of-band interaction (external entity)",
    "error_reflection": "XXE error-based reflection",
    "entity": "XXE entity expansion reflected",
    "resource_limit": "XML entity expansion (resource exhaustion)",
    "xinclude": "XXE via XInclude",
    "xslt": "XXE via XSLT document()",
    "unknown": "Suspected XML processing anomaly",
}

_REMEDIATION = {
    "file_read": "Disable DOCTYPE/DTD and external entity resolution in the XML "
                 "parser; upgrade Magento/Adobe Commerce to the fixed version "
                 "(see CVE fixed versions); add WAF rules blocking DOCTYPE in "
                 "XML bodies; sanitize/validate all XML inputs.",
    "oob_http": "Disable external entity loading (LIBXML_NOENT / noent off, "
                "XMLResolver disabled); reject DTDs in XML input; keep parser "
                "libraries patched.",
    "error_reflection": "Suppress parser error output; do not reflect parser "
                        "messages to clients.",
    "entity": "Disable entity substitution unless required; validate XML "
              "structure server-side.",
    "resource_limit": "Cap entity expansion, set parser limits "
                      "(libxml2 entity expansion limit), reject DTDs.",
    "xinclude": "Disable XInclude processing unless required by the feature.",
    "xslt": "Treat XSLT as untrusted input; disable document() in XSLT "
            "processors.",
    "unknown": "Review XML parsing configuration and upgrade parsers.",
}


class AnalysisEngine:
    def build_findings(self, result: ScanResult,
                       evidence_map: Dict[str, List[PrimitiveEvidence]],
                       profiles: Dict[str, object],
                       cve_candidates: List[CveCandidate],
                       oob_all: List[Dict]) -> List[Finding]:
        findings: List[Finding] = []
        url_by_uid = {e.uid(): e.url for e in result.endpoints}
        for ep_uid, evs in evidence_map.items():
            url = url_by_uid.get(ep_uid, ep_uid)
            prim = _pick_primary(evs)
            title = _PRIMITIVE_TITLES.get(prim, _PRIMITIVE_TITLES["unknown"])
            finding = Finding(
                id=new_id("f"),
                title=title,
                endpoint_url=url,
                cwe="CWE-611",
                evidence=evs,
                cve_candidates=list(cve_candidates),
                reproduction=self._reproduction(result, ep_uid),
                remediation=_REMEDIATION.get(prim, _REMEDIATION["unknown"]),
            )
            if prim in ("file_read",):
                finding.notes.append("arbitrary file read confirmed - chainable "
                                     "to RCE on vulnerable Magento (CosmicSting)")
            findings.append(finding)
        if not findings:
            log.info("analysis: no findings to report")
        return findings

    @staticmethod
    def _reproduction(result: ScanResult, ep_uid: str) -> List[str]:
        steps = []
        for raw in result.raw_results:
            if raw.endpoint_uid == ep_uid and raw.oob_hits:
                steps.append(
                    f"POST {raw.payload_kind} -> OOB callback "
                    f"(cid={[h.get('cid') for h in raw.oob_hits[:2]]}) "
                    f"status={raw.status}")
        return steps or ["See raw_results in JSON output"]


def _pick_primary(evs: List[PrimitiveEvidence]) -> str:
    order = {"file_read": 0, "oob_http": 1, "error_reflection": 2,
             "entity": 3, "resource_limit": 4, "xinclude": 5, "xslt": 6,
             "unknown": 7}
    strength = {"STRONG": 0, "MEDIUM": 1, "WEAK": 2, "UNKNOWN": 3}
    best = evs[0]
    for e in evs[1:]:
        if (order.get(e.primitive, 9), strength.get(e.strength, 3)) < \
           (order.get(best.primitive, 9), strength.get(best.strength, 3)):
            best = e
    return best.primitive

