"""Confidence engine.

Evidence taxonomy -> confidence:
  STRONG  -> confirmed
  MEDIUM  -> probable
  WEAK    -> suspected
  UNKNOWN -> insufficient

Also factors in negative-control validity and CVE match strength.
"""

from __future__ import annotations

from typing import Dict, List

from .logger import get_logger
from .models import Finding, PrimitiveEvidence, ScanResult

log = get_logger()

_STRENGTH_TO_CONF = {
    "STRONG": "confirmed",
    "MEDIUM": "probable",
    "WEAK": "suspected",
    "UNKNOWN": "insufficient",
}


class ConfidenceEngine:
    def __init__(self, result: ScanResult):
        self.result = result

    def evaluate(self, finding: Finding) -> str:
        if not finding.evidence:
            return "insufficient"

        # strongest evidence drives the baseline confidence
        strengths = [e.strength for e in finding.evidence]
        best = _best_strength(strengths)
        conf = _STRENGTH_TO_CONF.get(best, "insufficient")

        # independent retest / multiple payload kinds supporting the primitive
        prims = {e.primitive for e in finding.evidence
                 if e.strength in ("STRONG", "MEDIUM")}
        if len(prims) >= 2 and conf == "probable":
            conf = "confirmed"

        # CVE match strengthens version-based conclusions
        strong_match = any(c.match_strength == "STRONG" for c in
                           finding.cve_candidates)
        if strong_match and conf == "suspected":
            conf = "probable"

        # interference was already reflected as UNKNOWN strength
        if "interference" in " ".join(e.detail for e in finding.evidence):
            conf = "insufficient"
        return conf


def _best_strength(strengths: List[str]) -> str:
    order = {"STRONG": 0, "MEDIUM": 1, "WEAK": 2, "UNKNOWN": 3}
    return min(strengths, key=lambda s: order.get(s, 3))

