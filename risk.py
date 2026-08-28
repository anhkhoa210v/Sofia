"""Risk engine: combines CVSS, impact, and confidence into a severity rating."""

from __future__ import annotations

from typing import Any, Dict

from .logger import get_logger
from .models import Finding

log = get_logger()

_CONF_WEIGHT = {"confirmed": 1.0, "probable": 0.8, "suspected": 0.5,
                "insufficient": 0.2}
_CIA_WEIGHT = {"none": 0.0, "low": 0.2, "medium": 0.5, "high": 0.9}
_SEVERITY_BANDS = [
    (9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"),
]


class RiskEngine:
    def score(self, finding: Finding) -> float:
        # base from strongest matched CVE
        base = 0.0
        if finding.cve_candidates:
            base = max(c.cvss for c in finding.cve_candidates)
        imp = finding.impact or {}
        cia = (imp.get("confidentiality", "none"),
               imp.get("integrity", "none"),
               imp.get("availability", "none"))
        impact_term = 0.55 * (sum(_CIA_WEIGHT.get(c, 0) for c in cia) / 3.0)
        conf_term = _CONF_WEIGHT.get(finding.confidence, 0.2) * 0.45
        score = max(base * 0.7, 10.0 * (impact_term + conf_term))
        return round(min(10.0, max(0.0, score)), 1)

    def severity(self, finding: Finding) -> str:
        score = finding.risk_score
        for band, label in _SEVERITY_BANDS:
            if score >= band:
                return label
        return "info"

