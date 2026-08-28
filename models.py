"""Core data models for Sofia."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def link_canary(result: "ScanResult", test_id: str) -> str:
    """Resolve a raw result's test id back to its OOB canary."""
    for t in result.test_items:
        if t.id == test_id:
            return t.canary
    return ""


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

@dataclass
class ScanConfig:
    target: str = ""
    list_mode: bool = False
    max_depth: int = 2
    rate: float = 5.0                # requests per second ceiling
    timeout: float = 12.0
    oob_port: int = 17888
    use_tunnel: bool = True
    risk_tier: str = "standard"      # safe | standard | aggressive
    webhook_url: str = ""
    send_webhook: bool = False
    out_dir: str = "sofia_reports"
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    proxy: Optional[str] = None
    insecure: bool = False
    job_timeout: float = 900.0
    abort_after: int = 0             # max findings before abort (0 = unlimited)
    verbose: bool = False
    log_file: Optional[str] = None
    extra_param: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class RiskTier:
    name: str
    expansion_levels: int
    expansion_width: int
    allow_oob: bool
    allow_exfil: bool
    allow_entity_expansion: bool
    allow_xinclude: bool
    allow_xslt: bool
    max_requests_per_test: int
    description: str


RISK_TIERS: Dict[str, RiskTier] = {
    "safe": RiskTier(
        name="safe", expansion_levels=3, expansion_width=4,
        allow_oob=True, allow_exfil=False, allow_entity_expansion=False,
        allow_xinclude=True, allow_xslt=False, max_requests_per_test=6,
        description="Non-destructive: no entity expansion, no file exfil, "
                    "OOB probes only against the target's own parser.",
    ),
    "standard": RiskTier(
        name="standard", expansion_levels=6, expansion_width=16,
        allow_oob=True, allow_exfil=True, allow_entity_expansion=False,
        allow_xinclude=True, allow_xslt=True, max_requests_per_test=12,
        description="Controlled exfil of small files (env.php, /etc/passwd), "
                    "bounded expansion, OOB via Cloudflare tunnel.",
    ),
    "aggressive": RiskTier(
        name="aggressive", expansion_levels=10, expansion_width=64,
        allow_oob=True, allow_exfil=True, allow_entity_expansion=True,
        allow_xinclude=True, allow_xslt=True, max_requests_per_test=24,
        description="Full capability probing including entity expansion DoS "
                    "primitives. Only on clearly authorized targets.",
    ),
}


# --------------------------------------------------------------------------
# Discovery / endpoints
# --------------------------------------------------------------------------

@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    kind: str = "url"                # url|form|api|soap|import_export|webhook|upload|graphql|json_xml|rss|svg|admin|async
    source: str = "passive"          # passive|active|authenticated|recursive|seed
    params: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    depth: int = 0
    note: str = ""
    file_inputs: List[str] = field(default_factory=list)

    def uid(self) -> str:
        return f"{self.method} {self.url}"


# --------------------------------------------------------------------------
# Classification / baseline
# --------------------------------------------------------------------------

@dataclass
class Classification:
    endpoint_uid: str
    kind: str                        # xml_direct|soap|json_to_xml|multipart_upload|svg|rss|docx|parser_chain|none|unknown
    content_type: Optional[str] = None
    accepts_xml: bool = False
    reason: str = ""
    confidence: float = 0.0          # 0..1


@dataclass
class Baseline:
    endpoint_uid: str
    status: int = 0
    length: int = 0
    content_type: str = ""
    elapsed: float = 0.0
    body_head: str = ""
    digest: str = ""                 # stable hash of the normalized body
    error_signature: Optional[str] = None
    notes: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Test items / results
# --------------------------------------------------------------------------

@dataclass
class TestItem:
    id: str
    endpoint_uid: str
    payload_kind: str                # internal_entity|oob_probe_http|oob_parameter_entity|...
    xml: str
    method: str = "POST"
    content_type: str = "application/xml"
    purpose: str = "capability"      # baseline|negative_control|capability|exfil|retest
    control_group: str = ""
    canary: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    note: str = ""


@dataclass
class RawResult:
    test_id: str
    endpoint_uid: str
    payload_kind: str
    purpose: str
    status: int = 0
    length: int = 0
    content_type: str = ""
    elapsed: float = 0.0
    body_snippet: str = ""
    error: str = ""
    oob_hits: List[Dict[str, Any]] = field(default_factory=list)
    sent_at: float = 0.0
    received_at: float = 0.0


# --------------------------------------------------------------------------
# Analysis / findings
# --------------------------------------------------------------------------

@dataclass
class PrimitiveEvidence:
    primitive: str                   # file_read|oob_http|error_reflection|entity_expansion|xinclude|xslt|unknown
    strength: str                    # WEAK|MEDIUM|STRONG|UNKNOWN
    detail: str = ""
    proof: List[str] = field(default_factory=list)


@dataclass
class CveCandidate:
    cve_id: str
    name: str = ""
    cvss: float = 0.0
    cwe: str = "CWE-611"
    affected: str = ""
    fixed: str = ""
    advisory: str = ""
    match_reason: str = ""
    match_strength: str = "WEAK"     # WEAK|MEDIUM|STRONG


@dataclass
class Finding:
    id: str
    title: str
    endpoint_url: str = ""
    cve_id: str = ""
    cwe: str = "CWE-611"
    severity: str = "info"           # info|low|medium|high|critical
    confidence: str = "insufficient" # insufficient|suspected|probable|confirmed
    impact: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    evidence: List[PrimitiveEvidence] = field(default_factory=list)
    cve_candidates: List[CveCandidate] = field(default_factory=list)
    dedup_key: str = ""
    reproduction: List[str] = field(default_factory=list)
    remediation: str = ""
    notes: List[str] = field(default_factory=list)

    def line(self) -> str:
        """Report line: domain | cve | evidence"""
        domain = self.endpoint_url
        cve = self.cve_id or "-"
        ev = self._evidence_text()
        return f"{domain} | {cve} | {ev}"

    def _evidence_text(self) -> str:
        for e in self.evidence:
            if e.primitive == "file_read" and e.detail:
                return _snippet(e.detail, 220)
        return _snippet("; ".join(e.detail for e in self.evidence) or self.title, 220)


def _snippet(text: str, limit: int) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


# --------------------------------------------------------------------------
# Coverage accounting
# --------------------------------------------------------------------------

COVERAGE_STAGES = [
    "discovery", "classification", "baseline", "normalization", "fingerprint",
    "cve", "capability", "safety", "test_matrix", "response_analysis",
    "oob_analysis", "async_analysis", "evidence", "confidence", "impact",
    "cve_correlation", "dedup", "risk", "review", "report",
]

COVERAGE_STATUSES = ["tested", "skipped", "blocked", "unknown", "async_only", "auth_only"]


@dataclass
class CoverageRecord:
    stage: str
    total: int = 0
    tested: int = 0
    skipped: int = 0
    blocked: int = 0
    unknown: int = 0
    async_only: int = 0
    auth_only: int = 0
    detail: str = ""

    def pct(self) -> float:
        if not self.total:
            return 0.0
        return round(100.0 * self.tested / self.total, 1)


# --------------------------------------------------------------------------
# Final bundle
# --------------------------------------------------------------------------

@dataclass
class ScanResult:
    target: str
    started_at: str = ""
    finished_at: str = ""
    endpoints: List[Endpoint] = field(default_factory=list)
    classifications: Dict[str, Classification] = field(default_factory=dict)
    baselines: Dict[str, Baseline] = field(default_factory=dict)
    test_items: List[TestItem] = field(default_factory=list)
    raw_results: List[RawResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    coverage: List[CoverageRecord] = field(default_factory=list)
    fingerprints: Dict[str, Any] = field(default_factory=dict)
    oob_summary: Dict[str, Any] = field(default_factory=dict)
    aborted: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "endpoints": [asdict(e) for e in self.endpoints],
            "findings": [asdict(f) for f in self.findings],
            "coverage": [asdict(c) for c in self.coverage],
            "fingerprints": self.fingerprints,
            "oob_summary": self.oob_summary,
            "aborted": self.aborted,
            "notes": self.notes,
            "test_items": len(self.test_items),
            "raw_results": len(self.raw_results),
        }


