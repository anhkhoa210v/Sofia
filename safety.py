"""Safety gate: per-test admission control.

The gate sits between the capability matrix and the controlled test matrix.
It blocks payloads that exceed the selected risk tier, that would hit targets
outside the authorized scope, or that would exceed configured request budgets.

Risk tiers:
  safe       - no entity expansion, no exfil, probes only
  standard   - bounded expansion, controlled exfil, XInclude/XSLT allowed
  aggressive - full capability probing incl. resource-limit primitives
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

from .logger import get_logger
from .models import RiskTier, RISK_TIERS, ScanConfig, TestItem

log = get_logger()

_BLOCKLIST_SCHEMES = ("file:///proc", "file:///sys/", "file:///dev/")
_ALLOWED_EXFIL_TARGETS = (
    "app/etc/env.php", "/var/www/html/app/etc/env.php",
    "/var/www/app/etc/env.php", "/etc/passwd",
)


class SafetyGate:
    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg
        self.tier: RiskTier = RISK_TIERS.get(cfg.risk_tier, RISK_TIERS["standard"])
        self._requests_today: Dict[str, int] = {}
        self._blocked_reasons: Dict[str, int] = {}

    # ------------------------------------------------------------------
    def check(self, item: TestItem, capabilities: Dict[str, bool],
              oob_available: bool) -> bool:
        """Return True when the test may run."""
        reasons = self._reasons(item, capabilities, oob_available)
        for r in reasons:
            self._blocked_reasons[r] = self._blocked_reasons.get(r, 0) + 1
        if reasons:
            log.debug(f"blocked {item.id} ({item.payload_kind}): {reasons}")
            return False
        return True

    def _reasons(self, item: TestItem, capabilities: Dict[str, bool],
                 oob_available: bool) -> List[str]:
        reasons: List[str] = []

        if not self.tier.allow_oob and item.payload_kind in (
                "oob_probe_http", "oob_parameter_entity", "oob_file_exfil",
                "xinclude", "svg_entity", "soap_entity", "json_xml_chain",
                "rss_entity", "docx_upload"):
            reasons.append(f"tier '{self.tier.name}' disables OOB payloads")
        if not self.tier.allow_exfil and item.payload_kind == "oob_file_exfil":
            reasons.append(f"tier '{self.tier.name}' disables file exfiltration")
        if not self.tier.allow_entity_expansion and item.payload_kind == "entity_expansion":
            reasons.append(f"tier '{self.tier.name}' disables entity expansion")
        if not self.tier.allow_xinclude and item.payload_kind == "xinclude":
            reasons.append(f"tier '{self.tier.name}' disables XInclude")
        if not self.tier.allow_xslt and item.payload_kind == "xslt":
            reasons.append(f"tier '{self.tier.name}' disables XSLT")

        if item.payload_kind in ("oob_probe_http", "oob_parameter_entity",
                                 "oob_file_exfil", "xinclude", "svg_entity",
                                 "soap_entity", "json_xml_chain", "rss_entity",
                                 "docx_upload") and not oob_available:
            reasons.append("OOB channel unavailable")

        cap = capabilities.get(self._cap_of(item.payload_kind), True)
        if item.payload_kind in ("internal_entity", "oob_probe_http",
                                 "oob_parameter_entity", "oob_file_exfil",
                                 "error_based", "svg_entity", "soap_entity",
                                 "json_xml_chain", "rss_entity", "docx_upload"):
            if not cap:
                reasons.append(f"capability '{self._cap_of(item.payload_kind)}' "
                               "not present in normalized profile")

        # exfil target allowlist (scope safety)
        if item.payload_kind == "oob_file_exfil":
            tgt = (item.params.get("target") or "").replace("php://filter/read="
                                                            "convert.base64-encode/"
                                                            "resource=", "")
            if not any(a in tgt for a in _ALLOWED_EXFIL_TARGETS):
                reasons.append(f"exfil target outside allowlist: {tgt}")
            if any(tgt.startswith(s) for s in _BLOCKLIST_SCHEMES):
                reasons.append(f"blocked sensitive path: {tgt}")

        # request budget per endpoint
        key = item.endpoint_uid
        self._requests_today[key] = self._requests_today.get(key, 0) + 1
        if self._requests_today[key] > self.tier.max_requests_per_test:
            reasons.append("per-endpoint request budget exceeded")

        return reasons

    @staticmethod
    def _cap_of(kind: str) -> str:
        from .payloads import PAYLOAD_REGISTRY
        return (PAYLOAD_REGISTRY.get(kind) or {}).get("capability", "")

    # ------------------------------------------------------------------
    def blocked_summary(self) -> Dict[str, int]:
        return dict(self._blocked_reasons)

    def expansion_params(self) -> Dict[str, int]:
        return {
            "levels": self.tier.expansion_levels,
            "width": self.tier.expansion_width,
        }

