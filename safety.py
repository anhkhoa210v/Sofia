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

import threading
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

from .logger import get_logger
from .models import RiskTier, RISK_TIERS, ScanConfig, TestItem

log = get_logger()

_BLOCKLIST_SCHEMES = ("file:///proc", "file:///sys/", "file:///dev/")
# Default exfiltration targets.  Passing --exfil-targets replaces this list
# entirely (the user-supplied list becomes the allowlist for the scan).
_ALLOWED_EXFIL_TARGETS = (
    "app/etc/env.php", "/var/www/html/app/etc/env.php",
    "/var/www/app/etc/env.php", "/etc/passwd",
    # web app secrets / config
    "/var/www/html/.env", "/var/www/.env", ".env", "composer.json",
    "web.config", "C:\\inetpub\\wwwroot\\web.config",
    # low-sensitivity OS files used as canaries
    "/etc/hostname", "C:\\Windows\\win.ini", "C:\\boot.ini",
)

# payload kinds that need the OOB callback channel
_OOB_KINDS = (
    "oob_probe_http", "oob_probe_https", "oob_parameter_entity",
    "oob_general_entity_dtd", "oob_file_exfil",
    "xinclude", "xslt_oob", "svg_entity", "soap_entity", "json_xml_chain",
    "rss_entity", "docx_upload", "xlsx_upload", "cosmicsting_svg",
    "xml_layout_xxe",
)
# payload kinds that exfiltrate file content (in-band or OOB) - gated by the
# tier's allow_exfil flag and the exfil target allowlist
_EXFIL_KINDS = (
    "oob_file_exfil", "file_read_inband", "param_entity_file_read",
    "xinclude_file", "svg_file_read", "soap_file_read",
    "json_xml_chain_file", "docx_file_read",
)
# payload kinds whose capability flag must be present in the profile
_CAPABILITY_KINDS = (
    "internal_entity", "oob_probe_http", "oob_probe_https",
    "oob_parameter_entity", "oob_general_entity_dtd", "oob_file_exfil",
    "error_based", "xinclude", "xinclude_file", "xslt", "xslt_oob",
    "svg_entity", "svg_file_read", "soap_entity", "soap_file_read",
    "json_xml_chain", "json_xml_chain_file", "rss_entity", "docx_upload",
    "docx_file_read", "xlsx_upload", "cosmicsting_svg", "xml_layout_xxe",
)


class SafetyGate:
    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg
        self.tier: RiskTier = RISK_TIERS.get(cfg.risk_tier, RISK_TIERS["standard"])
        self._requests_today: Dict[str, int] = {}
        self._blocked_reasons: Dict[str, int] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    def reset_budget(self) -> None:
        """Clear per-scan request accounting (called once per scan run)."""
        with self._lock:
            self._requests_today = {}
            self._blocked_reasons = {}

    def check(self, item: TestItem, capabilities: Dict[str, bool],
              oob_available: bool) -> bool:
        """Return True when the test may run."""
        reasons = self._reasons(item, capabilities, oob_available)
        with self._lock:
            for r in reasons:
                self._blocked_reasons[r] = self._blocked_reasons.get(r, 0) + 1
        if reasons:
            log.debug(f"blocked {item.id} ({item.payload_kind}): {reasons}")
            return False
        return True

    def _reasons(self, item: TestItem, capabilities: Dict[str, bool],
                 oob_available: bool) -> List[str]:
        reasons: List[str] = []

        if not self.tier.allow_oob and item.payload_kind in _OOB_KINDS:
            reasons.append(f"tier '{self.tier.name}' disables OOB payloads")
        if not self.tier.allow_exfil and item.payload_kind in _EXFIL_KINDS:
            reasons.append(f"tier '{self.tier.name}' disables file exfiltration")
        if not self.tier.allow_entity_expansion and item.payload_kind == "entity_expansion":
            reasons.append(f"tier '{self.tier.name}' disables entity expansion")
        if not self.tier.allow_xinclude and item.payload_kind in ("xinclude", "xinclude_file"):
            reasons.append(f"tier '{self.tier.name}' disables XInclude")
        if not self.tier.allow_xslt and item.payload_kind in ("xslt", "xslt_oob"):
            reasons.append(f"tier '{self.tier.name}' disables XSLT")

        if item.payload_kind in _OOB_KINDS and not oob_available:
            reasons.append("OOB channel unavailable")

        # default-deny: capability payloads only run when the normalized
        # profile explicitly confirms the capability (empty/unknown profiles
        # must not unlock probing)
        cap = capabilities.get(self._cap_of(item.payload_kind), False)
        if item.payload_kind in _CAPABILITY_KINDS:
            if not cap:
                reasons.append(f"capability '{self._cap_of(item.payload_kind)}' "
                               "not present in normalized profile")

        # exfil target allowlist (scope safety); a user-supplied --exfil-targets
        # list replaces the default allowlist entirely
        if item.payload_kind in _EXFIL_KINDS:
            tgt = (item.params.get("target") or "").replace("php://filter/read="
                                                            "convert.base64-encode/"
                                                            "resource=", "")
            allow = tuple(self.cfg.exfil_targets or _ALLOWED_EXFIL_TARGETS)
            if not any(a in tgt for a in allow):
                reasons.append(f"exfil target outside allowlist: {tgt}")
            if any(tgt.startswith(s) for s in _BLOCKLIST_SCHEMES):
                reasons.append(f"blocked sensitive path: {tgt}")

        # request budget per endpoint - controls (baseline/negative) are
        # excluded so they cannot exhaust the probe budget
        if item.purpose not in ("baseline", "negative_control"):
            key = item.endpoint_uid
            with self._lock:
                self._requests_today[key] = self._requests_today.get(key, 0) + 1
                over = self._requests_today[key] > self.tier.max_requests_per_test
            if over:
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



