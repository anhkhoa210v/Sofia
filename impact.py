"""Impact / primitive correlation engine.

Maps demonstrated primitives to CIA impact and exploit-chain potential:
  file_read (env.php) -> high confidentiality, credential exposure, RCE chain
  file_read (other)   -> medium confidentiality
  oob_http            -> medium (SSRF / reachability proof)
  error_reflection    -> low-medium (information disclosure)
  resource_limit      -> availability impact (low unless expansion is severe)
"""

from __future__ import annotations

from typing import Any, Dict

from .logger import get_logger
from .models import Finding

log = get_logger()


class ImpactEngine:
    def evaluate(self, finding: Finding) -> Dict[str, Any]:
        prims = {e.primitive for e in finding.evidence}
        details = [e.detail for e in finding.evidence]
        joined = " ".join(details)

        conf = "none"
        integ = "none"
        avail = "none"
        scope = "limited"
        chain = []
        detail = ""

        if "file_read" in prims:
            if "env.php" in joined or "MAGE_MODE" in joined or "'db'" in joined:
                conf = "high"
                scope = "application credentials"
                chain.append("file read -> credentials (env.php) -> admin/RCE")
                detail = "Exfiltrated Magento env.php (DB credentials, crypt keys)"
            elif "/etc/passwd" in joined:
                conf = "medium"
                detail = "Exfiltrated /etc/passwd (user enumeration)"
            else:
                conf = "medium"
                detail = "Arbitrary file read demonstrated"
        elif "oob_http" in prims:
            conf = "medium"
            integ = "none"
            scope = "server-side request"
            chain.append("SSRF / external entity fetch")
            detail = "Out-of-band HTTP interaction from the XML parser"
        elif "error_reflection" in prims:
            conf = "low"
            detail = "Parser errors reflect sensitive data"
        elif "entity" in prims:
            conf = "low"
            detail = "Entity substitution reflected in response"
        elif "resource_limit" in prims:
            avail = "low"
            detail = "Entity expansion could degrade availability"
        else:
            conf = "low"

        if finding.cve_candidates:
            top = max(finding.cve_candidates, key=lambda c: c.cvss)
            if top.cvss >= 9.0 and "file_read" in prims:
                scope = "full application"
                if "RCE" in top.name or "CosmicSting" in top.name:
                    chain.append(f"{top.cve_id} chain: unauth XXE -> file read "
                                 "-> RCE via PHP filter chains")
                    integ = "high"
                    avail = "high"
                    conf = "high"

        return {
            "confidentiality": conf,
            "integrity": integ,
            "availability": avail,
            "scope": scope,
            "chain": chain,
            "detail": detail,
        }

