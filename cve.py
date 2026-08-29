"""CVE applicability engine.

Knowledge base (verified via public advisories):

  CVE-2024-34102 (CosmicSting)  - Magento/Adobe Commerce unauth XXE (CosmicSting)
    * CWE-611, CVSS 9.8
    * Affected: <=2.4.7, <=2.4.6-p5, <=2.4.5-p7, <=2.4.4-p8
    * Fixed:    2.4.7-p1, 2.4.6-p6, 2.4.5-p8, 2.4.4-p9  (APSB24-40)
    * Arbitrary file read -> RCE via PHP filter chains (unauth).
  CVE-2019-8126                 - Magento XXE via XML layout (admin auth)
    * CWE-611, CVSS ~6.5
    * Affected: 2.2 <2.2.10, 2.3 <2.3.3
  CVE-2020-9587                 - Magento XXE
    * CWE-611, CVSS 7.5
    * Affected: <=2.3.5-p1; fixed 2.3.5-p2 / 2.4.0 (APSB20-47)
  CVE-2023-3823                 - PHP XXE via libxml global state
    * CWE-611, CVSS 7.5
    * PHP <8.0.30, <8.1.22, <8.2.8
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from .fingerprint import (compare_versions, tokenize_version, version_in)
from .logger import get_logger
from .models import CveCandidate

log = get_logger()


class CveRule:
    def __init__(self, cve_id: str, name: str, cvss: float, cwe: str,
                 affected: str, fixed: str, advisory: str,
                 auth: bool = False, note: str = ""):
        self.cve_id = cve_id
        self.name = name
        self.cvss = cvss
        self.cwe = cwe
        self.affected = affected
        self.fixed = fixed
        self.advisory = advisory
        self.auth = auth
        self.note = note

    def matches_version(self, version: Optional[str]) -> bool:
        if not version:
            return False
        if self._is_fixed(version):
            return False
        return self._in_affected(version)

    def _in_affected(self, version: str) -> bool:
        for band in self._bands():
            low, low_incl, high, high_incl = band
            if version_in(version, low=low, high=high,
                          low_incl=low_incl, high_incl=high_incl):
                return True
        return False

    def _is_fixed(self, version: str) -> bool:
        """Fixed if version >= the fixed version on the same branch."""
        for fix in _parse_version_list(self.fixed):
            if _same_branch(version, fix) and compare_versions(version, fix) >= 0:
                return True
        return False

    def _bands(self) -> List[tuple]:
        """Parse '<=2.4.7, <=2.4.6-p5, 2.2.0-2.2.9' into bands."""
        bands = []
        for part in self.affected.replace(" ", "").split(","):
            if not part:
                continue
            if part.startswith("<="):
                bands.append((None, True, part[2:], True))
            elif part.startswith("<"):
                bands.append((None, True, part[1:], False))
            elif part.startswith(">"):
                bands.append((part[1:], False, None, True))
            elif "-" in part and _looks_versioned(part.split("-")[0]) and \
                    _looks_versioned(part.split("-")[1]):
                low, high = part.split("-", 1)
                bands.append((low, True, high, True))
            else:
                bands.append((part, True, part, True))
        return bands


CVE_DB: List[CveRule] = [
    CveRule(
        cve_id="CVE-2024-34102", name="CosmicSting XXE (unauth file read -> RCE)",
        cvss=9.8, cwe="CWE-611",
        affected="<=2.4.7, <=2.4.6-p5, <=2.4.5-p7, <=2.4.4-p8",
        fixed="2.4.7-p1 / 2.4.6-p6 / 2.4.5-p8 / 2.4.4-p9",
        advisory="APSB24-40",
        note="Unauthenticated XXE; arbitrary file read; RCE via PHP filter chains.",
    ),
    CveRule(
        cve_id="CVE-2019-8126", name="Magento XXE via XML layout",
        cvss=6.5, cwe="CWE-611",
        affected="2.2.0-2.2.9, 2.3.0-2.3.2",
        fixed="2.2.10 / 2.3.3",
        advisory="APSB19-50",
        auth=True,
        note="XXE through XML layout files; requires admin/authenticated surface.",
    ),
    CveRule(
        cve_id="CVE-2020-9587", name="Magento XXE",
        cvss=7.5, cwe="CWE-611",
        affected="<=2.3.5-p1",
        fixed="2.3.5-p2 / 2.4.0",
        advisory="APSB20-47",
        note="XXE in Magento Open Source / Commerce.",
    ),
    CveRule(
        cve_id="CVE-2023-3823", name="PHP XXE via libxml global state",
        cvss=7.5, cwe="CWE-611",
        affected="PHP <8.0.30, <8.1.22, <8.2.8",
        fixed="8.0.30 / 8.1.22 / 8.2.8",
        advisory="PHP bug #GH-11610",
        note="PHP's libxml state can be polluted to re-enable external entity "
             "loading (XXE) in otherwise-safe parsers.",
    ),
]


def evaluate_cves(version: Optional[str], patch: Optional[str],
                  php_version: Optional[str],
                  parser: Optional[List[str]],
                  endpoint_kinds: List[str],
                  authenticated: bool = False,
                  is_magento: bool = False) -> List[CveCandidate]:
    """Return CVE candidates grounded in version/parser evidence.

    S5: a Magento CVE is never emitted without either a matching Magento
    version or a Magento fingerprint hint (is_magento). "Unknown" is treated
    as "no basis", not as "possibly vulnerable".
    """
    candidates: List[CveCandidate] = []
    has_admin = any(k == "admin" for k in endpoint_kinds)
    parser_has_magento = any("magento" in (p or "").lower()
                             for p in (parser or []))
    for rule in CVE_DB:
        reason_parts = []
        strength = "WEAK"
        if "PHP" in rule.affected:  # CVE-2023-3823 style: PHP version rule
            if not php_version:
                # version unknown: no basis to emit a candidate (S5)
                continue
            php_match = _php_match(php_version)
            if php_match is None:
                continue
            _, php_strength, php_reason = php_match
            reason_parts.append(php_reason)
            strength = php_strength
        else:
            v = version or (patch and f"2.4.x-p{patch}")
            if rule.auth and not (authenticated or has_admin):
                reason_parts.append("auth required - surface not confirmed")
                strength = "WEAK"
            if v and rule.matches_version(v):
                reason_parts.append(f"Magento {v} within affected range "
                                    f"({rule.affected})")
                strength = "MEDIUM"
            elif v:
                # version known but outside range: not vulnerable
                continue
            elif is_magento or parser_has_magento:
                reason_parts.append("Magento detected but version unknown - "
                                    "version-independent matching only")
                strength = "WEAK"
            else:
                # no Magento evidence at all: do not guess (S5)
                continue
        candidates.append(CveCandidate(
            cve_id=rule.cve_id, name=rule.name, cvss=rule.cvss, cwe=rule.cwe,
            affected=rule.affected, fixed=rule.fixed, advisory=rule.advisory,
            match_reason="; ".join(reason_parts), match_strength=strength,
        ))
    return candidates


def _php_match(php_version: str) -> Optional[tuple]:
    """Return (vulnerable, strength, reason) or None when not vulnerable."""
    major, minor = _php_major_minor(php_version)
    if major == 8 and minor == 0:
        if version_in(php_version, high="8.0.30", high_incl=False):
            return (True, "MEDIUM",
                    f"PHP {php_version} < 8.0.30 within affected range")
        return None
    if major == 8 and minor == 1:
        if version_in(php_version, high="8.1.22", high_incl=False):
            return (True, "MEDIUM",
                    f"PHP {php_version} < 8.1.22 within affected range")
        return None
    if major == 8 and minor == 2:
        if version_in(php_version, high="8.2.8", high_incl=False):
            return (True, "MEDIUM",
                    f"PHP {php_version} < 8.2.8 within affected range")
        return None
    if major == 7:
        # EOL branch: advisory has no backport; conservative WEAK hint only
        return (True, "WEAK",
                f"PHP {php_version} (7.x EOL) - affected range unverifiable, "
                "conservative match")
    if major == 8 and minor >= 3:
        return None
    return (True, "WEAK", f"PHP {php_version} older than any patched branch")


def _php_major_minor(v: str) -> tuple:
    parts = v.split(".")
    major = int(parts[0]) if parts and parts[0].isdigit() else 0
    minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    return major, minor


def lookup_cve(cve_id: str) -> Optional[CveRule]:
    for rule in CVE_DB:
        if rule.cve_id.lower() == cve_id.lower():
            return rule
    return None


def rank_candidates(candidates: List[CveCandidate]) -> List[CveCandidate]:
    order = {"STRONG": 0, "MEDIUM": 1, "WEAK": 2}
    return sorted(candidates, key=lambda c: (order.get(c.match_strength, 3),
                                             -c.cvss))


def _parse_version_list(text: str) -> List[str]:
    """'2.4.7-p1 / 2.4.6-p6 / 2.4.5-p8' -> list of versions."""
    out = []
    for part in re.split(r"[/,|]", text):
        part = part.strip()
        if part and (part[0].isdigit() or part[:1].isdigit()):
            out.append(part)
    return out


def _same_branch(a: str, b: str) -> bool:
    """Same minor branch, e.g. 2.4.6-p5 and 2.4.6-p6; not 2.4.6 and 2.4.7."""
    ta = tokenize_version(a)
    tb = tokenize_version(b)
    nums_a = [t for t in ta if t[0] == "n"]
    nums_b = [t for t in tb if t[0] == "n"]
    return nums_a[:3] == nums_b[:3]


def _looks_versioned(s: str) -> bool:
    return bool(re.match(r"^\d+(\.\d+)*(-p\d+)?$", s))






