"""Fingerprinting: Magento version/patch level, composer data, parser stack.

Version comparison handles Magento's "-pN" patch suffix, e.g. 2.4.6-p5.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .http import HttpClient
from .logger import get_logger
from .models import Endpoint

log = get_logger()

_MAGENTO_VERSION_RE = re.compile(
    r"(?:Magento|Adobe Commerce)[^0-9]{0,40}(2\.\d+\.\d+(?:-[a-z]+\d+)?)", re.I)
_VERSION_JS_RE = re.compile(r"version\s*[:=]\s*['\"](2\.\d+\.\d+(?:-[a-z]+\d+)?)['\"]", re.I)
_PHP_VERSION_RE = re.compile(r"PHP/?(?:\s+)?(\d+\.\d+(?:\.\d+)?)", re.I)
_LIBXML_RE = re.compile(r"libxml2?\s*[/(]?\s*(\d+\.\d+(?:\.\d+)?)", re.I)

MAGENTO_PROBE_PATHS = [
    "/magento_version",
    "/pub/static/version.js",
    "/static/version.js",
    "/index.php/version",
    "/version",
    "/errors/report.php",
]

_COMPOSER_LOCK_HINTS = [
    "magento/product-community-edition",
    "magento/product-enterprise-edition",
    "magento/commerce",
    "magento/product-enterprise",
]


class Fingerprinter:
    def __init__(self, client: HttpClient):
        self.client = client

    def run(self, endpoints: List[Endpoint],
            profiles: Dict[str, Any]) -> Dict[str, Any]:
        fp: Dict[str, Any] = {
            "magento_version": None,
            "magento_patch": None,
            "magento_confidence": 0.0,
            "composer": [],
            "php_version": None,
            "libxml_version": None,
            "parser": None,
            "sources": [],
        }
        target = self.cfg_target(endpoints)
        if not target:
            return fp

        for path in MAGENTO_PROBE_PATHS:
            status, body, headers, _ = self.client.get(
                urljoin(target, path), timeout=min(self.client.cfg.timeout, 8))
            if status == 0:
                continue
            txt = (body or "")[:4000]
            m = _MAGENTO_VERSION_RE.search(txt)
            if m:
                fp["magento_version"] = m.group(1)
                fp["sources"].append(f"{path}:{m.group(1)}")
                break
            m = _VERSION_JS_RE.search(txt)
            if m:
                fp["magento_version"] = m.group(1)
                fp["sources"].append(f"{path}(js):{m.group(1)}")
                break

        # header hints
        for ep in endpoints[:30]:
            status, body, headers, _ = self.client.get(ep.url,
                                                       timeout=min(self.client.cfg.timeout, 8))
            if status == 0:
                continue
            server = headers.get("Server") or ""
            xpb = headers.get("X-Powered-By") or ""
            if not fp["php_version"]:
                m = _PHP_VERSION_RE.search(server + " " + xpb)
                if m:
                    fp["php_version"] = m.group(1)
            if not fp["libxml_version"]:
                m = _LIBXML_RE.search(server + " " + xpb)
                if m:
                    fp["libxml_version"] = m.group(1)
            for h in ("X-Magento-Cache", "X-Magento-Tags", "X-Magento-Layout"):
                if headers.get(h):
                    fp["magento_confidence"] = max(fp["magento_confidence"], 0.8)
                    fp["sources"].append(f"header:{h}")
            if "Magento" in server:
                fp["magento_confidence"] = max(fp["magento_confidence"], 0.9)

        if fp["magento_version"]:
            fp["magento_confidence"] = max(fp["magento_confidence"], 0.7)
            fp["magento_patch"] = _extract_patch(fp["magento_version"])

        # composer detection in page leaks / error text
        for ep in endpoints[:30]:
            status, body, headers, _ = self.client.get(ep.url,
                                                       timeout=min(self.client.cfg.timeout, 8))
            for pkg in _COMPOSER_LOCK_HINTS:
                if pkg in (body or ""):
                    fp["composer"].append(pkg)
                    fp["sources"].append(f"body:{pkg}")
        fp["composer"] = sorted(set(fp["composer"]))

        # parser from normalization profiles
        engines = {p.engine for p in profiles.values() if p is not None}
        if engines:
            fp["parser"] = sorted(engines)
        return fp

    @staticmethod
    def cfg_target(endpoints: List[Endpoint]) -> Optional[str]:
        if not endpoints:
            return None
        seed = next((e for e in endpoints if e.source == "seed"), endpoints[0])
        p = urlparse(seed.url)
        return f"{p.scheme}://{p.netloc}"


def _extract_patch(version: str) -> Optional[str]:
    m = re.search(r"-p(\d+)$", version)
    return m.group(1) if m else None


# --------------------------------------------------------------------------
# version comparison with "-pN" suffix
# --------------------------------------------------------------------------

def tokenize_version(v: str) -> List[Tuple[str, int]]:
    """'2.4.6-p5' -> [('n',2),('n',4),('n',6),('p',5)] ; '2.4.6' -> [('n',2),('n',4),('n',6)]"""
    tokens: List[Tuple[str, int]] = []
    for part in str(v).strip().lower().split("."):
        m = re.match(r"^(\d+)(?:-p(\d+))?$", part)
        if m:
            tokens.append(("n", int(m.group(1))))
            if m.group(2) is not None:
                tokens.append(("p", int(m.group(2))))
        else:
            m2 = re.match(r"^(\d+)(?:[a-z](\d+))?$", part)
            if m2:
                tokens.append(("n", int(m2.group(1))))
                if m2.group(2):
                    tokens.append(("p", int(m2.group(2))))
    return tokens


def compare_versions(a: str, b: str) -> int:
    """Return -1/0/1 comparing version strings with patch suffix."""
    ta, tb = tokenize_version(a), tokenize_version(b)
    for x, y in zip(ta, tb):
        if x[0] != y[0]:
            # any patch token sorts after a plain number continuation
            order = {"n": 0, "p": 1}
            return -1 if order[x[0]] < order[y[0]] else 1
        if x[1] != y[1]:
            return -1 if x[1] < y[1] else 1
    if len(ta) == len(tb):
        return 0
    return -1 if len(ta) < len(tb) else 1


def version_in(version: Optional[str], low: Optional[str] = None,
               high: Optional[str] = None, low_incl: bool = True,
               high_incl: bool = False) -> bool:
    if not version:
        return False
    if low is not None:
        c = compare_versions(version, low)
        if c < 0 or (c == 0 and not low_incl):
            return False
    if high is not None:
        c = compare_versions(version, high)
        if c > 0 or (c == 0 and not high_incl):
            return False
    return True


