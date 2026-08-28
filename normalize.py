"""Normalization analyzer.

Reconstructs the processing chain for each endpoint:
  Proxy/WAF -> Gateway -> Framework -> App -> Parser -> Secondary parser

Uses response headers, error pages and behavior to infer each layer, then
derives the effective XML parser engine and normalized capabilities.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .capability import (engine_capabilities, normalize_engine, capability_matrix)
from .http import HttpClient
from .logger import get_logger
from .models import Baseline, Endpoint

log = get_logger()

_HEADER_SIGNATURES = [
    ("cf-ray", "cloudflare", "proxy"),
    ("x-sucuri", "sucuri", "waf"),
    ("x-akamai", "akamai", "waf"),
    ("x-cdn", "cdn", "proxy"),
    ("via", "via", "gateway"),
    ("x-cache", "cache", "proxy"),
    ("x-varnish", "varnish", "proxy"),
    ("server", "nginx", "gateway"),
    ("server", "apache", "gateway"),
    ("server", "iis", "gateway"),
    ("server", "openresty", "gateway"),
    ("x-powered-by", "php", "framework"),
    ("x-powered-by", "asp.net", "framework"),
    ("x-powered-by", "express", "framework"),
    ("x-aspnet-version", "", "framework"),
    ("x-runtime", "ruby", "framework"),
    ("x-drupal", "drupal", "framework"),
    ("x-magento", "magento", "framework"),
    ("x-magento-cache", "magento", "framework"),
    ("x-magento-tags", "magento", "framework"),
    ("x-magento-layout", "magento", "framework"),
    ("set-cookie", "frontend", "app"),
    ("set-cookie", "adminhtml", "app"),
    ("set-cookie", "PHPSESSID", "app"),
    ("set-cookie", "JSESSIONID", "app"),
]

_BODY_SIGNATURES = [
    (r"magento", "magento", "framework"),
    (r"shopware", "shopware", "framework"),
    (r"woocommerce", "woocommerce", "framework"),
    (r"drupal", "drupal", "framework"),
    (r"joomla", "joomla", "framework"),
    (r"tomcat", "tomcat", "gateway"),
    (r"spring", "spring", "framework"),
    (r"laravel", "laravel", "framework"),
    (r"django", "django", "framework"),
    (r"rails", "rails", "framework"),
]


@dataclass
class ChainLayer:
    role: str          # proxy|waf|gateway|framework|app|parser|secondary
    name: str
    detail: str = ""


@dataclass
class NormalizationProfile:
    endpoint_uid: str
    chain: List[ChainLayer] = field(default_factory=list)
    engine: str = "unknown"
    capabilities: Dict[str, bool] = field(default_factory=dict)
    php_hint: bool = False
    magento_hint: bool = False
    notes: List[str] = field(default_factory=list)


class Normalizer:
    def __init__(self, client: HttpClient):
        self.client = client

    def run(self, endpoints: List[Endpoint],
            baselines: Dict[str, Baseline]) -> Dict[str, NormalizationProfile]:
        out: Dict[str, NormalizationProfile] = {}
        for ep in endpoints:
            out[ep.uid()] = self._profile(ep, baselines.get(ep.uid()))
        return out

    def _profile(self, ep: Endpoint, bl: Optional[Baseline]) -> NormalizationProfile:
        chain: List[ChainLayer] = []
        notes: List[str] = []

        status, body, headers, _ = self.client.get(ep.url,
                                                   timeout=min(self.client.cfg.timeout, 10))
        if bl is not None and bl.content_type:
            headers.setdefault("Content-Type", bl.content_type)

        for header, needle, role in _HEADER_SIGNATURES:
            val = (headers.get(header) or "").lower()
            if val and (not needle or needle in val):
                name = header
                if header == "server" and val:
                    name = val.split(" ")[0]
                chain.append(ChainLayer(role=role, name=name, detail=val))

        for pat, name, role in _BODY_SIGNATURES:
            if re.search(pat, (body or ""), re.I):
                if not any(l.name == name for l in chain):
                    chain.append(ChainLayer(role=role, name=name, detail="body signature"))

        # parser decision from strongest signal
        engine = "unknown"
        php_hint = any("php" in (l.name + l.detail).lower() for l in chain)
        magento_hint = any("magento" in (l.name + l.detail).lower() for l in chain)
        if magento_hint or php_hint:
            engine = "php_dom"
            chain.append(ChainLayer(role="parser", name="php/libxml2",
                                    detail="php stack hint"))
        elif any("asp.net" in (l.name + l.detail).lower() for l in chain):
            engine = "dotnet_xml"
            chain.append(ChainLayer(role="parser", name="System.Xml",
                                    detail=".NET stack hint"))
        elif any("tomcat" in (l.name + l.detail).lower()
                 or "spring" in (l.name + l.detail).lower() for l in chain):
            engine = "java_jaxp"
            chain.append(ChainLayer(role="parser", name="JAXP",
                                    detail="Java stack hint"))
        elif any("python" in (l.name + l.detail).lower()
                 or "django" in (l.name + l.detail).lower() for l in chain):
            engine = "python_xml"
            chain.append(ChainLayer(role="parser", name="ElementTree/lxml",
                                    detail="Python stack hint"))
        elif any("rails" in (l.name + l.detail).lower()
                 or "ruby" in (l.name + l.detail).lower() for l in chain):
            engine = "ruby_rexml"
            chain.append(ChainLayer(role="parser", name="REXML",
                                    detail="Ruby stack hint"))
        else:
            engine = normalize_engine("libxml2")
            chain.append(ChainLayer(role="parser", name="libxml2",
                                    detail="default assumption"))

        caps = engine_capabilities(engine)
        if not php_hint:
            caps = dict(caps)
            caps["php_filters"] = False
        profile = NormalizationProfile(
            endpoint_uid=ep.uid(),
            chain=chain,
            engine=engine,
            capabilities=caps,
            php_hint=php_hint,
            magento_hint=magento_hint,
            notes=notes,
        )
        if magento_hint:
            profile.notes.append("Magento framework detected")
        return profile


