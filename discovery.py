"""Endpoint discovery.

Modes: passive (page crawling), active (path probing), authenticated (with
provided cookies/headers), recursive (follow same-origin links to max_depth).

Finds XML-relevant surfaces:
  - XML/SOAP/RSS/SVG endpoints
  - API / REST / GraphQL (JSON->XML conversion candidates)
  - Import/Export & upload endpoints (multipart ingestion)
  - Webhooks / async workers (out-of-band processing)
  - admin areas (authenticated XXE, e.g. CVE-2019-8126 layout XML)

The crawl is bounded: max_pages, discovery_timeout and a per-origin endpoint
cap keep discovery deterministic and cheap; static assets are skipped and
robots.txt/sitemap.xml are preferred as high-signal seeds.
"""

from __future__ import annotations

import re
import time
from typing import Callable, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from .config import (ACTIVE_PATHS, ASYNC_PATHS, JSON_API_PATHS, MAGENTO_ADMIN_PATHS,
                     SOAP_PATHS, UPLOAD_PATHS)
from .http import HttpClient, is_same_origin, origin_of
from .logger import get_logger
from .models import Endpoint

log = get_logger()

_LINK_RE = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.I)
_SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_FORM_RE = re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.I)
_INPUT_FILE_RE = re.compile(r'<input[^>]+type=["\']file["\'][^>]*>', re.I)
_META_RE = re.compile(r'<meta[^>]+(?:content|name)=["\']([^"\']+)["\']', re.I)
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<]+?)\s*</loc>", re.I)
_ROBOTS_SITEMAP_RE = re.compile(r"^\s*[Ss]itemap:\s*(\S+)", re.M)

# Static assets never carry XML processing surfaces; .svg/.json are kept
# because SVG is an XML container and JSON endpoints may convert to XML.
_STATIC_EXTS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".avi",
    ".mov", ".zip", ".gz", ".pdf", ".map",
)
_MAX_PER_ORIGIN = 150


class Discoverer:
    def __init__(self, client: HttpClient, config, should_stop: Optional[Callable[[], bool]] = None):
        self.client = client
        self.cfg = config
        self.should_stop: Callable[[], bool] = should_stop or (lambda: False)
        self.endpoints: Dict[str, Endpoint] = {}
        self._visited: Set[str] = set()
        self._origin_counts: Dict[str, int] = {}
        self._pages = 0
        self._deadline = time.monotonic() + getattr(config, "discovery_timeout", 120.0)
        self._max_pages = getattr(config, "max_pages", 200)
        # S7: each stop condition is logged exactly once (not per worker thread)
        self._warned_stop = False
        self._warned_max_pages = False
        self._warned_timeout = False

    # ------------------------------------------------------------------
    def run(self) -> List[Endpoint]:
        target = self.cfg.target.rstrip("/")
        seed = Endpoint(url=target, method="GET", kind="url",
                        source="seed", depth=0)
        self._add(seed)

        self._seed_robots_sitemap(target)
        if self._stop():
            return self._result()

        self._passive(seed)
        self._active(target)
        self._authenticated(target)

        # recursion pass over discovered urls
        urls = [ep.url for ep in list(self.endpoints.values())
                if ep.kind == "url" and ep.depth < self.cfg.max_depth]
        for url in urls:
            if self._stop():
                break
            self._recursive(url, url)

        return self._result()

    # ------------------------------------------------------------------
    def _stop(self) -> bool:
        if self.should_stop():
            if not self._warned_stop:
                self._warned_stop = True
                log.info("discovery: external stop requested - stopping crawl")
            return True
        if self._pages >= self._max_pages:
            if not self._warned_max_pages:
                self._warned_max_pages = True
                log.info(f"discovery: max_pages={self._max_pages} reached - "
                         "stopping crawl")
            return True
        if time.monotonic() > self._deadline:
            if not self._warned_timeout:
                self._warned_timeout = True
                log.info("discovery: timeout reached - stopping crawl")
            return True
        return False

    def _get(self, url: str):
        self._pages += 1
        status, body, headers, elapsed = self.client.get(
            url, timeout=min(self.cfg.timeout, 10))
        return status, body, headers

    def _add(self, ep: Endpoint):
        if ep.uid() in self.endpoints:
            return
        origin = origin_of(ep.url)
        if self._origin_counts.get(origin, 0) >= _MAX_PER_ORIGIN:
            return
        self.endpoints[ep.uid()] = ep
        self._origin_counts[origin] = self._origin_counts.get(origin, 0) + 1

    # ------------------------------------------------------------------
    def _seed_robots_sitemap(self, target: str):
        """Prefer sitemap URLs declared in robots.txt, else /sitemap.xml."""
        sitemap_urls: List[str] = []
        status, body, _ = self._get(target + "/robots.txt")
        if status and status not in (404, 410) and body:
            sitemap_urls = _ROBOTS_SITEMAP_RE.findall(body)
        if not sitemap_urls:
            status, body, _ = self._get(target + "/sitemap.xml")
            if status and status not in (404, 410) and body:
                sitemap_urls = [target + "/sitemap.xml"]
        for sm in sitemap_urls[:5]:
            if self._stop():
                break
            self._ingest_sitemap(sm, target, depth=0)

    def _ingest_sitemap(self, sitemap_url: str, target: str, depth: int):
        if depth > 1 or self._stop():
            return
        status, body, _ = self._get(sitemap_url)
        if status == 0 or status in (404, 410) or not body:
            return
        locs = _SITEMAP_LOC_RE.findall(body)
        if not locs:
            return
        for loc in locs:
            if not is_same_origin(loc, target):
                continue
            low = loc.lower()
            if depth == 0 and "sitemap" in low and loc != sitemap_url:
                self._ingest_sitemap(loc, target, depth + 1)
                continue
            self._note_link(target, loc, "sitemap")

    def _passive(self, seed: Endpoint):
        if self._stop():
            return
        status, body, headers = self._get(seed.url)
        if status == 0:
            log.warn(f"target unreachable: {seed.url}")
            return
        log.debug(f"GET {seed.url} -> {status} ct={headers.get('Content-Type', '')}")
        ctype = (headers.get("Content-Type") or "").lower()
        if "xml" in ctype or "svg" in ctype or "rss" in ctype:
            self._add(Endpoint(
                url=seed.url, method="GET", kind="xml_direct",
                source="passive", depth=0,
                note=f"server-generated XML ({ctype})"))
        for href in _LINK_RE.findall(body or ""):
            self._note_link(seed.url, href, "passive")
        for src in _SCRIPT_RE.findall(body or ""):
            self._note_link(seed.url, src, "passive")
        for action in _FORM_RE.findall(body or ""):
            url = urljoin(seed.url, action)
            file_inputs = []
            if _INPUT_FILE_RE.search(body or ""):
                file_inputs.append("file")
            self._add(Endpoint(
                url=url, method="POST", kind="form", source="passive",
                depth=1, file_inputs=file_inputs,
                note="form discovered in page"))

    def _note_link(self, base: str, href: str, source: str):
        if href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return
        url = urljoin(base, href)
        if not is_same_origin(url, self.cfg.target):
            return
        path = (urlparse(url).path or "/").lower()
        if path.endswith(_STATIC_EXTS):
            return
        kind = "url"
        if path.endswith((".xml", ".svg", ".rss", ".rdf", ".atom", ".docx",
                          ".wsdl", ".xsd", ".xsl", ".xslt")):
            kind = "xml_direct"
        elif path.endswith(".json"):
            kind = "json_xml"
        self._add(Endpoint(
            url=url, method="GET", kind=kind, source=source, depth=1))

    # ------------------------------------------------------------------
    def _active(self, target: str):
        for path in ACTIVE_PATHS:
            if self._stop():
                break
            url = target + path
            status, body, headers = self._get(url)
            if status == 0 or status in (404, 410):
                continue
            kind = "url"
            ctype = (headers.get("Content-Type") or "").lower()
            if path in SOAP_PATHS or "soap" in path:
                kind = "soap"
            elif path in JSON_API_PATHS or "rest" in path or "graphql" in path:
                kind = "api"
            elif path in UPLOAD_PATHS or "import" in path or "upload" in path:
                kind = "upload"
            elif path in ASYNC_PATHS or "async" in path or "queue" in path \
                    or "cron" in path or "jobs" in path:
                kind = "async"
            elif path in MAGENTO_ADMIN_PATHS or "admin" in path:
                kind = "admin"
            elif "xml" in ctype or "svg" in ctype or "rss" in ctype:
                kind = "xml_direct"
            self._add(Endpoint(
                url=url, method="POST" if kind in ("soap", "api", "upload",
                                                   "form") else "GET",
                kind=kind, source="active", depth=1,
                note=f"active probe status={status}"))

    # ------------------------------------------------------------------
    def _authenticated(self, target: str):
        """Endpoints only meaningful with authenticated session (--cookie/--header)."""
        if not (self.cfg.cookies or self.cfg.headers):
            return
        for path in (MAGENTO_ADMIN_PATHS + ["/index.php/admin/import_export",
                                            "/admin/import_export"]):
            if self._stop():
                break
            url = target + path
            status, body, headers = self._get(url)
            if status and status not in (404, 410):
                self._add(Endpoint(
                    url=url, method="GET", kind="admin", source="authenticated",
                    depth=1, note=f"authenticated probe status={status}"))

    # ------------------------------------------------------------------
    def _recursive(self, url: str, base: str):
        if url in self._visited or self._stop():
            return
        self._visited.add(url)
        status, body, headers = self._get(url)
        if status == 0 or not body:
            return
        for href in _LINK_RE.findall(body):
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            child = urljoin(url, href)
            if not is_same_origin(child, self.cfg.target):
                continue
            cpath = urlparse(child).path or "/"
            if cpath.lower().endswith(_STATIC_EXTS):
                continue
            depth = cpath.count("/")
            if depth > self.cfg.max_depth:
                continue
            if self._stop():
                return
            self._add(Endpoint(
                url=child, method="GET", kind="url", source="recursive",
                depth=depth))
            if depth < self.cfg.max_depth:
                self._recursive(child, url)

    def _result(self) -> List[Endpoint]:
        # S8: deterministic ordering so runs are reproducible regardless of
        # crawl timing / dict insertion order
        result = sorted(self.endpoints.values(),
                        key=lambda e: (e.depth, e.url, e.method))
        non_seed = len([e for e in result if e.source != "seed"])
        log.info(f"discovery: {len(result)} endpoints "
                 f"({non_seed} from crawl/probes)")
        return result


