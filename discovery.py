"""Endpoint discovery.

Modes: passive (page crawling), active (path probing), authenticated (with
provided cookies/headers), recursive (follow same-origin links to max_depth).

Finds XML-relevant surfaces:
  - XML/SOAP/RSS/SVG endpoints
  - API / REST / GraphQL (JSON->XML conversion candidates)
  - Import/Export & upload endpoints (multipart ingestion)
  - Webhooks / async workers (out-of-band processing)
  - admin areas (authenticated XXE, e.g. CVE-2019-8126 layout XML)
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from .config import (ACTIVE_PATHS, ASYNC_PATHS, JSON_API_PATHS, MAGENTO_ADMIN_PATHS,
                     SOAP_PATHS, UPLOAD_PATHS)
from .http import HttpClient, is_same_origin
from .logger import get_logger
from .models import Endpoint

log = get_logger()

_LINK_RE = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.I)
_SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_FORM_RE = re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.I)
_INPUT_FILE_RE = re.compile(r'<input[^>]+type=["\']file["\'][^>]*>', re.I)
_META_RE = re.compile(r'<meta[^>]+(?:content|name)=["\']([^"\']+)["\']', re.I)


def _add(store: Dict[str, Endpoint], ep: Endpoint):
    store.setdefault(ep.uid(), ep)


class Discoverer:
    def __init__(self, client: HttpClient, config):
        self.client = client
        self.cfg = config
        self.endpoints: Dict[str, Endpoint] = {}
        self._visited: Set[str] = set()

    # ------------------------------------------------------------------
    def run(self) -> List[Endpoint]:
        target = self.cfg.target.rstrip("/")
        seed = Endpoint(url=target, method="GET", kind="url",
                        source="seed", depth=0)
        _add(self.endpoints, seed)

        self._passive(seed)
        self._active(target)
        self._authenticated(target)

        # recursion pass over discovered urls
        urls = [ep.url for ep in list(self.endpoints.values())
                if ep.kind == "url" and ep.depth < self.cfg.max_depth]
        for url in urls:
            self._recursive(url, url)

        # post-classification enrichment: upload/soap/api kinds set later
        result = list(self.endpoints.values())
        log.info(f"discovery: {len(result)} endpoints from "
                 f"{len([e for e in result if e.source != 'seed'])} sources")
        return result

    # ------------------------------------------------------------------
    def _get(self, url: str):
        status, body, headers, elapsed = self.client.get(
            url, timeout=min(self.cfg.timeout, 10))
        return status, body, headers

    def _passive(self, seed: Endpoint):
        status, body, headers = self._get(seed.url)
        if status == 0:
            log.warn(f"target unreachable: {seed.url}")
            return
        log.debug(f"GET {seed.url} -> {status} ct={headers.get('Content-Type', '')}")
        ctype = (headers.get("Content-Type") or "").lower()
        if "xml" in ctype or "svg" in ctype or "rss" in ctype:
            _add(self.endpoints, Endpoint(
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
            _add(self.endpoints, Endpoint(
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
        kind = "url"
        if path.endswith((".xml", ".svg", ".rss", ".rdf", ".atom", ".docx",
                          ".wsdl", ".xsd", ".xsl", ".xslt")):
            kind = "xml_direct"
        elif path.endswith((".json", ".js")):
            kind = "json_xml"
        _add(self.endpoints, Endpoint(
            url=url, method="GET", kind=kind, source=source, depth=1))

    # ------------------------------------------------------------------
    def _active(self, target: str):
        for path in ACTIVE_PATHS:
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
            _add(self.endpoints, Endpoint(
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
            url = target + path
            status, body, headers = self._get(url)
            if status and status not in (404, 410):
                _add(self.endpoints, Endpoint(
                    url=url, method="GET", kind="admin", source="authenticated",
                    depth=1, note=f"authenticated probe status={status}"))

    # ------------------------------------------------------------------
    def _recursive(self, url: str, base: str):
        if url in self._visited:
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
            depth = cpath.count("/")
            if depth > self.cfg.max_depth:
                continue
            _add(self.endpoints, Endpoint(
                url=child, method="GET", kind="url", source="recursive",
                depth=depth))
            if depth < self.cfg.max_depth:
                self._recursive(child, url)

