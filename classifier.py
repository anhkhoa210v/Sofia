"""Endpoint classifier: decide how each endpoint consumes XML.

Classes:
  xml_direct      - endpoint expects/parses raw XML
  soap            - SOAP endpoint
  json_to_xml     - JSON API that may convert embedded XML / accept XML body
  multipart_upload- multipart file upload (docx/svg ingestion)
  svg             - SVG endpoint
  rss             - RSS/Atom feed endpoint
  docx            - OOXML document ingestion
  parser_chain    - secondary parser (PDF, CSV->XML, etc.)
  none            - no XML surface
  unknown         - cannot determine
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

from .http import HttpClient
from .logger import get_logger
from .models import Classification, Endpoint

log = get_logger()

_SOAP_HINTS = re.compile(r"(/soap|soapv\d|/soap/|wsdl|/api/soap|xmlrpc)", re.I)
_REST_HINTS = re.compile(r"(/rest/|/v\d+|/graphql|/api\b|/api/|/json)", re.I)
_UPLOAD_HINTS = re.compile(r"(upload|import|ingest|media|attach|multipart|/import)", re.I)
_ASYNC_HINTS = re.compile(r"(async|queue|job|cron|worker|webhook|hook)", re.I)
_ADMIN_HINTS = re.compile(r"(/admin|adminhtml|/backend|/manage)", re.I)
_XML_CT = re.compile(r"(xml|svg|rss|atom|soap|docx|xslt|wsdl)", re.I)


class Classifier:
    def __init__(self, client: HttpClient):
        self.client = client

    def classify(self, endpoints: List[Endpoint],
                 existing: Optional[Dict[str, Classification]] = None) -> Dict[str, Classification]:
        out: Dict[str, Classification] = dict(existing or {})
        for ep in endpoints:
            out[ep.uid()] = self._classify_one(ep)
        return out

    def _classify_one(self, ep: Endpoint) -> Classification:
        url = ep.url
        path = (urlparse(url).path or "/").lower()
        kind = ep.kind

        if kind in ("soap",):
            return Classification(ep.uid(), "soap", reason="endpoint kind=soap",
                                  confidence=0.9)
        if kind in ("upload", "multipart_upload"):
            return Classification(ep.uid(), "multipart_upload",
                                  reason="upload endpoint", confidence=0.8)
        if kind in ("svg",):
            return Classification(ep.uid(), "svg", reason="endpoint kind=svg",
                                  confidence=0.9)
        if kind in ("rss",):
            return Classification(ep.uid(), "rss", reason="endpoint kind=rss",
                                  confidence=0.9)
        if kind in ("docx",):
            return Classification(ep.uid(), "docx", reason="endpoint kind=docx",
                                  confidence=0.9)
        if kind in ("api", "json_xml", "graphql"):
            return Classification(ep.uid(), "json_to_xml",
                                  reason=f"api endpoint ({kind})",
                                  confidence=0.7)
        if kind == "xml_direct":
            return Classification(ep.uid(), "xml_direct",
                                  reason="endpoint kind=xml_direct",
                                  confidence=0.9)
        if kind == "async":
            return Classification(ep.uid(), "parser_chain",
                                  reason="async worker may parse XML OOB",
                                  confidence=0.4)
        if kind == "admin":
            # Admin areas can parse XML layouts (CVE-2019-8126)
            return Classification(ep.uid(), "xml_direct",
                                  reason="admin layout XML surface",
                                  confidence=0.5)

        # heuristic by URL shape
        if _SOAP_HINTS.search(path):
            return Classification(ep.uid(), "soap",
                                  reason=f"soap path hint: {path}", confidence=0.8)
        if _UPLOAD_HINTS.search(path):
            return Classification(ep.uid(), "multipart_upload",
                                  reason=f"upload path hint: {path}", confidence=0.7)
        if _REST_HINTS.search(path):
            return Classification(ep.uid(), "json_to_xml",
                                  reason=f"api path hint: {path}", confidence=0.6)
        if _ASYNC_HINTS.search(path):
            return Classification(ep.uid(), "parser_chain",
                                  reason=f"async path hint: {path}", confidence=0.5)
        if _ADMIN_HINTS.search(path):
            return Classification(ep.uid(), "xml_direct",
                                  reason=f"admin path hint: {path}", confidence=0.5)
        if path.endswith((".xml", ".svg", ".rss", ".atom", ".wsdl", ".xsd")):
            return Classification(ep.uid(), "xml_direct",
                                  reason=f"xml extension: {path}", confidence=0.85)
        if path.endswith((".json",)):
            return Classification(ep.uid(), "json_to_xml",
                                  reason=f"json extension: {path}", confidence=0.6)

        # sniff the actual response
        status, body, headers, _ = self.client.get(
            ep.url, timeout=min(self.client.cfg.timeout, 10))
        ctype = (headers.get("Content-Type") or "").lower()
        if _XML_CT.search(ctype) or (body or "").lstrip().startswith("<"):
            return Classification(ep.uid(), "xml_direct",
                                  reason=f"response ct={ctype}", confidence=0.8)
        if "json" in ctype or (body or "").lstrip().startswith("{"):
            return Classification(ep.uid(), "json_to_xml",
                                  reason=f"response ct={ctype}", confidence=0.6)

        return Classification(ep.uid(), "unknown",
                              reason="no XML surface detected", confidence=0.2)


