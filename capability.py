"""Capability matrix: parser engines -> XXE-related capabilities.

Capabilities:
  dtd             - DOCTYPE/DTD processing
  entity          - internal entity expansion
  external_entity - external entity (SYSTEM) resolution
  parameter_entity- parameter entity support
  xinclude        - XInclude processing
  xslt            - XSLT / stylesheet processing
  error_reflection- parser errors surface entity content
  network         - outbound network fetches (http(s) entities)
  resource_limit  - entity expansion / resource exhaustion primitives
  file_scheme     - file:// scheme resolution
  php_filters     - php:// filter streams (php only)
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .models import RiskTier, RISK_TIERS

# Default (unpatched libxml2) behavior for common runtimes.
ENGINE_CAPABILITIES: Dict[str, Dict[str, bool]] = {
    "libxml2": {
        "dtd": True, "entity": True, "external_entity": True,
        "parameter_entity": True, "xinclude": True, "xslt": False,
        "error_reflection": False, "network": True, "resource_limit": True,
        "file_scheme": True, "php_filters": False,
    },
    "php_dom": {   # PHP DOMDocument / SimpleXML (libxml2-based)
        "dtd": True, "entity": True, "external_entity": True,
        "parameter_entity": True, "xinclude": True, "xslt": False,
        "error_reflection": True, "network": True, "resource_limit": True,
        "file_scheme": True, "php_filters": True,
    },
    "php_xmlreader": {
        "dtd": True, "entity": True, "external_entity": True,
        "parameter_entity": True, "xinclude": True, "xslt": False,
        "error_reflection": True, "network": True, "resource_limit": True,
        "file_scheme": True, "php_filters": True,
    },
    "java_jaxp": { # DOM/SAX via JAXP
        "dtd": True, "entity": True, "external_entity": True,
        "parameter_entity": True, "xinclude": False, "xslt": True,
        "error_reflection": False, "network": True, "resource_limit": True,
        "file_scheme": True, "php_filters": False,
    },
    "dotnet_xml": {  # System.Xml (XmlDocument, XmlReader)
        "dtd": True, "entity": True, "external_entity": True,
        "parameter_entity": True, "xinclude": False, "xslt": True,
        "error_reflection": False, "network": True, "resource_limit": True,
        "file_scheme": True, "php_filters": False,
    },
    "python_xml": {  # xml.etree / lxml defaults (vulnerable by default in etree)
        "dtd": True, "entity": True, "external_entity": True,
        "parameter_entity": True, "xinclude": False, "xslt": True,
        "error_reflection": False, "network": True, "resource_limit": True,
        "file_scheme": True, "php_filters": False,
    },
    "ruby_rexml": {  # REXML (has some protections historically)
        "dtd": True, "entity": True, "external_entity": False,
        "parameter_entity": True, "xinclude": False, "xslt": False,
        "error_reflection": False, "network": False, "resource_limit": True,
        "file_scheme": False, "php_filters": False,
    },
    "c_libxml": {
        "dtd": True, "entity": True, "external_entity": True,
        "parameter_entity": True, "xinclude": True, "xslt": True,
        "error_reflection": False, "network": True, "resource_limit": True,
        "file_scheme": True, "php_filters": False,
    },
    "unknown": {
        "dtd": True, "entity": True, "external_entity": True,
        "parameter_entity": True, "xinclude": False, "xslt": False,
        "error_reflection": False, "network": True, "resource_limit": True,
        "file_scheme": True, "php_filters": False,
    },
}

CAPABILITY_LABELS: Dict[str, str] = {
    "dtd": "DTD processing",
    "entity": "Internal entity",
    "external_entity": "External entity (SYSTEM)",
    "parameter_entity": "Parameter entity",
    "xinclude": "XInclude",
    "xslt": "XSLT",
    "error_reflection": "Error reflection",
    "network": "Outbound network fetch",
    "resource_limit": "Entity expansion / resource limits",
    "file_scheme": "file:// scheme",
    "php_filters": "php:// filter streams",
}


def capability_matrix() -> Dict[str, Dict[str, bool]]:
    return {k: dict(v) for k, v in ENGINE_CAPABILITIES.items()}


def engine_capabilities(engine: str) -> Dict[str, bool]:
    return dict(ENGINE_CAPABILITIES.get(engine, ENGINE_CAPABILITIES["unknown"]))


def normalize_engine(name: Optional[str]) -> str:
    """Map fingerprint strings to a canonical engine key."""
    if not name:
        return "unknown"
    n = name.lower()
    if "php" in n:
        if "xmlreader" in n or "simplexml" in n or "dom" in n:
            return "php_dom"
        return "php_dom"
    if "java" in n or "jaxp" in n or "tomcat" in n or "spring" in n:
        return "java_jaxp"
    if ".net" in n or "asp.net" in n or "aspnet" in n or "dotnet" in n:
        return "dotnet_xml"
    if "python" in n or "django" in n or "flask" in n or "tornado" in n:
        return "python_xml"
    if "ruby" in n or "rails" in n or "rexml" in n:
        return "ruby_rexml"
    if "libxml" in n or "apache" in n or "nginx" in n or "perl" in n:
        return "libxml2"
    if "c++" in n or "c/c++" in n:
        return "c_libxml"
    return "unknown"


def payloads_for_capabilities(caps: Dict[str, bool], tier: RiskTier) -> List[str]:
    """Select payload kinds permitted by the target's capabilities and risk tier."""
    kinds: List[str] = []
    # In-band file reads need DOCTYPE + general entity + file:// resolution.
    file_read = bool(
        caps.get("dtd", False) and caps.get("entity", False)
        and caps.get("external_entity", False) and caps.get("file_scheme", False)
    )
    if caps.get("dtd", False):
        if caps.get("entity", False):
            kinds.append("internal_entity")
        if caps.get("external_entity", False) and caps.get("network", False):
            kinds.append("oob_probe_http")
            if tier.allow_oob:
                kinds.append("oob_probe_https")
                kinds.append("oob_parameter_entity")
                kinds.append("oob_general_entity_dtd")
                kinds.append("cosmicsting_svg")
                kinds.append("xlsx_upload")
                if tier.allow_exfil:
                    kinds.append("oob_file_exfil")
        if file_read and tier.allow_exfil:
            kinds.append("file_read_inband")
            kinds.append("param_entity_file_read")
        if caps.get("error_reflection", False):
            kinds.append("error_based")
    if caps.get("xinclude", False) and tier.allow_xinclude:
        kinds.append("xinclude")
        if file_read and tier.allow_exfil:
            kinds.append("xinclude_file")
    if caps.get("xslt", False) and tier.allow_xslt:
        kinds.append("xslt")
        if tier.allow_oob:
            kinds.append("xslt_oob")
    if file_read and tier.allow_exfil:
        # Format-specific in-band file reads; the endpoint kind map decides
        # which formats apply to the probed endpoint.
        kinds.append("svg_file_read")
        kinds.append("soap_file_read")
        kinds.append("json_xml_chain_file")
        kinds.append("docx_file_read")
    if caps.get("resource_limit", False) and tier.allow_entity_expansion:
        kinds.append("entity_expansion")
    return dedupe(kinds)


def payloads_for_endpoint_kind(endpoint_kind: str, selected: List[str]) -> List[str]:
    """Map payload kinds appropriate to the endpoint XML kind."""
    allowed: Dict[str, List[str]] = {
        "xml_direct": ["internal_entity", "oob_probe_http", "oob_probe_https",
                       "oob_parameter_entity", "oob_general_entity_dtd",
                       "oob_file_exfil", "error_based", "xinclude", "xinclude_file",
                       "xslt", "xslt_oob", "entity_expansion", "xml_layout_xxe",
                       "file_read_inband", "param_entity_file_read"],
        "soap": ["soap_entity", "soap_file_read", "oob_parameter_entity",
                 "oob_general_entity_dtd", "oob_file_exfil", "error_based"],
        "json_to_xml": ["json_xml_chain", "json_xml_chain_file",
                        "oob_parameter_entity", "cosmicsting_svg"],
        "multipart_upload": ["docx_upload", "docx_file_read", "xlsx_upload",
                              "svg_entity", "cosmicsting_svg"],
        "svg": ["svg_entity", "svg_file_read", "internal_entity"],
        "rss": ["rss_entity", "internal_entity"],
        "docx": ["docx_upload", "docx_file_read", "xlsx_upload"],
        "parser_chain": ["internal_entity", "oob_probe_http", "error_based",
                         "file_read_inband", "param_entity_file_read"],
        "unknown": ["internal_entity", "oob_probe_http", "oob_parameter_entity",
                    "oob_general_entity_dtd", "error_based", "file_read_inband",
                    "param_entity_file_read"],
        "none": [],
    }
    want = allowed.get(endpoint_kind, allowed["unknown"])
    return [k for k in selected if k in want] or (want if endpoint_kind == "unknown" else [])


def dedupe(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out




