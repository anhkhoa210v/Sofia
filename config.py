"""Configuration defaults and helpers for Sofia."""

from __future__ import annotations

import os
from typing import Dict, List

from .models import ScanConfig

DEFAULT_OUT_DIR = "sofia_reports"
DEFAULT_OOB_PORT = 17888

# Files targeted for exfiltration (Magento/Adobe Commerce and generic).
ENV_PHP_TARGETS: List[str] = [
    "app/etc/env.php",
    "/var/www/html/app/etc/env.php",
    "/var/www/app/etc/env.php",
    "php://filter/read=convert.base64-encode/resource=app/etc/env.php",
    "php://filter/read=convert.base64-encode/resource=/var/www/html/app/etc/env.php",
    "/etc/passwd",
]

# Generic Linux/application secrets - in the default safety allowlist.
GENERIC_EXFIL_TARGETS: List[str] = [
    "/etc/hostname",
    "/etc/passwd",
    "/etc/motd",
    "/etc/os-release",
    "/etc/hosts",
    "file:///etc/hostname",
    ".env",
    "/var/www/html/.env",
    "/var/www/.env",
    "composer.json",
    "/var/www/html/composer.json",
    "/proc/self/cwd/.env",
    "php://filter/read=convert.base64-encode/resource=.env",
]

# Windows files - in the default safety allowlist (no NTLM/SAM material).
WINDOWS_EXFIL_TARGETS: List[str] = [
    "C:\\Windows\\win.ini",
    "C:\\boot.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\inetpub\\wwwroot\\web.config",
    "web.config",
    "file:///C:/Windows/win.ini",
]

# Cloud/credential material - NOT in the default allowlist.  Only reachable
# when the operator explicitly opts in with --exfil-targets (which becomes the
# allowlist for that run).
CLOUD_EXFIL_TARGETS: List[str] = [
    "/root/.aws/credentials",
    "/home/*/.aws/credentials",
    "/root/.ssh/id_rsa",
    "/home/*/.ssh/id_rsa",
    "/root/.kube/config",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/etc/kubernetes/admin.conf",
    "C:\\Users\\*\\.ssh\\id_rsa",
    "C:\\Users\\*\\.aws\\credentials",
    "/root/.config/gcloud/credentials.db",
]

def _dedupe(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


# Combined list used by the engine when the operator did not pass
# --exfil-targets/--exfil-file.  First entry matching the safety allowlist wins.
DEFAULT_EXFIL_TARGETS: List[str] = _dedupe(
    ENV_PHP_TARGETS + GENERIC_EXFIL_TARGETS + WINDOWS_EXFIL_TARGETS)


# Common discovery paths (relative to origin).
ACTIVE_PATHS: List[str] = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/graphql", "/rest/V1", "/rest/default/V1",
    "/soap", "/soapV2", "/index.php/soap", "/index.php/soapV2",
    "/index.php/rest/V1", "/index.php/rest/default/V1",
    "/index.php/admin/import_export", "/admin/import_export",
    "/importexport", "/import_export", "/export",
    "/index.php/rest/V1/import", "/rest/V1/import",
    "/webhooks", "/webhook", "/hooks",
    "/index.php/admin", "/admin", "/adminhtml",
    "/index.php/cron", "/cron", "/queue", "/jobs", "/async",
    "/index.php/rest/V1/async", "/async/V1",
    "/media/import", "/media", "/pub/media",
    "/downloadable", "/upload", "/index.php/admin/system_config",
    "/xmlrpc", "/index.php/xmlrpc", "/api", "/api/v1", "/api/v2",
    "/v1", "/v2", "/index.php/api",
    "/feed", "/rss", "/feeds", "/productfeed", "/product_feed",
    "/index.php/feed", "/index.php/rss",
    "/healthcheck", "/status", "/version", "/magento_version",
    "/setup", "/index.php/setup", "/setup/wizard",
    "/errors/report.php", "/errors/404.php",
    # modern stacks: Spring / Boot, .NET, Node, API gateways
    "/actuator", "/actuator/health", "/actuator/env",
    "/v3/api-docs", "/v2/api-docs", "/api-docs", "/swagger-ui.html",
    "/swagger.json", "/openapi.json", "/openapi.yaml",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/.well-known/openapi.json", "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    # generic XML/SAML ingestion surfaces
    "/xml", "/api/xml", "/xmlrpc", "/rpc", "/wsdl", "/soap",
    "/ws", "/api/ws", "/saml/acs", "/saml/sso", "/assert",
    "/api/soap", "/v1/soap", "/v1/xml", "/api/v1/xml",
    "/submit", "/import", "/upload", "/parse", "/convert",
    "/transform", "/render", "/preview", "/validate",
    "/graphql", "/api/graphql", "/gql",
    "/rest", "/api/rest", "/api", "/v1", "/v2",
    "/index.php/api", "/feed", "/rss", "/feeds", "/productfeed",
    "/product_feed", "/index.php/feed", "/index.php/rss",
    "/healthcheck", "/status", "/version", "/magento_version",
    "/setup", "/index.php/setup", "/setup/wizard",
    "/errors/report.php", "/errors/404.php",
]

# Upload-ish paths (multipart / file ingestion).
UPLOAD_PATHS: List[str] = [
    "/import", "/upload", "/media/import", "/index.php/admin/import",
    "/index.php/admin/system_convert", "/import_export/import",
    "/admin/import", "/api/upload", "/graphql",
]

# SOAP endpoints.
SOAP_PATHS: List[str] = [
    "/soap", "/soapV2", "/index.php/soap", "/index.php/soapV2",
    "/soap/default", "/index.php/soap/default",
]

# GraphQL / REST (JSON->XML conversion candidates).
JSON_API_PATHS: List[str] = [
    "/graphql", "/rest/V1", "/rest/default/V1",
    "/index.php/rest/V1", "/index.php/rest/default/V1",
    "/api", "/api/v1", "/api/v2",
]

# Async worker paths (processing may happen out-of-band).
ASYNC_PATHS: List[str] = [
    "/queue", "/jobs", "/async", "/index.php/rest/V1/async",
    "/async/V1", "/cron", "/index.php/cron",
]

MAGENTO_ADMIN_PATHS: List[str] = [
    "/admin", "/adminhtml", "/index.php/admin", "/backend",
    "/index.php/backend", "/administrator", "/manage",
]

DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": "Sofia-XXE-Scanner/1.0 (security assessment)",
    "Accept": "*/*",
}

# Static metadata embedded into the scan plan for attribution.
ATTRIBUTION = "Sofia XXE assessment framework - authorized security testing only"


def default_config() -> ScanConfig:
    cfg = ScanConfig()
    # Webhook is opt-in: either --webhook on the CLI or SOFIA_WEBHOOK env.
    cfg.webhook_url = os.environ.get("SOFIA_WEBHOOK", "")
    cfg.send_webhook = bool(cfg.webhook_url)
    cfg.out_dir = os.environ.get("SOFIA_OUT_DIR", DEFAULT_OUT_DIR)
    # Payload-kind / endpoint-kind filters via env (comma separated).
    env_pk = os.environ.get("SOFIA_PAYLOAD_KINDS", "").strip()
    if env_pk:
        cfg.payload_kinds = [k.strip() for k in env_pk.split(",") if k.strip()]
    env_ek = os.environ.get("SOFIA_ENDPOINT_KINDS", "").strip()
    if env_ek:
        cfg.endpoint_kinds = [k.strip() for k in env_ek.split(",") if k.strip()]
    env_xf = os.environ.get("SOFIA_EXFIL_TARGETS", "").strip()
    if env_xf:
        cfg.exfil_targets = [t.strip() for t in env_xf.splitlines() if t.strip()]
    env_wait = os.environ.get("SOFIA_OOB_WAIT", "").strip()
    if env_wait:
        try:
            cfg.oob_wait = float(env_wait)
        except ValueError:
            pass
    env_delay = os.environ.get("SOFIA_DELAY", "").strip()
    if env_delay:
        try:
            cfg.delay = float(env_delay)
        except ValueError:
            pass
    return cfg




