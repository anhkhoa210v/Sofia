"""Scan engine: orchestrates the 22-stage pipeline.

Stages:
  Discovery -> Coverage -> Classifier -> Baseline -> Normalization -> Fingerprint
  -> CVE engine -> Parser decision -> Capability matrix -> Safety gate
  -> Controlled test matrix -> Response/OOB/Async analysis -> Evidence taxonomy
  -> Confidence -> Impact -> CVE correlation -> Dedup -> Risk -> Human review
  -> Report
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

from .analysis import AnalysisEngine
from .baseline import BaselineEngine
from .capability import (payloads_for_capabilities, payloads_for_endpoint_kind)
from .classifier import Classifier
from .confidence import ConfidenceEngine
from .coverage import CoverageTracker
from .cve import evaluate_cves, rank_candidates
from .discovery import Discoverer
from .evidence import EvidenceClassifier
from .fingerprint import Fingerprinter
from .http import HttpClient
from .impact import ImpactEngine
from .logger import get_logger
from .models import (Endpoint, Finding, RawResult, ScanConfig, ScanResult,
                     TestItem, link_canary, new_id)
from .normalize import Normalizer
from .oob import OOBServer, new_canary
from .payloads import PAYLOAD_REGISTRY, dtd_payload, get_payload
from .risk import RiskEngine
from .safety import SafetyGate
from .tunnel import Tunnel, start_tunnel
from . import config as config_mod

log = get_logger()

# payload kinds grouped by purpose
_EXFIL_KIND = "oob_file_exfil"
_ASYNC_WINDOW = 8.0          # seconds to wait for async OOB hits
_RETEST_KINDS = ("oob_probe_http", "oob_parameter_entity")


class ScanEngine:
    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg
        self.client = HttpClient(cfg, headers=cfg.headers, cookies=cfg.cookies)
        self.oob = OOBServer(cfg.oob_port)
        self.tunnel: Optional[Tunnel] = None
        self.oob_base = self.oob.base_url
        self.gate = SafetyGate(cfg)
        self.coverage = CoverageTracker()
        self.result = ScanResult(target=cfg.target)
        self._abort = False
        self._abort_lock = threading.Lock()
        self._job_deadline = time.monotonic() + cfg.job_timeout

    # ------------------------------------------------------------------
    def run(self) -> ScanResult:
        started = datetime.now()
        self.result.started_at = started.isoformat()
        log.section("Sofia XXE assessment started")
        log.info(f"target={self.cfg.target} tier={self.cfg.risk_tier} "
                 f"oob_port={self.cfg.oob_port}")

        # OOB + tunnel
        if not self.oob.start():
            log.error("OOB server failed to start - aborting")
            self.result.finished_at = datetime.now().isoformat()
            return self.result
        if self.cfg.use_tunnel:
            self.tunnel = start_tunnel(self.cfg.oob_port)
            if self.tunnel:
                self.oob_base = self.tunnel.url
        log.info(f"OOB base: {self.oob_base}")
        self.coverage.stage("oob", 1, tested=1)

        try:
            self._stage_discovery()
            self._stage_classifier()
            self._stage_baseline()
            self._stage_normalize_fingerprint()
            self._stage_cve()
            self._stage_test_matrix()
            self._stage_async_window()
            self._stage_analysis()
            self._stage_findings()
            self._stage_report()
        finally:
            if self.tunnel:
                self.tunnel.stop()
            self.oob.stop()
            self.client.close()

        self.result.finished_at = datetime.now().isoformat()
        self.result.oob_summary = self.oob.summary()
        log.section("Sofia assessment finished")
        log.info(f"findings={len(self.result.findings)} "
                 f"tests={len(self.result.raw_results)}")
        return self.result

    # ------------------------------------------------------------------
    def _deadline_ok(self) -> bool:
        if time.monotonic() > self._job_deadline:
            log.warn("job timeout reached - stopping")
            self._abort = True
        return not self._abort

    def _maybe_abort(self):
        with self._abort_lock:
            if self.cfg.abort_after and \
                    len(self.result.findings) >= self.cfg.abort_after:
                self._abort = True
                self.result.aborted = True
                log.warn(f"abort_after={self.cfg.abort_after} reached")

    # ------------------------------------------------------------------
    def _stage_discovery(self):
        self.coverage.stage("discovery", 1, in_progress=True)
        disc = Discoverer(self.client, self.cfg)
        self.result.endpoints = disc.run()
        self.coverage.stage("discovery", len(self.result.endpoints), tested=1)

    def _stage_classifier(self):
        if not self._deadline_ok():
            return
        self.coverage.stage("classification", len(self.result.endpoints),
                            in_progress=True)
        clf = Classifier(self.client)
        self.result.classifications = clf.classify(self.result.endpoints)
        kinds = {}
        for c in self.result.classifications.values():
            kinds[c.kind] = kinds.get(c.kind, 0) + 1
        self.coverage.stage("classification", len(self.result.endpoints),
                            tested=len(kinds), detail=str(kinds))

    def _stage_baseline(self):
        if not self._deadline_ok():
            return
        self.coverage.stage("baseline", len(self.result.endpoints),
                            in_progress=True)
        be = BaselineEngine(self.client)
        self.result.baselines = be.run(self.result.endpoints,
                                       self.result.classifications)
        tested = sum(1 for b in self.result.baselines.values()
                     if b.status != 0)
        self.coverage.stage("baseline", len(self.result.endpoints),
                            tested=tested, detail="status!=0 counted")

    def _stage_normalize_fingerprint(self):
        if not self._deadline_ok():
            return
        self.coverage.stage("normalization", len(self.result.endpoints),
                            in_progress=True)
        norm = Normalizer(self.client)
        self._profiles = norm.run(self.result.endpoints, self.result.baselines)
        self.coverage.stage("normalization", len(self.result.endpoints),
                            tested=len(self._profiles))

        self.coverage.stage("fingerprint", 1, in_progress=True)
        fp = Fingerprinter(self.client)
        self.result.fingerprints = fp.run(self.result.endpoints, self._profiles)
        self.coverage.stage("fingerprint", 1, tested=1,
                            detail=str({k: v for k, v in
                                        self.result.fingerprints.items()
                                        if k != "sources"}))

    def _stage_cve(self):
        if not self._deadline_ok():
            return
        self.coverage.stage("cve", 1, in_progress=True)
        fp = self.result.fingerprints
        kinds = [c.kind for c in self.result.classifications.values()]
        auth = any(e.kind == "admin" for e in self.result.endpoints)
        self._cve_candidates = evaluate_cves(
            version=fp.get("magento_version"),
            patch=fp.get("magento_patch"),
            php_version=fp.get("php_version"),
            parser=fp.get("parser"),
            endpoint_kinds=kinds,
            authenticated=auth,
        )
        self.coverage.stage("cve", len(self._cve_candidates),
                            tested=len(self._cve_candidates),
                            detail=",".join(c.cve_id for c in self._cve_candidates))

    # ------------------------------------------------------------------
    def _stage_test_matrix(self):
        if not self._deadline_ok():
            return
        self.coverage.stage("test_matrix", 1, in_progress=True)
        total_tests = 0
        run_tests = 0
        for ep in self.result.endpoints:
            if not self._deadline_ok():
                break
            items = self._build_tests_for(ep)
            total_tests += len(items)
            for item in items:
                if not self._deadline_ok():
                    break
                caps = self._profiles.get(ep.uid(),
                                          type("P", (), {"capabilities": {}}))
                if self.gate.check(item, getattr(caps, "capabilities", {}),
                                   oob_available=bool(self.tunnel or self.oob)):
                    self._execute(item, ep)
                    run_tests += 1
            self._maybe_abort()
        self.coverage.stage("test_matrix", total_tests, tested=run_tests,
                            blocked=total_tests - run_tests,
                            detail="+".join(sorted(
                                self.gate.blocked_summary().keys()))[:200])

    def _build_tests_for(self, ep: Endpoint) -> List[TestItem]:
        cls = self.result.classifications.get(ep.uid())
        if cls is None or cls.kind == "none":
            return []
        profile = self._profiles.get(ep.uid())
        caps = profile.capabilities if profile else {}
        tier = self.gate.tier

        selected = payloads_for_capabilities(caps, tier)
        selected = payloads_for_endpoint_kind(cls.kind, selected)
        if not selected:
            # still run baseline + negative control for coverage accounting
            selected = ["baseline", "negative_control"]

        items: List[TestItem] = []
        cid0 = new_canary()
        items.append(self._make_item(ep, "baseline", cid0,
                                     purpose="baseline",
                                     control_group="control"))
        cid1 = new_canary()
        items.append(self._make_item(ep, "negative_control", cid1,
                                     purpose="negative_control",
                                     control_group="control"))

        for kind in selected:
            if kind in ("baseline", "negative_control"):
                continue
            cid = new_canary()
            if kind == "oob_file_exfil":
                tgt = self._pick_exfil_target()
                if not tgt:
                    continue
                items.append(self._make_item(ep, kind, cid,
                                             purpose="exfil",
                                             control_group="probe",
                                             target=tgt))
            else:
                items.append(self._make_item(ep, kind, cid,
                                             purpose="capability",
                                             control_group="probe"))
        return items

    @staticmethod
    def _pick_exfil_target() -> Optional[str]:
        """First allowlisted exfil target from ENV_PHP_TARGETS."""
        from .safety import _ALLOWED_EXFIL_TARGETS
        for t in config_mod.ENV_PHP_TARGETS:
            stripped = t.replace("php://filter/read=convert.base64-encode/"
                                 "resource=", "")
            if any(a in stripped for a in _ALLOWED_EXFIL_TARGETS):
                return stripped
        return None

    def _make_item(self, ep: Endpoint, kind: str, cid: str, purpose: str,
                   control_group: str, target: Optional[str] = None) -> TestItem:
        tier = self.gate.tier
        params: Dict = {}
        if target:
            params["target"] = target
        _, ctype, data = get_payload(
            kind,
            cid=cid,
            oob_base=self.oob_base,
            target=target,
            levels=tier.expansion_levels,
            width=tier.expansion_width,
        )
        if kind == "oob_file_exfil" and target:
            self.oob.register_dtd(cid, dtd_payload(cid, self.oob_base, target,
                                                   php=True))
        elif kind == "oob_parameter_entity":
            # probe DTD (no exfil)
            self.oob.register_dtd(cid, dtd_payload(cid, self.oob_base,
                                                   "file:///etc/hostname",
                                                   php=False))
        headers = dict(ep.headers)
        headers["Content-Type"] = ctype
        headers["X-Sofia-Cid"] = cid
        return TestItem(
            id=new_id("t"),
            endpoint_uid=ep.uid(),
            payload_kind=kind,
            xml=data if isinstance(data, str) else "",
            method="POST" if ep.method == "POST" else ep.method,
            content_type=ctype,
            purpose=purpose,
            control_group=control_group,
            canary=cid,
            params=params,
            headers=headers,
        )

    # ------------------------------------------------------------------
    def _execute(self, item: TestItem, ep: Endpoint):
        self.result.test_items.append(item)
        raw = RawResult(test_id=item.id, endpoint_uid=item.endpoint_uid,
                        payload_kind=item.payload_kind, purpose=item.purpose,
                        sent_at=time.time())
        try:
            if item.payload_kind == "docx_upload":
                _, _, data = get_payload("docx_upload", cid=item.canary,
                                         oob_base=self.oob_base)
                status, body, headers, elapsed = self.client.post(
                    ep.url, data=data, headers={"Content-Type": item.content_type},
                    allow_redirects=True)
            else:
                body_bytes = item.xml.encode("utf-8") if item.xml else b""
                if item.content_type == "application/json":
                    status, body, headers, elapsed = self.client.post(
                        ep.url, data=body_bytes,
                        headers={"Content-Type": "application/json",
                                 "Accept": "application/xml, application/json"},
                        allow_redirects=True)
                else:
                    status, body, headers, elapsed = self.client.post(
                        ep.url, data=body_bytes,
                        headers={"Content-Type": item.content_type,
                                 "Accept": "application/xml, text/xml, */*"},
                        allow_redirects=True)
            raw.status = status
            raw.length = len(body or "")
            raw.content_type = headers.get("Content-Type", "")
            raw.elapsed = elapsed
            raw.body_snippet = (body or "")[:2000]
            raw.received_at = time.time()
            raw.oob_hits = self.oob.hits_for(item.canary)
            log.debug(f"test {item.id} kind={item.payload_kind} "
                      f"-> {status} len={raw.length} oob={len(raw.oob_hits)}")
        except Exception as e:  # noqa: BLE001
            raw.error = repr(e)
        self.result.raw_results.append(raw)
        if raw.oob_hits or (raw.status and raw.status != 0):
            pass

    # ------------------------------------------------------------------
    def _stage_async_window(self):
        if not self._deadline_ok():
            return
        self.coverage.stage("async_analysis", len(self.result.raw_results),
                            in_progress=True)
        pending = [r for r in self.result.raw_results
                   if r.payload_kind not in ("baseline", "negative_control")
                   and not r.oob_hits]
        if not pending:
            self.coverage.stage("async_analysis", len(self.result.raw_results),
                                tested=0, skipped=len(self.result.raw_results),
                                detail="no pending async tests")
            return
        log.info(f"async window: waiting {_ASYNC_WINDOW:.0f}s for out-of-band "
                 f"processing ({len(pending)} pending)")
        time.sleep(min(_ASYNC_WINDOW, self._job_deadline - time.monotonic()))
        for r in pending:
            r.oob_hits = self.oob.hits_for(link_canary(self.result, r.test_id))
        fired = sum(1 for r in pending if r.oob_hits)
        self.coverage.stage("async_analysis", len(self.result.raw_results),
                            tested=fired,
                            async_only=len(pending) - fired,
                            detail="async callbacks collected")

    # ------------------------------------------------------------------
    def _stage_analysis(self):
        if not self._deadline_ok():
            return
        self.coverage.stage("response_analysis", len(self.result.raw_results),
                            in_progress=True)
        self._evidence_map = EvidenceClassifier().classify_all(
            self.result, self.oob.all_hits())
        n_strong = sum(1 for e in self._evidence_map.values()
                       if e.strength == "STRONG")
        n_weak = sum(1 for e in self._evidence_map.values()
                     if e.strength in ("WEAK", "MEDIUM"))
        self.coverage.stage("response_analysis", len(self.result.raw_results),
                            tested=len(self._evidence_map),
                            detail=f"strong={n_strong} weak/med={n_weak}")

        self.coverage.stage("oob_analysis", max(1, len(self.oob.all_hits())),
                            tested=len(self.oob.all_hits()),
                            detail=self.oob.summary().get("by_cid", {}))

    # ------------------------------------------------------------------
    def _stage_findings(self):
        if not self._deadline_ok():
            return
        self.coverage.stage("evidence", 1, in_progress=True)
        findings = AnalysisEngine().build_findings(
            self.result, self._evidence_map, self._profiles,
            self._cve_candidates, self.oob.all_hits())
        self.coverage.stage("evidence", len(findings), tested=len(findings),
                            detail="evidence classified")

        # confidence
        self.coverage.stage("confidence", len(findings), in_progress=True)
        conf = ConfidenceEngine(self.result)
        for f in findings:
            f.confidence = conf.evaluate(f)
        self.coverage.stage("confidence", len(findings), tested=len(findings))

        # impact
        self.coverage.stage("impact", len(findings), in_progress=True)
        imp = ImpactEngine()
        for f in findings:
            f.impact = imp.evaluate(f)
        self.coverage.stage("impact", len(findings), tested=len(findings))

        # cve correlation
        self.coverage.stage("cve_correlation", len(findings), in_progress=True)
        for f in findings:
            if not f.cve_id and f.cve_candidates:
                best = rank_candidates(f.cve_candidates)[0]
                f.cve_id = best.cve_id
        self.coverage.stage("cve_correlation", len(findings),
                            tested=len(findings))

        # dedup
        self.coverage.stage("dedup", len(findings), in_progress=True)
        findings = self._dedupe(findings)
        self.coverage.stage("dedup", len(findings), tested=len(findings),
                            detail=f"deduped to {len(findings)}")

        # risk
        self.coverage.stage("risk", len(findings), in_progress=True)
        risk = RiskEngine()
        for f in findings:
            f.risk_score = risk.score(f)
            f.severity = risk.severity(f)
        self.coverage.stage("risk", len(findings), tested=len(findings))

        # human review
        self.coverage.stage("review", len(findings), in_progress=True)
        review_notes = self._review_notes(findings)
        self.coverage.stage("review", len(findings), tested=len(findings),
                            detail=review_notes)

        self.result.findings = findings

    def _dedupe(self, findings: List[Finding]) -> List[Finding]:
        seen: Dict[str, Finding] = {}
        for f in findings:
            key = f.dedup_key or f"{f.endpoint_url}|{f.cve_id or f.title}"
            if key in seen:
                # merge evidence
                seen[key].evidence.extend(f.evidence)
                seen[key].reproduction.extend(f.reproduction)
            else:
                f.dedup_key = key
                seen[key] = f
        return list(seen.values())

    def _review_notes(self, findings: List[Finding]) -> str:
        notes = []
        for f in findings:
            if f.confidence == "confirmed":
                notes.append(f"{f.cve_id or f.title}: confirmed - immediate "
                             "remediation required")
            elif f.confidence == "probable":
                notes.append(f"{f.cve_id or f.title}: probable - manual "
                             "verification recommended")
            elif f.confidence == "suspected":
                notes.append(f"{f.cve_id or f.title}: suspected - needs "
                             "human confirmation")
        return "; ".join(notes) or "no review flags"

    # ------------------------------------------------------------------
    def _stage_report(self):
        self.coverage.stage("report", 1, in_progress=True)
        self.coverage.stage("report", 1, tested=1)
        self.result.coverage = self.coverage.records()






