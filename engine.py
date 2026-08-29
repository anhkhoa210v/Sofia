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
from concurrent.futures import ThreadPoolExecutor
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
_ASYNC_WINDOW = 8.0          # fallback OOB settle window when cfg.oob_wait <= 0
_RETEST_KINDS = ("oob_probe_http", "oob_parameter_entity")
# in-band file-read kinds that need an exfil target param
_FILE_READ_KINDS = (
    "file_read_inband", "param_entity_file_read", "xinclude_file",
    "svg_file_read", "soap_file_read", "json_xml_chain_file",
    "docx_file_read",
)


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
        self._test_lock = threading.Lock()
        self._job_deadline = time.monotonic() + cfg.job_timeout
        self._deadline_warned = False
        self._deadline_skips = 0      # tests dropped because the deadline hit
        self._evidence_map = {}       # set by _stage_analysis
        self._test_errors: Dict[str, int] = {}

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

        self.result.timeout_used = self.cfg.job_timeout
        # per-scan budget: never carry request accounting across runs
        self.gate.reset_budget()
        if self.cfg.job_timeout == 900.0:
            log.info("budget: using default job_timeout=900s - raise --job-timeout "
                     "for large targets (many endpoints increase discovery/baseline "
                     "time first, see S4)")

        try:
            phase_start = time.monotonic()
            self._stage_discovery()
            self._stage_classifier()
            self._stage_baseline()
            self._warn_budget(phase_start, before="test phase")
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
        """True while the job deadline has not been exceeded.

        Safe to call from worker threads: the timeout is logged only once.
        """
        if time.monotonic() > self._job_deadline and not self._abort:
            with self._abort_lock:
                if not self._deadline_warned:
                    self._deadline_warned = True
                    log.warn("job timeout reached - stopping")
                self._abort = True
                self.result.aborted = True
                if not self.result.aborted_reason:
                    self.result.aborted_reason = (
                        f"job timeout after {self.cfg.job_timeout:.0f}s")
        return not self._abort

    def _stage_guard(self, stage: str) -> bool:
        """Return True when a network stage may run; otherwise record a
        deadline-skip in coverage so the report explains WHY the stage is
        empty instead of showing a silent total=0."""
        if self._deadline_ok():
            return True
        self.coverage.stage(stage, 0, skipped=1,
                            detail="deadline - stage skipped")
        self.result.notes.append(
            f"stage '{stage}' skipped: job deadline exceeded")
        return False

    def _warn_budget(self, phase_start: float, before: str) -> None:
        """Warn early when the target scale consumes most of the job budget
        (S4): baseline/discovery on large targets routinely eats 60%+ of a
        default 900s budget, leaving the test matrix starved."""
        elapsed = time.monotonic() - phase_start
        remaining = self._job_deadline - time.monotonic()
        if remaining <= 0:
            log.warn(f"budget: exhausted ({elapsed:.0f}s used) before "
                     f"{before} - analysis will run on collected data only")
            self.result.notes.append(
                "budget exhausted before test phase - increase --job-timeout "
                "for full coverage on large targets")
            return
        if remaining < elapsed * 2 and remaining < self.cfg.job_timeout * 0.5:
            log.warn(f"budget: {elapsed:.0f}s consumed, only ~{remaining:.0f}s "
                     f"left before {before} ({remaining/self.cfg.job_timeout:.0%} "
                     f"of --job-timeout {self.cfg.job_timeout:.0f}s) - raise "
                     "--job-timeout for large targets (S4)")
            self.result.notes.append(
                "target scale exceeds job budget - raise --job-timeout "
                "(discovery/baseline consumed most of the time)")
        else:
            log.info(f"budget: {elapsed:.0f}s consumed, ~{remaining:.0f}s left "
                     f"before {before}")

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
        disc = Discoverer(self.client, self.cfg,
                          should_stop=lambda: not self._deadline_ok())
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
        self.result.baselines = be.run(
            self.result.endpoints, self.result.classifications,
            should_stop=lambda: not self._deadline_ok())
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
        is_magento = bool(
            fp.get("magento_version") or fp.get("composer")
            or (fp.get("magento_confidence") or 0.0) > 0.0
            or any("magento" in (k or "").lower() for k in kinds)
        )
        self._cve_candidates = evaluate_cves(
            version=fp.get("magento_version"),
            patch=fp.get("magento_patch"),
            php_version=fp.get("php_version"),
            parser=fp.get("parser"),
            endpoint_kinds=kinds,
            authenticated=auth,
            is_magento=is_magento,
        )
        self.coverage.stage("cve", len(self._cve_candidates),
                            tested=len(self._cve_candidates),
                            detail=",".join(c.cve_id for c in self._cve_candidates))

    # ------------------------------------------------------------------
    def _stage_test_matrix(self):
        # S1/S3: use the stage guard so a deadline hit is recorded in coverage
        # instead of silently dropping the whole matrix.
        if not self._stage_guard("test_matrix"):
            return
        self.coverage.stage("test_matrix", 1, in_progress=True)
        jobs: List[tuple] = []
        for ep in self.result.endpoints:
            if not self._deadline_ok():
                break
            for item in self._build_tests_for(ep):
                jobs.append((item, ep))
            self._maybe_abort()
        total_tests = len(jobs)
        self.result.tests_planned = total_tests
        ran = blocked = skipped = 0
        if jobs:
            workers = max(1, min(self.cfg.concurrency, len(jobs)))
            log.info(f"test matrix: {total_tests} tests on {workers} workers")
            with ThreadPoolExecutor(max_workers=workers,
                                    thread_name_prefix="sofia-test") as pool:
                outcomes = list(pool.map(self._run_gated_test, jobs))
            ran = outcomes.count("ran")
            blocked = outcomes.count("blocked")
            skipped = outcomes.count("skipped")
        self._deadline_skips += skipped
        detail_parts = [f"blocked={blocked} skipped={skipped}"]
        detail_parts += sorted(self.gate.blocked_summary().keys())
        self.coverage.stage("test_matrix", total_tests, tested=ran,
                            blocked=blocked, skipped=skipped,
                            detail="+".join(detail_parts)[:200])
        if skipped:
            log.warn(f"test matrix: {skipped}/{total_tests} tests skipped by "
                     f"job deadline - results below are partial (S3)")
            self.result.notes.append(
                f"{skipped} tests skipped by job deadline; scan incomplete")

    def _run_gated_test(self, job: tuple) -> str:
        """Admission-control + execute one test; safe for pool workers.

        Returns "ran" | "blocked" (safety gate) | "skipped" (deadline) so
        coverage accounting can tell a gate refusal from a deadline cut (S3).
        """
        item, ep = job
        if not self._deadline_ok():
            return "skipped"
        caps = self._profiles.get(ep.uid(),
                                  type("P", (), {"capabilities": {}}))
        if self.gate.check(item, getattr(caps, "capabilities", {}),
                           oob_available=bool(self.tunnel or self.oob)):
            if self.cfg.delay > 0:
                time.sleep(self.cfg.delay)
            self._execute(item, ep)
            return "ran"
        return "blocked"

    def _build_tests_for(self, ep: Endpoint) -> List[TestItem]:
        cls = self.result.classifications.get(ep.uid())
        if cls is None or cls.kind == "none":
            return []
        if self.cfg.endpoint_kinds and cls.kind not in self.cfg.endpoint_kinds:
            return []
        profile = self._profiles.get(ep.uid())
        caps = profile.capabilities if profile else {}
        tier = self.gate.tier

        selected = payloads_for_capabilities(caps, tier)
        selected = payloads_for_endpoint_kind(cls.kind, selected)
        if self.cfg.payload_kinds:
            selected = [k for k in selected if k in self.cfg.payload_kinds]
        # https-scheme probe is only meaningful over a TLS-reachable OOB base
        # (e.g. Cloudflare tunnel); drop it for plain local callbacks.
        if "oob_probe_https" in selected and not self.oob_base.startswith("https://"):
            selected.remove("oob_probe_https")
        # Magento admin XML layout import surface (CVE-2019-8126)
        if ep.kind == "admin" and cls.kind == "xml_direct" and tier.allow_oob:
            selected = list(dict.fromkeys(selected + ["xml_layout_xxe"]))
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
            if kind == _EXFIL_KIND or kind in _FILE_READ_KINDS:
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

    def _pick_exfil_target(self) -> Optional[str]:
        """First effective exfil target for this scan.

        A user-supplied --exfil-targets list is used as-is (that list IS the
        allowlist for the run); otherwise the first default target inside the
        default safety allowlist wins.
        """
        def _strip(t: str) -> str:
            return t.replace("php://filter/read=convert.base64-encode/"
                             "resource=", "")
        if self.cfg.exfil_targets:
            for t in self.cfg.exfil_targets:
                stripped = _strip(t).strip()
                if stripped:
                    return stripped
            return None
        from .safety import _ALLOWED_EXFIL_TARGETS
        for t in config_mod.DEFAULT_EXFIL_TARGETS:
            stripped = _strip(t)
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
        elif kind == "oob_general_entity_dtd":
            # general-entity DTD fetch (no exfil) - the builder points at
            # /dtd/{cid}.dtd so the callback must be registered up front
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
            elif item.payload_kind == "docx_file_read":
                _, _, data = get_payload("docx_file_read", cid=item.canary,
                                         oob_base=self.oob_base,
                                         target=item.params.get("target"))
                status, body, headers, elapsed = self.client.post(
                    ep.url, data=data, headers={"Content-Type": item.content_type},
                    allow_redirects=True)
            elif item.payload_kind == "xlsx_upload":
                _, _, data = get_payload("xlsx_upload", cid=item.canary,
                                         oob_base=self.oob_base)
                status, body, headers, elapsed = self.client.post_multipart(
                    ep.url,
                    files={"file": ("sofia_probe.xlsx", data,
                                     "application/vnd.openxmlformats-"
                                     "officedocument.spreadsheetml.sheet")},
                    data={"form_key": ""},
                    headers=dict(ep.headers),
                    allow_redirects=True)
            elif item.payload_kind == "cosmicsting_svg":
                # CVE-2024-34102: crafted SVG uploaded as a multipart file part
                _, _, data = get_payload("cosmicsting_svg", cid=item.canary,
                                         oob_base=self.oob_base)
                status, body, headers, elapsed = self.client.post_multipart(
                    ep.url,
                    files={"file": ("sofia_probe.svg",
                                     data.encode("utf-8"),
                                     "image/svg+xml")},
                    data={"form_key": ""},
                    headers=dict(ep.headers),
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
            with self._abort_lock:
                key = type(e).__name__
                self._test_errors[key] = self._test_errors.get(key, 0) + 1
        self.result.raw_results.append(raw)

    # ------------------------------------------------------------------
    def _stage_async_window(self):
        # async wait is the only stage that is safe to drop entirely: OOB hits
        # already recorded on raw results are still processed by _stage_analysis
        if not self._stage_guard("async_analysis"):
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
        window = self.cfg.oob_wait if self.cfg.oob_wait > 0 else _ASYNC_WINDOW
        log.info(f"async window: waiting {window:.0f}s for out-of-band "
                 f"processing ({len(pending)} pending)")
        time.sleep(max(0.0, min(window,
                                self._job_deadline - time.monotonic())))
        for r in pending:
            r.oob_hits = self.oob.hits_for(link_canary(self.result, r.test_id))
        fired = sum(1 for r in pending if r.oob_hits)
        self.coverage.stage("async_analysis", len(self.result.raw_results),
                            tested=fired,
                            async_only=len(pending) - fired,
                            detail="async callbacks collected")

    # ------------------------------------------------------------------
    def _stage_analysis(self):
        # S1: NEVER skip analysis silently. Even past the deadline we evaluate
        # the data already collected (local CPU work) so the report cannot
        # claim "no findings" for results that were never analyzed.
        if not self._deadline_ok():
            log.warn("analysis running past job deadline on collected data - "
                     "findings WILL still be evaluated")
            self.result.notes.append(
                "analysis ran past job deadline on collected data")
        self.coverage.stage("response_analysis", len(self.result.raw_results),
                            in_progress=True)
        self._evidence_map = EvidenceClassifier().classify_all(
            self.result, self.oob.all_hits())
        n_strong = sum(1 for evs in self._evidence_map.values()
                       for e in evs if e.strength == "STRONG")
        n_weak = sum(1 for evs in self._evidence_map.values()
                     for e in evs if e.strength in ("WEAK", "MEDIUM"))
        self.coverage.stage("response_analysis", len(self.result.raw_results),
                            tested=len(self._evidence_map),
                            detail=f"strong={n_strong} weak/med={n_weak}")

        self.coverage.stage("oob_analysis", max(1, len(self.oob.all_hits())),
                            tested=len(self.oob.all_hits()),
                            detail=self.oob.summary().get("by_cid", {}))

    # ------------------------------------------------------------------
    def _stage_findings(self):
        # S1: findings build is local CPU work; it runs on whatever raw results
        # were collected so `analysis_complete` reflects reality.
        if not self._deadline_ok():
            log.warn("findings build running past job deadline - results will "
                     "be marked analysis_complete on collected data")
            self.result.notes.append(
                "findings build ran past job deadline on collected data")
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
        self.result.analysis_complete = True

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

        # S7: surface bulk HTTP/transport failures instead of silently
        # reporting "no findings" when a proxy/WAF killed most tests.
        total_errs = sum(self._test_errors.values())
        if total_errs:
            detail = ", ".join(f"{k}={v}" for k, v in
                                sorted(self._test_errors.items(),
                                       key=lambda kv: -kv[1]))
            log.warn(f"{total_errs}/{len(self.result.raw_results)} tests "
                     f"raised exceptions ({detail}) - check proxy/WAF/"
                     "reachability; findings may be incomplete")
            self.result.notes.append(
                f"{total_errs} tests raised exceptions ({detail})")















