"""Coverage accounting: per-stage tested/skipped/blocked/unknown/async/auth."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .logger import get_logger
from .models import COVERAGE_STAGES, CoverageRecord

log = get_logger()


class CoverageTracker:
    def __init__(self):
        self._records: Dict[str, CoverageRecord] = {}
        for stage in COVERAGE_STAGES:
            self._records[stage] = CoverageRecord(stage=stage)
        self._extra_stages: List[str] = []

    def stage(self, name: str, total: int, tested: int = 0, skipped: int = 0,
              blocked: int = 0, unknown: int = 0, async_only: int = 0,
              auth_only: int = 0, detail: str = "",
              in_progress: bool = False) -> CoverageRecord:
        if name not in self._records:
            if name not in self._extra_stages:
                self._extra_stages.append(name)
            self._records[name] = CoverageRecord(stage=name)
        rec = self._records[name]
        rec.total = total
        rec.tested = tested
        rec.skipped = skipped
        rec.blocked = blocked
        rec.unknown = unknown
        rec.async_only = async_only
        rec.auth_only = auth_only
        if detail:
            rec.detail = detail
        if in_progress:
            log.debug(f"coverage {name}: in progress")
        return rec

    def records(self) -> List[CoverageRecord]:
        ordered = [self._records[s] for s in COVERAGE_STAGES
                   if s in self._records]
        ordered += [self._records[s] for s in self._extra_stages
                    if s not in COVERAGE_STAGES]
        return ordered

    def summary(self) -> Dict[str, Any]:
        total_tested = sum(r.tested for r in self._records.values())
        total = sum(r.total for r in self._records.values())
        return {
            "stages": len(self._records),
            "tested": total_tested,
            "total": total,
            "pct": round(100.0 * total_tested / total, 1) if total else 0.0,
        }


