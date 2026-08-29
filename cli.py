"""Command line interface for Sofia.

Commands:
  scan    - full XXE assessment pipeline (default)
  report  - regenerate a report from a saved JSON result
  verify  - re-verify findings from a saved JSON result with fresh canaries
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__, config as config_mod
from .config import default_config
from .engine import ScanEngine
from .feedback import verify_from_json
from .logger import get_logger, reconfigure
from .models import ScanConfig, ScanResult
from .report import ReportBuilder
from .tunnel import start_tunnel
from .webhook import (DiscordWebhook, replay_unsent,
                           summary_from_result)

log = get_logger()


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sofia",
        description="Sofia - XXE/XML security assessment framework "
                    "(authorized testing only)")
    p.add_argument("--version", action="version",
                   version=f"sofia {__version__}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="run the XXE assessment pipeline")
    scan.add_argument("--target", required=True, help="target base URL")
    scan.add_argument("--list", action="store_true",
                      help="list discovered endpoints then exit")
    scan.add_argument("--depth", type=int, default=2, help="crawl depth")
    scan.add_argument("--rate", type=float, default=5.0,
                      help="max requests per second")
    scan.add_argument("--timeout", type=float, default=12.0,
                      help="per-request timeout (s)")
    scan.add_argument("--oob-port", type=int, default=config_mod.DEFAULT_OOB_PORT,
                      help="OOB callback server port")
    scan.add_argument("--no-tunnel", action="store_true",
                      help="disable Cloudflare tunnel (localhost OOB)")
    scan.add_argument("--risk-tier", choices=["safe", "standard", "aggressive"],
                      default="standard", help="test aggressiveness")
    scan.add_argument("--webhook", default=None,
                      help="Discord webhook URL (default: $SOFIA_WEBHOOK)")
    scan.add_argument("--no-webhook", action="store_true",
                      help="do not send webhook, save fallback only")
    scan.add_argument("--out", default=config_mod.DEFAULT_OUT_DIR,
                      help="report output directory")
    scan.add_argument("--cookie", action="append", default=[],
                      help="Cookie header value (repeatable)")
    scan.add_argument("--header", action="append", default=[],
                      help="extra header Name: Value (repeatable)")
    scan.add_argument("--proxy", default=None, help="HTTP proxy URL")
    scan.add_argument("--insecure", action="store_true",
                      help="skip TLS verification")
    scan.add_argument("--job-timeout", type=float, default=900.0,
                      help="total scan timeout (s)")
    scan.add_argument("--abort-after", type=int, default=0,
                      help="abort after N findings (0 = unlimited)")
    scan.add_argument("--max-pages", type=int, default=None,
                      help="max pages crawled (default: config, 200)")
    scan.add_argument("--discovery-timeout", type=float, default=None,
                      help="discovery phase timeout in seconds")
    scan.add_argument("--concurrency", type=int, default=None,
                      help="concurrent test workers (default: config, 5)")
    scan.add_argument("--payload-kinds", default=None,
                      help="comma-separated payload kinds to run (default: all)")
    scan.add_argument("--endpoint-kinds", default=None,
                      help="comma-separated endpoint kinds to test (default: all)")
    scan.add_argument("--exfil-targets", default=None,
                      help="comma-separated exfil target allowlist "
                           "(replaces the defaults for this run)")
    scan.add_argument("--exfil-file", default=None,
                      help="file with exfil targets, one per line "
                           "(replaces the defaults for this run)")
    scan.add_argument("--delay", type=float, default=None,
                      help="extra delay between test requests (s)")
    scan.add_argument("--oob-wait", type=float, default=None,
                      help="OOB settle window after tests (s, default: 6)")
    scan.add_argument("--verbose", action="store_true")
    scan.add_argument("--log-file", default=None)

    rep = sub.add_parser("report", help="regenerate report from JSON result")
    rep.add_argument("--json", required=True, help="saved result JSON")
    rep.add_argument("--out", default=config_mod.DEFAULT_OUT_DIR)

    ver = sub.add_parser("verify", help="re-verify saved findings")
    ver.add_argument("--json", required=True, help="saved result JSON")
    ver.add_argument("--oob-port", type=int,
                     default=config_mod.DEFAULT_OOB_PORT)
    ver.add_argument("--rate", type=float, default=5.0)
    ver.add_argument("--timeout", type=float, default=12.0)
    ver.add_argument("--proxy", default=None)
    ver.add_argument("--insecure", action="store_true")
    ver.add_argument("--no-tunnel", action="store_true",
                     help="disable Cloudflare tunnel (localhost OOB)")
    ver.add_argument("--cookie", action="append", default=[],
                     help="Cookie header value (repeatable)")
    ver.add_argument("--header", action="append", default=[],
                     help="extra header Name: Value (repeatable)")
    ver.add_argument("--oob-wait", type=float, default=None,
                     help="OOB settle window for verify callbacks (s)")
    return p


def _parse_cookies(headers: List[str]) -> dict:
    """Parse cookies from either bare `k=v` entries or `Cookie: k=v; ...`."""
    cookies = {}
    for h in headers:
        if h.lower().startswith("cookie:"):
            h = h.split(":", 1)[1].strip()
        for pair in h.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies


def _parse_headers(headers: List[str]) -> dict:
    out = {}
    for h in headers:
        if ":" in h and not h.lower().startswith("cookie:"):
            k, v = h.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def _apply_scan_args(cfg: ScanConfig, args) -> ScanConfig:
    cfg.target = args.target
    cfg.list_mode = args.list
    cfg.max_depth = args.depth
    cfg.rate = args.rate
    cfg.timeout = args.timeout
    cfg.oob_port = args.oob_port
    cfg.use_tunnel = not args.no_tunnel
    cfg.risk_tier = args.risk_tier
    if args.no_webhook:
        cfg.webhook_url = ""
        cfg.send_webhook = False
    elif args.webhook:
        cfg.webhook_url = args.webhook
        cfg.send_webhook = True
    # else: keep opt-in default from config (SOFIA_WEBHOOK env)
    cfg.out_dir = args.out
    cfg.cookies.update(_parse_cookies(args.cookie))
    cfg.headers.update(_parse_headers(args.header))
    cfg.proxy = args.proxy
    cfg.insecure = args.insecure
    cfg.job_timeout = args.job_timeout
    cfg.abort_after = args.abort_after
    if args.max_pages is not None:
        cfg.max_pages = args.max_pages
    if args.discovery_timeout is not None:
        cfg.discovery_timeout = args.discovery_timeout
    if args.concurrency is not None:
        cfg.concurrency = args.concurrency
    if args.payload_kinds:
        cfg.payload_kinds = [k.strip() for k in
                             args.payload_kinds.split(",") if k.strip()]
    if args.endpoint_kinds:
        cfg.endpoint_kinds = [k.strip() for k in
                              args.endpoint_kinds.split(",") if k.strip()]
    if args.exfil_targets:
        cfg.exfil_targets = [t.strip() for t in
                             args.exfil_targets.split(",") if t.strip()]
    if args.exfil_file:
        try:
            with open(args.exfil_file, "r", encoding="utf-8") as f:
                cfg.exfil_targets = [t.strip() for t in
                                     f.read().splitlines() if t.strip()]
        except OSError as e:
            raise SystemExit(f"cannot read --exfil-file: {e}")
    if args.delay is not None:
        cfg.delay = args.delay
    if args.oob_wait is not None:
        cfg.oob_wait = args.oob_wait
    cfg.verbose = args.verbose
    cfg.log_file = args.log_file
    return cfg


def cmd_scan(args) -> int:
    cfg = _apply_scan_args(default_config(), args)
    reconfigure(level="debug" if cfg.verbose else "info",
                log_file=cfg.log_file)
    if not cfg.target.startswith(("http://", "https://")):
        cfg.target = "http://" + cfg.target
    log.info(f"Sofia {__version__} - target={cfg.target} "
             f"tier={cfg.risk_tier} tunnel={'on' if cfg.use_tunnel else 'off'}")

    # S6: retry payloads queued by earlier runs before starting a new scan
    fallback = os.path.join(cfg.out_dir, "webhook_unsent.json")
    if cfg.send_webhook and os.path.exists(fallback):
        delivered = replay_unsent(fallback)
        if delivered:
            log.info(f"webhook: replayed {delivered} queued payload(s)")

    engine = ScanEngine(cfg)
    try:
        result = engine.run()
    except KeyboardInterrupt:
        log.warn("scan interrupted by user")
        return 130
    except Exception:
        log.exception("scan failed")
        res = getattr(engine, "result", None)
        if res is not None and res.raw_results:
            try:
                paths = ReportBuilder(cfg.out_dir).build(res)
                print(f"\nPartial report: {paths['text']}")
            except Exception:
                log.exception("failed to write partial report")
        return 1

    if cfg.list_mode:
        for ep in result.endpoints:
            print(f"{ep.method:<5} {ep.kind:<16} {ep.url}")
        return 0

    if not result.endpoints:
        log.error("no endpoints discovered - check target reachability")
        return 1

    builder = ReportBuilder(cfg.out_dir)
    paths = builder.build(result)

    # webhook
    hook = DiscordWebhook(cfg.webhook_url, cfg.send_webhook)
    hook.send(cfg.target, ReportBuilder.report_lines(result),
              fallback_path=fallback,
              summary=summary_from_result(result))

    # console summary of report lines
    log.section("Report lines (domain | cve | evidence)")
    for line in ReportBuilder.report_lines(result):
        print(line)

    print(f"\nReports: {paths['text']} | {paths['json']} | {paths['markdown']}")
    return 0


def cmd_report(args) -> int:
    with open(args.json, "r", encoding="utf-8") as f:
        data = json.load(f)
    result = ScanResult(target=data.get("target", ""))
    result.__dict__.update(data)
    builder = ReportBuilder(args.out)
    paths = builder.build(result)
    print(f"Reports: {paths['text']} | {paths['json']} | {paths['markdown']}")
    return 0


def cmd_verify(args) -> int:
    cfg = default_config()
    cfg.oob_port = args.oob_port
    cfg.rate = args.rate
    cfg.timeout = args.timeout
    cfg.proxy = args.proxy
    cfg.insecure = args.insecure
    cfg.use_tunnel = not args.no_tunnel
    cfg.cookies.update(_parse_cookies(args.cookie))
    cfg.headers.update(_parse_headers(args.header))
    if args.oob_wait is not None:
        cfg.oob_wait = args.oob_wait
    tunnel = None
    oob_base = f"http://127.0.0.1:{cfg.oob_port}"
    try:
        if cfg.use_tunnel:
            tunnel = start_tunnel(cfg.oob_port)
            if tunnel:
                oob_base = tunnel.url
                log.info(f"verify OOB base: {oob_base}")
        result = verify_from_json(args.json, cfg, oob_base=oob_base)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    finally:
        if tunnel:
            tunnel.stop()


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command in (None, "scan"):
        if args.command is None:
            # support bare `sofia --target URL`
            if getattr(args, "target", None):
                args.command = "scan"
                return cmd_scan(args)
            parser.print_help()
            return 2
        return cmd_scan(args)
    if args.command == "report":
        return cmd_report(args)
    if args.command == "verify":
        return cmd_verify(args)
    parser.print_help()
    return 2





