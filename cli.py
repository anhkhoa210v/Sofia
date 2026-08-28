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
from .webhook import DiscordWebhook

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
    scan.add_argument("--webhook", default=config_mod.DEFAULT_WEBHOOK,
                      help="Discord webhook URL")
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
    return p


def _parse_cookies(headers: List[str]) -> dict:
    cookies = {}
    for h in headers:
        if h.lower().startswith("cookie:"):
            val = h.split(":", 1)[1].strip()
            for pair in val.split(";"):
                if "=" in pair:
                    k, v = pair.strip().split("=", 1)
                    cookies[k] = v
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
    else:
        cfg.webhook_url = args.webhook
        cfg.send_webhook = bool(args.webhook)
    cfg.out_dir = args.out
    cfg.cookies.update(_parse_cookies(args.cookie))
    cfg.headers.update(_parse_headers(args.header))
    cfg.proxy = args.proxy
    cfg.insecure = args.insecure
    cfg.job_timeout = args.job_timeout
    cfg.abort_after = args.abort_after
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

    engine = ScanEngine(cfg)
    result = engine.run()

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
              fallback_path=os.path.join(cfg.out_dir, "webhook_unsent.json"))

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
    result = verify_from_json(args.json, cfg)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


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

