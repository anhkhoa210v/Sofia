"""Cloudflare quick tunnel (cloudflared) management.

Spawns `cloudflared tunnel --url http://127.0.0.1:<port>` and parses the
trycloudflare.com URL from its logs. Degrades gracefully to localhost when
the binary is missing.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from typing import Optional

from .logger import get_logger

log = get_logger()

_TUNNEL_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")


def find_cloudflared() -> Optional[str]:
    for candidate in ("cloudflared",
                      shutil.which("cloudflared"),
                      "/usr/local/bin/cloudflared",
                      "/home/codespace/.local/bin/cloudflared",
                      "/home/codespace/.cloudflared/cloudflared"):
        if candidate and shutil.which(candidate):
            return shutil.which(candidate)
        if candidate and candidate.startswith("/") and __import__("os").path.exists(candidate):
            return candidate
    return None


class Tunnel:
    def __init__(self, url: str, process: subprocess.Popen):
        self.url = url
        self.process = process

    def stop(self):
        try:
            if self.process and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
        except Exception:
            pass


def start_tunnel(oob_port: int, binary: Optional[str] = None,
                 wait: float = 30.0) -> Optional[Tunnel]:
    binary = binary or find_cloudflared()
    if not binary:
        log.warn("cloudflared binary not found - falling back to localhost OOB "
                 "(no external callback URL)")
        return None
    try:
        proc = subprocess.Popen(
            [binary, "tunnel", "--url", f"http://127.0.0.1:{oob_port}",
             "--no-autoupdate", "--loglevel", "info"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except OSError as e:
        log.warn(f"failed to launch cloudflared: {e} - localhost fallback")
        return None

    deadline = time.monotonic() + wait
    seen = ""
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            continue
        seen += line
        m = _TUNNEL_RE.search(line)
        if m:
            url = m.group(0)
            log.info(f"Cloudflare tunnel ready: {url}")
            return Tunnel(url, proc)
        if "error" in line.lower() and "quic" not in line.lower():
            log.debug(f"cloudflared: {line.strip()}")
    log.warn("cloudflared did not provide a tunnel URL in time - localhost fallback")
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        pass
    return None

