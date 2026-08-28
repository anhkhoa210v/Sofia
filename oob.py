"""Out-of-band (OOB) callback server.

Routes (all served on 127.0.0.1:<port>, exposed via Cloudflare tunnel when used):
  GET  /probe/{cid}          - external entity fetch probe
  GET  /dtd/{cid}.dtd        - attacker-hosted DTD (built from target)
  GET  /x/{cid}?d=<data>     - exfil channel (GET, query param d)
  POST /x/{cid}              - exfil channel (POST body)
  GET  /beat                 - health / liveness
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from .logger import get_logger

log = get_logger()


def new_canary() -> str:
    return uuid.uuid4().hex[:10]


class OOBServer:
    def __init__(self, port: int = 17888, host: str = "127.0.0.1"):
        self.port = port
        self.host = host
        self.hits: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._dtds: Dict[str, str] = {}
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.base_url = f"http://{host}:{port}"

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> bool:
        if self._httpd:
            return True
        try:
            handler = self._make_handler()
            self._httpd = ThreadingHTTPServer((self.host, self.port), handler)
            self._thread = threading.Thread(target=self._httpd.serve_forever,
                                            daemon=True,
                                            name="sofia-oob")
            self._thread.start()
            log.info(f"OOB server listening on {self.base_url}")
            return True
        except OSError as e:
            log.error(f"cannot bind OOB server on {self.host}:{self.port}: {e}")
            self._httpd = None
            return False

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread:
            self._thread = None

    # -- content -----------------------------------------------------------

    def register_dtd(self, cid: str, content: str):
        with self._lock:
            self._dtds[cid] = content

    def hits_for(self, cid: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [h for h in self.hits if h.get("cid") == cid]

    def all_hits(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.hits)

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            by_cid: Dict[str, int] = {}
            for h in self.hits:
                by_cid[h["cid"]] = by_cid.get(h["cid"], 0) + 1
            return {"total_hits": len(self.hits), "by_cid": by_cid}

    # -- urls --------------------------------------------------------------

    def url(self, path: str, cid: str = "") -> str:
        return f"{self.base_url}/{path}/{cid}" if cid else f"{self.base_url}/{path}"

    def probe_url(self, cid: str) -> str:
        return self.url("probe", cid)

    def dtd_url(self, cid: str) -> str:
        return self.url("dtd", cid) + ".dtd"

    def exfil_url(self, cid: str) -> str:
        return self.url("x", cid)

    # -- internals ---------------------------------------------------------

    def _make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):  # silence default logging
                pass

            def _record(self, cid: str = "", extra: str = ""):
                entry = {
                    "time": time.time(),
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "cid": cid,
                    "path": self.path,
                    "method": self.command,
                    "headers": dict(self.headers),
                    "extra": extra,
                }
                with server._lock:
                    server.hits.append(entry)

            def _send(self, code: int, body: bytes, ctype: str = "text/plain"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path
                cid = ""
                if path.startswith("/probe/"):
                    cid = path.rsplit("/", 1)[-1]
                    self._record(cid)
                    self._send(200, b"probe-ok\n")
                elif path.startswith("/dtd/"):
                    cid = path.split("/")[-1].replace(".dtd", "")
                    with server._lock:
                        dtd = server._dtds.get(cid, "")
                    if dtd:
                        self._record(cid, "dtd-served")
                        self._send(200, dtd.encode("utf-8"),
                                   "application/xml-dtd")
                    else:
                        self._record(cid, "dtd-missing")
                        self._send(404, b"not found\n")
                elif path.startswith("/x/"):
                    cid = path.rsplit("/", 1)[-1]
                    q = parse_qs(parsed.query)
                    data = (q.get("d", [""])[0] or "").encode("utf-8", "replace")
                    self._record(cid, f"exfil:len={len(data)}")
                    self._send(200, b"ok\n")
                elif path == "/beat":
                    self._record("beat")
                    self._send(200, b"beat\n")
                else:
                    self._record("unknown")
                    self._send(404, b"not found\n")

            def do_POST(self):
                parsed = urlparse(self.path)
                if parsed.path.startswith("/x/"):
                    cid = parsed.path.rsplit("/", 1)[-1]
                    try:
                        length = int(self.headers.get("Content-Length", 0))
                    except ValueError:
                        length = 0
                    body = self.rfile.read(length) if length > 0 else b""
                    self._record(cid, f"exfil-post:len={len(body)}")
                    self._send(200, b"ok\n")
                else:
                    self._record("unknown-post")
                    self._send(404, b"not found\n")

        return Handler

