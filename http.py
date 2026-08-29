"""HTTP client wrapper: retries, rate limiting, redirects, proxies."""

from __future__ import annotations

import time
import threading
from typing import Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .logger import get_logger

log = get_logger()


class RateLimiter:
    def __init__(self, rate: float = 5.0):
        self.min_interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delta = self._last + self.min_interval - now
            if delta > 0:
                time.sleep(delta)
            self._last = time.monotonic()


class HttpClient:
    def __init__(self, config, headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None):
        self.cfg = config
        self.session = requests.Session()
        # Only idempotent methods are retried: a retried POST would duplicate
        # side effects and, for OOB tests, double-fire the canary callback.
        retry = Retry(total=2, backoff_factor=0.4,
                      status_forcelist=[429, 500, 502, 503, 504],
                      allowed_methods=["GET", "HEAD"])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        hdrs = dict(headers or {})
        hdrs.setdefault("User-Agent", "Sofia-XXE-Scanner/1.0 (security assessment)")
        self.session.headers.update(hdrs)
        if cookies:
            self.session.cookies.update(cookies)
        if config.proxy:
            self.session.proxies.update({"http": config.proxy, "https": config.proxy})
        if config.insecure:
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.limiter = RateLimiter(config.rate)

    def request(self, method: str, url: str, *, timeout: Optional[float] = None,
                allow_redirects: bool = False, max_redirects: int = 3,
                **kw) -> Tuple[int, str, Dict[str, str], float]:
        """Return (status_code, body_text, response_headers, elapsed)."""
        timeout = timeout or self.cfg.timeout
        self.limiter.wait()
        try:
            resp = self.session.request(
                method, url, timeout=timeout, allow_redirects=False, **kw
            )
            hops = 0
            while resp.is_redirect and allow_redirects and hops < max_redirects:
                loc = resp.headers.get("Location")
                if not loc:
                    break
                next_url = urljoin(url, loc)
                resp.close()
                resp = self.session.request(
                    method, next_url, timeout=timeout, allow_redirects=False, **kw
                )
                hops += 1
            body = resp.text
            return resp.status_code, body, dict(resp.headers), resp.elapsed.total_seconds()
        except requests.exceptions.SSLError as e:
            return 0, "", {}, 0.0
        except requests.exceptions.RequestException as e:
            log.debug(f"http error {method} {url}: {e}")
            return 0, "", {}, 0.0

    def get(self, url: str, **kw):
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw):
        return self.request("POST", url, **kw)

    def post_multipart(self, url: str, files=None, data=None, headers=None,
                       **kw):
        """POST with multipart/form-data encoding (file part + fields)."""
        return self.request("POST", url, files=files, data=data,
                            headers=headers or {}, **kw)

    def get_bytes(self, url: str, timeout: Optional[float] = None) -> Tuple[int, bytes]:
        timeout = timeout or self.cfg.timeout
        self.limiter.wait()
        try:
            resp = self.session.get(url, timeout=timeout, allow_redirects=False)
            return resp.status_code, resp.content
        except requests.exceptions.RequestException:
            return 0, b""

    def close(self):
        self.session.close()


def absolute(url: str, base: str) -> str:
    return urljoin(base, url) if url else base


def origin_of(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def is_same_origin(url: str, base: str) -> bool:
    return origin_of(url) == origin_of(base)


def norm_path(url: str) -> str:
    p = urlparse(url)
    path = p.path or "/"
    if not path.endswith("/"):
        path += "/"
    return f"{p.scheme}://{p.netloc}{path}"


