"""Console + file logger for Sofia."""

import os
import sys
import threading
from datetime import datetime

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"

_LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40, "critical": 50}


class Logger:
    def __init__(self, name="sofia", level="info", log_file=None, use_color=None):
        self.name = name
        self.level = _LEVELS.get(level, 20)
        if use_color is None:
            use_color = os.environ.get("NO_COLOR") is None and sys.stdout.isatty()
        self.use_color = use_color
        self._lock = threading.Lock()
        self._file = None
        if log_file:
            os.makedirs(os.path.dirname(os.path.abspath(log_file)) or ".", exist_ok=True)
            self._file = open(log_file, "a", encoding="utf-8")

    def _fmt(self, level, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        return f"{ts} [{level.upper():<4}] {msg}"

    def _emit(self, level, msg):
        if _LEVELS[level] < self.level:
            return
        line = self._fmt(level, msg)
        color = {
            "debug": DIM, "info": CYAN, "warn": YELLOW,
            "error": RED, "critical": RED + BOLD,
        }.get(level, "")
        with self._lock:
            if self.use_color:
                print(f"{color}{line}{RESET}", file=sys.stderr)
            else:
                print(line, file=sys.stderr)
            if self._file:
                self._file.write(line + "\n")
                self._file.flush()

    def debug(self, msg):
        self._emit("debug", msg)

    def info(self, msg):
        self._emit("info", msg)

    def warn(self, msg):
        self._emit("warn", msg)

    def error(self, msg):
        self._emit("error", msg)

    def exception(self, msg):
        """Log msg at error level with the current traceback appended."""
        import traceback
        tb = traceback.format_exc().strip()
        self._emit("error", f"{msg}\n{tb}" if tb else msg)

    def critical(self, msg):
        self._emit("critical", msg)

    def section(self, msg):
        self._emit("info", f"{BOLD}== {msg} =={RESET}" if self.use_color else f"== {msg} ==")

    def close(self):
        if self._file:
            self._file.close()
            self._file = None


_LOGGER = None


def get_logger(name="sofia", **kw):
    """Return a process-wide singleton logger (configurable on first call)."""
    global _LOGGER
    if _LOGGER is None:
        _LOGGER = Logger(name, **kw)
    return _LOGGER


def reconfigure(**kw):
    """Reconfigure the singleton in place so existing module refs see it."""
    global _LOGGER
    name = kw.pop("name", "sofia")
    if _LOGGER is None:
        _LOGGER = Logger(name, **kw)
        return _LOGGER
    level = kw.pop("level", "info")
    use_color = kw.pop("use_color", None)
    log_file = kw.pop("log_file", None)
    _LOGGER.level = _LEVELS.get(level, 20)
    if use_color is not None:
        _LOGGER.use_color = use_color
    if log_file:
        if _LOGGER._file:
            _LOGGER._file.close()
        os.makedirs(os.path.dirname(os.path.abspath(log_file)) or ".",
                    exist_ok=True)
        _LOGGER._file = open(log_file, "a", encoding="utf-8")
    return _LOGGER



