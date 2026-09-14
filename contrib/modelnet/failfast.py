#!/usr/bin/env python3
"""Fail-fast helpers for modeld e2e. Stop polling once a failure is already known."""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Callable, Optional

LOG_FATAL = (
    "unknown argument",
    "model subsystem fail-closed",
    "invalid -model",
    "terminate called",
    "Aborted (",
)


def pid_alive(pid: Optional[int]) -> bool:
    if not pid:
        return True
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


def log_tail(log: Optional[Path], n: int = 4000) -> str:
    if not log:
        return ""
    p = Path(log)
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")[-n:]


def helper_fatal(proc=None, pid: Optional[int] = None, log: Optional[Path] = None) -> Optional[str]:
    if proc is not None and proc.poll() is not None:
        return f"helper exited rc={proc.returncode}\n{log_tail(log)}"
    if pid and not pid_alive(pid):
        return f"helper pid {pid} is gone\n{log_tail(log)}"
    txt = log_tail(log, 8000)
    for needle in LOG_FATAL:
        if needle in txt:
            return f"helper log contains {needle!r}\n{txt[-2000:]}"
    return None


def wait_unix(
    connect: Callable[[], Any],
    *,
    timeout: float = 20.0,
    interval: float = 0.1,
    proc=None,
    pid: Optional[int] = None,
    log: Optional[Path] = None,
):
    """Retry connect() until it returns non-None. Abort at once if the helper is already dead."""
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        fatal = helper_fatal(proc=proc, pid=pid, log=log)
        if fatal:
            raise SystemExit(fatal)
        try:
            info = connect()
            if info is not None:
                return info
        except Exception as e:
            last = e
        time.sleep(interval)
    raise SystemExit(f"helper not ready in {timeout}s last={last}\n{log_tail(log)}")


def poll_job(
    fetch: Callable[[], Any],
    *,
    timeout: float,
    interval: float = 0.2,
    progress: Optional[Callable[[Any], None]] = None,
) -> dict:
    """Poll getmodeljob. status=failed/cancelled exits immediately (no remaining timeout)."""
    t0 = time.time()
    job: dict = {}
    while time.time() - t0 < timeout:
        raw = fetch()
        if isinstance(raw, dict):
            arr = raw.get("jobs")
            if arr:
                job = arr[0]
            elif raw.get("status"):
                job = raw
        if job:
            st = job.get("status")
            if progress:
                progress(job)
            if st == "failed":
                raise SystemExit(f"retrieve failed: {job}")
            if st == "cancelled":
                raise SystemExit(f"retrieve cancelled: {job}")
            if st == "done":
                return job
        time.sleep(interval)
    raise SystemExit(f"getmodeljob timeout: {job}")
