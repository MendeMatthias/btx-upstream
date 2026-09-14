#!/usr/bin/env python3
"""Poll an already-running second-process helper. Never starts or kills it.

Use this when a retrieve is in flight and the original poller must not be
allowed to SIGTERM the helper on timeout.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path

EXPECT_BYTES = 13888336427


def rpc(sock: Path, method, params, timeout):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode() + b"\n")
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    s.close()
    reply = json.loads(data.decode())
    if reply.get("error"):
        raise RuntimeError("%s: %s" % (method, reply["error"]))
    return reply["result"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sock", required=True)
    ap.add_argument("--timeout", type=float, default=28800)
    ap.add_argument("--expect-bytes", type=int, default=EXPECT_BYTES)
    args = ap.parse_args()
    sock = Path(args.sock)
    if not sock.exists():
        raise SystemExit("missing helper socket %s" % sock)
    t0 = time.time()
    job = {}
    while time.time() - t0 < args.timeout:
        jobs = rpc(sock, "getmodeljob", [], 120)
        arr = jobs.get("jobs") or []
        if arr:
            job = arr[0]
            st = job.get("status")
            print(
                "job",
                st,
                "elapsed",
                int(time.time() - t0),
                "used_bytes",
                jobs.get("used_bytes"),
                "bytes_committed",
                job.get("bytes_committed"),
                "pieces",
                job.get("pieces_committed"),
                "file",
                job.get("file_index"),
                "piece",
                job.get("piece_index"),
                "inflight",
                job.get("inflight"),
                "retries",
                job.get("peer_retries"),
                "last_err",
                job.get("last_err") or job.get("error"),
                flush=True,
            )
            if st == "failed":
                raise SystemExit("retrieve failed: %s" % job)
            if st == "cancelled":
                raise SystemExit("retrieve cancelled: %s" % job)
            if st == "done":
                break
        time.sleep(2)
    else:
        raise SystemExit("getmodeljob timeout: %s" % job)
    listed = rpc(sock, "listmodels", [], 30)
    models = listed.get("models") or []
    if not models:
        raise SystemExit("listmodels empty: %s" % listed)
    m = models[0]
    if int(m.get("bytes") or 0) != args.expect_bytes:
        raise SystemExit("bytes %s != %s" % (m.get("bytes"), args.expect_bytes))
    if m.get("seeded") is not True:
        raise SystemExit("not demand-seeded: %s" % listed)
    if m.get("content_admission") not in ("BYTES_VERIFIED",) and m.get("bytes_verified") is not True:
        raise SystemExit("admission: %s" % listed)
    print("GRANITE_ATTACH PASS", json.dumps({
        "bytes": m.get("bytes"),
        "seeded": m.get("seeded"),
        "content_admission": m.get("content_admission"),
        "elapsed_poll_s": int(time.time() - t0),
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
