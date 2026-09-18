#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""BCP/1 mock external signer (command + loopback HTTPS).

Speaks the existing `-signer` argv protocol (enumerate / getdescriptors /
getp2mrpubkeys / displayaddress / signtx) plus SignerProvider methods:
health, getpubkey, derivepubkey (UNSUPPORTED for public children), signdigest.

ML-DSA-44 cannot do Bitcoin-style non-hardened public child derivation.
Canonical seed-side path: m/87h / coin_typeh / accounth / branch / index
(branch 0 = deposit, 1 = change). Signatures are deterministic stubs sized
like ML-DSA-44; they are not live custody keys.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

FINGERPRINT = "00000001"
MLDSA44_PUBKEY_SIZE = 1312
MLDSA44_SIGNATURE_SIZE = 2420
SLHDSA128S_PUBKEY_SIZE = 32
PROFILE = "BTX_EXCHANGE_PROFILE_V1"
UNSUPPORTED_PUBLIC_CHILD = (
    "ML-DSA-44 cannot do Bitcoin-style non-hardened public child derivation; "
    "derive from the master seed on the signer and export pubkeys "
    "(getp2mrpubkeys / importdepositpool)"
)


def _expand(label: str, size: int) -> bytes:
    out = bytearray()
    i = 0
    seed = label.encode("utf-8")
    while len(out) < size:
        out.extend(hashlib.sha256(seed + i.to_bytes(4, "big")).digest())
        i += 1
    return bytes(out[:size])


def _emit(obj) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")))


def _path_for(branch: int, index: int, coin_type: int = 1, account: int = 0) -> str:
    return f"m/87h/{coin_type}h/{account}h/{branch}/{index}"


def perform_pre_checks() -> None:
    mock_result_path = os.path.join(os.getcwd(), "mock_result")
    if os.path.isfile(mock_result_path):
        with open(mock_result_path, "r", encoding="utf8") as f:
            mock_result = f.read()
        if mock_result and mock_result[0]:
            sys.stdout.write(mock_result[2:])
            sys.exit(int(mock_result[0]))


def enumerate_cmd(_args) -> None:
    _emit([{
        "fingerprint": FINGERPRINT,
        "type": "command",
        "model": "bcp1_mock",
        "name": "bcp1_mock",
        "capabilities": {
            "p2mr": True,
            "pq_algorithms": ["ml_dsa_44", "slh_dsa_128s"],
            "public_child_derivation": False,
            "profile": PROFILE,
        },
    }])


def getdescriptors(args) -> None:
    # Existing -signer import path. Default monetary tree is two-leaf
    # mr(pqhd(...), pk_slh(pqhd(...))). Fingerprint-only pqhd() still cannot
    # mint public ML-DSA children; getpubkey / importdepositpool supply the
    # concrete pubkeys.
    receive_key = f"pqhd({FINGERPRINT}/1h/0h/0/*)"
    internal_key = f"pqhd({FINGERPRINT}/1h/0h/1/*)"
    _emit({
        "receive": [f"mr({receive_key},pk_slh({receive_key}))"],
        "internal": [f"mr({internal_key},pk_slh({internal_key}))"],
    })


def getp2mrpubkeys(args) -> None:
    if args.fingerprint and args.fingerprint != FINGERPRINT:
        _emit({"error": "Unexpected fingerprint", "fingerprint": args.fingerprint})
        return
    if args.desc is None or args.index is None:
        _emit({"error": "Missing descriptor/index"})
        return
    index = str(args.index)
    slh = hashlib.sha256(f"{args.desc}|{index}|0|slh_dsa_128s".encode("utf-8")).digest()
    mldsa = _expand(f"{args.desc}|{index}|ml_dsa_44", MLDSA44_PUBKEY_SIZE)
    _emit({
        "entries": [
            {"expr_index": 0, "algo": "slh_dsa_128s", "pubkey": slh.hex()},
            {"expr_index": 1, "algo": "ml_dsa_44", "pubkey": mldsa.hex()},
        ],
    })


def displayaddress(args) -> None:
    if args.fingerprint and args.fingerprint != FINGERPRINT:
        _emit({"error": "Unexpected fingerprint", "fingerprint": args.fingerprint})
        return
    digest = hashlib.sha256((args.desc or "").encode("utf-8")).hexdigest()[:32]
    _emit({"address": f"btxrt1zmock{digest}"})


def signtx(args) -> None:
    if args.fingerprint and args.fingerprint != FINGERPRINT:
        _emit({"error": "Unexpected fingerprint", "fingerprint": args.fingerprint})
        return
    mock_psbt_path = os.path.join(os.getcwd(), "mock_psbt")
    if os.path.isfile(mock_psbt_path):
        with open(mock_psbt_path, "r", encoding="utf8") as f:
            mock_psbt = f.read().strip()
        _emit({"psbt": mock_psbt, "complete": True})
        return
    _emit({"psbt": args.psbt, "complete": False})


def health(args) -> None:
    chain = args.chain or "regtest"
    _emit({
        "ok": True,
        "fingerprint": FINGERPRINT,
        "profile": PROFILE,
        "network": chain,
        "algorithms": ["ML-DSA-44", "SLH-DSA-128s"],
        "pq_algorithms": ["ml_dsa_44", "slh_dsa_128s"],
        "p2mr": True,
        "public_child_derivation": False,
        "path": "m/87h/coin_typeh/accounth/branch/index",
    })


def getpubkey(args) -> None:
    path = args.path or _path_for(0, 0)
    algo_raw = getattr(args, "algo", None) or getattr(args, "algorithm", None) or "ml_dsa_44"
    algo = str(algo_raw).replace("-", "_").lower()
    if "slh" in algo:
        size = SLHDSA128S_PUBKEY_SIZE
        wire = "slh_dsa_128s"
        pretty = "SLH-DSA-128s"
    else:
        size = MLDSA44_PUBKEY_SIZE
        wire = "ml_dsa_44"
        pretty = "ML-DSA-44"
    pubkey = _expand(f"getpubkey|{path}|{wire}", size)
    _emit({
        "pubkey": pubkey.hex(),
        "path": path,
        "algo": wire,
        "algorithm": pretty,
        "fingerprint": FINGERPRINT,
    })


def derivepubkey(_args) -> None:
    _emit({
        "error": "UNSUPPORTED",
        "code": "UNSUPPORTED",
        "reason": UNSUPPORTED_PUBLIC_CHILD,
    })


def signdigest(args) -> None:
    digest = args.digest or ""
    path = args.path or _path_for(0, 0)
    algo = (args.algo or "ml_dsa_44").replace("-", "_").lower()
    if "slh" in algo:
        size = 7856
        wire_algo = "slh_dsa_128s"
        pretty = "SLH-DSA-128s"
    else:
        size = MLDSA44_SIGNATURE_SIZE
        wire_algo = "ml_dsa_44"
        pretty = "ML-DSA-44"
    signature = _expand(f"signdigest|{path}|{digest}|{wire_algo}", size)
    _emit({
        "signature": signature.hex(),
        "algo": wire_algo,
        "algorithm": pretty,
        "digest": digest,
        "path": path,
        "fingerprint": FINGERPRINT,
        "stub": True,
    })


def _provider_dispatch(method: str, params: dict) -> dict:
    method = method.replace("-", "_").lower().strip("/")
    aliases = {
        "health": "health",
        "get_public_key": "getpubkey",
        "getpublickey": "getpubkey",
        "getpubkey": "getpubkey",
        "derive_public_key": "derivepubkey",
        "derivepublickey": "derivepubkey",
        "derivepubkey": "derivepubkey",
        "sign_digest": "signdigest",
        "signdigest": "signdigest",
        "enumerate": "enumerate",
    }
    mapped = aliases.get(method)
    if mapped is None:
        return {"error": f"unknown method {method}"}
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        ns = argparse.Namespace(
            fingerprint=params.get("fingerprint", FINGERPRINT),
            chain=params.get("chain", "regtest"),
            account=params.get("account", "0"),
            desc=params.get("desc"),
            index=params.get("index"),
            path=params.get("path"),
            digest=params.get("digest"),
            algo=params.get("algorithm") or params.get("algo"),
            psbt=params.get("psbt"),
        )
        {
            "health": health,
            "getpubkey": getpubkey,
            "derivepubkey": derivepubkey,
            "signdigest": signdigest,
            "enumerate": enumerate_cmd,
        }[mapped](ns)
    finally:
        sys.stdout = old
    raw = buf.getvalue()
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {"raw": raw}


class SignerHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: A003
        sys.stderr.write("[mock-signer] " + (fmt % args) + "\n")

    def _send(self, code: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path in ("/", "/health"):
            self._send(200, _provider_dispatch("health", {"chain": "regtest"}))
            return
        if path == "/events":
            events = getattr(self.server, "events", [])
            self._send(200, {"events": events})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        body = self._read_json()
        if path == "/event":
            events = getattr(self.server, "events", None)
            if events is None:
                self.server.events = []
                events = self.server.events
            events.append(body)
            self._send(200, {"ok": True, "stored": len(events)})
            return
        method = body.get("method") if isinstance(body.get("method"), str) else path.strip("/")
        params = body.get("params") if isinstance(body.get("params"), dict) else body
        if not method or method == "event":
            self._send(400, {"error": "missing method"})
            return
        result = _provider_dispatch(method, params)
        code = 200
        if isinstance(result, dict) and str(result.get("error", "")).startswith("unknown"):
            code = 404
        self._send(code, result)


def serve(bind: str, webhook: bool) -> None:
    if ":" in bind:
        host, port_s = bind.rsplit(":", 1)
        port = int(port_s)
    else:
        host, port = "127.0.0.1", int(bind)
    httpd = ThreadingHTTPServer((host, port), SignerHandler)
    httpd.events = []
    kind = "webhook" if webhook else "signer"
    sys.stderr.write(f"BCP/1 mock {kind} listening on {host}:{port}\n")
    httpd.serve_forever()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mock_signer.py",
        description=(
            "BCP/1 mock external signer: argv -signer protocol, SignerProvider JSON "
            "(health, getpubkey, derivepubkey, signdigest), loopback --http, and --webhook event sink."
        ),
    )
    parser.add_argument("--fingerprint", help="Expected device fingerprint (default 00000001)")
    parser.add_argument("--chain", default="regtest", help="Chain name for health responses")
    parser.add_argument("--stdin", action="store_true", help="Read JSON command from stdin when argv is empty")
    parser.add_argument("--http", metavar="HOST:PORT", help="Serve SignerProvider over loopback HTTP")
    parser.add_argument("--webhook", metavar="HOST:PORT", help="Serve a JSON event sink (POST /event)")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("enumerate", help="List mock signer devices")
    p.set_defaults(func=enumerate_cmd)

    p = sub.add_parser("getdescriptors", help="Return pqhd descriptors for -signer import")
    p.add_argument("--account", metavar="account")
    p.set_defaults(func=getdescriptors)

    p = sub.add_parser("getp2mrpubkeys", help="Return stub P2MR pubkeys for a descriptor index")
    p.add_argument("--desc", metavar="desc")
    p.add_argument("--index", metavar="index")
    p.set_defaults(func=getp2mrpubkeys)

    p = sub.add_parser("displayaddress", help="Return a mock bech32m display address")
    p.add_argument("--desc", metavar="desc")
    p.set_defaults(func=displayaddress)

    p = sub.add_parser("signtx", help="Stub PSBT signing for legacy -signer signtx")
    p.add_argument("psbt", nargs="?", default="")
    p.set_defaults(func=signtx)

    p = sub.add_parser("signtransaction", help="Alias for signtx")
    p.add_argument("psbt", nargs="?", default="")
    p.set_defaults(func=signtx)

    p = sub.add_parser("health", help="SignerProvider health probe")
    p.set_defaults(func=health)

    p = sub.add_parser("getpubkey", help="Export a PQ pubkey for a BIP-87 path")
    p.add_argument("--path")
    p.add_argument("--algo")
    p.add_argument("--algorithm")
    p.set_defaults(func=getpubkey)

    p = sub.add_parser("get_public_key", help="Alias for getpubkey")
    p.add_argument("--path")
    p.add_argument("--algo")
    p.add_argument("--algorithm")
    p.set_defaults(func=getpubkey)

    p = sub.add_parser("derivepubkey", help="Public child derivation (always UNSUPPORTED for ML-DSA-44)")
    p.add_argument("--path")
    p.set_defaults(func=derivepubkey)

    p = sub.add_parser("derive_public_key", help="Alias for derivepubkey")
    p.add_argument("--path")
    p.set_defaults(func=derivepubkey)

    p = sub.add_parser("signdigest", help="Return deterministic stub signature for a 32-byte digest")
    p.add_argument("--path")
    p.add_argument("--digest")
    p.add_argument("--algo")
    p.add_argument("--algorithm")
    p.set_defaults(func=signdigest)

    p = sub.add_parser("sign_digest", help="Alias for signdigest")
    p.add_argument("--path")
    p.add_argument("--digest")
    p.add_argument("--algo")
    p.add_argument("--algorithm")
    p.set_defaults(func=signdigest)

    return parser


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    # Existing ExternalSigner may pass leftover tokens via stdin.
    if not sys.stdin.isatty():
        buffer = sys.stdin.read()
        if buffer and buffer.rstrip() != "":
            stripped = buffer.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError:
                    payload = None
                if isinstance(payload, dict):
                    method = str(payload.get("command") or payload.get("method") or "signdigest")
                    params = payload.get("params") if isinstance(payload.get("params"), dict) else payload
                    _emit(_provider_dispatch(method, params))
                    return 0
            else:
                argv.extend(stripped.split(" "))

    args = parser.parse_args(argv)
    if args.http:
        serve(args.http, webhook=False)
        return 0
    if args.webhook:
        serve(args.webhook, webhook=True)
        return 0
    if not args.command:
        parser.print_help()
        return 2
    perform_pre_checks()
    if args.command in ("signdigest", "sign_digest", "getpubkey", "get_public_key") and getattr(args, "algorithm", None) and not getattr(args, "algo", None):
        args.algo = args.algorithm
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
