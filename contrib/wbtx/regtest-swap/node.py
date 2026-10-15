"""A throwaway regtest btxd for the HTLC tests: start, JSON-RPC, stop.

Each node gets its own data folder and ports on 127.0.0.1 only. The regtest
arguments are upstream's own (test/functional/wallet_htlc_atomicswap.py): the
MatMul heights pushed out of reach, so a CPU-only node mines past height 100.
"""
import base64
import json
import os
import shutil
import subprocess
import time
import urllib.request

REGTEST_ARGS = [
    "-regtest", "-server", "-txindex=1", "-fallbackfee=0.0001",
    "-autoshieldcoinbase=0", "-modelbind=off",
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
    "-dnsseed=0", "-fixedseeds=0", "-discover=0", "-upnp=0", "-natpmp=0",
]


class RpcError(Exception):
    def __init__(self, method, error):
        super().__init__(f"{method}: {error}")
        self.method, self.error = method, error
        self.code = error.get("code") if isinstance(error, dict) else None
        self.message = error.get("message", "") if isinstance(error, dict) else str(error)


class Node:
    def __init__(self, name, bindir, root, rpcport, port, extra=()):
        self.name, self.bindir, self.rpcport, self.port = name, bindir, rpcport, port
        self.datadir = os.path.join(root, name)
        self.extra = list(extra)
        self.proc = None

    def start(self):
        os.makedirs(self.datadir, exist_ok=True)
        args = [os.path.join(self.bindir, "btxd"), f"-datadir={self.datadir}",
                f"-rpcport={self.rpcport}", f"-port={self.port}", "-bind=127.0.0.1",
                "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", *REGTEST_ARGS, *self.extra]
        self.log = open(os.path.join(self.datadir, "stdout.log"), "ab")
        self.proc = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(300):
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.name} exited with {self.proc.returncode}: "
                                   + open(os.path.join(self.datadir, "stdout.log")).read()[-800:])
            try:
                self.call("getblockcount")
                return self
            except Exception:
                time.sleep(0.2)
        raise RuntimeError(f"{self.name} did not answer")

    def _auth(self):
        cookie = open(os.path.join(self.datadir, "regtest", ".cookie")).read().strip()
        return "Basic " + base64.b64encode(cookie.encode()).decode()

    def call(self, method, *params, wallet=None, timeout=300):
        url = f"http://127.0.0.1:{self.rpcport}/" + (f"wallet/{wallet}" if wallet else "")
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(url, data=body, headers={"Authorization": self._auth(),
                                                               "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                d = json.load(r)
        except urllib.error.HTTPError as e:
            d = json.load(e)
        if d.get("error"):
            raise RpcError(method, d["error"])
        return d["result"]

    def w(self, wallet):
        return lambda method, *params: self.call(method, *params, wallet=wallet)

    def version(self):
        return self.call("getnetworkinfo")["subversion"]

    def stop(self):
        if not self.proc:
            return
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None
