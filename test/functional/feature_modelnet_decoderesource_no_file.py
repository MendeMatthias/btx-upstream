#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""decoderesource parses its argument and never opens a file named by it.

btxd's own decoderesource is a pure parse. The helper's decoderesource,
and decoderesourceuri (documented as its alias, "pure local parse"), used
to open any regular file the argument named and decode the first btx://
link inside it. A UI that validates user input with decoderesource then
made the helper read local files. The share-card openers (openbtxuri,
openmodelshare) and getmodel keep reading .btx cards.
"""

import json
import os
import socket
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, get_datadir_path


class ModelnetDecodeResourceNoFileTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-modelnet=1", "-modelbind=off", "-modelstorage=8MiB"]]

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        exeext = self.config["environment"].get("EXEEXT", "")
        builddir = self.config["environment"].get("BUILDDIR", "")
        candidates = [Path(builddir) / "bin" / f"btx-modeld{exeext}"]
        bitcoind = getattr(self.options, "bitcoind", None)
        if bitcoind:
            candidates.append(Path(bitcoind).resolve().parent / f"btx-modeld{exeext}")
        if not any(c.is_file() and os.access(c, os.X_OK) for c in candidates):
            raise SkipTest("btx-modeld not found")

    def _helper(self, method, params):
        sock_path = Path(get_datadir_path(self.options.tmpdir, 0)) / self.chain / "modelnet" / "modeld.sock"
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(30)
        try:
            s.connect(str(sock_path))
            s.sendall((json.dumps({"jsonrpc": "1.0", "id": "t", "method": method, "params": params}) + "\n").encode())
            s.shutdown(socket.SHUT_WR)
            buf = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        finally:
            s.close()
        return json.loads(buf)

    def run_test(self):
        node = self.nodes[0]

        def ready():
            try:
                return bool(node.getmodelnetworkinfo().get("helper_ready"))
            except JSONRPCException:
                return False
        self.wait_until(ready, timeout=60)

        uri = node.encoderesource("MODEL", "ab" * 48)
        card_uri = node.encoderesource("MODEL", "cd" * 48)
        files = Path(self.options.tmpdir) / "files"
        files.mkdir()
        link = files / "notes.txt"
        link.write_text(f"local notes {uri} more notes\n", encoding="utf-8")
        card = files / "model.btx"
        card.write_text(json.dumps({"uri": card_uri}) + "\n", encoding="utf-8")

        self.log.info("A URI still decodes")
        assert_equal(node.decoderesourceuri(uri)["uri"], uri)
        assert_equal(self._helper("decoderesource", [uri])["result"]["uri"], uri)

        self.log.info("A path is not opened by decoderesource or decoderesourceuri")
        for name in ("decoderesource", "decoderesourceuri"):
            try:
                getattr(node, name)(str(link))
                raise AssertionError(f"{name} must not decode a file's contents")
            except JSONRPCException as exc:
                # v0.35 passes the helper's refusal through as -8. v0.34.15's
                # btxd relabels it "model helper unavailable" (-1), with the
                # helper's INVALID_PARAMETER inside the message.
                code = exc.error["code"]
                assert code == -8 or (code == -1 and "INVALID_PARAMETER" in exc.error["message"]), exc.error
        for method in ("decoderesource", "decoderesourceuri"):
            reply = self._helper(method, [str(link)])
            assert reply.get("result") is None, reply
            assert_equal(reply["error"]["code"], "INVALID_PARAMETER")

        self.log.info("Share-card openers and getmodel still read a .btx card")
        assert_equal(node.openmodelshare(str(card))["uri"], card_uri)
        assert_equal(node.openbtxuri(str(card))["uri"], card_uri)
        assert_equal(node.getmodel(str(card), "FREE_ONLY")["uri"], card_uri)


if __name__ == "__main__":
    ModelnetDecodeResourceNoFileTest(__file__).main()
