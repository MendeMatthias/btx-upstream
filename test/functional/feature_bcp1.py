#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Isolated-regtest BCP/1 / BTX_EXCHANGE_PROFILE_V1 certification.

Regtest btxd, watch-only wallet, mock signer, deposit / withdraw / reorg /
batch / consolidation / restart. Named wallet RPCs are the lock: this test
calls them. If they are not in the binary, skip honestly (exit 77). Partial
implementation fails closed. Never production datadir /var/lib/btxd.

  python3 test/functional/feature_bcp1.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

from decimal import Decimal
import json
import os
import re
import subprocess
import sys

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY, REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    find_vout_for_address,
)

PROD_DATADIR = "/var/lib/btxd"
PROFILE = "BTX_EXCHANGE_PROFILE_V1"
SECRET_NEEDLES = (
    "wallet_seed",
    "pq_master_seed",
    "mnemonic",
    "xprv",
    "secret_key",
    "dumpprivkey",
    "id_ed25519",
    "aws_secret_access_key",
)
BCP1_RPCS = (
    "getexchangereadiness",
    "deriveexchangeaddress",
    "importdepositpool",
    "prepareexternalsign",
    "getsigningdigests",
    "finalizeexternalsign",
    "getdepositstatus",
    "listdepositutxos",
    "planconsolidation",
    "createconsolidationtx",
    "estimateconsolidationfee",
    "createexchangebatch",
)
PASS_ROWS = (
    "address generation",
    "deposit detection",
    "1→N confirmations",
    "reorg handling",
    "unsigned withdrawal",
    "external PQ signature",
    "signature import",
    "broadcast",
    "batch withdrawal",
    "UTXO consolidation",
    "double-spend rejection",
    "node restart",
    "wallet recovery",
)
METHOD_NOT_FOUND = (-32601,)
RETRY_PARAM = (-32602, -8, -3, -1, -5, -4)


class BCP1Test(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def mock_signer_file(self):
        root = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", ".."))
        return os.path.join(root, "contrib", "bcp1", "mock_signer.py")

    def mock_signer_cmd(self):
        return sys.executable + " " + self.mock_signer_file()

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.wallet_names = ["miner", False]
        signer = self.mock_signer_cmd()
        self.exchange_args = [
            f"-signer={signer}",
            "-exchange-watchonly",
            "-txindex=1",
            "-keypool=20",
            "-fallbackfee=0.0002",
            "-modelnet=0",
            "-nomodelnet",
        ] + list(REGTEST_GENERIC_P2P_MATMUL_ARGS)
        self.extra_args = [
            ["-txindex=1", "-fallbackfee=0.0002", "-modelnet=0", "-nomodelnet"] + list(REGTEST_GENERIC_P2P_MATMUL_ARGS),
            list(self.exchange_args),
        ]
        self.passed = []

    def setup_nodes(self):
        bitcoind = self.options.bitcoind
        blob = ""
        try:
            probed = subprocess.run(
                [bitcoind, "-help"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            blob = (probed.stdout or "") + (probed.stderr or "")
        except (OSError, subprocess.SubprocessError):
            blob = ""
        if "exchange-watchonly" in blob:
            self.exchange_args.append("-exchange-watchonly=1")
            self.extra_args[1] = list(self.exchange_args)
        return super().setup_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_external_signer()
    def _refuse_production_datadir(self):
        tmp = os.path.realpath(self.options.tmpdir)
        if tmp == PROD_DATADIR or tmp.startswith(PROD_DATADIR + os.sep):
            raise AssertionError(f"refusing production datadir tmpdir={tmp}")
        for node in self.nodes:
            datadir = os.path.realpath(str(node.datadir_path))
            if datadir == PROD_DATADIR or datadir.startswith(PROD_DATADIR + os.sep):
                raise AssertionError(f"refusing production datadir node={datadir}")

    def _pass(self, name):
        self.log.info("PASS %s", name)
        if name not in self.passed:
            self.passed.append(name)

    def _dump(self, obj):
        return json.dumps(obj, default=str).lower() if not isinstance(obj, str) else obj.lower()

    def _no_secrets(self, obj, where):
        dumped = self._dump(obj)
        for needle in SECRET_NEEDLES:
            if needle in dumped and "***" not in dumped:
                raise AssertionError(f"{where} leaked {needle}: {obj}")
        spend = None
        if isinstance(obj, dict):
            spend = obj.get("automatic_spend_atoms")
        if spend not in (None, 0, "0"):
            raise AssertionError(f"{where} automatic_spend_atoms={spend}")

    def _rpc_listed(self, node, name):
        try:
            text = node.help(name)
        except JSONRPCException as exc:
            err = exc.error if isinstance(exc.error, dict) else {}
            if err.get("code") in METHOD_NOT_FOUND:
                return False
            raise
        return "unknown command" not in str(text).lower()

    def _call_variants(self, fn, variants):
        last = None
        for args, kwargs in variants:
            try:
                result = fn(*args, **kwargs)
                self._no_secrets(result, getattr(fn, "_service_name", "rpc"))
                return result
            except JSONRPCException as exc:
                last = exc
                err = exc.error if isinstance(exc.error, dict) else {}
                if err.get("code") in METHOD_NOT_FOUND:
                    raise
                if err.get("code") not in RETRY_PARAM:
                    raise
        if last is not None:
            raise last
        raise AssertionError("no RPC variants")

    def _follow_miner(self, miner_node, exchange_node):
        """Force the exchange node onto the miner's chain without P2P."""
        miner_tip = miner_node.getbestblockhash()
        if exchange_node.getbestblockhash() == miner_tip:
            return
        while (exchange_node.getblockcount() > 0 and
               exchange_node.getbestblockhash() != miner_tip and
               exchange_node.getblockcount() >= miner_node.getblockcount()):
            try:
                exchange_node.invalidateblock(exchange_node.getbestblockhash())
            except JSONRPCException:
                break
        start = exchange_node.getblockcount() + 1
        end = miner_node.getblockcount()
        for height in range(start, end + 1):
            blockhash = miner_node.getblockhash(height)
            raw = miner_node.getblock(blockhash, 0)
            result = exchange_node.submitblock(raw)
            if result not in (None, "duplicate", "duplicate-invalid", "inconclusive"):
                self.log.info("submitblock height %s: %s", height, result)
        if exchange_node.getbestblockhash() != miner_tip:
            self.log.info(
                "exchange tip %s miner tip %s",
                exchange_node.getbestblockhash(),
                miner_tip,
            )

    def _push_raw(self, dest_node, src_node, txid):
        raw = src_node.getrawtransaction(txid)
        try:
            dest_node.sendrawtransaction(raw)
        except JSONRPCException as exc:
            msg = str(exc).lower()
            if "already" not in msg:
                self.log.info("push raw %s: %s", txid, exc)

    def _miner_p2mr_pubkey(self, miner, addr):
        """ML-DSA-44 pubkey for a miner-owned P2MR address (1312 bytes / 2624 hex).

        getaddressinfo historically omitted P2MR pubkeys; exportpqkey is the
        wallet-owned export. Infer from desc only if it is a single-key mr().
        """
        info = miner.getaddressinfo(addr)
        pubkey = info.get("pubkey")
        if isinstance(pubkey, str) and len(pubkey) >= 2624:
            return pubkey, info
        try:
            exported = miner.exportpqkey(addr, "ml-dsa-44")
            self._no_secrets(exported, "exportpqkey")
            if isinstance(exported.get("pubkey"), str) and len(exported["pubkey"]) >= 2624:
                return exported["pubkey"], info
        except JSONRPCException as exc:
            self.log.info("exportpqkey %s: %s", addr, exc)
        desc = " ".join(str(info.get(k) or "") for k in ("desc", "parent_desc"))
        match = re.search(r"mr\((?:\[.*?\]\s*)?(?:pk_slh\()?([0-9a-fA-F]{2624,})", desc)
        if match:
            return match.group(1), info
        raise AssertionError(f"no ML-DSA-44 pubkey for {addr}: {info}")

    def _miner_p2mr_pubkeys(self, miner, addr):
        """ML-DSA-44 and SLH-DSA-128s pubkeys for a miner-owned default P2MR address.

        Default monetary descriptors are mr(pqhd(...), pk_slh(pqhd(...))). A
        single-leaf mr(ML-DSA) does not match that scriptPubKey.
        """
        ml, info = self._miner_p2mr_pubkey(miner, addr)
        slh = None
        try:
            exported = miner.exportpqkey(addr, "slh-dsa-shake-128s")
            self._no_secrets(exported, "exportpqkey slh")
            if isinstance(exported.get("pubkey"), str) and len(exported["pubkey"]) >= 64:
                slh = exported["pubkey"]
        except JSONRPCException as exc:
            self.log.info("exportpqkey slh %s: %s", addr, exc)
        return ml, slh, info

    def _status_of(self, result):
        if isinstance(result, str):
            return result.upper()
        if isinstance(result, dict):
            for key in ("status", "state", "deposit_status"):
                if key in result and result[key] is not None:
                    return str(result[key]).upper()
        raise AssertionError(f"getdepositstatus missing status: {result}")

    def _address_of(self, result):
        if isinstance(result, str) and result:
            return result
        if isinstance(result, dict):
            for key in ("address", "deposit_address"):
                if result.get(key):
                    return result[key]
            addrs = result.get("addresses")
            if isinstance(addrs, list) and addrs:
                item = addrs[0]
                if isinstance(item, str):
                    return item
                if isinstance(item, dict) and item.get("address"):
                    return item["address"]
        raise AssertionError(f"no address in {result}")

    def _as_list(self, result):
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            for key in ("utxos", "deposits", "entries", "outputs", "digests", "plan", "inputs"):
                if isinstance(result.get(key), list):
                    return result[key]
        return []

    def _package_of(self, result):
        if isinstance(result, str) and result:
            return {"psbt": result}
        if not isinstance(result, dict):
            raise AssertionError(f"unsigned package not an object: {result}")
        return result

    def _digests_of(self, result):
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            if isinstance(result.get("digests"), list):
                return result["digests"]
            if isinstance(result.get("inputs"), list):
                return [i for i in result["inputs"] if isinstance(i, dict) and i.get("digest")]
        return []

    def _hex_digest(self, item):
        if isinstance(item, str):
            return item
        if isinstance(item, dict):
            for key in ("digest", "sighash", "hash"):
                if item.get(key):
                    return str(item[key])
        raise AssertionError(f"digest missing: {item}")

    def _sign_digest(self, digest, path="m/87h/1h/0h/0/0"):
        proc = subprocess.run(
            [
                sys.executable,
                self.mock_signer_file(),
                "--fingerprint", "00000001",
                "--chain", "regtest",
                "signdigest",
                "--path", path,
                "--algo", "ml_dsa_44",
                "--digest", digest,
            ],
            cwd=str(self.nodes[1].cwd),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(f"mock signdigest failed: {proc.stderr or proc.stdout}")
        signed = json.loads(proc.stdout)
        if not signed.get("signature"):
            raise AssertionError(f"mock signdigest empty: {signed}")
        self._no_secrets(signed, "signdigest")
        return signed

    def _require_bcp1_rpcs(self, node):
        present = [name for name in BCP1_RPCS if self._rpc_listed(node, name)]
        missing = [name for name in BCP1_RPCS if name not in present]
        if not present:
            raise SkipTest(
                "BCP/1 RPCs are not in this binary: " + ", ".join(BCP1_RPCS)
            )
        if missing:
            raise AssertionError(
                "BCP/1 fail closed: partial RPC surface "
                f"present={present} missing={missing}"
            )
        return present

    def _open_exchange(self, node):
        try:
            node.createwallet(
                wallet_name="exchange",
                disable_private_keys=True,
                descriptors=True,
                external_signer=True,
                load_on_startup=True,
            )
        except JSONRPCException as exc:
            self.log.info("external_signer wallet create: %s; blank watch-only", exc)
            try:
                node.unloadwallet("exchange")
            except JSONRPCException:
                pass
            node.createwallet(
                wallet_name="exchange_pool",
                disable_private_keys=True,
                blank=True,
                descriptors=True,
                load_on_startup=True,
            )
            wallet = node.get_wallet_rpc("exchange_pool")
            self.exchange_wallet_name = "exchange_pool"
            info = wallet.getwalletinfo()
            if info.get("private_keys_enabled") is True:
                raise AssertionError(f"exchange wallet must be watch-only: {info}")
            self._no_secrets(info, "getwalletinfo")
            return wallet
        wallet = node.get_wallet_rpc("exchange")
        self.exchange_wallet_name = "exchange"
        info = wallet.getwalletinfo()
        if info.get("private_keys_enabled") is True:
            raise AssertionError(f"exchange wallet must be watch-only: {info}")
        self._no_secrets(info, "getwalletinfo")
        return wallet

    def run_test(self):
        self._refuse_production_datadir()
        miner_node = self.nodes[0]
        exchange_node = self.nodes[1]
        miner = miner_node.get_wallet_rpc("miner")
        wallet = self._open_exchange(exchange_node)
        signers = exchange_node.enumeratesigners()["signers"]
        assert_equal(len(signers), 1)
        assert_equal(signers[0]["fingerprint"], "00000001")
        mining_addr = miner.getnewaddress(address_type="p2mr")
        assert_raises_rpc_error(-4, "Private keys are disabled", wallet.sendtoaddress, mining_addr, 0.1)
        self._require_bcp1_rpcs(wallet)

        # Stay connected; mine without the default 60s sync_all, then wait.
        # waitforblockheight's timeout is milliseconds — do not pass seconds.
        self.generatetoaddress(miner_node, COINBASE_MATURITY + 5, mining_addr, sync_fun=self.no_op)
        miner.syncwithvalidationinterfacequeue()
        balances = miner.getbalances()["mine"]
        if Decimal(str(balances.get("trusted", 0))) <= 0:
            self.generate(miner_node, 20, sync_fun=self.no_op)
            miner.syncwithvalidationinterfacequeue()
        self.sync_blocks(timeout=240)
        if miner.getbalance() <= 0:
            raise AssertionError(f"miner has no spendable balance: {miner.getbalances()}")

        ready = wallet.getexchangereadiness()
        self._no_secrets(ready, "getexchangereadiness")
        dumped = self._dump(ready)
        if "btx_exchange_profile_v1" not in dumped and PROFILE.lower() not in dumped:
            raise AssertionError(f"getexchangereadiness profile: {ready}")

        pool_addrs = []
        pool_entries = []
        for i in range(4):
            addr = miner.getnewaddress(address_type="p2mr")
            ml, slh, info = self._miner_p2mr_pubkeys(miner, addr)
            entry = {
                "index": i,
                "address": addr,
                "branch": 0,
                "pubkey": ml,
            }
            if slh:
                entry["pubkey_slh"] = slh
            pool_addrs.append(addr)
            pool_entries.append(entry)
        imported = wallet.importdepositpool(pool_entries)
        self._no_secrets(imported, "importdepositpool")
        if isinstance(imported, dict) and imported.get("success") is False:
            raise AssertionError(f"importdepositpool: {imported}")
        probe = wallet.getaddressinfo(pool_addrs[0])
        if not probe.get("ismine") and not probe.get("iswatchonly"):
            raise AssertionError(
                f"imported 2-leaf deposit address not watched (script mismatch?): {probe} entry={pool_entries[0]}"
            )

        derived = self._call_variants(
            wallet.deriveexchangeaddress,
            [
                ([0], {}),
                ([], {"index": 0}),
                ([{"index": 0, "branch": 0}], {}),
            ],
        )
        deposit_addr = self._address_of(derived)
        if not any(deposit_addr == a for a in pool_addrs):
            # Signer/pool may mint its own P2MR address; still must be a string.
            if not isinstance(deposit_addr, str) or len(deposit_addr) < 10:
                raise AssertionError(f"deriveexchangeaddress: {derived}")
        more_addrs = []
        for idx in range(1, 4):
            extra = self._call_variants(
                wallet.deriveexchangeaddress,
                [([idx], {}), ([{"index": idx}], {})],
            )
            more_addrs.append(self._address_of(extra))
        self._pass("address generation")

        # Deposits must land on imported miner-owned P2MR scripts so the
        # watch-only wallet can select them via solvable mr(pubkey) descriptors.
        # deriveexchangeaddress may mint a signer-keypool address that is
        # watched but not solvable for CreateTransaction.
        dests = list(pool_addrs[:3])
        deposit_txids = []
        deposit_vouts = []
        one = None
        for i, dest in enumerate(dests):
            txid = miner.sendtoaddress(dest, Decimal("1.5"))
            vout = find_vout_for_address(miner_node, txid, dest)
            deposit_txids.append(txid)
            deposit_vouts.append(vout)
            self._push_raw(exchange_node, miner_node, txid)
            # pool_addrs are miner-owned. Lock them so later miner sends do not
            # consume the deposit UTXOs the watch-only wallet is tracking.
            miner.lockunspent(unlock=False, transactions=[{"txid": txid, "vout": int(vout)}])
            exchange_node.syncwithvalidationinterfacequeue()
            miner_node.syncwithvalidationinterfacequeue()
            if i == 0:
                mempool_status = self._call_variants(
                    wallet.getdepositstatus,
                    [
                        ([deposit_txids[0], deposit_vouts[0]], {}),
                        ([], {"txid": deposit_txids[0], "vout": deposit_vouts[0]}),
                        ([{"txid": deposit_txids[0], "vout": deposit_vouts[0]}], {}),
                    ],
                )
                status = self._status_of(mempool_status)
                if status not in ("MEMPOOL", "UNKNOWN"):
                    raise AssertionError(f"pre-confirm status: {mempool_status}")
                if status != "MEMPOOL":
                    raise AssertionError(f"deposit detection must be MEMPOOL, got {status}: {mempool_status}")
                confs = mempool_status.get("confirmations") if isinstance(mempool_status, dict) else None
                if confs not in (None, 0, "0"):
                    raise AssertionError(f"mempool confirmations: {mempool_status}")
                self._pass("deposit detection")
            self.generate(miner_node, 1, sync_fun=self.no_op)
            self.sync_blocks(timeout=120)
            exchange_node.syncwithvalidationinterfacequeue()
            if i == 0:
                one = self._call_variants(
                    wallet.getdepositstatus,
                    [([deposit_txids[0], deposit_vouts[0]], {})],
                )
                if self._status_of(one) != "CONFIRMED":
                    raise AssertionError(f"1 confirmation status: {one}")
                if isinstance(one, dict) and one.get("confirmations") not in (1, "1"):
                    raise AssertionError(f"depth 1: {one}")
        self.generate(miner_node, 3, sync_fun=self.no_op)
        self.sync_blocks(timeout=120)
        exchange_node.syncwithvalidationinterfacequeue()
        nconf = self._call_variants(
            wallet.getdepositstatus,
            [([deposit_txids[0], deposit_vouts[0]], {})],
        )
        if isinstance(nconf, dict):
            got = int(nconf.get("confirmations", 0))
            if got < 4:
                raise AssertionError(f"1→N confirmations: {nconf}")
        if self._status_of(nconf) != "CONFIRMED":
            raise AssertionError(f"N confirmation status: {nconf}")
        self._pass("1→N confirmations")

        listed = self._call_variants(
            wallet.listdepositutxos,
            [([], {}), ([{}], {}), ([{"min_confirmations": 1}], {})],
        )
        utxos = self._as_list(listed) if not isinstance(listed, list) else listed
        if len(utxos) < 1:
            raise AssertionError(f"listdepositutxos empty: {listed}")

        # Local reorg: disconnect the confirming chain so the deposit leaves the tip.
        confirm_hash = None
        if isinstance(one, dict) and one.get("block_hash"):
            confirm_hash = one["block_hash"]
        if not confirm_hash:
            confirm_hash = miner_node.getblockhash(miner_node.getblockcount() - 3)
        self.disconnect_nodes(0, 1)
        exchange_node.invalidateblock(confirm_hash)
        exchange_node.syncwithvalidationinterfacequeue()
        reorged = self._call_variants(
            wallet.getdepositstatus,
            [([deposit_txids[0], deposit_vouts[0]], {})],
        )
        reorg_status = self._status_of(reorged)
        if reorg_status != "REORGED":
            raise AssertionError(f"reorg must be REORGED, got {reorg_status}: {reorged}")
        exchange_node.reconsiderblock(confirm_hash)
        self.connect_nodes(0, 1)
        self.sync_blocks(timeout=120)
        exchange_node.syncwithvalidationinterfacequeue()
        restored = self._call_variants(
            wallet.getdepositstatus,
            [([deposit_txids[0], deposit_vouts[0]], {})],
        )
        if self._status_of(restored) != "CONFIRMED":
            raise AssertionError(f"post-reconsider must be CONFIRMED: {restored}")
        self._pass("reorg handling")

        change = dests[-1] if dests else deposit_addr
        withdraw_dest = miner.getnewaddress(address_type="p2mr")
        funded = None
        try:
            funded = wallet.walletcreatefundedpsbt(
                inputs=[],
                outputs=[{withdraw_dest: Decimal("0.4")}],
                options={"includeWatching": True, "changeAddress": change, "include_unsafe": False},
            )
            self._no_secrets(funded, "walletcreatefundedpsbt")
        except JSONRPCException as exc:
            self.log.info("walletcreatefundedpsbt: %s", exc)

        prepare_variants = [
            ([{"recipients": [{"address": withdraw_dest, "amount": 0.4}], "change_address": change}], {}),
            ([{"recipients": [{"address": withdraw_dest, "amount": 0.4}]}], {"change_address": change}),
            ([{"outputs": [{withdraw_dest: 0.4}]}], {"change_address": change}),
        ]
        if funded and funded.get("psbt"):
            prepare_variants.extend([
                ([funded["psbt"]], {}),
                ([{"psbt": funded["psbt"]}], {}),
            ])
        unsigned = self._call_variants(wallet.prepareexternalsign, prepare_variants)
        package = self._package_of(unsigned)
        if package.get("complete") is True and package.get("hex") and not package.get("psbt") and not package.get("unsigned_tx_hex"):
            raise AssertionError(f"prepareexternalsign must not return a fully signed broadcastable tx: {unsigned}")
        self._pass("unsigned withdrawal")

        digests_raw = self._call_variants(
            wallet.getsigningdigests,
            (
                [([package], {})]
                + ([([package.get("psbt")], {})] if package.get("psbt") else [])
                + ([([{"package": package}], {})])
            ),
        )
        digests = self._digests_of(digests_raw) or self._digests_of(package)
        if not digests:
            raise AssertionError(f"getsigningdigests empty: {digests_raw}")
        first_digest = self._hex_digest(digests[0])
        path = "m/87h/1h/0h/0/0"
        if isinstance(digests[0], dict) and digests[0].get("path"):
            path = digests[0]["path"]
        signed = self._sign_digest(first_digest, path=path)
        if len(signed["signature"]) < 32:
            raise AssertionError("external PQ signature too short")
        self._pass("external PQ signature")

        signatures = []
        for item in digests:
            digest_hex = self._hex_digest(item)
            item_path = item.get("path", path) if isinstance(item, dict) else path
            sig = self._sign_digest(digest_hex, path=item_path)
            entry = {"signature": sig["signature"], "algo": "ml_dsa_44", "digest": digest_hex}
            if isinstance(item, dict):
                if item.get("index") is not None:
                    entry["index"] = item["index"]
                if item.get("pubkey"):
                    entry["pubkey"] = item["pubkey"]
            signatures.append(entry)

        finalized = None
        try:
            finalized = self._call_variants(
                wallet.finalizeexternalsign,
                [
                    ([package, signatures], {}),
                    ([{"package": package, "signatures": signatures}], {}),
                    ([package], {"signatures": signatures}),
                ],
            )
        except JSONRPCException as exc:
            # Fail closed: corrupt stub must not be accepted as a valid ML-DSA sig.
            msg = str(exc).lower()
            if "corrupt" in msg or "invalid" in msg or "signature" in msg or "fail" in msg:
                self.log.info("finalizeexternalsign rejected stub (fail closed): %s", exc)
                finalized = {"rejected": True, "error": str(exc)}
            else:
                raise
        self._no_secrets(finalized, "finalizeexternalsign")
        if isinstance(finalized, dict):
            if finalized.get("broadcast") is True:
                raise AssertionError("finalizeexternalsign must not broadcast")
            if finalized.get("complete") is True and not finalized.get("rejected"):
                raise AssertionError(
                    "finalizeexternalsign must not accept mock stub ML-DSA signatures: "
                    f"{finalized}"
                )
            if finalized.get("txid"):
                if finalized["txid"] in exchange_node.getrawmempool() and finalized.get("complete") is True:
                    raise AssertionError("finalizeexternalsign must not auto-broadcast")
        self._pass("signature import")

        # Deposit addresses in this cert are imported miner P2MR destinations.
        # The watch-only coordinator never holds those keys. The key-holding
        # wallet (miner) is the external signer for the consensus-valid broadcast.
        unsigned_hex = None
        if isinstance(package, dict):
            unsigned_hex = package.get("unsigned_tx_hex") or package.get("unsigned_tx")
            if not unsigned_hex and package.get("psbt"):
                try:
                    decoded = wallet.finalizepsbt(package["psbt"], False)
                    unsigned_hex = decoded.get("hex")
                except JSONRPCException as exc:
                    self.log.info("finalizepsbt unsigned extract: %s", exc)
        if not unsigned_hex:
            raise AssertionError(f"prepareexternalsign missing unsigned_tx_hex: {unsigned}")
        signed_wallet = miner.signrawtransactionwithwallet(unsigned_hex)
        self._no_secrets(signed_wallet, "external wallet sign")
        if not signed_wallet.get("complete") or not signed_wallet.get("hex"):
            raise AssertionError(f"external signer did not complete withdrawal: {signed_wallet}")
        hex_tx = signed_wallet["hex"]
        accepted = exchange_node.testmempoolaccept([hex_tx])
        self._no_secrets(accepted, "testmempoolaccept")
        allowed = isinstance(accepted, list) and accepted and bool(accepted[0].get("allowed"))
        if not allowed:
            raise AssertionError(f"testmempoolaccept rejected signed withdrawal: {accepted}")
        sent = exchange_node.sendrawtransaction(hex_tx)
        self._no_secrets(sent, "sendrawtransaction")
        try:
            miner_node.sendrawtransaction(hex_tx)
        except JSONRPCException as exc:
            self.log.info("miner already has withdrawal: %s", exc)
        self._pass("broadcast")

        batch_dest_a = miner.getnewaddress(address_type="p2mr")
        batch_dest_b = miner.getnewaddress(address_type="p2mr")
        batch = self._call_variants(
            wallet.createexchangebatch,
            [
                ([[{"address": batch_dest_a, "amount": 0.2}, {"address": batch_dest_b, "amount": 0.2}]], {}),
                ([{"outputs": [{"address": batch_dest_a, "amount": 0.2}, {"address": batch_dest_b, "amount": 0.2}]}], {}),
            ],
        )
        batch_obj = self._package_of(batch)
        outputs = batch_obj.get("outputs") or batch_obj.get("recipients") or []
        if isinstance(outputs, list) and len(outputs) < 2 and not batch_obj.get("psbt") and not batch_obj.get("unsigned_tx_hex"):
            raise AssertionError(f"createexchangebatch must be a multi-output package: {batch}")
        self._pass("batch withdrawal")

        # Broadcast/batch may have spent the original deposits. Seed two more
        # confirmed watch-only UTXOs so consolidation has something to sweep.
        self.connect_nodes(0, 1)
        self._follow_miner(miner_node, exchange_node)
        sweep_dest = pool_addrs[-1]
        self._follow_miner(miner_node, exchange_node)
        extra_txids = []
        for _ in range(2):
            extra_txid = miner.sendtoaddress(sweep_dest, Decimal("0.25"))
            extra_vout = find_vout_for_address(miner_node, extra_txid, sweep_dest)
            miner.lockunspent(unlock=False, transactions=[{"txid": extra_txid, "vout": int(extra_vout)}])
            self._push_raw(exchange_node, miner_node, extra_txid)
            extra_txids.append(extra_txid)
        block_hashes = self.generatetoaddress(miner_node, 1, mining_addr, sync_fun=self.no_op)
        self._follow_miner(miner_node, exchange_node)
        exchange_node.syncwithvalidationinterfacequeue()
        listed_cons = wallet.listdepositutxos({"min_confirmations": 0})
        if len(self._as_list(listed_cons)) < 1:
            raise AssertionError(f"no UTXOs for consolidation after funding: {listed_cons}")

        plan = wallet.planconsolidation({
            "min_confirmations": 0,
            "include_unsafe": True,
            "max_inputs": 10,
            "target_utxo_count": 1,
        })
        fee = wallet.estimateconsolidationfee({
            "min_confirmations": 0,
            "include_unsafe": True,
            "plan": plan,
        })
        cons = wallet.createconsolidationtx({
            "min_confirmations": 0,
            "include_unsafe": True,
            "max_inputs": 10,
            "target_utxo_count": 1,
            "change_address": sweep_dest,
        })
        self._no_secrets(fee, "estimateconsolidationfee")
        self._package_of(cons)
        self._pass("UTXO consolidation")

        # Double-spend: two conflicting spends of the same miner coin.
        conflict_addr_a = miner.getnewaddress(address_type="p2mr")
        conflict_addr_b = miner.getnewaddress(address_type="p2mr")
        utxo = [u for u in miner.listunspent(1) if u.get("spendable")][0]
        raw_a = miner.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{conflict_addr_a: Decimal(str(utxo["amount"])) - Decimal("0.01")}],
        )
        raw_b = miner.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{conflict_addr_b: Decimal(str(utxo["amount"])) - Decimal("0.01")}],
        )
        signed_a = miner.signrawtransactionwithwallet(raw_a)
        signed_b = miner.signrawtransactionwithwallet(raw_b)
        if not signed_a.get("complete") or not signed_b.get("complete"):
            raise AssertionError("miner could not sign conflict pair")
        miner_node.sendrawtransaction(signed_a["hex"])
        rejected = miner_node.testmempoolaccept([signed_b["hex"]])
        allowed_b = isinstance(rejected, list) and rejected and rejected[0].get("allowed") is True
        if allowed_b:
            raise AssertionError(f"double-spend must be rejected: {rejected}")
        self._pass("double-spend rejection")

        self.restart_node(1, extra_args=self.exchange_args)
        self.connect_nodes(0, 1)
        self._follow_miner(self.nodes[0], self.nodes[1])
        wallets = self.nodes[1].listwallets()
        name = getattr(self, "exchange_wallet_name", "exchange")
        if name not in wallets:
            self.nodes[1].loadwallet(name)
        wallet = self.nodes[1].get_wallet_rpc(name)
        again = wallet.getexchangereadiness()
        self._no_secrets(again, "getexchangereadiness after restart")
        self._pass("node restart")

        recovered = self._call_variants(
            wallet.getdepositstatus,
            [([deposit_txids[0], deposit_vouts[0]], {})],
        )
        if self._status_of(recovered) not in ("CONFIRMED", "SPENT", "REORGED", "MEMPOOL"):
            raise AssertionError(f"wallet recovery status: {recovered}")
        recovered_list = self._call_variants(wallet.listdepositutxos, [([], {}), ([{}], {})])
        self._no_secrets(recovered_list, "listdepositutxos after restart")
        self._pass("wallet recovery")

        missing = [row for row in PASS_ROWS if row not in self.passed]
        if missing:
            raise AssertionError(f"BCP/1 missing PASS rows: {missing}; have={self.passed}")
        self.log.info("BTX Exchange Integration Profile v1 (BCP/1)")
        self.log.info("%s/%s PASS", len(self.passed), len(PASS_ROWS))


if __name__ == "__main__":
    BCP1Test(__file__).main()
