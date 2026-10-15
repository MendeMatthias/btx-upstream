#!/usr/bin/env python3
"""BTX HTLC atomic swaps on regtest, through upstream's own swap SDK.

    python3 -I lab/htlc/swap_tests.py <btxd bin dir> <btx_wbtx.py> [--peer-bindir <other version's bin dir>]

Regtest coins only; every node is a throwaway in a temp folder, on 127.0.0.1,
stopped and deleted at the end. What it covers (each prints PASS, FINDING or
FAIL with the evidence):

  S1  a two-chain swap end to end: Alice funds the long leg on chain A, Bob the
      short leg on chain B, Alice claims B (revealing the secret), Bob reads the
      secret off chain B with the SDK and claims A
  S2  the walk-away: neither claims; each refund is refused before its height
      and accepted at it
  S3  claim guards: unconfirmed funding, a late claim after the refund height,
      both valid at once, the higher fee wins
  S4  a stuck claim is fee-bumped by replacement; the SDK's default fee relays
  S5  a lock that is already refundable is refused (height and timestamp)
  S6  the SDK's live timeout check against a tip dated in the future
  S7  (with --peer-bindir) both versions on one chain: HTLC claims and refunds
      built by one version are mined by the other
"""
import hashlib
FEE = 8000  # sat: an HTLC claim or refund is ~3,900 vB; the SDK default 1000 sat does not relay (S4)
import importlib.util
import os
import shutil
import sys
import tempfile
import time
from decimal import Decimal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from node import Node, RpcError  # noqa: E402

results = []


def report(name, status, detail):
    results.append((name, status, detail))
    print(f"[{status}] {name}: {detail}", flush=True)


def load_sdk(path):
    spec = importlib.util.spec_from_file_location("btx_wbtx", path)
    m = importlib.util.module_from_spec(spec)
    sys.modules["btx_wbtx"] = m  # dataclasses look the module up while the class is made
    sys.path.insert(0, os.path.dirname(os.path.abspath(path)))  # its _ripemd160 fallback
    spec.loader.exec_module(m)
    return m


def rpc_of(node, wallet=None):
    return (lambda method, *p: node.call(method, *p, wallet=wallet))


class Chain:
    """One regtest chain: a node, a miner wallet, and named party wallets."""

    def __init__(self, node):
        self.n = node
        node.call("createwallet", "miner")
        self.mine_addr = node.call("getnewaddress", "", "p2mr", wallet="miner")
        self.mine(110)

    def mine(self, k=1, to=None):
        return self.n.call("generatetoaddress", k, to or self.mine_addr)

    def height(self):
        return self.n.call("getblockcount")

    def party(self, name, fund=Decimal("20")):
        self.n.call("createwallet", name)
        addr = self.n.call("getnewaddress", "", "p2mr", wallet=name)
        self.n.call("sendtoaddress", addr, str(fund), wallet="miner")
        self.mine()
        return name

    def pk(self, wallet):
        a = self.n.call("getnewaddress", "", "p2mr", wallet=wallet)
        return self.n.call("exportpqkey", a, wallet=wallet)["pubkey"]

    def bal(self, wallet):
        return Decimal(str(self.n.call("getbalance", wallet=wallet)))


def lock(chain, sdk, funder, claimer_pk, funder_pk, h256, refund_height, amount):
    """Fund an HTLC through the SDK's helpers (no EVM leg: descriptor built directly)."""
    desc = sdk.add_checksum(rpc_of(chain.n),
                            f"mr(htlc_sha256({h256},{claimer_pk}),refund({refund_height},{funder_pk}))")
    addr = sdk.swap_address(rpc_of(chain.n), desc)
    txid = chain.n.call("sendtoaddress", addr, str(amount), wallet=funder)
    return desc, addr, txid


def deposit_of(chain, sdk, wallet, desc, addr, minconf):
    sdk.import_watch(rpc_of(chain.n, wallet), desc)
    deps = sdk.find_deposits(rpc_of(chain.n, wallet), addr, minconf=minconf, unsafe=minconf < 100)
    assert len(deps) == 1, deps
    return deps[0]


def send(chain, hexstr):
    return chain.n.call("sendrawtransaction", hexstr)


def err_of(fn):
    try:
        fn()
        return None
    except RpcError as e:
        return e.message
    except Exception as e:  # SDK-level ValueError etc.
        return f"{type(e).__name__}: {e}"


# ----------------------------------------------------------------------------- scenarios

def s1_swap(A, B, sdk):
    alice_a, bob_a = A.party("alice"), A.party("bob")
    alice_b, bob_b = B.party("alice"), B.party("bob")
    secret = sdk.new_preimage()
    h = sdk.btx_sha256_hex(secret)
    # Alice holds the secret: she funds the LONG leg (A) and claims the SHORT leg (B) first.
    ha, hb = A.height(), B.height()
    desc_a, addr_a, _ = lock(A, sdk, "alice", A.pk("bob"), A.pk("alice"), h, ha + 300, Decimal("5"))
    A.mine(100)  # the SDK's safety floor before treating a deposit as final
    dep_a = deposit_of(A, sdk, "bob", desc_a, addr_a, 100)
    desc_b, addr_b, _ = lock(B, sdk, "bob", B.pk("alice"), B.pk("bob"), h, hb + 150, Decimal("5"))
    B.mine(100)
    dep_b = deposit_of(B, sdk, "alice", desc_b, addr_b, 100)
    # Alice claims B, revealing the secret.
    dest_alice = B.n.call("getnewaddress", "", "p2mr", wallet="alice")
    claim_b = sdk.build_claim(rpc_of(B.n, "alice"), desc_b, dep_b, secret, dest_alice, fee_sat=FEE)
    txid_b = send(B, claim_b)
    B.mine()
    # Bob only sees chain B: he reads the secret off Alice's claim and claims A.
    got = sdk.extract_preimage(rpc_of(B.n), txid_b, h)
    if got != secret:
        return report("S1 two-chain swap", "FAIL", "the SDK did not recover the secret from the claim")
    dest_bob = A.n.call("getnewaddress", "", "p2mr", wallet="bob")
    claim_a = sdk.build_claim(rpc_of(A.n, "bob"), desc_a, dep_a, got, dest_bob, fee_sat=FEE)
    txid_a = send(A, claim_a)
    A.mine()
    spent_a = A.n.call("gettxout", dep_a.txid, dep_a.vout) is None
    spent_b = B.n.call("gettxout", dep_b.txid, dep_b.vout) is None
    vsize = A.n.call("getrawtransaction", txid_a, True)["vsize"]
    ok = spent_a and spent_b and A.bal("bob") > Decimal("24") and B.bal("alice") > Decimal("24")
    report("S1 two-chain swap", "PASS" if ok else "FAIL",
           f"both legs claimed, secret read off chain B by the SDK; claim vsize {vsize} vB; "
           f"bob on A {A.bal('bob')}, alice on B {B.bal('alice')}")


def s2_walkaway(A, B, sdk):
    secret = sdk.new_preimage()
    h = sdk.btx_sha256_hex(secret)
    ha = A.height()
    rh = ha + 120
    desc, addr, _ = lock(A, sdk, "alice", A.pk("bob"), A.pk("alice"), h, rh, Decimal("2"))
    A.mine(100)
    dep = deposit_of(A, sdk, "alice", desc, addr, 100)
    dest = A.n.call("getnewaddress", "", "p2mr", wallet="alice")
    early = err_of(lambda: sdk.build_refund(rpc_of(A.n, "alice"), desc, dep, dest, rh, fee_sat=FEE))
    # A refund forged to the right height but broadcast early must not relay either.
    A.mine(rh - A.height() - 1)  # tip = rh - 1: the next block is rh
    at_minus1 = err_of(lambda: send(A, sdk.build_refund(rpc_of(A.n, "alice"), desc, dep, dest, rh, fee_sat=FEE)))
    A.mine(1)
    ok_tx = sdk.build_refund(rpc_of(A.n, "alice"), desc, dep, dest, rh, fee_sat=FEE)
    txid = send(A, ok_tx)
    A.mine()
    spent = A.n.call("gettxout", dep.txid, dep.vout) is None
    # buildhtlcrefund may sign a refund early (a presigned refund is a normal pattern); what must
    # hold is that the network does not take it before its height (help: final in block L+1).
    good = at_minus1 is not None and spent
    report("S2 walk-away refund", "PASS" if good else "FAIL",
           f"built early: {('refused: ' + early) if early else 'signed (documented)'}; relayed at tip rh-1: "
           f"{(at_minus1 or 'ACCEPTED into the mempool')[:60]}; at tip rh relayed and confirmed ({txid[:12]})")


def s3_claim_guards(A, sdk):
    secret = sdk.new_preimage()
    h = sdk.btx_sha256_hex(secret)
    rh = A.height() + 30
    desc, addr, txid = lock(A, sdk, "alice", A.pk("bob"), A.pk("alice"), h, rh, Decimal("1"))
    sdk.import_watch(rpc_of(A.n, "bob"), desc)
    utxos = A.n.call("listunspent", 0, 9999999, [addr], wallet="bob")
    dep0 = sdk.Deposit(utxos[0]["txid"], utxos[0]["vout"], str(utxos[0]["amount"]), 0)
    dest = A.n.call("getnewaddress", "", "p2mr", wallet="bob")
    unconf = err_of(lambda: sdk.build_claim(rpc_of(A.n, "bob"), desc, dep0, secret, dest, fee_sat=FEE))
    A.mine(rh - A.height())  # tip = rh: the refund is final now
    dep = sdk.Deposit(dep0.txid, dep0.vout, dep0.amount_btx, A.n.call("gettxout", dep0.txid, dep0.vout)["confirmations"])
    late = err_of(lambda: sdk.build_claim(rpc_of(A.n, "bob"), desc, dep, secret, dest, fee_sat=FEE))
    # With the explicit opt-in both are valid; they conflict; the higher fee wins.
    claim = A.n.call("buildhtlcclaim", desc, {"txid": dep.txid, "vout": dep.vout}, secret.hex(), dest, FEE,
                     {"allow_late_claim": True}, wallet="bob")
    refund_dest = A.n.call("getnewaddress", "", "p2mr", wallet="alice")
    refund = A.n.call("buildhtlcrefund", desc, {"txid": dep.txid, "vout": dep.vout}, refund_dest, rh, FEE - 1000, wallet="alice")
    send(A, claim["hex"])
    low_refund = err_of(lambda: send(A, refund["hex"]))
    refund_hi = A.n.call("buildhtlcrefund", desc, {"txid": dep.txid, "vout": dep.vout}, refund_dest, rh, 50000, wallet="alice")
    hi_refund = err_of(lambda: send(A, refund_hi["hex"]))
    A.mine()
    winner = "refund" if A.bal("alice") > 0 and hi_refund is None else "claim"
    good = unconf is not None and late is not None
    report("S3 claim guards", "PASS" if good else "FINDING",
           f"unconfirmed funding: {(unconf or 'NOT refused')[:80]}; after the refund height: {(late or 'NOT refused')[:80]}; "
           f"opt-in late claim relayed, then a lower-fee refund: {(low_refund or 'accepted')[:70]}; "
           f"a higher-fee refund: {(hi_refund or 'replaced the claim')[:70]} -> {winner} confirmed")


def s4_fees(A, sdk):
    secret = sdk.new_preimage()
    h = sdk.btx_sha256_hex(secret)
    rh = A.height() + 400
    desc, addr, _ = lock(A, sdk, "alice", A.pk("bob"), A.pk("alice"), h, rh, Decimal("1"))
    A.mine(100)
    dep = deposit_of(A, sdk, "bob", desc, addr, 100)
    dest = A.n.call("getnewaddress", "", "p2mr", wallet="bob")
    default_fee = sdk.build_claim.__defaults__[-1]
    c1 = sdk.build_claim(rpc_of(A.n, "bob"), desc, dep, secret, dest)  # the SDK's default fee
    r1 = err_of(lambda: send(A, c1))
    info = A.n.call("getmempoolinfo")
    mi = A.n.call("getmempoolentry", A.n.call("decoderawtransaction", c1)["txid"]) if r1 is None else None
    c2 = sdk.build_claim(rpc_of(A.n, "bob"), desc, dep, secret, dest, fee_sat=20000)
    r2 = err_of(lambda: send(A, c2))
    seq = A.n.call("decoderawtransaction", c2)["vin"][0]["sequence"]
    A.mine()
    good = r2 is None
    report("S4 fee bump", ("FINDING" if r1 else "PASS") if good else "FAIL",
           f"the SDK's default {default_fee} sat claim: {(r1 or 'relayed')[:80]}"
           + (f" (vsize {mi['vsize']}, {Decimal(default_fee)/mi['vsize']:.2f} sat/vB; min relay {info['minrelaytxfee']} BTX/kvB)" if mi else "")
           + f"; 20000 sat replacement: {(r2 or 'replaced it')[:80]}; nSequence {seq}")


def s5_already_refundable(A, sdk):
    secret = sdk.new_preimage()
    h = sdk.btx_sha256_hex(secret)
    tip = A.height()
    ck, sk = A.pk("bob"), A.pk("alice")
    out = []
    for label, lt in (("height at the tip", tip), ("height in the past", tip - 10),
                      ("timestamp in the past", int(time.time()) - 3600), ("height ahead", tip + 50)):
        d = f"mr(htlc_sha256({h},{ck}),refund({lt},{sk}))"
        e = err_of(lambda: A.n.call("deriveaddresses", sdk.add_checksum(rpc_of(A.n), d)))
        out.append(f"{label}: {'refused (' + e[:60] + ')' if e else 'address derived'}")
    refused_past = all("refused" in o for o in out[:3])
    report("S5 already-refundable lock", "PASS" if refused_past else "FINDING", "; ".join(out))


def s6_future_tip(A, sdk):
    """check_timeout_ordering() takes the tip block's time as 'now'. Consensus accepts a block
    dated up to MAX_FUTURE_BLOCK_TIME (2 h = 80 blocks of 90 s) ahead of a node's clock."""
    real_now = int(time.time())
    A.n.call("setmocktime", real_now + 7000)  # this node's miner believes it is ~1h57m later
    A.mine(1)
    A.n.call("setmocktime", 0)
    tip = A.height()
    tip_time = A.n.call("getblockheader", A.n.call("getblockhash", tip))["time"]
    margin_blocks = 10  # what an integrator might pass as reorg margin
    # EVM timeout and BTX refund chosen so that against REAL time the BTX refund comes
    # 40 blocks (an hour) BEFORE the EVM timeout: unsafe, the funder can take both legs.
    evm_timeout = real_now + 6 * 3600
    btx_refund_height = tip + (6 * 3600 // 90) - 40
    real_refund_unix = real_now + (btx_refund_height - tip) * 90
    by_wall_clock = err_of(lambda: sdk.check_timeout_ordering(btx_refund_height, evm_timeout, real_now, tip, 90, margin_blocks))
    at_tip = err_of(lambda: sdk.assert_timeout_ordering_at_tip(rpc_of(A.n), btx_refund_height, evm_timeout, 90, margin_blocks))
    finding = by_wall_clock is not None and at_tip is None
    report("S6 SDK live check, future-dated tip", "FINDING" if finding else "PASS",
           f"tip dated {tip_time - real_now} s ahead (consensus allows up to 7200); a BTX refund ~"
           f"{(evm_timeout - real_refund_unix) // 60} min BEFORE the EVM timeout is "
           f"{'refused' if by_wall_clock else 'ACCEPTED'} against the wall clock and "
           f"{'refused' if at_tip else 'ACCEPTED'} by assert_timeout_ordering_at_tip()")


def s7_mixed(root, bindir, peer_bindir, sdk):
    a = Node("mixA", bindir, root, 28621, 28631).start()
    b = Node("mixB", peer_bindir, root, 28622, 28632).start()
    try:
        a.call("addnode", "127.0.0.1:28632", "onetry")
        for _ in range(100):
            if a.call("getconnectioncount") > 0:
                break
            time.sleep(0.2)
        A = Chain(a)
        for _ in range(100):
            if b.call("getblockcount") == a.call("getblockcount"):
                break
            time.sleep(0.2)
        b.call("createwallet", "carol")
        lines = []
        # Lock on A's wallet, claim built on B's wallet, mined by A; and the reverse for a refund.
        secret = sdk.new_preimage()
        h = sdk.btx_sha256_hex(secret)
        ca = b.call("getnewaddress", "", "p2mr", wallet="carol")
        cpk = b.call("exportpqkey", ca, wallet="carol")["pubkey"]
        A.party("dave")
        dpk = A.pk("dave")
        rh = A.height() + 20
        desc = sdk.add_checksum(rpc_of(a), f"mr(htlc_sha256({h},{cpk}),refund({rh},{dpk}))")
        addr = sdk.swap_address(rpc_of(a), desc)
        t1 = a.call("sendtoaddress", addr, "1", wallet="dave")
        t2 = a.call("sendtoaddress", addr, "1", wallet="dave")
        A.mine(2)
        for _ in range(100):
            if b.call("getblockcount") == a.call("getblockcount"):
                break
            time.sleep(0.2)
        sdk.import_watch(rpc_of(b, "carol"), desc)
        sdk.import_watch(rpc_of(a, "dave"), desc)
        b.call("rescanblockchain", wallet="carol")
        a.call("rescanblockchain", wallet="dave")
        ut = {u["txid"]: u for u in b.call("listunspent", 1, 9999999, [addr], wallet="carol")}
        u1 = ut[t1]
        dest = b.call("getnewaddress", "", "p2mr", wallet="carol")
        claim = b.call("buildhtlcclaim", desc, {"txid": t1, "vout": u1["vout"]}, secret.hex(), dest, 20000, wallet="carol")
        cid = a.call("sendrawtransaction", claim["hex"])  # built by B's version, relayed by A's
        A.mine()
        lines.append(f"claim built by {b.version()} mined by {a.version()}: {'confirmed' if a.call('gettxout', t1, u1['vout']) is None else 'NOT spent'}")
        A.mine(rh - A.height())
        u2 = next(u for u in a.call("listunspent", 0, 9999999, [addr], wallet="dave") if u["txid"] == t2)
        rd = a.call("getnewaddress", "", "p2mr", wallet="dave")
        refund = a.call("buildhtlcrefund", desc, {"txid": t2, "vout": u2["vout"]}, rd, rh, 20000, wallet="dave")
        rid = b.call("sendrawtransaction", refund["hex"])  # built by A's version, relayed by B's
        b.call("generatetoaddress", 1, b.call("getnewaddress", "", "p2mr", wallet="carol"))
        for _ in range(100):
            if a.call("getblockcount") == b.call("getblockcount"):
                break
            time.sleep(0.2)
        lines.append(f"refund built by {a.version()} mined by {b.version()}: "
                     f"{'confirmed on both' if a.call('gettxout', t2, u2['vout']) is None and b.call('gettxout', t2, u2['vout']) is None else 'NOT spent'}")
        same = a.call("getbestblockhash") == b.call("getbestblockhash")
        report("S7 mixed versions on one chain", "PASS" if same and all("NOT" not in l for l in lines) else "FAIL",
               "; ".join(lines) + f"; same tip on both: {same}")
    finally:
        a.stop()
        b.stop()


def main():
    bindir, sdk_path = sys.argv[1], sys.argv[2]
    peer = sys.argv[sys.argv.index("--peer-bindir") + 1] if "--peer-bindir" in sys.argv else None
    sdk = load_sdk(sdk_path)
    root = tempfile.mkdtemp(prefix="htlc-swap-")
    nodes = []
    try:
        a = Node("chainA", bindir, root, 28601, 28611).start()
        nodes.append(a)
        b = Node("chainB", bindir, root, 28602, 28612).start()
        nodes.append(b)
        print(f"== {a.version()} on two separate regtest chains, SDK {os.path.basename(sdk_path)}", flush=True)
        A, B = Chain(a), Chain(b)
        for fn, args in ((s1_swap, (A, B, sdk)), (s2_walkaway, (A, B, sdk)), (s3_claim_guards, (A, sdk)),
                         (s4_fees, (A, sdk)), (s5_already_refundable, (A, sdk)), (s6_future_tip, (A, sdk))):
            try:
                fn(*args)
            except Exception as e:  # a scenario that breaks is a result too
                report(fn.__name__, "ERROR", f"{type(e).__name__}: {e}")
        for n in nodes:
            n.stop()
        nodes.clear()
        if peer:
            try:
                s7_mixed(root, bindir, peer, sdk)
            except Exception as e:
                report("s7_mixed", "ERROR", f"{type(e).__name__}: {e}")
    finally:
        for n in nodes:
            n.stop()
        shutil.rmtree(root, ignore_errors=True)
    print("== summary: " + ", ".join(f"{s}={sum(1 for r in results if r[1] == s)}"
                                     for s in ("PASS", "FINDING", "FAIL", "ERROR")))


if __name__ == "__main__":
    main()
