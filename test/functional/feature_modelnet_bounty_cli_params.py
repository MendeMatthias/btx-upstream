#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Bounty lookups by id accept the object form from btx-cli too.

btx-cli has no conversion entry for the helper's bounty methods, so an
object argument such as '{"bounty_id":"..."}' reaches the helper as a JSON
string. Methods that read their argument with ObjArg parse that string.
Lookups by id used StrArg, which took the whole string as the id, so
getbounty and the other id lookups answered NOT_FOUND for a bounty that
exists. The same call over JSON-RPC with a real object, or with the bare
id, worked. updatebountydraft failed the same way; it must also take its
patch from that string, not only from a real object.
"""

import json
import os
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal

MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]


def sample_terms(council_hex):
    return {
        "terms_version": 1,
        "network_id": "0" * 64,
        "requester_identity": "",
        "title": "regtest-bounty-cli-params",
        "description": "Object arguments from btx-cli.",
        "tags": ["cli"],
        "deliverable_classes": ["BASE_MODEL"],
        "evaluation_spec_id": "e2e-exact-checks",
        "submission_mode": "PUBLIC",
        "payout_authority": "COUNCIL_MULTISIG",
        "council": [{"public_key_hex": k} for k in council_hex],
        "threshold": 2,
        "nomination_min_bps": 0,
        "target_atoms": "100000000",
        "max_lots_per_round": 4,
        "funding_close_height": 200,
        "submission_close_height": 300,
        "evaluation_close_height": 400,
        "earliest_award_height": 450,
        "last_safe_award_height": 480,
        "refund_height": 600,
        "minimum_confirmations": 6,
        "claim_margin_blocks": 20,
        "challenge_policy": "BOUNDED_TYPED",
        "selection_rule": "EXACT_CANDIDATE",
        "license_statement": "MIT",
        "max_model_bytes": 1048576,
        "fee_policy": "USER_CEILING",
        "sealed_confidentiality_disclosure": "",
    }


class ModelnetBountyCliParamsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-modelnet=1",
            "-modelbind=off",
            "-modelstorage=8MiB",
            "-autoshieldcoinbase=0",
            *MATMUL_OFF_ARGS,
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        self.skip_if_no_wallet()
        self.skip_if_no_cli()
        exeext = self.config["environment"].get("EXEEXT", "")
        builddir = self.config["environment"].get("BUILDDIR", "")
        candidates = [Path(builddir) / "bin" / f"btx-modeld{exeext}"]
        bitcoind = getattr(self.options, "bitcoind", None)
        if bitcoind:
            candidates.append(Path(bitcoind).resolve().parent / f"btx-modeld{exeext}")
        if not any(c.is_file() and os.access(c, os.X_OK) for c in candidates):
            raise SkipTest("btx-modeld not found")

    def _wait_helper(self, node):
        def ready():
            try:
                return bool(node.getmodelnetworkinfo().get("helper_ready"))
            except JSONRPCException:
                return False
        self.wait_until(ready, timeout=60)

    def run_test(self):
        node = self.nodes[0]
        self._wait_helper(node)
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        keys = []
        for _ in range(2):
            exported = wallet.exportpqkey(wallet.getnewaddress())
            keys.append(exported.get("pubkey") or exported.get("key"))

        terms = sample_terms(keys)
        published_draft = node.createbountydraft({"terms": terms})["draft_id"]
        bounty_id = node.publishbounty({"draft_id": published_draft})["bounty_id"]
        draft_id = node.createbountydraft({"terms": {**terms, "title": "regtest-bounty-cli-draft"}})["draft_id"]

        self.log.info("Lookups by id through btx-cli with an object argument")
        as_object = json.dumps({"bounty_id": bounty_id})
        # getbountyterms returns the signed envelope, whose record_id is the bounty id.
        for method, key in (("getbounty", "bounty_id"), ("getbountyterms", "record_id"), ("getbountyeconomy", "bounty_id")):
            got = getattr(node.cli, method)(as_object)
            assert_equal(got[key], bounty_id)
        got = node.cli.getbountydraft(json.dumps({"draft_id": draft_id}))
        assert_equal(got["draft_id"], draft_id)

        self.log.info("updatebountydraft with one object from btx-cli edits the draft")
        node.cli.updatebountydraft(json.dumps({"draft_id": draft_id, "title": "regtest-bounty-cli-renamed"}))
        assert_equal(node.getbountydraft(draft_id)["terms"]["title"], "regtest-bounty-cli-renamed")

        self.log.info("The bare id and the JSON-RPC object still work")
        assert_equal(node.cli.getbounty(bounty_id)["bounty_id"], bounty_id)
        assert_equal(node.getbounty({"bounty_id": bounty_id})["bounty_id"], bounty_id)
        assert_equal(node.getbounty(bounty_id)["bounty_id"], bounty_id)

        self.log.info("An unknown id is still NOT_FOUND")
        try:
            node.cli.getbounty(json.dumps({"bounty_id": "00" * 48}))
            raise AssertionError("unknown bounty id must fail")
        except JSONRPCException as exc:
            assert "NOT_FOUND" in str(exc.error)


if __name__ == "__main__":
    ModelnetBountyCliParamsTest(__file__).main()
