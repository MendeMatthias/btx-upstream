// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native cases for remaining HCP stub-quality handlers.

#include <modelnet/catalog.h>
#include <test/modelnet_hcp_test.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_hcp_gap_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hcp_gap_gethandoff_returns_signed_envelope)
{
    auto e = hcp_test::Lab();
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/handoffs", tok));
    BOOST_REQUIRE_EQUAL(created.status, 201);
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    BOOST_REQUIRE_EQUAL(env["object_type"].get_str(), modelnet::HCP_TYPE_CAPABILITY_HANDOFF);
    const std::string hid = env["body"]["handoff_id"].get_str();
    BOOST_REQUIRE(!hid.empty());
    auto got = e->Handle(hcp_test::AuthReq(*e, "GET", "/handoffs/" + hid, tok));
    BOOST_REQUIRE_EQUAL(got.status, 200);
    UniValue again;
    BOOST_REQUIRE(again.read(got.body));
    BOOST_CHECK_EQUAL(again["object_type"].get_str(), modelnet::HCP_TYPE_CAPABILITY_HANDOFF);
    BOOST_CHECK_EQUAL(again["body"]["handoff_id"].get_str(), hid);
    BOOST_CHECK(again.exists("body_id"));
    BOOST_CHECK(again.exists("signature"));
    auto missing = e->Handle(hcp_test::AuthReq(*e, "GET", "/handoffs/handoff-missing", tok));
    BOOST_CHECK_EQUAL(missing.status, 404);
    auto unauth = e->Handle({.method = "GET", .path = "/handoffs/" + hid});
    BOOST_CHECK_EQUAL(unauth.status, 401);
}

BOOST_AUTO_TEST_CASE(hcp_gap_events_stream_is_sse)
{
    auto e = hcp_test::Lab();
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    e->Handle(hcp_test::AuthReq(*e, "POST", "/handoffs", tok));
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/events/stream", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(r.content_type, "text/event-stream");
    BOOST_CHECK(r.body.find("event: hcp\n") == 0);
    BOOST_CHECK(r.body.find("data: {") != std::string::npos);
    BOOST_CHECK(r.body.find("at_least_once") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_gap_research_validate_can_fail)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("title", "draft");
    auto d = e->Handle(hcp_test::AuthReq(*e, "POST", "/research/drafts", tok, &body));
    BOOST_REQUIRE_EQUAL(d.status, 201);
    UniValue dj;
    BOOST_REQUIRE(dj.read(d.body));
    const std::string did = dj["draft_id"].get_str();
    auto pub0 = e->Handle(hcp_test::AuthReq(*e, "POST", "/research/drafts/" + did + "/publish", tok));
    BOOST_CHECK_EQUAL(pub0.status, 400);
    UniValue fail(UniValue::VOBJ);
    fail.pushKV("fail", true);
    auto bad = e->Handle(hcp_test::AuthReq(*e, "POST", "/research/drafts/" + did + "/validate", tok, &fail));
    BOOST_CHECK_EQUAL(bad.status, 400);
    UniValue j;
    BOOST_REQUIRE(j.read(bad.body));
    BOOST_CHECK(j["valid"].isFalse());
    auto ok = e->Handle(hcp_test::AuthReq(*e, "POST", "/research/drafts/" + did + "/validate", tok));
    BOOST_REQUIRE_EQUAL(ok.status, 200);
    auto pub = e->Handle(hcp_test::AuthReq(*e, "POST", "/research/drafts/" + did + "/publish", tok));
    BOOST_CHECK_EQUAL(pub.status, 202);
    auto missing = e->Handle(hcp_test::AuthReq(*e, "POST", "/research/drafts/draft-missing/validate", tok));
    BOOST_CHECK_EQUAL(missing.status, 404);
}

BOOST_AUTO_TEST_CASE(hcp_gap_export_persists_and_unknown_404)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/exports", tok));
    BOOST_REQUIRE_EQUAL(created.status, 202);
    UniValue man;
    BOOST_REQUIRE(man.read(created.body));
    BOOST_REQUIRE(man.exists("export_id"));
    BOOST_CHECK(man["ready"].isFalse());
    const std::string eid = man["export_id"].get_str();
    auto got = e->Handle(hcp_test::AuthReq(*e, "GET", "/exports/" + eid, tok));
    BOOST_REQUIRE_EQUAL(got.status, 200);
    UniValue ready;
    BOOST_REQUIRE(ready.read(got.body));
    BOOST_CHECK(ready["ready"].isTrue());
    BOOST_CHECK_EQUAL(ready["export_id"].get_str(), eid);
    auto missing = e->Handle(hcp_test::AuthReq(*e, "GET", "/exports/export-missing", tok));
    BOOST_CHECK_EQUAL(missing.status, 404);
}

BOOST_AUTO_TEST_CASE(hcp_gap_economy_requires_discovery)
{
    auto e = hcp_test::Lab();
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/economy/target-demo", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    UniValue o;
    BOOST_REQUIRE(o.read(r.body));
    BOOST_CHECK(o["anchor_required_for_finance"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_gap_helper_rpc_import_report_readiness)
{
    modelnet::ModelCatalog cat{m_path_root / "hcp-gap-rpc", 1 << 20};
    UniValue result;
    std::string code, err;
    UniValue off(UniValue::VOBJ);
    off.pushKV("on", false);
    BOOST_REQUIRE(modelnet::DispatchHcpRpc(cat, "sethcpreporting", off, result, code, err));
    BOOST_CHECK(result["reporting"].isFalse());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    UniValue secrets(UniValue::VOBJ);
    secrets.pushKV("include_secrets", true);
    BOOST_CHECK(!modelnet::DispatchHcpRpc(cat, "importhcpstate", secrets, result, code, err));
    BOOST_CHECK_EQUAL(code, "SECRETS");
    UniValue ok(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHcpRpc(cat, "importhcpstate", ok, result, code, err));
    BOOST_CHECK(result["imported"].isTrue());
    BOOST_CHECK(result["secrets_omitted"].isTrue());
    BOOST_REQUIRE(modelnet::DispatchHcpRpc(cat, "gethcpreadiness", UniValue(UniValue::VOBJ), result, code, err));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(result.exists("readiness"));
    BOOST_CHECK(result["financial_receipt_is_not_runtime_ready"].isTrue());
    UniValue on(UniValue::VOBJ);
    on.pushKV("on", true);
    BOOST_REQUIRE(modelnet::DispatchHcpRpc(cat, "sethcpreporting", on, result, code, err));
    BOOST_CHECK(result["reporting"].isTrue());
}

BOOST_AUTO_TEST_SUITE_END()
