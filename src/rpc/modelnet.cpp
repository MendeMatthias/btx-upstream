// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <common/args.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/bridge.h>
#include <modelnet/policy.h>
#include <modelnet/resource_uri.h>
#include <core_io.h>
#include <node/context.h>
#include <node/transaction.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/protocol.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <txmempool.h>
#include <uint256.h>
#include <map>
#include <memory>
#include <sync.h>
#include <univalue.h>
#include <util/fs.h>

#ifdef ENABLE_WALLET
#include <interfaces/wallet.h>
#include <wallet/model_funding.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#endif

namespace {

fs::path ModelRpcSocket()
{
#ifdef ENABLE_MODELNET
    const std::string explicit_path = gArgs.GetArg("-modelrpcsocket", "");
    if (!explicit_path.empty()) return fs::PathFromString(explicit_path);
    return gArgs.GetDataDirNet() / "modelnet" / "modeld.sock";
#else
    return {};
#endif
}

bool HelperCall(const std::string& method, const UniValue& params, UniValue& result, std::string& err)
{
    return modelnet::CallUnixRpc(ModelRpcSocket(), method, params, result, err);
}

UniValue LocalNetworkInfo()
{
    const auto st = modelnet::GetModelBridge().SnapshotStatus();
    UniValue r(UniValue::VOBJ);
    r.pushKV("schema_version", 2);
    r.pushKV("enabled", true);
    r.pushKV("helper_ready", false);
    r.pushKV("pq1_ready", st.pq1_ready);
    r.pushKV("error", "btx-modeld not connected");
    r.pushKV("retrieval_default", "FREE_ONLY");
    r.pushKV("automatic_spend_atoms", 0);
    r.pushKV("capabilities", modelnet::CapabilitiesObject());
    r.pushKV("note", "A BTX node already has compute. BTX gives it models and money. Not inference-as-a-service.");
    r.pushKV("htlc", "reuses final 0.34.6 htlc_sha256 / buildhtlcclaim / buildhtlcrefund; HASH160 htlc_tx is recovery-only");
    return r;
}

#ifdef ENABLE_WALLET
std::shared_ptr<wallet::CWallet> WalletForModelFunding(const JSONRPCRequest& request)
{
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    if (!node.wallet_loader || !node.wallet_loader->context()) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND,
                           "No wallet is loaded. Load a wallet using loadwallet or create a new one with createwallet. Model funding RPCs run in btxd, not btx-modeld.");
    }
    JSONRPCRequest wallet_req = request;
    node.wallet_loader->assignContextHACK(wallet_req.context);
    return wallet::GetWalletForJSONRPCRequest(wallet_req);
}

wallet::FrozenFundingQuote QuoteFromRequest(const std::string& release_id, const UniValue& options)
{
    wallet::FrozenFundingQuote q;
    q.release_id = release_id;
    std::string err;
    if (!wallet::ParseFrozenFundingQuote(options.isNull() ? UniValue(UniValue::VOBJ) : options, q, err)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, err);
    }
    if (!release_id.empty()) q.release_id = release_id;
    UniValue helper;
    std::string helper_err;
    UniValue params(UniValue::VARR);
    if (!release_id.empty()) params.push_back(release_id);
    if (HelperCall("getmodelrelease", params, helper, helper_err)) {
        wallet::MergeHelperCampaign(helper, release_id, q);
    }
    return q;
}
#endif

RPCHelpMan ProxyOrLocal(const std::string& name, const std::string& help, std::vector<RPCArg> args)
{
    return RPCHelpMan{
        name,
        help,
        std::move(args),
        RPCResult{RPCResult::Type::OBJ, "", /*optional=*/false, "Helper result object", {
            {RPCResult::Type::ELISION, "", "helper-defined keys (rpcdoccheck-safe)"},
        }},
        RPCExamples{HelpExampleCli(name, "")},
        [name](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            UniValue params(UniValue::VARR);
            for (size_t i = 0; i < request.params.size(); ++i) params.push_back(request.params[i]);
            UniValue req(UniValue::VOBJ);
            req.pushKV("method", name);
            req.pushKV("params", params);
            UniValue result;
            std::string err;
            if (HelperCall(name, params, result, err)) return result;
            if (err.find("WALLET_REQUIRED") != std::string::npos) {
                throw JSONRPCError(RPC_WALLET_ERROR, err);
            }
            if (name == "getmodelnetworkinfo" || name == "getmodelcryptoinfo") {
                UniValue r = LocalNetworkInfo();
                r.pushKV("helper_error", err);
                return r;
            }
            throw JSONRPCError(RPC_MISC_ERROR, "model helper unavailable: " + err);
        },
    };
}

} // namespace

static RPCHelpMan getmodelnetworkinfo()
{
    return ProxyOrLocal("getmodelnetworkinfo",
                        "Return model-network helper state. Model failures never affect chain validity.\n",
                        {});
}

static RPCHelpMan getmodelcryptoinfo()
{
    return ProxyOrLocal("getmodelcryptoinfo",
                        "Return negotiated/required PQ1 suite identity for the model helper.\n",
                        {});
}

static RPCHelpMan decoderesource()
{
    return RPCHelpMan{
        "decoderesource",
        "Decode a canonical btx:// resource URI (or permitted convenience form).\n",
        {
            {"uri", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// token"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR, "uri", "canonical URI"},
                {RPCResult::Type::STR, "kind", "resource class"},
                {RPCResult::Type::STR, "digest", "SHA-384 hex"},
            }},
        RPCExamples{HelpExampleCli("decoderesource", "btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            modelnet::Resource r;
            std::string err;
            if (!modelnet::DecodeResource(request.params[0].get_str(), r, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("schema_version", 2);
            obj.pushKV("uri", r.Uri());
            obj.pushKV("kind", modelnet::ResourceKindName(r.kind));
            obj.pushKV("digest", r.digest.Hex());
            return obj;
        },
    };
}

static RPCHelpMan encoderesource()
{
    return RPCHelpMan{
        "encoderesource",
        "Encode a SHA-384 digest and resource kind as a canonical btx:// URI.\n",
        {
            {"kind", RPCArg::Type::STR, RPCArg::Optional::NO, "MODEL, ARTIFACT, COLLECTION, IDENTITY, RELEASE, POLICY_BUNDLE, CIRCLE, ALIAS, PROVIDER"},
            {"digest", RPCArg::Type::STR, RPCArg::Optional::NO, "96 lowercase hex characters"},
        },
        RPCResult{RPCResult::Type::STR, "uri", "canonical btx:// URI"},
        RPCExamples{HelpExampleCli("encoderesource", "MODEL <96-hex>")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            const std::string name = request.params[0].get_str();
            modelnet::ResourceKind kind = modelnet::ResourceKind::MODEL;
            bool found = false;
            for (int i = 0; i <= 8; ++i) {
                modelnet::ResourceKind k;
                if (modelnet::ResourceKindFromInt(i, k) && name == modelnet::ResourceKindName(k)) {
                    kind = k;
                    found = true;
                    break;
                }
            }
            if (!found) throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown resource kind");
            modelnet::Digest48 d;
            std::string err;
            if (!modelnet::Digest48::FromHex(request.params[1].get_str(), d, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            std::string uri;
            if (!modelnet::EncodeResource(kind, d, uri, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            return uri;
        },
    };
}

static RPCHelpMan getmodel()
{
    return ProxyOrLocal("getmodel",
                        "Plan or retrieve an exact model. Default mode is FREE_ONLY; automatic spend is zero.\n"
                        "A qualified public retrieve/import is demand-seeded when -modelseed=auto and storage > 0.\n",
                        {
                            {"uri", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// MODEL token or digest48 hex"},
                            {"mode", RPCArg::Type::STR, RPCArg::Default{"FREE_ONLY"}, "FREE_ONLY | FREE_FIRST_APPROVAL | FREE_FIRST_BUDGET | EXPLICIT_PAID, or an options object", RPCArgOptions{.skip_type_check = true}},
                        });
}

static RPCHelpMan listmodels()
{
    return ProxyOrLocal("listmodels", "List locally known models. Remote coverage is always incomplete.\n", {});
}

static RPCHelpMan searchmodels()
{
    return ProxyOrLocal("searchmodels", "Bounded local/remote search. Coverage is always incomplete.\n",
                        {{"query", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "query object", {
                            {"text", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "search text"},
                            {"limit", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "max results"},
                        }}});
}

static RPCHelpMan getmodelmanifest()
{
    return ProxyOrLocal("getmodelmanifest", "Return verified metadata for a known model or artifact root.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// URI or 96-hex id"}});
}

static RPCHelpMan importmodel()
{
    return ProxyOrLocal("importmodel", "Import a local file or directory, hash, chunk, and optionally pin. Never executes pickle/.pt.\n",
                        {
                            {"path", RPCArg::Type::STR, RPCArg::Optional::NO, "filesystem path"},
                            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "import options", {
                                {"pin", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "pin after import"},
                            }},
                        });
}

static RPCHelpMan seedmodel()
{
    return ProxyOrLocal("seedmodel", "Publish a free hosting offer. Default -modelseed=auto already does this after import/getmodel; required only for -modelseed=manual.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// MODEL URI or hex"}});
}

static RPCHelpMan unseedmodel()
{
    return ProxyOrLocal("unseedmodel", "Withdraw a previously published hosting offer.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// MODEL URI or hex"}});
}

static RPCHelpMan qualifymodel()
{
    return ProxyOrLocal("qualifymodel", "Static SafeTensors/GGUF check. Never a usefulness or safety claim.\n",
                        {{"path", RPCArg::Type::STR, RPCArg::Optional::NO, "filesystem path"}});
}

static RPCHelpMan addmodelnode()
{
    return ProxyOrLocal("addmodelnode", "Add a model-plane contact (not a monetary addnode; not AddrMan).\n",
                        {{"endpoint", RPCArg::Type::STR, RPCArg::Optional::NO, "host:port of a model helper"}});
}

static RPCHelpMan getmodelpeers()
{
    return ProxyOrLocal("getmodelpeers", "Inspect model-purpose contacts.\n", {});
}

static RPCHelpMan getmodeljob()
{
    return ProxyOrLocal("getmodeljob", "Job progress. Payment consequences shown when a paid job exists.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "job id"}});
}

static RPCHelpMan cancelmodeljob()
{
    return ProxyOrLocal("cancelmodeljob", "Cancel a model job and show payment consequences.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "job id"}});
}

static RPCHelpMan createmodelrelease()
{
    return ProxyOrLocal("createmodelrelease", "Commit an encrypted release campaign (secret stored as SHA-256 only). Monetary claim/refund uses 0.34.6 buildhtlcclaim / buildhtlcrefund.\n",
                        {{"body", RPCArg::Type::OBJ, RPCArg::Optional::NO, "campaign", {
                            {"uri", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "model uri"},
                            {"secret32_hex", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "32-byte secret hex; stored as SHA-256 only"},
                            {"refund_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "refund height"},
                        }}});
}

static RPCHelpMan pledgemodelrelease()
{
    return ProxyOrLocal("pledgemodelrelease", "Nonbinding local pledge accounting. Does not send BTX.\n",
                        {
                            {"release_id", RPCArg::Type::STR, RPCArg::Optional::NO, "digest48 hex"},
                            {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::NO, "atoms pledged locally"},
                        });
}

static RPCHelpMan getmodelrelease()
{
    return ProxyOrLocal("getmodelrelease", "List or inspect local campaign objects (pledge/funded/claimed are coordination state, not consensus).\n",
                        {{"release_id", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "digest48 hex"}});
}

static RPCHelpMan claimmodelrelease()
{
    return ProxyOrLocal("claimmodelrelease", "Local campaign pointer; monetary claim is buildmodelhtlcclaim (0.34.6 htlc_sha256).\n", {});
}

static RPCHelpMan refundmodelrelease()
{
    return ProxyOrLocal("refundmodelrelease", "Local campaign pointer; monetary refund is buildmodelhtlcrefund (0.34.6 htlc_sha256). HASH160 htlc_tx is recovery-only.\n", {});
}

static RPCHelpMan decoderesourceuri()
{
    return ProxyOrLocal("decoderesourceuri", "Alias of decoderesource. Pure local parse; no network.\n",
                        {{"uri", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// token"}});
}

static RPCHelpMan encoderesourceuri()
{
    return ProxyOrLocal("encoderesourceuri", "Alias of encoderesource.\n",
                        {
                            {"kind", RPCArg::Type::STR, RPCArg::Optional::NO, "MODEL | ARTIFACT | ..."},
                            {"digest", RPCArg::Type::STR, RPCArg::Optional::NO, "96-hex digest48"},
                        });
}

static RPCHelpMan openbtxuri()
{
    return ProxyOrLocal("openbtxuri", "Preview-only URI dispatch. Never runs inference, mining, or wallet spend.\n",
                        {{"uri", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// token"}});
}

static RPCHelpMan resolveresource()
{
    return ProxyOrLocal("resolveresource", "Typed lookup with incomplete coverage. Local catalog first.\n",
                        {{"query", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "digest48 / text", {
                            {"digest48", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "96-hex"},
                            {"text", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "search text"},
                        }}});
}

static RPCHelpMan exportmodelpath()
{
    return ProxyOrLocal("exportmodelpath", "Return verified local store paths. Never starts a runtime.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// URI or digest48"}});
}

static RPCHelpMan getmodelpolicy()
{
    return ProxyOrLocal("getmodelpolicy",
                        "Local free-first and propagation policy. Automatic spend default is 0.\n"
                        "Demand-seed is the default once a storage budget is allocated; unsolicited fetch requires preserve_rare.\n",
                        {});
}

static RPCHelpMan setmodelpolicy()
{
    return ProxyOrLocal("setmodelpolicy", "Update local policy. auto_pay and non-zero automatic spend are refused.\n",
                        {{"policy", RPCArg::Type::OBJ, RPCArg::Optional::NO, "policy object", {
                            {"seed", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "auto | manual | off"},
                            {"seed_upon_download", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "B0 alias of seed=auto (true) or seed=off (false); not a second opt-in"},
                            {"preserve_rare", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "fetch under-replicated qualified models into spare quota"},
                            {"retrieval_default", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "FREE_ONLY"},
                            {"upload_bps", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "serving cap in bytes/s; 0 = connection ceilings only"},
                        }}});
}

static RPCHelpMan listmodelidentities()
{
    return ProxyOrLocal("listmodelidentities", "Identity-only key store. Never wallet keys.\n", {});
}

static RPCHelpMan createmodelidentity()
{
    return ProxyOrLocal("createmodelidentity", "Create a local ML-DSA research identity. Not a spending key.\n",
                        {{"label", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "local label"}});
}

static RPCHelpMan getmodelreciprocity()
{
    return ProxyOrLocal("getmodelreciprocity", "Local useful-byte observations. Not money and not consensus.\n", {});
}

static RPCHelpMan exportmodelcontacts()
{
    return ProxyOrLocal("exportmodelcontacts", "Public model-plane contacts. No secret keys.\n", {});
}

static RPCHelpMan importmodelcontacts()
{
    return ProxyOrLocal("importmodelcontacts", "Previewed import of public endpoints. Downloading a model cannot modify trust.\n",
                        {{"peers", RPCArg::Type::ARR, RPCArg::Optional::NO, "host:port list", {
                            {"peer", RPCArg::Type::STR, RPCArg::Optional::NO, "host:port"},
                        }}});
}

static RPCHelpMan exportmodelpeers()
{
    return ProxyOrLocal("exportmodelpeers", "Alias of exportmodelcontacts.\n", {});
}

static RPCHelpMan importmodelpeers()
{
    return ProxyOrLocal("importmodelpeers", "Alias of importmodelcontacts.\n",
                        {{"peers", RPCArg::Type::ARR, RPCArg::Optional::NO, "host:port list", {
                            {"peer", RPCArg::Type::STR, RPCArg::Optional::NO, "host:port"},
                        }}});
}

static RPCHelpMan importmodeltrust()
{
    return ProxyOrLocal("importmodeltrust", "Operator-authorized peer import. Downloading a model cannot modify trusted identities.\n",
                        {{"peers", RPCArg::Type::ARR, RPCArg::Optional::NO, "host:port list", {
                            {"peer", RPCArg::Type::STR, RPCArg::Optional::NO, "host:port"},
                        }}});
}

static RPCHelpMan listmodelrules()
{
    return ProxyOrLocal("listmodelrules", "Scoped model ACL. Never writes BanMan.\n", {});
}

static RPCHelpMan setmodelrule()
{
    return ProxyOrLocal("setmodelrule", "Add a local model ACL rule. Never a monetary ban.\n",
                        {{"rule", RPCArg::Type::OBJ, RPCArg::Optional::NO, "rule object", {
                            {"deny_endpoint", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "endpoint"},
                            {"deny_artifact", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "artifact id"},
                        }}});
}

static RPCHelpMan removemodelrule()
{
    return ProxyOrLocal("removemodelrule", "Remove a local model ACL rule by index.\n",
                        {{"index", RPCArg::Type::NUM, RPCArg::Optional::NO, "rule index"}});
}

static RPCHelpMan joinmodelcircle()
{
    return ProxyOrLocal("joinmodelcircle", "Local voluntary storage/egress policy. No on-chain membership.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "circle id"}});
}

static RPCHelpMan leavemodelcircle()
{
    return ProxyOrLocal("leavemodelcircle", "Leave a local preservation circle.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "circle id"}});
}

static RPCHelpMan subscribemodelcollection()
{
    return ProxyOrLocal("subscribemodelcollection", "Local collection subscription. Preview by default.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "collection id"}});
}

static RPCHelpMan subscribemodelpolicy()
{
    return ProxyOrLocal("subscribemodelpolicy", "Local policy subscription. Does not approve spend.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "policy id"}});
}

static RPCHelpMan unsubscribemodelcollection()
{
    return ProxyOrLocal("unsubscribemodelcollection",
                        "Stop new automatic preservation for a collection. Local pins are kept. No on-chain membership.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "collection id"}});
}

static RPCHelpMan unsubscribemodelpolicy()
{
    return ProxyOrLocal("unsubscribemodelpolicy",
                        "Stop following a policy bundle. Local denials and pins remain.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "policy id"}});
}

static RPCHelpMan delegatemodelservice()
{
    return ProxyOrLocal("delegatemodelservice", "Typed root-authorized operation. Never a money signature.\n",
                        {{"body", RPCArg::Type::OBJ, RPCArg::Optional::NO, "delegation", {
                            {"delegate", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "delegate id"},
                            {"scope", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "scope"},
                        }}});
}

static RPCHelpMan revokemodelservice()
{
    return ProxyOrLocal("revokemodelservice", "Revoke a local service delegation. Never a money signature.\n",
                        {{"body", RPCArg::Type::OBJ, RPCArg::Optional::NO, "revocation", {
                            {"target_id", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "target id"},
                        }}});
}

static RPCHelpMan preparemodelfunding()
{
    return RPCHelpMan{
        "preparemodelfunding",
        "Freeze a bounded cohort and exact unsigned funding transaction paying a 0.34.6 htlc_sha256 HTLC.\n"
        "Coordinator only: never signs and never broadcasts. Claim/refund use buildhtlcclaim / buildhtlcrefund.\n",
        {
            {"release_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Campaign release id (digest48 hex). An options object may be passed as the first argument instead.", RPCArgOptions{.skip_type_check = true}},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Funding terms if the model helper is unavailable", {
                {"key_hash", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "32-byte SHA-256 hex of the release secret"},
                {"claimant", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "PQ claimant pubkey hex (or pk_slh(...))"},
                {"claimant_pubkey", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Alias of claimant"},
                {"refund_pubkey", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "PQ refund pubkey hex"},
                {"refund_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "CLTV refund height"},
                {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "HTLC output value in atoms"},
                {"fee_cap_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Maximum network fee in atoms"},
                {"max_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Alias of amount_atoms / approval ceiling"},
                {"auto_pay", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Must be false; automatic spend is zero"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "frozen quote fields (key_hash, claimant, refund_*, amount, fee, scripts, note)"},
            {RPCResult::Type::NUM, "schema_version", "2"},
            {RPCResult::Type::BOOL, "frozen", "true"},
            {RPCResult::Type::STR_HEX, "unsigned_hex", "Unsigned funding transaction"},
            {RPCResult::Type::STR, "descriptor", "mr(htlc_sha256(...),refund(...))"},
            {RPCResult::Type::NUM, "fee_cap_atoms", "Fee ceiling"},
            {RPCResult::Type::NUM, "automatic_spend", "Always 0"},
            {RPCResult::Type::STR, "htlc", "Always htlc_sha256"},
        }},
        RPCExamples{HelpExampleCli("preparemodelfunding", "\"<release_id>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            std::string release_id;
            UniValue options(UniValue::VOBJ);
            if (request.params[0].isStr()) {
                release_id = request.params[0].get_str();
                if (!request.params[1].isNull()) options = request.params[1];
            } else if (request.params[0].isObject()) {
                options = request.params[0];
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "release_id string or options object required");
            }
            wallet::FrozenFundingQuote q = QuoteFromRequest(release_id, options);
            if (q.amount_atoms == 0 && options.exists("max_atoms") && options["max_atoms"].isNum()) {
                q.amount_atoms = options["max_atoms"].getInt<int64_t>();
            }
            std::string err;
            if (!wallet::ValidateFundingAmount(q.amount_atoms, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            if (!wallet::BuildHtlcSha256Descriptor(q, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            auto pwallet = WalletForModelFunding(request);
            if (!wallet::CreateUnsignedFunding(*pwallet, q, err)) {
                const bool funds = err.find("nsufficient") != std::string::npos;
                throw JSONRPCError(funds ? RPC_WALLET_INSUFFICIENT_FUNDS : RPC_WALLET_ERROR, err);
            }
            return wallet::FrozenQuoteToJson(q);
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}

static RPCHelpMan signmodelfunding()
{
    return RPCHelpMan{
        "signmodelfunding",
        "Validate and sign an exact frozen model-funding transaction through wallet policy.\n"
        "Txid mutation or HTLC output-script change is rejected; run preparemodelfunding again.\n"
        "Never auto_pay. Never broadcasts.\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Unsigned (or partially signed) funding transaction hex"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Frozen quote from preparemodelfunding", {
                {"unsigned_hex", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Exact unsigned template hex from prepare"},
                {"unsigned_txid", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Frozen unsigned txid"},
                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "mr(htlc_sha256(...),refund(...))"},
                {"output_script", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "HTLC scriptPubKey hex"},
                {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Frozen HTLC output value"},
                {"key_hash", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "SHA-256 hex"},
                {"claimant", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "claimant pubkey"},
                {"refund_pubkey", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "refund pubkey"},
                {"refund_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "refund height"},
                {"auto_pay", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Must be false"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "echoed frozen quote fields"},
            {RPCResult::Type::NUM, "schema_version", "2"},
            {RPCResult::Type::STR_HEX, "hex", "Signed transaction hex"},
            {RPCResult::Type::BOOL, "complete", "Whether all inputs are signed"},
            {RPCResult::Type::NUM, "automatic_spend", "Always 0"},
            {RPCResult::Type::STR, "htlc", "Always htlc_sha256"},
        }},
        RPCExamples{HelpExampleCli("signmodelfunding", "\"<hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            UniValue options(UniValue::VOBJ);
            std::string hex;
            if (request.params[0].isStr()) {
                hex = request.params[0].get_str();
                if (!request.params[1].isNull()) options = request.params[1];
            } else if (request.params[0].isObject()) {
                options = request.params[0];
                if (!options.exists("hex") || !options["hex"].isStr()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "hex required");
                }
                hex = options["hex"].get_str();
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "hex required");
            }
            wallet::FrozenFundingQuote frozen = QuoteFromRequest(/*release_id=*/"", options);
            std::string err;
            CMutableTransaction mtx;
            if (!wallet::DecodeFundingTxHex(hex, mtx, err)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
            }
            if (!wallet::MatchFrozenTemplate(frozen, mtx, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            auto pwallet = WalletForModelFunding(request);
            bool complete{false};
            if (!wallet::SignFrozenFunding(*pwallet, mtx, complete, err)) {
                throw JSONRPCError(RPC_WALLET_ERROR, err);
            }
            UniValue out(UniValue::VOBJ);
            out.pushKV("schema_version", 2);
            out.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
            out.pushKV("complete", complete);
            out.pushKV("txid", mtx.GetHash().GetHex());
            out.pushKV("frozen", true);
            out.pushKV("automatic_spend", 0);
            out.pushKV("htlc", "htlc_sha256");
            if (!complete && !err.empty()) out.pushKV("error", err);
            return out;
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}

static RPCHelpMan submitmodelfunding()
{
    return RPCHelpMan{
        "submitmodelfunding",
        "Revalidate a signed model-funding transaction and broadcast it.\n"
        "A duplicate txid is reported and is not double-spent.\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Signed funding transaction hex"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Frozen quote from preparemodelfunding", {
                {"unsigned_hex", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Exact unsigned template hex from prepare"},
                {"unsigned_txid", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Frozen unsigned txid"},
                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "mr(htlc_sha256(...),refund(...))"},
                {"output_script", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "HTLC scriptPubKey hex"},
                {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Frozen HTLC output value"},
                {"auto_pay", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Must be false"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "echoed frozen quote fields"},
            {RPCResult::Type::NUM, "schema_version", "2"},
            {RPCResult::Type::STR_HEX, "txid", "Broadcast or duplicate txid"},
            {RPCResult::Type::BOOL, "submitted", "true if this call introduced the tx"},
            {RPCResult::Type::BOOL, "duplicate", "true if the txid was already known"},
            {RPCResult::Type::NUM, "automatic_spend", "Always 0"},
            {RPCResult::Type::STR, "htlc", "Always htlc_sha256"},
        }},
        RPCExamples{HelpExampleCli("submitmodelfunding", "\"<hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            UniValue options(UniValue::VOBJ);
            std::string hex;
            if (request.params[0].isStr()) {
                hex = request.params[0].get_str();
                if (!request.params[1].isNull()) options = request.params[1];
            } else if (request.params[0].isObject()) {
                options = request.params[0];
                if (!options.exists("hex") || !options["hex"].isStr()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "hex required");
                }
                hex = options["hex"].get_str();
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "hex required");
            }
            std::string err;
            CMutableTransaction mtx;
            if (!wallet::DecodeFundingTxHex(hex, mtx, err)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
            }
            if (options.isObject() && !options.empty()) {
                wallet::FrozenFundingQuote frozen = QuoteFromRequest(/*release_id=*/"", options);
                if (!frozen.unsigned_txid.IsNull() || !frozen.output_script.empty()) {
                    if (!wallet::MatchFrozenTemplate(frozen, mtx, err)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, err);
                    }
                }
            }
            const uint256 txid = mtx.GetHash().ToUint256();
            node::NodeContext& node = EnsureAnyNodeContext(request.context);
            std::shared_ptr<wallet::CWallet> pwallet;
            try {
                pwallet = WalletForModelFunding(request);
            } catch (const UniValue&) {
                pwallet = nullptr;
            }
            bool duplicate = false;
            if (pwallet) {
                LOCK(pwallet->cs_wallet);
                if (pwallet->GetWalletTx(txid)) duplicate = true;
            }
            if (node.mempool && node.mempool->exists(GenTxid::Txid(txid))) duplicate = true;

            auto result_obj = [&](bool submitted, bool dup) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("schema_version", 2);
                o.pushKV("txid", txid.GetHex());
                o.pushKV("submitted", submitted);
                o.pushKV("duplicate", dup);
                o.pushKV("automatic_spend", 0);
                o.pushKV("htlc", "htlc_sha256");
                return o;
            };
            if (duplicate) return result_obj(false, true);

            CTransactionRef tx = MakeTransactionRef(std::move(mtx));
            std::string bcast_err;
            const node::TransactionError terr = node::BroadcastTransaction(
                node, tx, bcast_err, node::DEFAULT_MAX_RAW_TX_FEE_RATE, /*relay=*/true, /*wait_callback=*/true);
            if (terr == node::TransactionError::ALREADY_IN_UTXO_SET) {
                return result_obj(false, true);
            }
            if (terr != node::TransactionError::OK) {
                throw JSONRPCTransactionError(terr, bcast_err);
            }
            if (pwallet) {
                wallet::mapValue_t map_value;
                map_value["modelnet"] = "funding";
                pwallet->CommitTransaction(tx, std::move(map_value), /*orderForm=*/{});
            }
            return result_obj(true, false);
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}

static RPCHelpMan exportmodelrecovery()
{
    return RPCHelpMan{
        "exportmodelrecovery",
        "Export public recovery material for a model-funding HTLC (descriptor, key_hash, refund height, addresses).\n"
        "Never dumps wallet seeds or ML-DSA service secret keys.\n",
        {
            {"release_id", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Campaign release id (digest48 hex)", RPCArgOptions{.skip_type_check = true}},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Public terms if the helper is unavailable", {
                {"key_hash", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "32-byte SHA-256 hex"},
                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "mr(htlc_sha256(...),refund(...))"},
                {"claimant", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "PQ claimant pubkey hex"},
                {"refund_pubkey", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "PQ refund pubkey hex"},
                {"refund_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "CLTV refund height"},
                {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "HTLC output value"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "schema_version", "2"},
            {RPCResult::Type::STR, "descriptor", "Public descriptor"},
            {RPCResult::Type::STR, "key_hash", "SHA-256 hashlock"},
            {RPCResult::Type::NUM, "refund_height", "CLTV height"},
            {RPCResult::Type::BOOL, "secrets", "Always false"},
        }},
        RPCExamples{HelpExampleCli("exportmodelrecovery", "\"<release_id>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            std::string release_id;
            UniValue options(UniValue::VOBJ);
            if (!request.params[0].isNull()) {
                if (request.params[0].isStr()) {
                    release_id = request.params[0].get_str();
                } else if (request.params[0].isObject()) {
                    options = request.params[0];
                }
            }
            if (!request.params[1].isNull() && request.params[1].isObject()) {
                options = request.params[1];
            }
            wallet::FrozenFundingQuote q = QuoteFromRequest(release_id, options);
            std::string err;
            if (q.descriptor.empty() && !q.key_hash_hex.empty() && !q.claimant_key.empty() &&
                !q.refund_key.empty() && q.refund_height > 0) {
                if (!wallet::BuildHtlcSha256Descriptor(q, err)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, err);
                }
            } else if (!q.descriptor.empty() && q.output_script.empty()) {
                std::string canonical;
                if (!wallet::ExpandHtlcSha256Descriptor(q.descriptor, q.output_script, canonical, err)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, err);
                }
                q.descriptor = canonical;
            }
            UniValue out = wallet::ExportModelRecoveryJson(q);
            if (q.descriptor.empty() && q.key_hash_hex.empty()) {
                out.pushKV("error", "no public recovery material; pass descriptor/key_hash or a known release_id");
            }
            return out;
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}

static RPCHelpMan buildmodelhtlcclaim()
{
    return ProxyOrLocal("buildmodelhtlcclaim",
                        "Build an unsigned 0.34.6 htlc_sha256 claim (SHA-256 preimage). HASH160 htlc_tx is recovery-only.\n"
                        "The helper never holds wallet keys: complete=false until the tx is signed.\n",
                        {
                            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Claim terms", {
                                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "mr(htlc_sha256(...),refund(...))"},
                                {"preimage", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "SHA-256 preimage hex"},
                                {"prevout", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Funding outpoint", {
                                    {"txid", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Funding txid"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Output index"},
                                }},
                                {"destination", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Claim destination address"},
                                {"destination_script", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Claim scriptPubKey hex"},
                                {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "HTLC output value"},
                                {"fee_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Absolute fee"},
                            }},
                        });
}

static RPCHelpMan buildmodelhtlcrefund()
{
    return ProxyOrLocal("buildmodelhtlcrefund",
                        "Build an unsigned 0.34.6 htlc_sha256 refund (CLTV). HASH160 htlc_tx is recovery-only.\n",
                        {
                            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Refund terms", {
                                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "mr(htlc_sha256(...),refund(...))"},
                                {"refund_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "CLTV height"},
                                {"prevout", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Funding outpoint", {
                                    {"txid", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Funding txid"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Output index"},
                                }},
                                {"destination", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Refund destination address"},
                                {"destination_script", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Refund scriptPubKey hex"},
                                {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "HTLC output value"},
                                {"fee_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Absolute fee"},
                            }},
                        });
}

void RegisterModelNetRPCCommands(CRPCTable& t)
{
#ifdef ENABLE_MODELNET
    static const CRPCCommand commands[]{
        {"modelnet", &getmodelnetworkinfo},
        {"modelnet", &getmodelcryptoinfo},
        {"modelnet", &decoderesource},
        {"modelnet", &encoderesource},
        {"modelnet", &decoderesourceuri},
        {"modelnet", &encoderesourceuri},
        {"modelnet", &openbtxuri},
        {"modelnet", &resolveresource},
        {"modelnet", &getmodel},
        {"modelnet", &listmodels},
        {"modelnet", &searchmodels},
        {"modelnet", &getmodelmanifest},
        {"modelnet", &importmodel},
        {"modelnet", &seedmodel},
        {"modelnet", &unseedmodel},
        {"modelnet", &qualifymodel},
        {"modelnet", &addmodelnode},
        {"modelnet", &getmodelpeers},
        {"modelnet", &getmodeljob},
        {"modelnet", &cancelmodeljob},
        {"modelnet", &exportmodelpath},
        {"modelnet", &getmodelpolicy},
        {"modelnet", &setmodelpolicy},
        {"modelnet", &listmodelidentities},
        {"modelnet", &createmodelidentity},
        {"modelnet", &getmodelreciprocity},
        {"modelnet", &exportmodelcontacts},
        {"modelnet", &importmodelcontacts},
        {"modelnet", &exportmodelpeers},
        {"modelnet", &importmodelpeers},
        {"modelnet", &importmodeltrust},
        {"modelnet", &listmodelrules},
        {"modelnet", &setmodelrule},
        {"modelnet", &removemodelrule},
        {"modelnet", &joinmodelcircle},
        {"modelnet", &leavemodelcircle},
        {"modelnet", &subscribemodelcollection},
        {"modelnet", &subscribemodelpolicy},
        {"modelnet", &unsubscribemodelcollection},
        {"modelnet", &unsubscribemodelpolicy},
        {"modelnet", &delegatemodelservice},
        {"modelnet", &revokemodelservice},
        {"modelnet", &createmodelrelease},
        {"modelnet", &pledgemodelrelease},
        {"modelnet", &getmodelrelease},
        {"modelnet", &claimmodelrelease},
        {"modelnet", &refundmodelrelease},
        {"modelnet", &preparemodelfunding},
        {"modelnet", &signmodelfunding},
        {"modelnet", &submitmodelfunding},
        {"modelnet", &exportmodelrecovery},
        {"modelnet", &buildmodelhtlcclaim},
        {"modelnet", &buildmodelhtlcrefund},
    };
    for (const auto& c : commands) t.appendCommand(c.name, &c);
#else
    (void)t;
#endif
}
