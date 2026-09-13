// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <modelnet/bridge.h>
#include <modelnet/policy.h>
#include <modelnet/resource_uri.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <univalue.h>

static RPCHelpMan getmodelnetworkinfo()
{
    return RPCHelpMan{
        "getmodelnetworkinfo",
        "Return model-network helper state. Model failures never affect chain validity.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::BOOL, "enabled", "compiled with WITH_MODELNET"},
                {RPCResult::Type::BOOL, "helper_ready", ""},
                {RPCResult::Type::BOOL, "pq1_ready", "strict ML-KEM-768 / ML-DSA-44 / AES-256-GCM-SHA384"},
                {RPCResult::Type::STR, "error", "fail-closed reason if any"},
                {RPCResult::Type::STR, "retrieval_default", "FREE_ONLY; automatic spend is zero"},
                {RPCResult::Type::STR, "note", "not a remote inference service"},
            }},
        RPCExamples{HelpExampleCli("getmodelnetworkinfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            (void)request;
            const auto st = modelnet::GetModelBridge().SnapshotStatus();
            UniValue r(UniValue::VOBJ);
            r.pushKV("enabled", true);
            r.pushKV("helper_ready", st.helper_ready);
            r.pushKV("pq1_ready", st.pq1_ready);
            r.pushKV("error", st.helper_error);
            r.pushKV("retrieval_default", "FREE_ONLY");
            r.pushKV("automatic_spend_atoms", 0);
            r.pushKV("note", "A BTX node already has compute. BTX gives it models and money. Not inference-as-a-service.");
            r.pushKV("htlc", "reuses final 0.34.6 htlc_sha256 / buildhtlcclaim / buildhtlcrefund; HASH160 htlc_tx is recovery-only");
            return r;
        },
    };
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
    return RPCHelpMan{
        "getmodel",
        "Plan retrieval of an exact btx:// model. Default mode is FREE_ONLY; automatic spend is zero.\n",
        {
            {"uri", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// MODEL token"},
            {"mode", RPCArg::Type::STR, RPCArg::Default{"FREE_ONLY"}, "FREE_ONLY | FREE_FIRST_APPROVAL | FREE_FIRST_BUDGET | EXPLICIT_PAID"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR, "plan", "FREE / WAIT_FREE / PAID / APPROVAL_REQUIRED"},
                {RPCResult::Type::STR, "uri", ""},
            }},
        RPCExamples{HelpExampleCli("getmodel", "btx://...")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            modelnet::Resource r;
            std::string err;
            if (!modelnet::DecodeResource(request.params[0].get_str(), r, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            if (r.kind != modelnet::ResourceKind::MODEL) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "resource is not a MODEL");
            }
            modelnet::RetrievalMode mode = modelnet::RetrievalMode::FREE_ONLY;
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                if (!modelnet::RetrievalModeFromName(request.params[1].get_str(), mode)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown retrieval mode");
                }
            }
            modelnet::PlanChoice choice;
            if (!modelnet::ChoosePlan(mode, std::nullopt, nullptr, 0, true, std::nullopt, 0, false, choice, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("uri", r.Uri());
            obj.pushKV("plan", modelnet::PlanChoiceName(choice));
            obj.pushKV("automatic_spend_atoms", 0);
            return obj;
        },
    };
}

static RPCHelpMan listmodels()
{
    return RPCHelpMan{
        "listmodels",
        "List locally known models. Remote coverage is always incomplete.\n",
        {},
        RPCResult{RPCResult::Type::ARR, "", "", {{RPCResult::Type::OBJ, "", "", {}}}},
        RPCExamples{HelpExampleCli("listmodels", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            (void)request;
            UniValue arr(UniValue::VARR);
            UniValue note(UniValue::VOBJ);
            note.pushKV("coverage", "incomplete");
            note.pushKV("local_count", 0);
            arr.push_back(note);
            return arr;
        },
    };
}

static RPCHelpMan addmodelnode()
{
    return RPCHelpMan{
        "addmodelnode",
        "Add a model-plane contact (not a monetary addnode; not AddrMan).\n",
        {
            {"endpoint", RPCArg::Type::STR, RPCArg::Optional::NO, "host:port of a model helper"},
        },
        RPCResult{RPCResult::Type::BOOL, "", ""},
        RPCExamples{HelpExampleCli("addmodelnode", "127.0.0.1:18445")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            modelnet::BoundedModelHint hint;
            hint.from_addr = request.params[0].get_str();
            return modelnet::GetModelBridge().TryEnqueuePublicHint(std::move(hint));
        },
    };
}

void RegisterModelNetRPCCommands(CRPCTable& t)
{
#ifdef ENABLE_MODELNET
    static const CRPCCommand commands[]{
        {"modelnet", &getmodelnetworkinfo},
        {"modelnet", &decoderesource},
        {"modelnet", &encoderesource},
        {"modelnet", &getmodel},
        {"modelnet", &listmodels},
        {"modelnet", &addmodelnode},
    };
    for (const auto& c : commands) t.appendCommand(c.name, &c);
#else
    (void)t;
#endif
}
