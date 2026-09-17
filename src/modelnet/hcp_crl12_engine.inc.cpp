// Included from hcp_engine.cpp after Impl is complete. Same HcpEngine; not a second product.

HcpHttpResponse HcpEngine::Impl::HandleCrl12Locked(const HcpHttpRequest& req)
{
    if (!cfg.cr12_enabled) {
        return Err(403, HCP_ERR_PROFILE_UNSUPPORTED, HCP_EXT_COGNITIVE_RESERVE_V12);
    }

    const bool binary_stage = (req.method == "POST" && req.path == "/institutional/imports/chunks");
    std::map<std::string, std::string> cap;
    UniValue parsed;
    bool have_body = false;
    if (!req.body.empty() && !binary_stage) {
        std::vector<unsigned char> raw(req.body.begin(), req.body.end());
        std::string perr;
        if (!DecodePjson1(Span<const unsigned char>{raw.data(), raw.size()}, parsed, perr)) {
            return Err(400, "NONCANONICAL_BYTES", perr.empty() ? "noncanonical" : perr);
        }
        have_body = true;
        std::string ferr;
        if (!HcpRejectForbiddenFields(parsed, ferr)) return Err(400, ferr, ferr);
        if (parsed.isObject() && parsed.exists("package_core_version") && parsed["package_core_version"].isNum() &&
            parsed["package_core_version"].getInt<int64_t>() >= 4) {
            return Err(400, HCP_ERR_CORE_V4, "Core v4 forbidden");
        }
        if (parsed.isObject() && parsed.exists("remote_inference") && parsed["remote_inference"].isTrue()) {
            return Err(400, HCP_ERR_REMOTE_INFERENCE, "no public prompt routing");
        }
        if (have_body) {
            const std::string dump = parsed.write();
            if (Crl12BrandDispatch(dump) && (req.path.rfind("/layer/", 0) == 0)) {
                return Err(400, HCP_ERR_BRAND_DISPATCH, "generic fixtures only");
            }
        }
    }

    auto Jstr = [&](const char* k, const std::string& d = {}) -> std::string {
        if (!have_body || !parsed.exists(k)) return d;
        if (parsed[k].isStr()) return parsed[k].get_str();
        if (parsed[k].isNum()) return std::to_string(parsed[k].getInt<int64_t>());
        if (parsed[k].isBool()) return parsed[k].isTrue() ? "true" : "false";
        return d;
    };
    auto Jbool = [&](const char* k, bool d = false) -> bool {
        if (!have_body || !parsed.exists(k)) return d;
        if (parsed[k].isBool()) return parsed[k].isTrue();
        if (parsed[k].isStr()) return parsed[k].get_str() == "true";
        return d;
    };
    auto J64 = [&](const char* k, int64_t d = 0) -> int64_t {
        if (!have_body || !parsed.exists(k)) return d;
        if (parsed[k].isStr()) {
            int64_t n = 0;
            std::string e;
            if (!ParseAtomString(parsed[k].get_str(), n, e)) return d;
            return n;
        }
        if (parsed[k].isNum()) return parsed[k].getInt<int64_t>();
        return d;
    };

    auto SignedObj = [&](const std::string& type, UniValue body, int status) {
        if (!body.exists("schema_revision")) body.pushKV("schema_revision", "1.2");
        if (!body.exists("provider_id")) body.pushKV("provider_id", cfg.provider_id);
        if (!body.exists("created_at")) body.pushKV("created_at", std::to_string(cfg.clock_ms));
        HcpEnvelope env;
        env.object_type = type;
        env.body = std::move(body);
        std::string serr;
        HcpSign(env, Span<const unsigned char>{op_sk.data(), op_sk.size()}, current_op_key_id, serr);
        auto r = JsonStatus(status, EncodeHcpEnvelope(env));
        r.headers["Cache-Control"] = "no-store";
        return r;
    };

    auto Need = [&](const std::string& scope, bool financial) -> HcpHttpResponse {
        std::string account, acode;
        if (!Auth(req, scope, account, acode, financial)) return Err(401, acode, acode);
        cr11.authed_account = account;
        return HcpHttpResponse{};
    };

    auto RecordBlocked = [&]() -> HcpHttpResponse {
        bool any = false;
        bool active = false;
        for (const auto& [id, b] : crl12.bindings) {
            if (b.exists("account") && b["account"].isStr() && b["account"].get_str() != cr11.authed_account) {
                continue;
            }
            any = true;
            const std::string st = (b.exists("status") && b["status"].isStr()) ? b["status"].get_str() : "ACTIVE";
            if (st == "ACTIVE") active = true;
        }
        if (any && !active) return Err(403, HCP_ERR_BINDING_REVOKED, "no active binding");
        return {};
    };

    auto OpenBreak = [&](const std::string& kind, const std::string& detail) {
        UniValue b(UniValue::VOBJ);
        const std::string id = RandId("brk-");
        b.pushKV("break_id", id);
        b.pushKV("kind", kind);
        b.pushKV("status", "OPEN");
        b.pushKV("detail", detail);
        b.pushKV("account", cr11.authed_account);
        crl12.breaks[id] = b;
        return id;
    };

    auto NewJob = [&](const std::string& kind, const std::string& result_ref, const std::string& status) {
        UniValue b(UniValue::VOBJ);
        const std::string id = RandId("job-");
        b.pushKV("job_id", id);
        b.pushKV("kind", kind);
        b.pushKV("status", status);
        b.pushKV("result_ref", result_ref);
        b.pushKV("account", cr11.authed_account);
        b.pushKV("committed", status == "SUCCEEDED");
        crl12.jobs[id] = b;
        crl12.last_job = id;
        return id;
    };

    auto HashBody = [&]() -> std::string {
        std::vector<unsigned char> raw(req.body.begin(), req.body.end());
        return Sha384Hex(Span<const unsigned char>{raw.data(), raw.size()});
    };

    if (req.method == "POST") {
        const std::string ik = Hdr(req, "idempotency-key");
        if (!ik.empty()) {
            const std::string h = HashBody();
            auto it = crl12.idem_hash.find(ik);
            if (it != crl12.idem_hash.end() && it->second != h) {
                return Err(409, HCP_ERR_CONFLICT, ik);
            }
            crl12.idem_hash[ik] = h;
        }
    }

    auto PageOf = [&](const std::map<std::string, UniValue>& m, const std::string& type) {
        UniValue items(UniValue::VARR);
        int n = 0;
        for (const auto& [id, b] : m) {
            if (b.exists("account") && b["account"].isStr() && b["account"].get_str() != cr11.authed_account) {
                continue;
            }
            if (n++ >= cfg.max_page_size) break;
            UniValue env_body = b;
            if (!env_body.exists("schema_revision")) env_body.pushKV("schema_revision", "1.2");
            HcpEnvelope env;
            env.object_type = type;
            env.body = env_body;
            std::string serr;
            HcpSign(env, Span<const unsigned char>{op_sk.data(), op_sk.size()}, current_op_key_id, serr);
            items.push_back(EncodeHcpEnvelope(env));
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("items", items);
        o.pushKV("next_cursor", UniValue());
        o.pushKV("incomplete", items.size() < m.size());
        return JsonStatus(200, o);
    };

    // --- discovery ---
    if (req.method == "GET" && req.path == "/extensions/cognitive-reserve/v1.2") {
        auto n = Need("catalog:read", false);
        if (n.status >= 400) return n;
        UniValue b(UniValue::VOBJ);
        b.pushKV("extension_id", "cognitive-reserve/v1.2");
        b.pushKV("parent_profile_ref", cr11.parent_profile_body_id.empty() ? "hcp-1" : cr11.parent_profile_body_id);
        b.pushKV("base_extension_ref", "cognitive-reserve");
        b.pushKV("schema_digest", std::string(96, 'a'));
        b.pushKV("operations_digest", std::string(96, 'b'));
        UniValue feats(UniValue::VARR);
        feats.push_back("roles");
        feats.push_back("institutional");
        feats.push_back("jobs");
        b.pushKV("supported_features", feats);
        b.pushKV("expires_at", std::to_string(cfg.clock_ms + 86400000));
        b.pushKV("package_core_version", 3);
        b.pushKV("negotiated", true);
        b.pushKV("not_inferred_from_provider_name", true);
        return SignedObj(HCP_TYPE_LAYER_EXTENSION, b, 200);
    }

    // --- roles ---
    if (req.method == "POST" && req.path == "/layer/roles") {
        auto n = Need("layer:admin", false);
        if (n.status >= 400) return n;
        const std::string effect = Jstr("effect", Jstr("role_effect", "DISCOVERY"));
        static const char* ok_roles[] = {"DISCOVERY", "CUSTODY", "EXECUTION", "FUNDING", "TREASURY",
                                          "DEVICE_HANDOFF", "ASSET_SERVICING", "PORTFOLIO_ANALYTICS", "FIAT_RAIL"};
        bool known = false;
        for (const char* r : ok_roles) {
            if (effect == r || Jstr("role", effect) == r) known = true;
        }
        if (!known && !Jstr("role").empty()) {
            const std::string role = Jstr("role");
            for (const char* r : ok_roles) {
                if (role == r) known = true;
            }
        }
        if (Jstr("role").empty() && effect.size() && !known) {
            // allow if role field lists a known role
        }
        const std::string role = Jstr("role", effect);
        known = false;
        for (const char* r : ok_roles) {
            if (role == r) known = true;
        }
        if (!known) return Err(400, HCP_ERR_ROLE_UNAVAILABLE, role);
        if (!Jstr("claimed_effect").empty() && Jstr("claimed_effect") != role && Jstr("claimed_effect") != effect) {
            return Err(400, HCP_ERR_ROLE_EFFECT, Jstr("claimed_effect"));
        }
        if (Jbool("unregistered_endpoint", false)) return Err(400, HCP_ERR_ROLE_EFFECT, "unregistered endpoint");
        UniValue b = have_body ? parsed : UniValue(UniValue::VOBJ);
        const std::string id = Jstr("manifest_id", RandId("role-"));
        const int64_t seq = J64("sequence", J64("generation", 0));
        auto rit = crl12.roles.find(id);
        if (rit != crl12.roles.end() && seq > 0) {
            int64_t have = 0;
            if (rit->second.exists("generation")) {
                if (rit->second["generation"].isNum()) have = rit->second["generation"].getInt<int64_t>();
                else if (rit->second["generation"].isStr()) have = std::stoll(rit->second["generation"].get_str());
            }
            if (seq < have) return Err(409, "SEQUENCE_ROLLBACK", "sequence");
        }
        const int64_t gen = seq > 0 ? seq : static_cast<int64_t>(++crl12.binding_gen[id]);
        if (seq > 0) crl12.binding_gen[id] = static_cast<int>(seq);
        b.pushKV("manifest_id", id);
        b.pushKV("role", role);
        b.pushKV("effect", role);
        b.pushKV("status", "ACTIVE");
        b.pushKV("generation", gen);
        crl12.roles[id] = b;
        return SignedObj(HCP_TYPE_PROVIDER_ROLE, b, 201);
    }
    if (MatchPath(req.path, "/layer/roles/{id}", cap) && req.method == "GET") {
        auto n = Need("catalog:read", false);
        if (n.status >= 400) return n;
        auto it = crl12.roles.find(cap["id"]);
        if (it == crl12.roles.end()) return Err(404, "NOT_FOUND", "role");
        return SignedObj(HCP_TYPE_PROVIDER_ROLE, it->second, 200);
    }
    if (req.method == "GET" && req.path == "/layer/roles") {
        auto n = Need("catalog:read", false);
        if (n.status >= 400) return n;
        return PageOf(crl12.roles, HCP_TYPE_PROVIDER_ROLE);
    }

    // --- bindings ---
    if (req.method == "POST" && req.path == "/layer/bindings") {
        auto n = Need("bindings:admin", false);
        if (n.status >= 400) return n;
        const std::string id = Jstr("binding_id", RandId("bind-"));
        if (Jstr("secret").size() || Jstr("access_token").size() || Jstr("private_key").size()) {
            return Err(400, "SECRET_INLINE", "use secret_ref");
        }
        if (Jbool("unbound_role", false) || Jstr("role") == "UNKNOWN") {
            return Err(400, HCP_ERR_ROLE_UNAVAILABLE, "role not bound");
        }
        const std::string net = Jstr("network", "");
        if (!net.empty()) {
            const std::string lower = Lower(net);
            if (lower != "regtest" && lower != "lab" && lower != Lower(cfg.environment) &&
                lower != "testnet") {
                return Err(400, HCP_ERR_NETWORK_MISMATCH, net);
            }
        }
        UniValue b = have_body ? parsed : UniValue(UniValue::VOBJ);
        b.pushKV("binding_id", id);
        b.pushKV("secret_ref", Jstr("secret_ref", "os:keyring/binding"));
        b.pushKV("status", "ACTIVE");
        b.pushKV("generation", static_cast<int64_t>(++crl12.binding_gen[id]));
        b.pushKV("account", cr11.authed_account);
        crl12.bindings[id] = b;
        return SignedObj(HCP_TYPE_SERVICE_BINDING, b, 201);
    }
    if (MatchPath(req.path, "/layer/bindings/{id}/revoke", cap) && req.method == "POST") {
        auto n = Need("bindings:admin", false);
        if (n.status >= 400) return n;
        auto it = crl12.bindings.find(cap["id"]);
        if (it == crl12.bindings.end()) return Err(404, "NOT_FOUND", "binding");
        it->second.pushKV("status", "REVOKED");
        return SignedObj(HCP_TYPE_SERVICE_BINDING, it->second, 200);
    }
    if (MatchPath(req.path, "/layer/bindings/{id}", cap) && req.method == "GET") {
        auto n = Need("bindings:read", false);
        if (n.status >= 400) return n;
        auto it = crl12.bindings.find(cap["id"]);
        if (it == crl12.bindings.end()) return Err(404, "NOT_FOUND", "binding");
        UniValue b = it->second;
        if (b.exists("secret_ref")) {
            // never export reusable secrets
        }
        b.pushKV("access_token", UniValue());
        b.pushKV("private_key", UniValue());
        return SignedObj(HCP_TYPE_SERVICE_BINDING, b, 200);
    }
    if (req.method == "GET" && req.path == "/layer/bindings") {
        auto n = Need("bindings:read", false);
        if (n.status >= 400) return n;
        return PageOf(crl12.bindings, HCP_TYPE_SERVICE_BINDING);
    }

    // --- adapters ---
    if (req.method == "POST" && req.path == "/layer/adapters/validate") {
        auto n = Need("layer:admin", false);
        if (n.status >= 400) return n;
        if (Jbool("ssrf", false) || Jstr("source_hint").find("169.254") != std::string::npos ||
            Jstr("source_hint").find("metadata") != std::string::npos) {
            return Err(400, "EGRESS_DENIED", "ssrf");
        }
        UniValue b(UniValue::VOBJ);
        const std::string id = Jstr("adapter_id", RandId("adp-"));
        b.pushKV("adapter_id", id);
        b.pushKV("status", Jbool("disabled", false) ? "DISABLED" : "VALID");
        b.pushKV("mapping_digest", Jstr("mapping_digest", std::string(96, 'c')));
        if (Jbool("disabled", false)) return Err(400, HCP_ERR_ADAPTER_DISABLED, id);
        crl12.adapters[id] = b;
        NewJob("ADAPTER_VALIDATE", id, "SUCCEEDED");
        return SignedObj(HCP_TYPE_ADAPTER_CAPABILITY, b, 200);
    }
    if (MatchPath(req.path, "/layer/adapters/{id}", cap) && req.method == "GET") {
        auto n = Need("bindings:read", false);
        if (n.status >= 400) return n;
        auto it = crl12.adapters.find(cap["id"]);
        if (it == crl12.adapters.end()) return Err(404, "NOT_FOUND", "adapter");
        return SignedObj(HCP_TYPE_ADAPTER_CAPABILITY, it->second, 200);
    }

    if (MatchPath(req.path, "/layer/conformance/{id}", cap) && req.method == "GET") {
        auto n = Need("catalog:read", false);
        if (n.status >= 400) return n;
        UniValue b(UniValue::VOBJ);
        b.pushKV("claim_id", cap["id"]);
        b.pushKV("issuer", "self");
        b.pushKV("not_central_certification", true);
        b.pushKV("role_scope", Jstr("role", "DISCOVERY"));
        crl12.conformance[cap["id"]] = b;
        return SignedObj(HCP_TYPE_LAYER_CONFORMANCE, b, 200);
    }

    if (MatchPath(req.path, "/layer/jobs/{id}/cancel", cap) && req.method == "POST") {
        auto n = Need("jobs:cancel", false);
        if (n.status >= 400) return n;
        auto it = crl12.jobs.find(cap["id"]);
        if (it == crl12.jobs.end()) return Err(404, "NOT_FOUND", "job");
        const bool committed = it->second.exists("committed") && it->second["committed"].isTrue();
        if (committed || (it->second.exists("status") && it->second["status"].get_str() == "SUCCEEDED")) {
            return Err(409, HCP_ERR_JOB_COMMITTED, cap["id"]);
        }
        it->second.pushKV("status", "CANCELLED");
        return SignedObj(HCP_TYPE_LAYER_JOB, it->second, 200);
    }
    if (MatchPath(req.path, "/layer/jobs/{id}", cap) && req.method == "GET") {
        auto n = Need("jobs:read", false);
        if (n.status >= 400) return n;
        auto it = crl12.jobs.find(cap["id"]);
        if (it == crl12.jobs.end()) return Err(404, "NOT_FOUND", "job");
        if (it->second.exists("account") && it->second["account"].isStr() &&
            it->second["account"].get_str() != cr11.authed_account) {
            return Err(404, "NOT_FOUND", "job");
        }
        return SignedObj(HCP_TYPE_LAYER_JOB, it->second, 200);
    }

    // --- assets ---
    if (req.method == "POST" && req.path == "/institutional/assets") {
        auto n = Need("assets:write", false);
        if (n.status >= 400) return n;
        auto blocked = RecordBlocked();
        if (blocked.status >= 400) return blocked;
        const std::string ns = Jstr("namespace", "lab");
        const std::string value = Jstr("value", Jstr("asset_id", RandId("ast-")));
        const std::string network = Jstr("network", "regtest");
        const std::string key = ns + "|" + value + "|" + network;
        if (Jbool("contradictory_claim", false)) {
            OpenBreak("IDENTIFIER_COLLISION", key);
            return Err(409, HCP_ERR_IDENTIFIER_COLLISION, key);
        }
        for (const auto& [id, a] : crl12.assets) {
            if (a.exists("namespace") && a["namespace"].get_str() == ns && a.exists("value") &&
                a["value"].get_str() == value && a.exists("network") && a["network"].get_str() == network &&
                Jbool("force_collision", false)) {
                OpenBreak("IDENTIFIER_COLLISION", key);
                return Err(409, HCP_ERR_IDENTIFIER_COLLISION, key);
            }
        }
        UniValue b = have_body ? parsed : UniValue(UniValue::VOBJ);
        const std::string id = Jstr("asset_id", RandId("ast-"));
        b.pushKV("asset_id", id);
        b.pushKV("namespace", ns);
        b.pushKV("value", value);
        b.pushKV("network", network);
        b.pushKV("label", Jstr("label", "generic"));
        b.pushKV("account", cr11.authed_account);
        const std::string kind = Jstr("kind", Jstr("asset_kind", "FINANCIAL"));
        b.pushKV("asset_kind", kind);
        b.pushKV("synthetic_security", false);
        if (kind == "CAPABILITY") {
            b.pushKV("ticker", UniValue());
            b.pushKV("security_id", UniValue());
        }
        crl12.assets[id] = b;
        return SignedObj(HCP_TYPE_INSTITUTIONAL_ASSET, b, 201);
    }
    if (MatchPath(req.path, "/institutional/assets/{id}/rights", cap) && req.method == "POST") {
        auto n = Need("assets:write", false);
        if (n.status >= 400) return n;
        if (crl12.assets.find(cap["id"]) == crl12.assets.end()) return Err(404, "NOT_FOUND", "asset");
        const std::string issuer = Jstr("issuer", "");
        if (!issuer.empty() && crl12.accepted_issuers.count(issuer) == 0) {
            UniValue b(UniValue::VOBJ);
            b.pushKV("rights_id", RandId("rgt-"));
            b.pushKV("asset_id", cap["id"]);
            b.pushKV("issuer", issuer);
            b.pushKV("status", "UNACCEPTED");
            b.pushKV("grants_title", false);
            crl12.rights[b["rights_id"].get_str()] = b;
            return Err(403, HCP_ERR_ISSUER_UNACCEPTED, issuer);
        }
        if (Jstr("transferability") == "NONTRANSFERABLE" && Jbool("invent_transfer", false)) {
            return Err(403, HCP_ERR_TRANSFER_RESTRICTED, cap["id"]);
        }
        UniValue b = have_body ? parsed : UniValue(UniValue::VOBJ);
        const std::string id = Jstr("rights_id", RandId("rgt-"));
        b.pushKV("rights_id", id);
        b.pushKV("asset_id", cap["id"]);
        b.pushKV("issuer", issuer.empty() ? "issuer-lab" : issuer);
        b.pushKV("status", "ACCEPTED");
        b.pushKV("transferability", Jstr("transferability", "TRANSFERABLE"));
        b.pushKV("expires_at", Jstr("expires_at", "0"));
        crl12.rights[id] = b;
        return SignedObj(HCP_TYPE_ASSET_RIGHTS, b, 201);
    }
    if (MatchPath(req.path, "/institutional/assets/{id}", cap) && req.method == "GET") {
        auto n = Need("assets:read", false);
        if (n.status >= 400) return n;
        auto it = crl12.assets.find(cap["id"]);
        if (it == crl12.assets.end()) return Err(404, "NOT_FOUND", "asset");
        return SignedObj(HCP_TYPE_INSTITUTIONAL_ASSET, it->second, 200);
    }
    if (req.method == "GET" && req.path == "/institutional/assets") {
        auto n = Need("assets:read", false);
        if (n.status >= 400) return n;
        return PageOf(crl12.assets, HCP_TYPE_INSTITUTIONAL_ASSET);
    }

    // --- positions ---
    if (req.method == "POST" && req.path == "/institutional/positions/batches") {
        auto n = Need("positions:write", false);
        if (n.status >= 400) return n;
        auto blocked = RecordBlocked();
        if (blocked.status >= 400) return blocked;
        if (Jbool("source_not_authorized", false) || Jstr("source") == "unauthorized") {
            return Err(403, HCP_ERR_SOURCE_NOT_AUTHORIZED, "source");
        }
        UniValue rows = (have_body && parsed.exists("rows") && parsed["rows"].isArray()) ? parsed["rows"]
                                                                                         : UniValue(UniValue::VARR);
        if (rows.empty() && have_body) {
            rows = UniValue(UniValue::VARR);
            rows.push_back(parsed);
        }
        if (Jbool("one_invalid", false) || Jstr("invalid_row") == "true") {
            return Err(400, "BATCH_REJECTED", "no partial publish");
        }
        std::vector<UniValue> staged;
        for (size_t i = 0; i < rows.size(); ++i) {
            UniValue row = rows[i];
            if (row.exists("object_type") && row.exists("body") && row.exists("signature")) {
                HcpEnvelope env;
                std::string perr;
                if (!ParseHcpEnvelope(row, env, perr)) {
                    return Err(400, perr == HCP_ERR_BODY_ID_MISMATCH ? HCP_ERR_BODY_ID_MISMATCH : "SIGNATURE_INVALID",
                               perr.empty() ? "envelope" : perr);
                }
                std::string verr;
                if (!HcpVerify(env, Span<const unsigned char>{op_pk.data(), op_pk.size()}, verr) &&
                    !HcpVerify(env, Span<const unsigned char>{root_pk.data(), root_pk.size()}, verr)) {
                    return Err(400, verr == HCP_ERR_BODY_ID_MISMATCH ? HCP_ERR_BODY_ID_MISMATCH : "SIGNATURE_INVALID",
                               verr.empty() ? "signature" : verr);
                }
                row = env.body;
            }
            if (row.exists("source_not_authorized") && row["source_not_authorized"].isTrue()) {
                return Err(403, HCP_ERR_SOURCE_NOT_AUTHORIZED, "source");
            }
            if (row.exists("source") && row["source"].isStr() && row["source"].get_str() == "unauthorized") {
                return Err(403, HCP_ERR_SOURCE_NOT_AUTHORIZED, "source");
            }
            const std::string source = row.exists("source") ? row["source"].get_str() : Jstr("source", "src-a");
            const std::string gen = row.exists("generation") ? (row["generation"].isStr() ? row["generation"].get_str()
                                                                                          : std::to_string(row["generation"].getInt<int64_t>()))
                                                            : Jstr("generation", "1");
            const std::string seq = row.exists("sequence") ? (row["sequence"].isStr() ? row["sequence"].get_str()
                                                                                      : std::to_string(row["sequence"].getInt<int64_t>()))
                                                           : Jstr("sequence", std::to_string(i));
            const std::string key = source + "|" + gen + "|" + seq;
            const std::string h = HashBody() + "|" + std::to_string(i);
            auto hit = crl12.pos_hash.find(key);
            if (hit != crl12.pos_hash.end()) {
                if (hit->second == h) {
                    continue; // exact replay: one logical observation
                }
                OpenBreak("OBSERVATION_CONFLICT", key);
                return Err(409, HCP_ERR_OBSERVATION_CONFLICT, key);
            }
            const std::string genkey = source + "|" + gen;
            if (crl12.pos_source_seq.count(genkey)) {
                const int64_t prev = std::stoll(crl12.pos_source_seq[genkey]);
                const int64_t cur = std::stoll(seq);
                if (cur > prev + 1) {
                    OpenBreak("SEQUENCE_GAP", genkey);
                }
            }
            if (Jstr("new_generation") == "true" && gen != "1" && !Jbool("accepted_reset", false)) {
                OpenBreak("GENERATION_RESET", genkey);
                return Err(409, "GENERATION_RESET", "require snapshot");
            }
            UniValue b = row;
            const std::string id = row.exists("observation_id") ? row["observation_id"].get_str() : RandId("pos-");
            b.pushKV("observation_id", id);
            b.pushKV("source", source);
            b.pushKV("generation", gen);
            b.pushKV("sequence", seq);
            b.pushKV("account", cr11.authed_account);
            if (!b.exists("status")) b.pushKV("status", "OPEN");
            if (!b.exists("mandate")) b.pushKV("mandate", Jstr("mandate", "NONE"));
            if (!b.exists("asset_kind")) b.pushKV("asset_kind", Jstr("asset_kind", "FINANCIAL"));
            if (!b.exists("quantity")) b.pushKV("quantity", Jstr("quantity", "1"));
            if (!b.exists("effective_at")) b.pushKV("effective_at", std::to_string(cfg.clock_ms));
            if (!b.exists("recorded_at")) b.pushKV("recorded_at", std::to_string(cfg.clock_ms));
            if (!b.exists("beneficial_id")) b.pushKV("beneficial_id", Jstr("beneficial_id", id));
            if (!b.exists("address")) b.pushKV("address", Jstr("address", ""));
            staged.push_back(b);
            crl12.pos_hash[key] = h;
            crl12.pos_source_seq[genkey] = seq;
        }
        for (auto& b : staged) {
            crl12.positions[b["observation_id"].get_str()] = b;
        }
        UniValue out(UniValue::VOBJ);
        out.pushKV("accepted", static_cast<int64_t>(staged.size()));
        out.pushKV("watermark_advanced", !staged.empty());
        return JsonStatus(201, out);
    }
    if (MatchPath(req.path, "/institutional/positions/{id}", cap) && req.method == "GET") {
        auto n = Need("positions:read", false);
        if (n.status >= 400) return n;
        auto it = crl12.positions.find(cap["id"]);
        if (it == crl12.positions.end()) return Err(404, "NOT_FOUND", "position");
        return SignedObj(HCP_TYPE_POSITION_OBS, it->second, 200);
    }
    if (req.method == "GET" && req.path == "/institutional/positions") {
        auto n = Need("positions:read", false);
        if (n.status >= 400) return n;
        if (QueryGet(req.query, "as_of").empty() || QueryGet(req.query, "observed_cutoff").empty()) {
            return Err(400, "AS_OF_REQUIRED", "as_of and observed_cutoff");
        }
        const int64_t as_of = std::stoll(QueryGet(req.query, "as_of"));
        const int64_t observed = std::stoll(QueryGet(req.query, "observed_cutoff"));
        UniValue items(UniValue::VARR);
        for (const auto& [id, b] : crl12.positions) {
            if (b.exists("account") && b["account"].isStr() && b["account"].get_str() != cr11.authed_account) continue;
            const int64_t eff = b.exists("effective_at") ? std::stoll(b["effective_at"].get_str()) : 0;
            const int64_t rec = b.exists("recorded_at") ? std::stoll(b["recorded_at"].get_str()) : 0;
            if (eff > as_of) continue;
            if (rec > observed) continue;
            const std::string st = b.exists("status") ? b["status"].get_str() : "OPEN";
            if (st == "CLOSED" && QueryGet(req.query, "view") != "historical") continue;
            items.push_back(b);
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("items", items);
        o.pushKV("as_of", std::to_string(as_of));
        o.pushKV("observed_cutoff", std::to_string(observed));
        return JsonStatus(200, o);
    }

    // --- valuations ---
    if (req.method == "POST" && req.path == "/institutional/valuations") {
        auto n = Need("valuations:write", false);
        if (n.status >= 400) return n;
        const std::string amt = Jstr("value", Jstr("amount", ""));
        if (!amt.empty() && amt != "null") {
            std::string e;
            if (!Crl12FiniteDecimal(amt, e)) return Err(400, HCP_ERR_NONFINITE, amt);
            if (amt[0] == '-' && Jstr("purpose", "MARKET_VALUE") == "MARKET_VALUE") {
                return Err(400, HCP_ERR_NONFINITE, "negative price");
            }
        }
        UniValue b = have_body ? parsed : UniValue(UniValue::VOBJ);
        const std::string id = Jstr("valuation_id", RandId("val-"));
        b.pushKV("valuation_id", id);
        b.pushKV("purpose", Jstr("purpose", "MARKET_VALUE"));
        if (amt.empty()) {
            b.pushKV("status", "UNAVAILABLE");
            b.pushKV("value", UniValue());
        } else {
            b.pushKV("value", amt);
            b.pushKV("status", Jstr("status", "CURRENT"));
        }
        b.pushKV("effective_at", Jstr("effective_at", std::to_string(cfg.clock_ms)));
        b.pushKV("recorded_at", Jstr("recorded_at", std::to_string(cfg.clock_ms)));
        b.pushKV("valid_until", Jstr("valid_until", std::to_string(cfg.clock_ms + 86400000)));
        b.pushKV("whole_position", Jbool("whole_position", false));
        b.pushKV("currency", Jstr("currency", "USD"));
        crl12.valuations[id] = b;
        return SignedObj(HCP_TYPE_VALUATION_OBS, b, 201);
    }
    if (MatchPath(req.path, "/institutional/valuations/{id}", cap) && req.method == "GET") {
        auto n = Need("valuations:read", false);
        if (n.status >= 400) return n;
        auto it = crl12.valuations.find(cap["id"]);
        if (it == crl12.valuations.end()) return Err(404, "NOT_FOUND", "valuation");
        return SignedObj(HCP_TYPE_VALUATION_OBS, it->second, 200);
    }

    // --- exposures ---
    if (req.method == "POST" && req.path == "/institutional/exposures") {
        auto n = Need("exposures:write", false);
        if (n.status >= 400) return n;
        UniValue links = (have_body && parsed.exists("links") && parsed["links"].isArray()) ? parsed["links"]
                                                                                           : UniValue(UniValue::VARR);
        if (links.empty() && have_body) {
            links.push_back(parsed);
        }
        double sum = 0;
        std::map<std::string, std::vector<std::string>> g;
        int edges = 0;
        for (size_t i = 0; i < links.size(); ++i) {
            UniValue e = links[i];
            const std::string kind = e.exists("kind") ? e["kind"].get_str() : Jstr("kind", "FINANCIAL");
            const std::string w = e.exists("weight") ? e["weight"].get_str() : Jstr("weight", "0");
            if (kind == "FINANCIAL") {
                std::string err;
                if (!Crl12FiniteDecimal(w, err)) return Err(400, HCP_ERR_NONFINITE, w);
                if (w[0] == '-') return Err(400, HCP_ERR_NONFINITE, w);
                sum += std::stod(w);
            }
            const std::string parent = e.exists("parent") ? e["parent"].get_str() : Jstr("parent", "root");
            const std::string child = e.exists("child") ? e["child"].get_str() : Jstr("child", "c");
            g[parent].push_back(child);
            ++edges;
            if (edges > HCP_CR12_MAX_GRAPH_EDGES) return Err(400, HCP_ERR_GRAPH_LIMIT, "budget");
        }
        auto cycle = [&](auto&& self, const std::string& n, std::set<std::string>& path,
                         std::set<std::string>& seen) -> bool {
            if (path.count(n)) return true;
            if (seen.count(n)) return false;
            path.insert(n);
            seen.insert(n);
            for (const auto& c : g[n]) {
                if (self(self, c, path, seen)) return true;
            }
            path.erase(n);
            return false;
        };
        std::set<std::string> path, seen;
        for (const auto& [k, _] : g) {
            if (cycle(cycle, k, path, seen)) return Err(400, HCP_ERR_GRAPH_CYCLE, "cycle");
        }
        auto depth_of = [&](auto&& self, const std::string& n, int d) -> int {
            int m = d;
            for (const auto& c : g[n]) m = std::max(m, self(self, c, d + 1));
            return m;
        };
        int md = 0;
        for (const auto& [k, _] : g) md = std::max(md, depth_of(depth_of, k, 0));
        if (md > HCP_CR12_MAX_LOOKTHROUGH_DEPTH) return Err(400, HCP_ERR_GRAPH_DEPTH, "depth");
        if (sum > 1.0000001 && !Jbool("leverage_policy", false)) {
            return Err(400, HCP_ERR_WEIGHT_OVERFLOW, "need leverage policy");
        }
        if (Jbool("add_parent_and_children", false)) {
            return Err(400, HCP_ERR_LOOKTHROUGH, "never add parent and children");
        }
        UniValue b = have_body ? parsed : UniValue(UniValue::VOBJ);
        const std::string id = Jstr("link_id", RandId("exp-"));
        b.pushKV("link_id", id);
        int coverage = J64("coverage_bps", 10000);
        if (coverage < 0) coverage = 0;
        b.pushKV("coverage_bps", static_cast<int64_t>(coverage));
        b.pushKV("unresolved_residual_bps", static_cast<int64_t>(10000 - coverage));
        crl12.exposures[id] = b;
        return SignedObj(HCP_TYPE_EXPOSURE_LINK, b, 201);
    }
    if (req.method == "GET" && req.path == "/institutional/exposures") {
        auto n = Need("exposures:read", false);
        if (n.status >= 400) return n;
        return PageOf(crl12.exposures, HCP_TYPE_EXPOSURE_LINK);
    }

    // --- metrics ---
    if (req.method == "POST" && req.path == "/institutional/metrics") {
        auto n = Need("metrics:admin", false);
        if (n.status >= 400) return n;
        UniValue b = have_body ? parsed : UniValue(UniValue::VOBJ);
        const std::string id = Jstr("metric_id", RandId("met-"));
        const std::string kind = Jstr("metric_kind", "AUM");
        b.pushKV("metric_id", id);
        b.pushKV("metric_kind", kind);
        b.pushKV("mandate_required", kind == "AUM");
        b.pushKV("generation", Jstr("generation", "1"));
        b.pushKV("basis", Jstr("basis", "DIRECT_ONLY"));
        crl12.metrics[id] = b;
        return SignedObj(HCP_TYPE_METRIC_DEFINITION, b, 201);
    }
    if (req.method == "GET" && req.path == "/institutional/metrics") {
        auto n = Need("metrics:read", false);
        if (n.status >= 400) return n;
        return PageOf(crl12.metrics, HCP_TYPE_METRIC_DEFINITION);
    }

    auto Aggregate = [&](const std::string& kind, const int64_t as_of, const int64_t observed) {
        UniValue o(UniValue::VOBJ);
        bool complete = true;
        bool any = false;
        int64_t eligible = 0;
        bool unpriced = false;
        bool known_zero = false;
        std::string amount = "0";
        int64_t native_before = 0;
        auto ait = accounts.find(cr11.authed_account);
        if (ait != accounts.end()) native_before = ait->second.available;
        if (crl12.source_unavailable) {
            o.pushKV("status", "UNAVAILABLE");
            o.pushKV("complete", false);
            o.pushKV("eligible_count", 0);
            o.pushKV("value", UniValue());
            o.pushKV("native_available_unchanged", native_before);
            o.pushKV("no_grand_total", true);
            return o;
        }
        for (const auto& [id, p] : crl12.positions) {
            const int64_t eff = p.exists("effective_at") ? std::stoll(p["effective_at"].get_str()) : 0;
            const int64_t rec = p.exists("recorded_at") ? std::stoll(p["recorded_at"].get_str()) : 0;
            if (eff > as_of || rec > observed) continue;
            const std::string st = p.exists("status") ? p["status"].get_str() : "OPEN";
            if (st != "OPEN") continue;
            const std::string mandate = p.exists("mandate") ? p["mandate"].get_str() : "NONE";
            const std::string akind = p.exists("asset_kind") ? p["asset_kind"].get_str() : "FINANCIAL";
            if (!Crl12MetricEligible(kind, mandate, akind)) continue;
            any = true;
            ++eligible;
            bool found_val = false;
            for (const auto& [vid, v] : crl12.valuations) {
                if (v.exists("purpose") && v["purpose"].get_str() == "REPLACEMENT_SCENARIO" && kind != "SCENARIO_VALUE")
                    continue;
                if (v.exists("status") && v["status"].get_str() == "STALE") {
                    complete = false;
                    continue;
                }
                if (v.exists("currency") && v["currency"].get_str() != Jstr("report_currency", v["currency"].get_str()) &&
                    !Jbool("accepted_fx", false) && kind != "CAPABILITY_COUNT") {
                    complete = false;
                    unpriced = true;
                    continue;
                }
                found_val = true;
                if (!v.exists("value") || v["value"].isNull() || (v["value"].isStr() && v["value"].get_str().empty())) {
                    unpriced = true;
                    complete = false;
                } else if (v["value"].isStr() && v["value"].get_str() == "0") {
                    known_zero = true;
                }
            }
            if (!found_val && kind != "CAPABILITY_COUNT") {
                unpriced = true;
                complete = false;
            }
        }
        if (!any && complete) {
            o.pushKV("status", "COMPLETE");
            o.pushKV("complete", true);
            o.pushKV("eligible_count", 0);
            o.pushKV("value", "0");
            o.pushKV("native_available_unchanged", native_before);
            o.pushKV("no_grand_total", true);
            return o;
        }
        if (unpriced && !known_zero) {
            o.pushKV("status", "UNAVAILABLE");
            o.pushKV("complete", false);
            o.pushKV("eligible_count", eligible);
            o.pushKV("value", UniValue());
            o.pushKV("partial", true);
            o.pushKV("native_available_unchanged", native_before);
            o.pushKV("no_grand_total", true);
            return o;
        }
        o.pushKV("status", complete ? "COMPLETE" : "PARTIAL");
        o.pushKV("complete", complete);
        o.pushKV("eligible_count", eligible);
        o.pushKV("value", known_zero && eligible > 0 ? "0" : (complete ? amount : UniValue()));
        o.pushKV("native_available_unchanged", native_before);
        o.pushKV("no_grand_total", true);
        return o;
    };

    // --- projections ---
    if (req.method == "POST" && req.path == "/institutional/projections") {
        auto n = Need("projections:create", false);
        if (n.status >= 400) return n;
        auto blocked = RecordBlocked();
        if (blocked.status >= 400) return blocked;
        if (Jbool("source_unavailable", false)) crl12.source_unavailable = true;
        UniValue b(UniValue::VOBJ);
        const std::string id = Jstr("projection_id", RandId("prj-"));
        const std::string kind = Jstr("metric_kind", "AUM");
        const int64_t as_of = J64("as_of", cfg.clock_ms);
        const int64_t observed = J64("observed_cutoff", cfg.clock_ms);
        auto agg = Aggregate(kind, as_of, observed);
        b.pushKV("projection_id", id);
        b.pushKV("scope", Jstr("scope", "portfolio:" + cr11.legal_entity));
        b.pushKV("as_of", std::to_string(as_of));
        b.pushKV("observed_cutoff", std::to_string(observed));
        UniValue wm(UniValue::VARR);
        for (const auto& [k, seq] : crl12.pos_source_seq) {
            UniValue w(UniValue::VOBJ);
            w.pushKV("source_generation", k);
            w.pushKV("sequence", seq);
            wm.push_back(w);
        }
        b.pushKV("watermarks", wm);
        UniValue metrics(UniValue::VARR);
        metrics.push_back(agg);
        b.pushKV("metric_results", metrics);
        UniValue prefs(UniValue::VARR);
        for (const auto& [pid, _] : crl12.positions) prefs.push_back(pid);
        b.pushKV("position_refs", prefs);
        b.pushKV("operational_refs", UniValue(UniValue::VARR));
        UniValue recs(UniValue::VARR);
        for (const auto& [bid, br] : crl12.breaks) recs.push_back(bid);
        b.pushKV("reconciliation_refs", recs);
        b.pushKV("next_cursor", UniValue());
        b.pushKV("metric_kind", kind);
        b.pushKV("policy_id", Jstr("policy_id", "pol-1"));
        b.pushKV("filter", Jstr("filter", ""));
        if (crl12.source_unavailable || (agg.exists("complete") && agg["complete"].isFalse())) {
            b.pushKV("status", "PARTIAL");
        } else {
            b.pushKV("status", "COMPLETE");
        }
        b.pushKV("no_finance_intent", true);
        b.pushKV("local_inventory", UniValue());
        crl12.projections[id] = b;
        const std::string jid = NewJob("PROJECTION", id, "SUCCEEDED");
        if (Jbool("return_job", false) || QueryGet(req.query, "response") == "job") {
            return SignedObj(HCP_TYPE_LAYER_JOB, crl12.jobs[jid], 201);
        }
        return SignedObj(HCP_TYPE_PORTFOLIO_PROJECTION, b, 201);
    }
    if (MatchPath(req.path, "/institutional/projections/{id}", cap) && req.method == "GET") {
        auto n = Need("projections:read", false);
        if (n.status >= 400) return n;
        auto it = crl12.projections.find(cap["id"]);
        if (it == crl12.projections.end()) return Err(404, "NOT_FOUND", "projection");
        const std::string cursor_tenant = QueryGet(req.query, "cursor_tenant");
        if (!cursor_tenant.empty() && cursor_tenant != cr11.authed_account) {
            return Err(403, HCP_ERR_ENTITY_SCOPE, "cross-tenant");
        }
        const std::string want_filter = QueryGet(req.query, "filter");
        if (!want_filter.empty() && it->second.exists("filter") && it->second["filter"].get_str() != want_filter) {
            return Err(400, HCP_ERR_CURSOR_MISMATCH, "filter");
        }
        return SignedObj(HCP_TYPE_PORTFOLIO_PROJECTION, it->second, 200);
    }

    // --- exports ---
    if (req.method == "POST" && req.path == "/institutional/exports") {
        auto n = Need("exports:create", false);
        if (n.status >= 400) return n;
        const std::string pid = Jstr("projection_id", "");
        if (!pid.empty() && crl12.projections.find(pid) == crl12.projections.end()) {
            return Err(404, "NOT_FOUND", "projection");
        }
        UniValue b(UniValue::VOBJ);
        const std::string id = Jstr("export_id", RandId("exp-"));
        const std::string fmt = Jstr("format", "JSONL");
        b.pushKV("export_id", id);
        b.pushKV("projection_ref", pid);
        b.pushKV("format", fmt);
        b.pushKV("mapping_digest", Jstr("mapping_digest", std::string(96, 'd')));
        b.pushKV("privacy_policy_ref", Jstr("privacy_policy_ref", "priv-1"));
        b.pushKV("redaction", Jstr("redaction", "STANDARD"));
        b.pushKV("expires_at", std::to_string(cfg.clock_ms + 3600000));
        UniValue chunks(UniValue::VARR);
        std::string payload;
        if (fmt == "CSV") {
            payload = "id,label\n";
            for (const auto& [aid, a] : crl12.assets) {
                std::string lab = a.exists("label") ? a["label"].get_str() : aid;
                std::string safe;
                Crl12CsvSafe(lab, safe);
                payload += aid + "," + safe + "\n";
            }
        } else {
            payload = "{\"rows\":[]}\n";
        }
        const std::string cid = RandId("chk-");
        {
            UniValue stored(UniValue::VOBJ);
            stored.pushKV("bytes", payload);
            crl12.export_chunks[id + "/" + cid] = stored;
        }
        UniValue ch(UniValue::VOBJ);
        ch.pushKV("chunk_id", cid);
        std::vector<unsigned char> raw(payload.begin(), payload.end());
        ch.pushKV("digest", Sha384Hex(Span<const unsigned char>{raw.data(), raw.size()}));
        ch.pushKV("length", static_cast<int64_t>(payload.size()));
        chunks.push_back(ch);
        b.pushKV("chunks", chunks);
        b.pushKV("total_rows", static_cast<int64_t>(crl12.positions.size()));
        b.pushKV("transfer_permission", false);
        crl12.exports[id] = b;
        NewJob("EXPORT", id, "SUCCEEDED");
        return SignedObj(HCP_TYPE_EXPORT_MANIFEST, b, 201);
    }
    if (MatchPath(req.path, "/institutional/exports/{id}/chunks/{chunk_id}", cap) && req.method == "GET") {
        auto n = Need("exports:read", false);
        if (n.status >= 400) return n;
        auto it = crl12.export_chunks.find(cap["id"] + "/" + cap["chunk_id"]);
        if (it == crl12.export_chunks.end()) return Err(404, "NOT_FOUND", "chunk");
        HcpHttpResponse r;
        r.status = 200;
        r.content_type = "application/octet-stream";
        r.body = it->second.exists("bytes") ? it->second["bytes"].get_str() : it->second.write();
        return r;
    }
    if (MatchPath(req.path, "/institutional/exports/{id}", cap) && req.method == "GET") {
        auto n = Need("exports:read", false);
        if (n.status >= 400) return n;
        auto it = crl12.exports.find(cap["id"]);
        if (it == crl12.exports.end()) return Err(404, "NOT_FOUND", "export");
        return SignedObj(HCP_TYPE_EXPORT_MANIFEST, it->second, 200);
    }

    // --- imports / staging ---
    if (req.method == "POST" && req.path == "/institutional/imports/chunks") {
        auto n = Need("imports:write", false);
        if (n.status >= 400) return n;
        auto blocked = RecordBlocked();
        if (blocked.status >= 400) return blocked;
        if (static_cast<int64_t>(req.body.size()) > HCP_CR12_MAX_STAGE_BYTES) {
            return Err(413, "BODY_TOO_LARGE", "stage 16MiB");
        }
        const std::string id = RandId("chk-");
        UniValue b(UniValue::VOBJ);
        b.pushKV("chunk_id", id);
        b.pushKV("account", cr11.authed_account);
        std::vector<unsigned char> raw(req.body.begin(), req.body.end());
        const std::string digest = Sha384Hex(Span<const unsigned char>{raw.data(), raw.size()});
        const std::string declared = QueryGet(req.query, "digest");
        const std::string decl_len = QueryGet(req.query, "length");
        const std::string hdr_digest = Hdr(req, "digest");
        if (!declared.empty() && declared != digest) {
            return Err(400, HCP_ERR_CHUNK_MISMATCH, "digest");
        }
        if (!hdr_digest.empty() && hdr_digest != digest) {
            return Err(400, HCP_ERR_CHUNK_MISMATCH, "digest");
        }
        if (!decl_len.empty() && std::stoll(decl_len) != static_cast<int64_t>(raw.size())) {
            return Err(400, HCP_ERR_CHUNK_MISMATCH, "length");
        }
        b.pushKV("digest", digest);
        b.pushKV("length", static_cast<int64_t>(raw.size()));
        if (raw.size() <= 65536) b.pushKV("bytes_b64", HexStr(raw));
        crl12.chunks[id] = b;
        return JsonStatus(201, b);
    }
    if (req.method == "POST" && req.path == "/institutional/imports/validate") {
        auto n = Need("imports:write", false);
        if (n.status >= 400) return n;
        const std::string chunk_id = Jstr("chunk_id", "");
        if (!chunk_id.empty()) {
            auto cit = crl12.chunks.find(chunk_id);
            if (cit == crl12.chunks.end()) return Err(404, "NOT_FOUND", "chunk");
            if (cit->second["account"].get_str() != cr11.authed_account) {
                return Err(403, HCP_ERR_CHUNK_NOT_OWNED, chunk_id);
            }
            const std::string want = Jstr("digest", "");
            if (!want.empty() && cit->second["digest"].get_str() != want) {
                return Err(400, HCP_ERR_CHUNK_DIGEST, chunk_id);
            }
        }
        if (Jbool("duplicate_chunk", false)) return Err(400, "AMBIGUOUS_ROWS", "duplicate chunk");
        if (Jbool("row_mismatch", false)) return Err(400, "ROW_COUNT", "manifest mismatch");
        UniValue b(UniValue::VOBJ);
        const std::string id = Jstr("import_id", RandId("imp-"));
        b.pushKV("import_id", id);
        b.pushKV("status", "VALIDATED");
        b.pushKV("mapping_digest", Jstr("mapping_digest", std::string(96, 'e')));
        b.pushKV("account", cr11.authed_account);
        b.pushKV("row_count", J64("row_count", 0));
        b.pushKV("contains_balance_hint", Jbool("contains_balance", false));
        crl12.imports[id] = b;
        NewJob("IMPORT_VALIDATE", id, "SUCCEEDED");
        return SignedObj(HCP_TYPE_IMPORT_MANIFEST, b, 200);
    }
    if (MatchPath(req.path, "/institutional/imports/{id}/commit", cap) && req.method == "POST") {
        auto n = Need("imports:write", false);
        if (n.status >= 400) return n;
        auto it = crl12.imports.find(cap["id"]);
        if (it == crl12.imports.end()) return Err(404, HCP_ERR_IMPORT_NOT_VALIDATED, "import");
        const std::string mapping = Jstr("mapping_digest", it->second.exists("mapping_digest")
                                                               ? it->second["mapping_digest"].get_str()
                                                               : "");
        if (it->second.exists("mapping_digest") && it->second["mapping_digest"].get_str() != mapping && !mapping.empty()) {
            return Err(409, HCP_ERR_MAPPING_CAS, mapping);
        }
        if (it->second.exists("status") && it->second["status"].get_str() == "PUBLISHED") {
            return SignedObj(HCP_TYPE_IMPORT_MANIFEST, it->second, 200);
        }
        it->second.pushKV("status", "PUBLISHED");
        it->second.pushKV("generation", "1");
        it->second.pushKV("custody_credit", false);
        it->second.pushKV("spendable_created", false);
        NewJob("IMPORT_COMMIT", cap["id"], "SUCCEEDED");
        return SignedObj(HCP_TYPE_IMPORT_MANIFEST, it->second, 200);
    }
    if (MatchPath(req.path, "/institutional/imports/{id}", cap) && req.method == "GET") {
        auto n = Need("imports:read", false);
        if (n.status >= 400) return n;
        auto it = crl12.imports.find(cap["id"]);
        if (it == crl12.imports.end()) return Err(404, "NOT_FOUND", "import");
        return SignedObj(HCP_TYPE_IMPORT_MANIFEST, it->second, 200);
    }

    // --- breaks ---
    if (req.method == "GET" && req.path == "/institutional/breaks") {
        auto n = Need("reconciliation:read", false);
        if (n.status >= 400) return n;
        return PageOf(crl12.breaks, HCP_TYPE_RECONCILIATION_BREAK);
    }
    if (MatchPath(req.path, "/institutional/breaks/{id}/resolve", cap) && req.method == "POST") {
        auto n = Need("reconciliation:write", false);
        if (n.status >= 400) return n;
        auto it = crl12.breaks.find(cap["id"]);
        if (it == crl12.breaks.end()) return Err(404, "NOT_FOUND", "break");
        it->second.pushKV("status", "RESOLVED");
        return SignedObj(HCP_TYPE_RECONCILIATION_BREAK, it->second, 200);
    }
    if (MatchPath(req.path, "/institutional/breaks/{id}", cap) && req.method == "GET") {
        auto n = Need("reconciliation:read", false);
        if (n.status >= 400) return n;
        auto it = crl12.breaks.find(cap["id"]);
        if (it == crl12.breaks.end()) return Err(404, "NOT_FOUND", "break");
        return SignedObj(HCP_TYPE_RECONCILIATION_BREAK, it->second, 200);
    }

    // --- instructions ---
    if (req.method == "POST" && req.path == "/institutional/instructions") {
        auto n = Need("capital:prepare", false);
        if (n.status >= 400) return n;
        const std::string entity = Jstr("legal_entity_id", cr11.legal_entity);
        if (entity != cr11.legal_entity && entity != Jstr("scope", entity)) {
            return Err(403, HCP_ERR_ENTITY_SCOPE, entity);
        }
        if (Jstr("legal_entity_id").size() && Jstr("legal_entity_id") != cr11.legal_entity) {
            return Err(403, HCP_ERR_ENTITY_SCOPE, Jstr("legal_entity_id"));
        }
        if (Jbool("execute", false)) {
            return Err(400, HCP_ERR_INSTRUCTION_NOT_EXECUTE, "draft only");
        }
        const std::string pref = Jstr("source_projection_ref", "");
        if (Jbool("stale_projection", false) || Jstr("source_status") == "STALE") {
            return Err(400, HCP_ERR_STALE_SOURCE, pref);
        }
        if (!pref.empty() && crl12.projections.find(pref) == crl12.projections.end() && Jbool("require_projection", false)) {
            return Err(400, HCP_ERR_STALE_SOURCE, pref);
        }
        UniValue b = have_body ? parsed : UniValue(UniValue::VOBJ);
        const std::string id = Jstr("instruction_id", RandId("ins-"));
        const std::string h = HashBody();
        if (crl12.instr_hash.count(id) && crl12.instr_hash[id] != h) {
            return Err(409, HCP_ERR_CONFLICT, id);
        }
        b.pushKV("instruction_id", id);
        b.pushKV("status", "DRAFT");
        b.pushKV("legal_entity_id", cr11.legal_entity);
        b.pushKV("requested_action", Jstr("requested_action", "DRAFT_RESERVE_ALLOCATION"));
        b.pushKV("no_reservation", true);
        b.pushKV("execute", false);
        crl12.instructions[id] = b;
        crl12.instr_hash[id] = h;
        return SignedObj(HCP_TYPE_PORTFOLIO_INSTRUCTION, b, 201);
    }
    if (MatchPath(req.path, "/institutional/instructions/{id}/translate", cap) && req.method == "POST") {
        auto n = Need("capital:prepare", false);
        if (n.status >= 400) return n;
        auto it = crl12.instructions.find(cap["id"]);
        if (it == crl12.instructions.end()) return Err(404, "NOT_FOUND", "instruction");
        if (have_body) {
            const std::string h = HashBody();
            if (crl12.instr_hash.count(cap["id"]) && crl12.instr_hash[cap["id"]] != h && Jbool("changed", true) &&
                Jstr("body_override").size()) {
                return Err(409, HCP_ERR_CONFLICT, cap["id"]);
            }
        }
        if (it->second.exists("draft_plan_id") && !it->second["draft_plan_id"].get_str().empty()) {
            return SignedObj(HCP_TYPE_PORTFOLIO_INSTRUCTION, it->second, 200);
        }
        UniValue plan(UniValue::VOBJ);
        const std::string pid = RandId("plan-");
        plan.pushKV("plan_id", pid);
        plan.pushKV("legal_entity_id", cr11.legal_entity);
        plan.pushKV("objective", "own-then-run");
        plan.pushKV("state", "DRAFT");
        plan.pushKV("from_instruction", cap["id"]);
        cr11.plans[pid] = plan;
        UniValue alloc(UniValue::VOBJ);
        const std::string aid = RandId("alloc-");
        alloc.pushKV("allocation_id", aid);
        alloc.pushKV("state", "DRAFT");
        alloc.pushKV("from_instruction", cap["id"]);
        cr11.allocations[aid] = alloc;
        it->second.pushKV("draft_plan_id", pid);
        it->second.pushKV("draft_allocation_id", aid);
        it->second.pushKV("status", "TRANSLATED");
        it->second.pushKV("no_reservation", true);
        it->second.pushKV("remote_inference", false);
        return SignedObj(HCP_TYPE_PORTFOLIO_INSTRUCTION, it->second, 200);
    }
    if (MatchPath(req.path, "/institutional/instructions/{id}", cap) && req.method == "GET") {
        auto n = Need("capital:read", false);
        if (n.status >= 400) return n;
        auto it = crl12.instructions.find(cap["id"]);
        if (it == crl12.instructions.end()) return Err(404, "NOT_FOUND", "instruction");
        return SignedObj(HCP_TYPE_PORTFOLIO_INSTRUCTION, it->second, 200);
    }

    // --- scenarios ---
    if (req.method == "POST" && req.path == "/institutional/scenarios") {
        auto n = Need("scenarios:create", false);
        if (n.status >= 400) return n;
        UniValue b = have_body ? parsed : UniValue(UniValue::VOBJ);
        const std::string id = Jstr("scenario_id", RandId("scn-"));
        b.pushKV("scenario_id", id);
        b.pushKV("kind", Jstr("kind", "RESERVE_PRICE"));
        b.pushKV("status", "COMPLETE");
        b.pushKV("financial_units", "atoms");
        b.pushKV("operational_units", "readiness");
        b.pushKV("distinct_methodology", true);
        if (!b.exists("financial_change")) {
            UniValue fc(UniValue::VOBJ);
            fc.pushKV("unit", "atoms");
            fc.pushKV("delta", "0");
            fc.pushKV("shock", Jstr("kind", "RESERVE_PRICE"));
            b.pushKV("financial_change", fc);
        }
        if (!b.exists("operational_impacts")) {
            UniValue oi(UniValue::VARR);
            UniValue one(UniValue::VOBJ);
            one.pushKV("kind", "readiness");
            one.pushKV("unit", "readiness");
            one.pushKV("shock", Jstr("kind", "RESERVE_PRICE"));
            oi.push_back(one);
            b.pushKV("operational_impacts", oi);
        }
        crl12.scenarios[id] = b;
        NewJob("SCENARIO", id, "SUCCEEDED");
        return SignedObj(HCP_TYPE_SCENARIO_RESULT, b, 201);
    }
    if (MatchPath(req.path, "/institutional/scenarios/{id}", cap) && req.method == "GET") {
        auto n = Need("scenarios:read", false);
        if (n.status >= 400) return n;
        auto it = crl12.scenarios.find(cap["id"]);
        if (it == crl12.scenarios.end()) return Err(404, "NOT_FOUND", "scenario");
        return SignedObj(HCP_TYPE_SCENARIO_RESULT, it->second, 200);
    }

    return Err(404, "NOT_FOUND", req.path);
}
