// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/release.h>

#include <modelnet/crypto.h>
#include <util/strencodings.h>

#include <fstream>

namespace modelnet {

Hash32 ReleaseHash(Span<const unsigned char> secret32)
{
    return Sha256(secret32);
}

bool ValidRefundWindow(uint32_t latest_funding, uint32_t min_conf, uint32_t claim_margin, uint32_t refund_height)
{
    if (!(latest_funding > 0 && latest_funding < refund_height && refund_height < 500000000u)) return false;
    return latest_funding + min_conf + claim_margin < refund_height;
}

UniValue CampaignToJson(const ReleaseCampaign& c)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("release_id", c.release_id.Hex());
    o.pushKV("model_id", c.model_id.Hex());
    o.pushKV("artifact_id", c.artifact_id.Hex());
    o.pushKV("key_hash", c.key_hash.Hex());
    o.pushKV("target_atoms", c.target_atoms);
    o.pushKV("pledged_atoms", c.pledged_atoms);
    o.pushKV("refund_height", static_cast<int64_t>(c.refund_height));
    o.pushKV("latest_funding_height", static_cast<int64_t>(c.latest_funding_height));
    o.pushKV("frozen", c.frozen);
    o.pushKV("secret_disclosed", c.secret_disclosed);
    o.pushKV("plaintext_verified", c.plaintext_verified);
    o.pushKV("claim", "buildmodelhtlcclaim / buildhtlcclaim with 0.34.6 htlc_sha256(key_hash, claimant)");
    o.pushKV("refund", "buildmodelhtlcrefund / buildhtlcrefund after refund_height");
    o.pushKV("note", "HASH160 htlc_tx is recovery-only.");
    return o;
}

bool LoadCampaigns(const fs::path& dir, std::vector<ReleaseCampaign>& out, std::string& err)
{
    out.clear();
    const fs::path path = dir / "campaigns.json";
    if (!fs::exists(path)) return true;
    std::ifstream in(path);
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue o;
    if (!o.read(raw) || !o.isObject() || !o.exists("campaigns")) return true;
    for (const auto& cj : o["campaigns"].getValues()) {
        ReleaseCampaign c;
        if (!Digest48::FromHex(cj["release_id"].get_str(), c.release_id, err)) return false;
        if (!Digest48::FromHex(cj["model_id"].get_str(), c.model_id, err)) return false;
        if (cj.exists("artifact_id") && !cj["artifact_id"].get_str().empty()) {
            if (!Digest48::FromHex(cj["artifact_id"].get_str(), c.artifact_id, err)) return false;
        }
        if (!Hash32::FromHex(cj["key_hash"].get_str(), c.key_hash, err)) return false;
        c.target_atoms = cj.exists("target_atoms") ? cj["target_atoms"].getInt<int64_t>() : 0;
        c.pledged_atoms = cj.exists("pledged_atoms") ? cj["pledged_atoms"].getInt<int64_t>() : 0;
        c.refund_height = cj.exists("refund_height") ? cj["refund_height"].getInt<uint32_t>() : 0;
        c.latest_funding_height = cj.exists("latest_funding_height") ? cj["latest_funding_height"].getInt<uint32_t>() : 0;
        c.frozen = cj.exists("frozen") && cj["frozen"].get_bool();
        c.secret_disclosed = cj.exists("secret_disclosed") && cj["secret_disclosed"].get_bool();
        c.plaintext_verified = cj.exists("plaintext_verified") && cj["plaintext_verified"].get_bool();
        out.push_back(c);
    }
    return true;
}

bool SaveCampaigns(const fs::path& dir, const std::vector<ReleaseCampaign>& campaigns, std::string& err)
{
    UniValue o(UniValue::VOBJ);
    UniValue arr(UniValue::VARR);
    for (const auto& c : campaigns) arr.push_back(CampaignToJson(c));
    o.pushKV("campaigns", arr);
    std::ofstream out(dir / "campaigns.json", std::ios::trunc);
    if (!out) {
        err = "campaigns.json write";
        return false;
    }
    out << o.write() << "\n";
    return true;
}

} // namespace modelnet
