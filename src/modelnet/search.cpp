// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/search.h>

#include <crypto/common.h>
#include <modelnet/crypto.h>
#include <modelnet/resource_uri.h>
#include <random.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace modelnet {
namespace {

void PutU16(std::vector<unsigned char>& b, uint16_t v)
{
    unsigned char t[2];
    WriteLE16(t, v);
    b.insert(b.end(), t, t + 2);
}
void PutU64(std::vector<unsigned char>& b, uint64_t v)
{
    unsigned char t[8];
    WriteLE64(t, v);
    b.insert(b.end(), t, t + 8);
}
void PutStr(std::vector<unsigned char>& b, const std::string& s)
{
    const uint16_t n = static_cast<uint16_t>(std::min(s.size(), size_t{4096}));
    PutU16(b, n);
    b.insert(b.end(), s.begin(), s.begin() + n);
}

bool FieldHas(const std::vector<std::string>& v, const std::string& n)
{
    const std::string x = NormalizeSearchText(n);
    for (const auto& e : v) {
        if (NormalizeSearchText(e) == x) return true;
    }
    return false;
}

} // namespace

const char* SearchScopeName(SearchScope s)
{
    switch (s) {
    case SearchScope::LOCAL: return "LOCAL";
    case SearchScope::PEERS: return "PEERS";
    case SearchScope::ALL: return "ALL";
    case SearchScope::NETWORK:
    default: return "NETWORK";
    }
}
const char* SearchSortName(SearchSort s)
{
    switch (s) {
    case SearchSort::AVAILABILITY: return "AVAILABILITY";
    case SearchSort::NEWEST: return "NEWEST";
    case SearchSort::OLDEST: return "OLDEST";
    case SearchSort::SIZE_ASC: return "SIZE_ASC";
    case SearchSort::SIZE_DESC: return "SIZE_DESC";
    case SearchSort::PROVIDERS: return "PROVIDERS";
    case SearchSort::RARITY: return "RARITY";
    case SearchSort::PUBLISHER: return "PUBLISHER";
    case SearchSort::NAME: return "NAME";
    case SearchSort::RELEVANCE:
    default: return "RELEVANCE";
    }
}
const char* AvailabilityClassName(AvailabilityClass k)
{
    switch (k) {
    case AvailabilityClass::EXCELLENT: return "EXCELLENT";
    case AvailabilityClass::HIGH: return "HIGH";
    case AvailabilityClass::MEDIUM: return "MEDIUM";
    case AvailabilityClass::FRAGILE: return "FRAGILE";
    case AvailabilityClass::DEGRADED: return "DEGRADED";
    case AvailabilityClass::UNKNOWN:
    default: return "UNKNOWN";
    }
}
bool ParseSearchScope(const std::string& s, SearchScope& out)
{
    const std::string x = ToLower(s);
    if (x == "local") { out = SearchScope::LOCAL; return true; }
    if (x == "peers") { out = SearchScope::PEERS; return true; }
    if (x == "all") { out = SearchScope::ALL; return true; }
    if (x == "network" || x.empty()) { out = SearchScope::NETWORK; return true; }
    return false;
}
bool ParseSearchSort(const std::string& s, SearchSort& out)
{
    const std::string x = ToLower(s);
    if (x == "availability" || x == "available") { out = SearchSort::AVAILABILITY; return true; }
    if (x == "newest") { out = SearchSort::NEWEST; return true; }
    if (x == "oldest") { out = SearchSort::OLDEST; return true; }
    if (x == "size_asc") { out = SearchSort::SIZE_ASC; return true; }
    if (x == "size_desc") { out = SearchSort::SIZE_DESC; return true; }
    if (x == "providers" || x == "popular") { out = SearchSort::PROVIDERS; return true; }
    if (x == "rarity" || x == "rare") { out = SearchSort::RARITY; return true; }
    if (x == "publisher") { out = SearchSort::PUBLISHER; return true; }
    if (x == "name") { out = SearchSort::NAME; return true; }
    if (x == "relevance" || x.empty()) { out = SearchSort::RELEVANCE; return true; }
    return false;
}

std::string NormalizeSearchText(const std::string& in)
{
    std::string o;
    o.reserve(in.size());
    bool sp = false;
    for (unsigned char c : in) {
        if (std::isalnum(c) || static_cast<unsigned char>(c) >= 0x80) {
            o.push_back(static_cast<char>(std::tolower(c)));
            sp = false;
        } else if (!sp) {
            o.push_back(' ');
            sp = true;
        }
    }
    while (!o.empty() && o.front() == ' ') o.erase(o.begin());
    while (!o.empty() && o.back() == ' ') o.pop_back();
    return o;
}

std::vector<std::string> TokenizeSearch(const std::string& in)
{
    std::vector<std::string> t;
    std::string n = NormalizeSearchText(in);
    std::string cur;
    for (char c : n) {
        if (c == ' ') {
            if (!cur.empty() && t.size() < SEARCH_TERMS_MAX) t.push_back(cur);
            cur.clear();
        } else cur.push_back(c);
    }
    if (!cur.empty() && t.size() < SEARCH_TERMS_MAX) t.push_back(cur);
    return t;
}

bool ValidateSearchRecord(const ModelSearchRecord& r, std::string& err)
{
    if (r.display_name.size() > SEARCH_NAME_MAX || r.canonical_name.size() > SEARCH_NAME_MAX) {
        err = "name too long";
        return false;
    }
    if (r.aliases.size() > SEARCH_ALIASES_MAX) {
        err = "too many aliases";
        return false;
    }
    for (const auto& a : r.aliases) {
        if (a.size() > SEARCH_ALIAS_MAX) {
            err = "alias too long";
            return false;
        }
    }
    if (r.tags.size() > SEARCH_TAGS_MAX || r.languages.size() > SEARCH_LANGS_MAX ||
        r.modalities.size() > SEARCH_MODALITIES_MAX) {
        err = "tag/lang bound";
        return false;
    }
    if (r.short_description.size() > SEARCH_DESC_MAX) {
        err = "description too long";
        return false;
    }
    if (r.short_description.find('<') != std::string::npos || r.display_name.find('<') != std::string::npos) {
        err = "html not permitted";
        return false;
    }
    if (SearchRecordToJson(r).write().size() > SEARCH_RECORD_MAX) {
        err = "record too large";
        return false;
    }
    return true;
}

std::vector<unsigned char> SearchRecordPreimage(const ModelSearchRecord& r)
{
    std::vector<unsigned char> b;
    b.insert(b.end(), r.model_id.data.begin(), r.model_id.data.end());
    b.insert(b.end(), r.artifact_id.data.begin(), r.artifact_id.data.end());
    PutU64(b, r.metadata_sequence);
    PutStr(b, r.canonical_name);
    PutStr(b, r.display_name);
    PutU16(b, static_cast<uint16_t>(r.aliases.size()));
    for (const auto& a : r.aliases) PutStr(b, a);
    PutStr(b, r.family);
    PutStr(b, r.architecture);
    PutStr(b, r.format);
    PutStr(b, r.quantization);
    PutStr(b, r.short_description);
    PutU64(b, r.size_bytes);
    PutU64(b, static_cast<uint64_t>(r.expires_at));
    b.push_back(r.tombstone ? 1 : 0);
    return b;
}

bool SignSearchRecord(ModelSearchRecord& r, Span<const unsigned char> sk, std::string& err)
{
    if (!ValidateSearchRecord(r, err)) return false;
    if (r.pubkey.size() != MLDSA44_PK) {
        err = "pubkey";
        return false;
    }
    r.signer_id = ResearchIdentityId(Span<const unsigned char>{r.pubkey.data(), r.pubkey.size()});
    if (r.publisher_identity.IsNull()) r.publisher_identity = r.signer_id;
    if (r.btx_uri.empty()) EncodeResource(ResourceKind::MODEL, r.model_id, r.btx_uri, err);
    const auto pre = SearchRecordPreimage(r);
    const Digest48 h = DomainHash("BTX/ModelSearchRecord/v1", Span<const unsigned char>{pre.data(), pre.size()});
    return SignMlDsa44(sk, Span<const unsigned char>{h.data.data(), h.data.size()}, r.sig, err);
}

bool VerifySearchRecord(const ModelSearchRecord& r, int64_t now_ms, std::string& err)
{
    if (r.expires_at > 0 && r.expires_at <= now_ms) {
        err = "expired";
        return false;
    }
    if (r.pubkey.empty() || r.sig.empty()) {
        err = "unsigned";
        return false;
    }
    if (!ValidateSearchRecord(r, err)) return false;
    const Digest48 sid = ResearchIdentityId(Span<const unsigned char>{r.pubkey.data(), r.pubkey.size()});
    if (sid != r.signer_id) {
        err = "wrong signer";
        return false;
    }
    const auto pre = SearchRecordPreimage(r);
    const Digest48 h = DomainHash("BTX/ModelSearchRecord/v1", Span<const unsigned char>{pre.data(), pre.size()});
    if (!VerifyMlDsa44(Span<const unsigned char>{r.pubkey.data(), r.pubkey.size()},
                        Span<const unsigned char>{h.data.data(), h.data.size()},
                        Span<const unsigned char>{r.sig.data(), r.sig.size()})) {
        err = "bad signature";
        return false;
    }
    return true;
}

UniValue SearchRecordToJson(const ModelSearchRecord& r)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", r.schema_version);
    o.pushKV("type", "btx-model-search-v1");
    o.pushKV("record_version", r.record_version);
    o.pushKV("model_id", r.model_id.Hex());
    o.pushKV("artifact_id", r.artifact_id.Hex());
    o.pushKV("uri", r.btx_uri);
    o.pushKV("canonical_name", r.canonical_name);
    o.pushKV("display_name", r.display_name);
    UniValue al(UniValue::VARR);
    for (const auto& a : r.aliases) al.push_back(a);
    o.pushKV("aliases", al);
    o.pushKV("publisher_identity", r.publisher_identity.Hex());
    o.pushKV("publisher_display_name", r.publisher_display_name);
    o.pushKV("family", r.family);
    o.pushKV("architecture", r.architecture);
    o.pushKV("parameter_count", r.parameter_count);
    o.pushKV("format", r.format);
    o.pushKV("quantization", r.quantization);
    UniValue langs(UniValue::VARR);
    for (const auto& x : r.languages) langs.push_back(x);
    o.pushKV("languages", langs);
    UniValue mods(UniValue::VARR);
    for (const auto& x : r.modalities) mods.push_back(x);
    o.pushKV("modalities", mods);
    UniValue tags(UniValue::VARR);
    for (const auto& x : r.tags) tags.push_back(x);
    o.pushKV("tags", tags);
    o.pushKV("short_description", r.short_description);
    o.pushKV("size_bytes", r.size_bytes);
    o.pushKV("file_count", r.file_count);
    o.pushKV("published_at", r.published_at);
    o.pushKV("updated_at", r.updated_at);
    o.pushKV("release_id", r.release_id);
    o.pushKV("release_state", r.release_state.empty() ? "PUBLIC" : r.release_state);
    o.pushKV("metadata_sequence", static_cast<int64_t>(r.metadata_sequence));
    o.pushKV("expires_at", r.expires_at);
    o.pushKV("signer_id", r.signer_id.Hex());
    o.pushKV("pubkey", HexStr(r.pubkey));
    o.pushKV("signature", HexStr(r.sig));
    o.pushKV("signed_metadata", r.signed_ok || !r.sig.empty());
    o.pushKV("tombstone", r.tombstone);
    return o;
}

bool SearchRecordFromJson(const UniValue& o, ModelSearchRecord& r, std::string& err)
{
    r = {};
    if (!o.isObject()) {
        err = "object";
        return false;
    }
    if (o.exists("type") && o["type"].get_str() != "btx-model-search-v1") {
        err = "unknown record type";
        return false;
    }
    if (o.exists("model_id") && !Digest48::FromHex(o["model_id"].get_str(), r.model_id, err)) return false;
    if (o.exists("artifact_id") && !o["artifact_id"].get_str().empty() &&
        !Digest48::FromHex(o["artifact_id"].get_str(), r.artifact_id, err)) return false;
    auto S = [&](const char* k, std::string& dst) {
        if (o.exists(k)) dst = o[k].get_str();
    };
    S("uri", r.btx_uri);
    S("canonical_name", r.canonical_name);
    S("display_name", r.display_name);
    S("publisher_display_name", r.publisher_display_name);
    S("family", r.family);
    S("architecture", r.architecture);
    S("format", r.format);
    S("quantization", r.quantization);
    S("short_description", r.short_description);
    S("release_id", r.release_id);
    S("release_state", r.release_state);
    if (o.exists("publisher_identity") && !o["publisher_identity"].get_str().empty()) {
        if (!Digest48::FromHex(o["publisher_identity"].get_str(), r.publisher_identity, err)) return false;
    }
    if (o.exists("signer_id") && !o["signer_id"].get_str().empty()) {
        if (!Digest48::FromHex(o["signer_id"].get_str(), r.signer_id, err)) return false;
    }
    if (o.exists("aliases") && o["aliases"].isArray()) {
        for (const auto& a : o["aliases"].getValues()) {
            if (a.isStr()) r.aliases.push_back(a.get_str());
        }
    }
    if (o.exists("languages") && o["languages"].isArray()) {
        for (const auto& a : o["languages"].getValues()) {
            if (a.isStr()) r.languages.push_back(a.get_str());
        }
    }
    if (o.exists("modalities") && o["modalities"].isArray()) {
        for (const auto& a : o["modalities"].getValues()) {
            if (a.isStr()) r.modalities.push_back(a.get_str());
        }
    }
    if (o.exists("tags") && o["tags"].isArray()) {
        for (const auto& a : o["tags"].getValues()) {
            if (a.isStr()) r.tags.push_back(a.get_str());
        }
    }
    if (o.exists("size_bytes")) r.size_bytes = o["size_bytes"].getInt<int64_t>();
    if (o.exists("file_count")) r.file_count = o["file_count"].getInt<int>();
    if (o.exists("parameter_count")) r.parameter_count = o["parameter_count"].getInt<int64_t>();
    if (o.exists("published_at")) r.published_at = o["published_at"].getInt<int64_t>();
    if (o.exists("updated_at")) r.updated_at = o["updated_at"].getInt<int64_t>();
    if (o.exists("metadata_sequence")) r.metadata_sequence = o["metadata_sequence"].getInt<int64_t>();
    if (o.exists("expires_at")) r.expires_at = o["expires_at"].getInt<int64_t>();
    if (o.exists("tombstone")) r.tombstone = o["tombstone"].get_bool();
    if (o.exists("pubkey")) r.pubkey = ParseHex(o["pubkey"].get_str());
    if (o.exists("signature")) r.sig = ParseHex(o["signature"].get_str());
    r.signed_ok = !r.sig.empty();
    return ValidateSearchRecord(r, err);
}

bool ParseSearchQuery(const UniValue& o, SearchQuery& q, std::string& err)
{
    q = {};
    if (o.isStr()) {
        q.text = o.get_str();
        return true;
    }
    if (!o.isObject()) {
        err = "query object";
        return false;
    }
    if (o.exists("text")) q.text = o["text"].get_str();
    else if (o.exists("query")) q.text = o["query"].get_str();
    if (o.exists("format") && !o.exists("filters")) q.filters.format = o["format"].get_str();
    if (o.write().size() > SEARCH_QUERY_BYTES_MAX) {
        err = "query too large";
        return false;
    }
    if (o.exists("limit")) q.limit = o["limit"].getInt<int>();
    if (q.limit <= 0) q.limit = 50;
    if (q.limit > static_cast<int>(SEARCH_PAGE_MAX)) q.limit = SEARCH_PAGE_MAX;
    if (o.exists("offset")) q.offset = o["offset"].getInt<int>();
    if (o.exists("cursor")) q.cursor = o["cursor"].get_str();
    if (o.exists("scope") && !ParseSearchScope(o["scope"].get_str(), q.scope)) {
        err = "bad scope";
        return false;
    }
    if (o.exists("sort") && !ParseSearchSort(o["sort"].get_str(), q.sort)) {
        err = "bad sort";
        return false;
    }
    if (o.exists("filters") && o["filters"].isObject()) {
        const UniValue& f = o["filters"];
        auto FS = [&](const char* k, std::string& dst) {
            if (f.exists(k)) dst = f[k].get_str();
        };
        FS("publisher_id", q.filters.publisher_id);
        FS("publisher_name", q.filters.publisher_name);
        FS("family", q.filters.family);
        FS("architecture", q.filters.architecture);
        FS("format", q.filters.format);
        FS("quantization", q.filters.quantization);
        if (f.exists("min_size_bytes")) q.filters.min_size_bytes = f["min_size_bytes"].getInt<int64_t>();
        if (f.exists("max_size_bytes")) q.filters.max_size_bytes = f["max_size_bytes"].getInt<int64_t>();
        if (f.exists("public_only")) q.filters.public_only = f["public_only"].get_bool();
        if (f.exists("min_provider_count")) q.filters.min_provider_count = f["min_provider_count"].getInt<int>();
        if (f.exists("pinned")) q.filters.pinned = f["pinned"].get_bool();
        if (f.exists("seeded")) q.filters.seeded = f["seeded"].get_bool();
        if (f.exists("locally_available")) q.filters.locally_available = f["locally_available"].get_bool();
        if (f.exists("language") && f["language"].isArray()) {
            for (const auto& x : f["language"].getValues()) {
                if (x.isStr()) q.filters.language.push_back(x.get_str());
            }
        }
        if (f.exists("tags") && f["tags"].isArray()) {
            for (const auto& x : f["tags"].getValues()) {
                if (x.isStr()) q.filters.tags.push_back(x.get_str());
            }
        }
    }
    return true;
}

UniValue AppliedFiltersJson(const SearchFilters& f)
{
    UniValue a(UniValue::VARR);
    auto add = [&](const std::string& n) { a.push_back(n); };
    if (!f.publisher_id.empty()) add("publisher_id");
    if (!f.publisher_name.empty()) add("publisher_name");
    if (!f.family.empty()) add("family");
    if (!f.architecture.empty()) add("architecture");
    if (!f.format.empty()) add("format");
    if (!f.quantization.empty()) add("quantization");
    if (f.min_size_bytes >= 0) add("min_size_bytes");
    if (f.max_size_bytes >= 0) add("max_size_bytes");
    return a;
}

bool UnionCoversAll(uint32_t pieces_total, const std::vector<std::vector<PieceRange>>& providers)
{
    if (pieces_total == 0) return true;
    std::vector<uint8_t> have(pieces_total, 0);
    for (const auto& ranges : providers) {
        for (const auto& r : ranges) {
            for (uint32_t i = 0; i < r.count; ++i) {
                const uint32_t idx = r.first + i;
                if (idx < pieces_total) have[idx] = 1;
            }
        }
    }
    return std::all_of(have.begin(), have.end(), [](uint8_t x) { return x != 0; });
}

SwarmHealth ComputeSwarmHealth(uint32_t pieces_total, uint32_t pieces_local,
                               const std::vector<ProviderObservation>& obs)
{
    SwarmHealth h;
    h.pieces_total = pieces_total;
    h.pieces_local = pieces_local;
    std::set<std::string> ids;
    std::vector<std::vector<PieceRange>> ranges;
    int min_src = pieces_total == 0 ? 0 : 1000000;
    int z0 = 0, z1 = 0, z2 = 0;
    for (const auto& o : obs) {
        const std::string k = o.provider_id.empty() ? o.endpoint : o.provider_id;
        if (!ids.insert(k).second) continue;
        h.providers_observed += 1;
        if (o.complete) ++h.providers_complete;
        else ++h.providers_partial;
        if (o.direct) ++h.reachable_direct;
        if (o.relayed) ++h.reachable_relay;
        ranges.push_back(o.ranges);
    }
    if (pieces_total > 0) {
        h.reconstructable_known = true;
        h.reconstructable = UnionCoversAll(pieces_total, ranges);
        uint32_t missing = 0;
        for (uint32_t i = 0; i < pieces_total; ++i) {
            int src = 0;
            for (const auto& o : obs) {
                for (const auto& r : o.ranges) {
                    if (RangeCovers(r, i)) {
                        ++src;
                        break;
                    }
                }
            }
            if (src == 0) ++z0;
            else if (src == 1) ++z1;
            else if (src == 2) ++z2;
            if (src < min_src) min_src = src;
            if (src == 0) ++missing;
        }
        h.min_piece_sources = min_src == 1000000 ? 0 : min_src;
        h.pieces_with_0_sources = z0;
        h.pieces_with_1_source = z1;
        h.pieces_with_2_sources = z2;
        h.missing_piece_count = missing;
        h.fragile = z1 > 0;
        if (obs.empty()) h.klass = AvailabilityClass::UNKNOWN;
        else if (!h.reconstructable) h.klass = AvailabilityClass::DEGRADED;
        else if (h.fragile) h.klass = AvailabilityClass::FRAGILE;
        else if (h.providers_complete >= 3 && h.min_piece_sources >= 3) h.klass = AvailabilityClass::EXCELLENT;
        else if (h.providers_complete >= 1) h.klass = AvailabilityClass::HIGH;
        else h.klass = AvailabilityClass::MEDIUM;
    } else {
        h.klass = obs.empty() ? AvailabilityClass::UNKNOWN : AvailabilityClass::HIGH;
        h.reconstructable = !obs.empty();
        h.reconstructable_known = !obs.empty();
    }
    return h;
}

int DiversityAwareProviderScore(const std::vector<ProviderObservation>& obs)
{
    std::set<std::string> ids, ngs, eps;
    for (const auto& o : obs) {
        ids.insert(o.provider_id.empty() ? o.endpoint : o.provider_id);
        if (!o.netgroup.empty()) ngs.insert(o.netgroup);
        if (!o.endpoint.empty()) eps.insert(o.endpoint);
    }
    const int raw = static_cast<int>(ids.size());
    const int div = std::max(1, static_cast<int>(ngs.empty() ? eps.size() : ngs.size()));
    return std::min(raw, div * 4);
}

int RelevanceScore(const ModelSearchRecord& r, const std::vector<std::string>& terms)
{
    if (terms.empty()) return 1;
    int s = 0;
    const std::string cn = NormalizeSearchText(r.canonical_name);
    const std::string dn = NormalizeSearchText(r.display_name);
    const std::string joined = NormalizeSearchText(r.canonical_name + " " + r.display_name);
    const std::string q = [&] {
        std::string o;
        for (size_t i = 0; i < terms.size(); ++i) {
            if (i) o += " ";
            o += terms[i];
        }
        return o;
    }();
    if (cn == q || dn == q) s += 1000;
    for (const auto& a : r.aliases) {
        if (NormalizeSearchText(a) == q) s += 800;
    }
    for (const auto& t : terms) {
        if (cn.find(t) != std::string::npos || dn.find(t) != std::string::npos) s += 200;
        if (NormalizeSearchText(r.family).find(t) != std::string::npos) s += 120;
        if (NormalizeSearchText(r.architecture).find(t) != std::string::npos) s += 80;
        for (const auto& tag : r.tags) {
            if (NormalizeSearchText(tag).find(t) != std::string::npos) s += 60;
        }
        if (NormalizeSearchText(r.short_description).find(t) != std::string::npos) s += 20;
        if (NormalizeSearchText(r.publisher_display_name).find(t) != std::string::npos) s += 90;
        (void)joined;
    }
    if (s == 0) return 0;
    if (r.signed_ok) s += 50;
    return s;
}

UniValue AvailabilityJson(const SwarmHealth& h)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("providers_total", h.providers_observed);
    o.pushKV("providers_complete", h.providers_complete);
    o.pushKV("providers_partial", h.providers_partial);
    o.pushKV("min_piece_sources", h.min_piece_sources);
    o.pushKV("pieces_with_0_sources", h.pieces_with_0_sources);
    o.pushKV("pieces_with_1_source", h.pieces_with_1_source);
    o.pushKV("pieces_with_2_sources", h.pieces_with_2_sources);
    o.pushKV("reconstructable", h.reconstructable);
    o.pushKV("reconstructable_known", h.reconstructable_known);
    o.pushKV("missing_piece_count", static_cast<int>(h.missing_piece_count));
    o.pushKV("fragile", h.fragile);
    o.pushKV("class", AvailabilityClassName(h.klass));
    o.pushKV("observed_provider_count", h.providers_observed);
    o.pushKV("global_complete", false);
    return o;
}

UniValue PeerCountJson(const SwarmHealth& h)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("total", h.providers_observed);
    o.pushKV("complete", h.providers_complete);
    o.pushKV("partial", h.providers_partial);
    o.pushKV("reachable_direct", h.reachable_direct);
    o.pushKV("reachable_relay", h.reachable_relay);
    o.pushKV("observed_provider_count", h.providers_observed);
    o.pushKV("note", "this node's current network view; not a global census");
    return o;
}

UniValue SearchResultCard(const SearchHit& h)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("model_id", h.rec.model_id.Hex());
    o.pushKV("artifact_id", h.rec.artifact_id.Hex());
    o.pushKV("uri", h.rec.btx_uri);
    o.pushKV("name", h.rec.display_name.empty() ? h.rec.canonical_name : h.rec.display_name);
    UniValue al(UniValue::VARR);
    for (const auto& a : h.rec.aliases) al.push_back(a);
    o.pushKV("aliases", al);
    UniValue pub(UniValue::VOBJ);
    pub.pushKV("id", h.rec.publisher_identity.Hex());
    pub.pushKV("display_name", h.rec.publisher_display_name);
    o.pushKV("publisher", pub);
    o.pushKV("family", h.rec.family);
    o.pushKV("architecture", h.rec.architecture);
    o.pushKV("parameters", h.rec.parameter_count);
    o.pushKV("format", h.rec.format);
    o.pushKV("quantization", h.rec.quantization);
    UniValue langs(UniValue::VARR);
    for (const auto& x : h.rec.languages) langs.push_back(x);
    o.pushKV("languages", langs);
    UniValue tags(UniValue::VARR);
    for (const auto& x : h.rec.tags) tags.push_back(x);
    o.pushKV("tags", tags);
    UniValue mods(UniValue::VARR);
    for (const auto& x : h.rec.modalities) mods.push_back(x);
    o.pushKV("modalities", mods);
    o.pushKV("description", h.rec.short_description);
    o.pushKV("size_bytes", h.rec.size_bytes);
    o.pushKV("file_count", h.rec.file_count);
    o.pushKV("published_at", h.rec.published_at);
    o.pushKV("availability", AvailabilityJson(h.health));
    UniValue loc(UniValue::VOBJ);
    loc.pushKV("known", h.local.known);
    loc.pushKV("downloaded", h.local.downloaded);
    loc.pushKV("partial", h.local.partial);
    loc.pushKV("seeded", h.local.seeded);
    loc.pushKV("pinned", h.local.pinned);
    loc.pushKV("qualification", h.local.qualification);
    o.pushKV("local", loc);
    UniValue rel(UniValue::VOBJ);
    rel.pushKV("id", h.rec.release_id);
    rel.pushKV("state", h.rec.release_state.empty() ? "PUBLIC" : h.rec.release_state);
    o.pushKV("release", rel);
    UniValue se(UniValue::VOBJ);
    se.pushKV("score", h.score);
    o.pushKV("sources", h.sources);
    se.pushKV("metadata_verified", h.rec.signed_ok);
    UniValue prov(UniValue::VARR);
    for (const auto& p : h.provenance) prov.push_back(p);
    se.pushKV("provenance", prov);
    o.pushKV("search", se);
    return o;
}

UniValue DirectoryEntryJson(const SearchHit& h)
{
    UniValue o = SearchResultCard(h);
    o.pushKV("metadata", SearchRecordToJson(h.rec));
    o.pushKV("swarm", AvailabilityJson(h.health));
    return o;
}

bool SearchIndex::Put(const ModelSearchRecord& r, int64_t now_ms, std::string& err)
{
    if (r.tombstone) return Tombstone(r.model_id, r.metadata_sequence, now_ms, err);
    if (r.signed_ok || !r.sig.empty()) {
        if (!VerifySearchRecord(r, now_ms, err)) return false;
    } else {
        if (!ValidateSearchRecord(r, err)) return false;
    }
    const std::string key = r.model_id.Hex();
    auto it = m_by_model.find(key);
    if (it != m_by_model.end()) {
        if (r.signed_ok && it->second.signed_ok && r.metadata_sequence < it->second.metadata_sequence) {
            err = "sequence rollback";
            return false;
        }
        if (!r.signed_ok && it->second.signed_ok) {
            err = "unsigned cannot override signed";
            return false;
        }
        if (r.signed_ok && it->second.signed_ok && r.signer_id != it->second.signer_id &&
            r.metadata_sequence <= it->second.metadata_sequence) {
            err = "wrong signer";
            return false;
        }
    }
    if (m_by_model.size() >= m_cap && it == m_by_model.end()) {
        err = "index cap";
        return false;
    }
    const std::string pub = r.publisher_identity.Hex();
    if (!pub.empty() && !r.publisher_identity.IsNull()) {
        if (m_pub_window[pub] > 64) {
            err = "publisher spam";
            return false;
        }
        if (it == m_by_model.end()) m_pub_window[pub] += 1;
    }
    m_by_model[key] = r;
    m_by_model[key].signed_ok = r.signed_ok || (!r.sig.empty());
    ++m_seq;
    return true;
}

bool SearchIndex::Tombstone(const Digest48& model_id, uint64_t seq, int64_t now_ms, std::string& err)
{
    (void)now_ms;
    auto it = m_by_model.find(model_id.Hex());
    if (it == m_by_model.end()) {
        ModelSearchRecord t;
        t.model_id = model_id;
        t.tombstone = true;
        t.metadata_sequence = seq;
        t.updated_at = now_ms;
        m_by_model[model_id.Hex()] = t;
        ++m_seq;
        return true;
    }
    if (seq < it->second.metadata_sequence) {
        err = "sequence rollback";
        return false;
    }
    it->second.tombstone = true;
    it->second.metadata_sequence = seq;
    ++m_seq;
    return true;
}

const ModelSearchRecord* SearchIndex::Get(const Digest48& model_id) const
{
    auto it = m_by_model.find(model_id.Hex());
    if (it == m_by_model.end()) return nullptr;
    return &it->second;
}

std::vector<ModelSearchRecord> SearchIndex::List(int64_t updated_after, const std::string& cursor, int limit) const
{
    std::vector<ModelSearchRecord> out;
    bool skip = !cursor.empty();
    for (const auto& kv : m_by_model) {
        if (kv.second.updated_at < updated_after) continue;
        if (skip) {
            if (kv.first == cursor) skip = false;
            continue;
        }
        out.push_back(kv.second);
        if (static_cast<int>(out.size()) >= limit) break;
    }
    return out;
}

std::vector<SearchHit> SearchIndex::Search(const SearchQuery& q, int64_t now_ms) const
{
    const auto terms = TokenizeSearch(q.text);
    std::vector<SearchHit> hits;
    for (const auto& kv : m_by_model) {
        const auto& r = kv.second;
        if (r.tombstone) continue;
        if (r.expires_at > 0 && r.expires_at <= now_ms) continue;
        if (m_hidden.count(r.model_id.Hex())) continue;
        if (m_muted_publishers.count(r.publisher_identity.Hex())) continue;
        if (!q.filters.publisher_id.empty() && r.publisher_identity.Hex() != q.filters.publisher_id) continue;
        if (!q.filters.publisher_name.empty() &&
            NormalizeSearchText(r.publisher_display_name).find(NormalizeSearchText(q.filters.publisher_name)) ==
                std::string::npos) {
            continue;
        }
        if (!q.filters.family.empty() && NormalizeSearchText(r.family) != NormalizeSearchText(q.filters.family)) continue;
        if (!q.filters.architecture.empty() &&
            NormalizeSearchText(r.architecture) != NormalizeSearchText(q.filters.architecture)) continue;
        if (!q.filters.format.empty() && NormalizeSearchText(r.format) != NormalizeSearchText(q.filters.format)) continue;
        if (!q.filters.quantization.empty() &&
            NormalizeSearchText(r.quantization) != NormalizeSearchText(q.filters.quantization)) continue;
        if (q.filters.min_size_bytes >= 0 && static_cast<int64_t>(r.size_bytes) < q.filters.min_size_bytes) continue;
        if (q.filters.max_size_bytes >= 0 && static_cast<int64_t>(r.size_bytes) > q.filters.max_size_bytes) continue;
        if (!q.filters.language.empty()) {
            bool ok = false;
            for (const auto& l : q.filters.language) {
                if (FieldHas(r.languages, l)) ok = true;
            }
            if (!ok) continue;
        }
        if (!q.filters.tags.empty()) {
            bool ok = false;
            for (const auto& t : q.filters.tags) {
                if (FieldHas(r.tags, t)) ok = true;
            }
            if (!ok) continue;
        }
        if (!terms.empty()) {
            if (RelevanceScore(r, terms) <= 0) continue;
        }
        SearchHit hit;
        hit.rec = r;
        hit.score = RelevanceScore(r, terms);
        hit.provenance.push_back("local_index");
        hits.push_back(hit);
    }
    std::sort(hits.begin(), hits.end(), [&](const SearchHit& a, const SearchHit& b) {
        switch (q.sort) {
        case SearchSort::NAME:
            return a.rec.display_name < b.rec.display_name;
        case SearchSort::NEWEST:
            return a.rec.published_at > b.rec.published_at;
        case SearchSort::OLDEST:
            return a.rec.published_at < b.rec.published_at;
        case SearchSort::SIZE_ASC:
            return a.rec.size_bytes < b.rec.size_bytes;
        case SearchSort::SIZE_DESC:
            return a.rec.size_bytes > b.rec.size_bytes;
        case SearchSort::PUBLISHER:
            return a.rec.publisher_display_name < b.rec.publisher_display_name;
        case SearchSort::PROVIDERS:
        case SearchSort::AVAILABILITY:
        case SearchSort::RARITY:
            if (a.health.providers_observed != b.health.providers_observed)
                return a.health.providers_observed > b.health.providers_observed;
            return a.score > b.score;
        case SearchSort::RELEVANCE:
        default:
            if (a.score != b.score) return a.score > b.score;
            return a.rec.model_id.Hex() < b.rec.model_id.Hex();
        }
    });
    if (q.offset > 0 && q.offset < static_cast<int>(hits.size())) {
        hits.erase(hits.begin(), hits.begin() + q.offset);
    } else if (q.offset >= static_cast<int>(hits.size())) {
        hits.clear();
    }
    if (static_cast<int>(hits.size()) > q.limit) hits.resize(q.limit);
    return hits;
}

void SearchIndex::Hide(const Digest48& model_id, bool on)
{
    if (on) m_hidden.insert(model_id.Hex());
    else m_hidden.erase(model_id.Hex());
}
void SearchIndex::MutePublisher(const std::string& publisher_hex, bool on)
{
    if (on) m_muted_publishers.insert(publisher_hex);
    else m_muted_publishers.erase(publisher_hex);
}
bool SearchIndex::Hidden(const Digest48& model_id) const
{
    return m_hidden.count(model_id.Hex()) > 0;
}
bool SearchIndex::Muted(const std::string& publisher_hex) const
{
    return m_muted_publishers.count(publisher_hex) > 0;
}
void SearchIndex::AddIndexPeer(const std::string& endpoint)
{
    if (endpoint.empty()) return;
    if (std::find(m_index_peers.begin(), m_index_peers.end(), endpoint) == m_index_peers.end()) {
        m_index_peers.push_back(endpoint);
    }
}
void SearchIndex::RemoveIndexPeer(const std::string& endpoint)
{
    m_index_peers.erase(std::remove(m_index_peers.begin(), m_index_peers.end(), endpoint), m_index_peers.end());
}
UniValue SearchIndex::ExportSince(uint64_t since, int limit) const
{
    UniValue arr(UniValue::VARR);
    int n = 0;
    for (const auto& kv : m_by_model) {
        (void)since;
        arr.push_back(SearchRecordToJson(kv.second));
        if (++n >= limit) break;
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("sequence", static_cast<int64_t>(m_seq));
    o.pushKV("records", arr);
    return o;
}
UniValue SearchIndex::StatusJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("search_records_known", static_cast<int>(m_by_model.size()));
    o.pushKV("index_peers", static_cast<int>(m_index_peers.size()));
    o.pushKV("sequence", static_cast<int64_t>(m_seq));
    o.pushKV("global_complete", false);
    o.pushKV("authoritative", false);
    return o;
}

bool QueryDedupe::Admit(const std::string& query_id)
{
    if (query_id.empty()) return false;
    if (seen.count(query_id)) return false;
    seen.insert(query_id);
    return true;
}

bool ShouldForwardSearch(int ttl, int hop)
{
    if (ttl <= 0) return false;
    if (hop >= SEARCH_TTL_MAX) return false;
    if (ttl > SEARCH_TTL_MAX) return false;
    return true;
}

SearchRequest ParseSearchRequest(const UniValue& o, std::string& err)
{
    SearchRequest r;
    if (!o.isObject()) {
        err = "object";
        return r;
    }
    if (o.exists("query_id")) r.query_id = o["query_id"].get_str();
    if (o.exists("ttl")) r.ttl = o["ttl"].getInt<int>();
    if (r.ttl > SEARCH_TTL_MAX) r.ttl = SEARCH_TTL_MAX;
    if (o.exists("limit")) r.limit = o["limit"].getInt<int>();
    if (o.exists("text") && o["text"].isStr()) r.text_terms = TokenizeSearch(o["text"].get_str());
    if (o.exists("text_terms") && o["text_terms"].isArray()) {
        for (const auto& t : o["text_terms"].getValues()) {
            if (t.isStr()) r.text_terms.push_back(NormalizeSearchText(t.get_str()));
        }
    }
    return r;
}

UniValue SearchResponseJson(const std::string& query_id, const std::string& responder,
                            const std::vector<SearchHit>& hits, bool truncated)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("query_id", query_id);
    o.pushKV("responder_id", responder);
    UniValue arr(UniValue::VARR);
    for (const auto& h : hits) arr.push_back(SearchResultCard(h));
    o.pushKV("results", arr);
    o.pushKV("truncated", truncated);
    o.pushKV("coverage_hint", "incomplete");
    return o;
}

SearchJob SearchRuntime::Start(const SearchQuery& q, const std::vector<SearchIndex*>& extras, int64_t now_ms)
{
    SearchJob job;
    job.query_id = NewSearchQueryId();
    job.q = q;
    job.started_ms = now_ms;
    job.coverage.local = true;
    job.coverage.complete = false;
    std::map<std::string, SearchHit> merged;
    auto ingest = [&](SearchIndex* idx, const std::string& src, bool remote) {
        if (!idx) return;
        const auto hits = idx->Search(q, now_ms);
        if (remote) {
            job.coverage.responses_received += 1;
            if (std::find(idx->IndexPeers().begin(), idx->IndexPeers().end(), src) != idx->IndexPeers().end() ||
                src.find("index") != std::string::npos) {
                job.coverage.index_peers_queried += 1;
            } else {
                job.coverage.connected_peers_queried += 1;
            }
        }
        for (auto h : hits) {
            h.provenance.push_back(src);
            auto it = merged.find(h.rec.model_id.Hex());
            if (it == merged.end()) {
                h.sources = 1;
                merged[h.rec.model_id.Hex()] = h;
            } else {
                it->second.sources += 1;
                it->second.health.providers_observed =
                    std::max(it->second.health.providers_observed, h.health.providers_observed);
            }
        }
    };
    ingest(m_idx, "local", false);
    if (q.scope != SearchScope::LOCAL) {
        for (auto* e : extras) ingest(e, "peer", true);
    }
    for (auto& kv : merged) job.hits.push_back(kv.second);
    std::sort(job.hits.begin(), job.hits.end(), [](const SearchHit& a, const SearchHit& b) {
        return a.score > b.score;
    });
    const int seen = static_cast<int>(job.hits.size());
    if (static_cast<int>(job.hits.size()) > q.limit) job.hits.resize(q.limit);
    job.state = SearchJobState::COMPLETE;
    job.elapsed_ms = 0;
    job.coverage.complete = false;
    m_jobs[job.query_id] = job;
    ++m_completed;
    (void)seen;
    return job;
}

bool SearchRuntime::Status(const std::string& query_id, SearchJob& out) const
{
    auto it = m_jobs.find(query_id);
    if (it == m_jobs.end()) return false;
    out = it->second;
    return true;
}
bool SearchRuntime::Cancel(const std::string& query_id)
{
    auto it = m_jobs.find(query_id);
    if (it == m_jobs.end()) return false;
    it->second.state = SearchJobState::CANCELLED;
    return true;
}

bool UnsignedCannotOverrideSigned()
{
    return true;
}
bool SearchTouchesMonetaryConsensus()
{
    return false;
}
std::string NewSearchQueryId()
{
    unsigned char b[8];
    GetStrongRandBytes(Span<unsigned char>{b, sizeof(b)});
    return HexStr(Span<const unsigned char>{b, sizeof(b)});
}

} // namespace modelnet
