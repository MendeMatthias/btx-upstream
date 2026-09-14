// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/helper.h>

#include <crypto/sha256.h>
#include <modelnet/community.h>
#include <modelnet/crypto.h>
#include <modelnet/free_grant.h>
#include <modelnet/identity.h>
#include <modelnet/policy.h>
#include <modelnet/pq1_runtime.h>
#include <modelnet/protocol.h>
#include <modelnet/records.h>
#include <modelnet/qualification.h>
#include <modelnet/release.h>
#include <modelnet/resource_uri.h>
#include <modelnet/router.h>
#include <modelnet/swarm.h>
#include <modelnet/transfer.h>
#include <random.h>
#include <span.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <openssl/opensslv.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <sstream>
#include <thread>
#include <vector>

namespace modelnet {
namespace {

constexpr size_t MAX_HTTP_HEADERS = PQ1_HTTP_HEADER_CAP;
constexpr size_t MAX_RPC_BODY = 64 * 1024;
constexpr size_t MAX_PIECE_HTTP = MAX_HTTP_HEADERS + PIECE_SIZE + 4096;
constexpr uint64_t PQ1_RECONNECT_BYTES = 8ULL << 30;

std::string TrimCopy(std::string s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.pop_back();
    return s;
}

std::string OpensslBin()
{
    if (const char* e = std::getenv("BTX_OPENSSL")) return e;
    return "openssl";
}

std::string HeaderGet(const NativeResponse& resp, const std::string& name)
{
    const std::string want = ToLower(name);
    for (const auto& h : resp.headers) {
        if (ToLower(h.first) == want) return h.second;
    }
    return {};
}

std::string RequestHeader(const NativeRequest& req, const std::string& name)
{
    const std::string want = ToLower(name);
    for (const auto& h : req.headers) {
        if (ToLower(h.first) == want) return h.second;
    }
    return {};
}

std::string JsonError(const std::string& code, const std::string& message)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("error_code", code);
    o.pushKV("message", message);
    return o.write();
}

bool SplitHostPort(const std::string& in, std::string& host, uint16_t& port)
{
    const auto colon = in.rfind(':');
    if (colon == std::string::npos) return false;
    host = in.substr(0, colon);
    try {
        const int p = std::stoi(in.substr(colon + 1));
        if (p <= 0 || p > 65535) return false;
        port = static_cast<uint16_t>(p);
    } catch (...) {
        return false;
    }
    if (host.empty()) host = "0.0.0.0";
    return true;
}

void SetListenOpts(int fd)
{
    SetPq1SocketOpts(fd, /*nonblock=*/true);
}

constexpr uint32_t EXT_VERSION = 257;
constexpr uint32_t FEAT_RESOURCE_RESOLVE = 1u;
constexpr uint32_t FEAT_FREE_GRANT = 2u;
constexpr uint32_t FEAT_SERVICE_RECEIPT = 4u;
constexpr uint32_t FEAT_RESEARCH_IDENTITY = 8u;
constexpr uint32_t FEAT_COLLECTIONS_ALIAS = 16u;
constexpr uint32_t FEAT_POLICY_BUNDLE = 32u;
constexpr uint32_t FEAT_PRESERVATION_CIRCLE = 64u;
constexpr uint32_t EXT_FEATURES = FEAT_RESOURCE_RESOLVE | FEAT_FREE_GRANT | FEAT_SERVICE_RECEIPT |
                                  FEAT_RESEARCH_IDENTITY | FEAT_COLLECTIONS_ALIAS | FEAT_POLICY_BUNDLE |
                                  FEAT_PRESERVATION_CIRCLE;
std::mutex g_ext_mu;

fs::path HelperDir(const ModelCatalog& cat)
{
    return cat.Store().Root().parent_path();
}

bool ReadJsonFile(const fs::path& path, UniValue& out)
{
    std::ifstream in(path);
    if (!in) {
        out = UniValue(UniValue::VOBJ);
        return true;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    if (!out.read(ss.str())) {
        out = UniValue(UniValue::VOBJ);
        return false;
    }
    if (!out.isObject() && !out.isArray()) out = UniValue(UniValue::VOBJ);
    return true;
}

bool WriteJsonFile(const fs::path& path, const UniValue& obj, std::string& err)
{
    fs::create_directories(path.parent_path());
    std::ofstream out(path);
    if (!out) {
        err = "write " + fs::PathToString(path);
        return false;
    }
    out << obj.write() << "\n";
    return true;
}

RouterCache& RecordsFor(const ModelCatalog& cat)
{
    static std::mutex mu;
    static std::map<std::string, RouterCache> caches;
    static std::map<std::string, bool> loaded;
    const std::string key = fs::PathToString(HelperDir(cat));
    std::lock_guard<std::mutex> lock(mu);
    RouterCache& cache = caches[key];
    if (!loaded[key]) {
        loaded[key] = true;
        UniValue arr;
        ReadJsonFile(HelperDir(cat) / "records.json", arr);
        if (arr.isArray()) {
            const int64_t now = static_cast<int64_t>(std::time(nullptr));
            for (const auto& rec : arr.getValues()) {
                if (!rec.isObject() || !rec.exists("record_id")) continue;
                SignedRecordHint h;
                std::string e;
                if (!Digest48::FromHex(rec["record_id"].get_str(), h.record_id, e)) continue;
                h.kind = rec.exists("kind") ? static_cast<uint8_t>(rec["kind"].getInt<int>()) : 0;
                h.expiry = rec.exists("expiry") ? rec["expiry"].getInt<int64_t>() : 0;
                h.provider_id = rec.exists("provider_id") ? rec["provider_id"].get_str() : "";
                if (rec.exists("payload_hex")) {
                    if (auto bytes = TryParseHex<unsigned char>(rec["payload_hex"].get_str())) h.payload = *bytes;
                }
                if (rec.exists("sig_hex")) {
                    if (auto bytes = TryParseHex<unsigned char>(rec["sig_hex"].get_str())) h.signature = *bytes;
                }
                if (rec.exists("pubkey_hex")) {
                    if (auto bytes = TryParseHex<unsigned char>(rec["pubkey_hex"].get_str())) h.pubkey = *bytes;
                }
                h.signed_ok = rec.exists("signed_ok") && rec["signed_ok"].get_bool();
                cache.Insert(h, now, e);
            }
        }
    }
    return cache;
}

bool PersistRecords(const ModelCatalog& cat, RouterCache& cache)
{
    UniValue arr(UniValue::VARR);
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    for (const auto& h : cache.All(now)) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("record_id", h.record_id.Hex());
        o.pushKV("kind", h.kind);
        o.pushKV("expiry", h.expiry);
        o.pushKV("provider_id", h.provider_id);
        o.pushKV("payload_hex", HexStr(h.payload));
        if (!h.signature.empty()) o.pushKV("sig_hex", HexStr(h.signature));
        if (!h.pubkey.empty()) o.pushKV("pubkey_hex", HexStr(h.pubkey));
        o.pushKV("signed_ok", h.signed_ok);
        arr.push_back(o);
    }
    std::string err;
    return WriteJsonFile(HelperDir(cat) / "records.json", arr, err);
}

UniValue HintJson(const SignedRecordHint& h)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("record_id", h.record_id.Hex());
    o.pushKV("kind", h.kind);
    o.pushKV("expiry", h.expiry);
    o.pushKV("provider_id", h.provider_id);
    o.pushKV("payload_hex", HexStr(h.payload));
    o.pushKV("signed_ok", h.signed_ok);
    return o;
}

NegativeResolveCache& NegCache()
{
    static NegativeResolveCache c;
    return c;
}

bool LoadOrCreateResearchIdentity(const fs::path& dir, std::vector<unsigned char>& pk, std::vector<unsigned char>& sk,
                                  Digest48& id, std::string& err)
{
    UniValue store;
    ReadJsonFile(dir / "research_identity.json", store);
    if (store.exists("pk_hex") && store.exists("sk_hex")) {
        auto pkb = TryParseHex<unsigned char>(store["pk_hex"].get_str());
        auto skb = TryParseHex<unsigned char>(store["sk_hex"].get_str());
        if (pkb && skb) {
            pk = *pkb;
            sk = *skb;
            id = ResearchIdentityId(pk);
            return true;
        }
    }
    if (!GenerateMlDsa44(pk, sk, err)) return false;
    id = ResearchIdentityId(pk);
    store.pushKV("pk_hex", HexStr(pk));
    store.pushKV("sk_hex", HexStr(sk));
    store.pushKV("id", id.Hex());
    return WriteJsonFile(dir / "research_identity.json", store, err);
}

bool AcceptSignedAnnounce(const UniValue& body, int64_t now, SignedRecordHint& h, std::string& err)
{
    if (!body.exists("kind") || !body.exists("payload_hex") || !body.exists("sig_hex") || !body.exists("pubkey_hex")) {
        err = "unsigned announce rejected";
        return false;
    }
    h.kind = static_cast<uint8_t>(body["kind"].getInt<int>());
    const auto payload = TryParseHex<unsigned char>(body["payload_hex"].get_str());
    const auto sig = TryParseHex<unsigned char>(body["sig_hex"].get_str());
    const auto pk = TryParseHex<unsigned char>(body["pubkey_hex"].get_str());
    if (!payload || !sig || !pk) {
        err = "announce hex";
        return false;
    }
    UniValue decoded;
    Digest48 rid;
    if (!VerifyTypedRecord(h.kind, *payload, *sig, *pk, now, decoded, rid, err)) return false;
    if (body.exists("record_id")) {
        Digest48 claimed;
        if (!Digest48::FromHex(body["record_id"].get_str(), claimed, err) || claimed != rid) {
            err = "record_id does not match typed object";
            return false;
        }
    }
    h.record_id = rid;
    h.payload = *payload;
    h.signature = *sig;
    h.pubkey = *pk;
    h.signed_ok = true;
    h.expiry = decoded.exists("expires_at") ? decoded["expires_at"].getInt<int64_t>() : 0;
    h.provider_id = body.exists("provider_id") ? body["provider_id"].get_str() : decoded["signer_id"].get_str();
    return true;
}

uint8_t RecordKindForResourceKind(uint8_t resource_kind)
{
    switch (resource_kind) {
    case static_cast<uint8_t>(ResourceKind::COLLECTION): return RECORD_COLLECTION;
    case static_cast<uint8_t>(ResourceKind::IDENTITY): return RECORD_IDENTITY_CARD;
    case static_cast<uint8_t>(ResourceKind::POLICY_BUNDLE): return RECORD_POLICY_BUNDLE;
    case static_cast<uint8_t>(ResourceKind::CIRCLE): return RECORD_PRESERVATION_CIRCLE;
    case static_cast<uint8_t>(ResourceKind::ALIAS): return RECORD_ALIAS;
    case static_cast<uint8_t>(ResourceKind::PROVIDER): return RECORD_IDENTITY_CARD;
    default: return 0;
    }
}

bool KindFromJson(const UniValue& v, uint8_t& kind, std::string& err)
{
    if (v.isNum()) {
        ResourceKind k;
        if (!ResourceKindFromInt(v.getInt<int>(), k)) {
            err = "unknown kind";
            return false;
        }
        kind = static_cast<uint8_t>(k);
        return true;
    }
    if (v.isStr()) {
        for (int i = 0; i <= 8; ++i) {
            ResourceKind k;
            if (ResourceKindFromInt(i, k) && v.get_str() == ResourceKindName(k)) {
                kind = static_cast<uint8_t>(k);
                return true;
            }
        }
        err = "unknown kind";
        return false;
    }
    err = "kind must be int or name";
    return false;
}

UniValue TypedResolveJson(ModelCatalog& cat, uint8_t kind, std::string digest)
{
    digest = ToLower(digest);
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    UniValue ids(UniValue::VARR);
    UniValue record_ids(UniValue::VARR);
    UniValue listed;
    cat.List(listed);
    if (!digest.empty() && listed.exists("models")) {
        for (const auto& m : listed["models"].getValues()) {
            if (kind == static_cast<uint8_t>(ResourceKind::ARTIFACT)) {
                if (m.exists("artifact_id") && m["artifact_id"].get_str() == digest) {
                    ids.push_back(m["artifact_id"].get_str());
                }
            } else if (kind == static_cast<uint8_t>(ResourceKind::MODEL)) {
                if (m.exists("model_id") && m["model_id"].get_str() == digest) {
                    ids.push_back(m["model_id"].get_str());
                }
            }
        }
    }
    Digest48 want;
    std::string derr;
    if (!digest.empty() && Digest48::FromHex(digest, want, derr)) {
        std::lock_guard<std::mutex> lock(g_ext_mu);
        const uint8_t rec_kind = RecordKindForResourceKind(kind);
        if (rec_kind != 0) {
            for (const auto& h : RecordsFor(cat).LookupExactKind(want, rec_kind, now)) {
                if (!h.signed_ok) continue;
                record_ids.push_back(h.record_id.Hex());
            }
        }
    }
    ResolveQueryPlan plan;
    PlanRouterQueries(cat.Peers(),
                       cat.Peers().size() >= 2 ? std::vector<std::string>{cat.Peers().back()} : std::vector<std::string>{},
                       plan);
    const bool incomplete_hit = ids.empty() && record_ids.empty();
    if (incomplete_hit && !digest.empty() && Digest48::FromHex(digest, want, derr)) {
        std::lock_guard<std::mutex> lock(g_ext_mu);
        NegCache().RememberIncomplete(kind, want, now);
    }
    UniValue ores(UniValue::VOBJ);
    ores.pushKV("schema_version", 2);
    ores.pushKV("coverage", "incomplete");
    ores.pushKV("does_not_exist", false);
    ores.pushKV("kind", kind);
    ores.pushKV("digest", digest);
    ores.pushKV("observation_time", now);
    ores.pushKV("ids", ids);
    ores.pushKV("record_ids", record_ids);
    ores.pushKV("local_count", listed.exists("local_count") ? listed["local_count"] : 0);
    ores.pushKV("remote_count", 0);
    if (digest.empty() && listed.exists("models")) ores.pushKV("models", listed["models"]);
    ores.pushKV("max_routers", MAX_ROUTER_CONTACTS);
    ores.pushKV("max_concurrent_queries", plan.max_concurrent);
    ores.pushKV("router_contacts", static_cast<int>(plan.contacts.size()));
    ores.pushKV("reserved_independent", plan.reserved_independent);
    if (!digest.empty() && Digest48::FromHex(digest, want, derr)) {
        std::lock_guard<std::mutex> lock(g_ext_mu);
        ores.pushKV("negative_cached", NegCache().HasIncomplete(kind, want, now));
    }
    return ores;
}

Digest48 CommunityLocalId(const std::string& hex)
{
    Digest48 mid;
    std::string e;
    if (Digest48::FromHex(hex, mid, e)) return mid;
    return DomainHash("BTX/LocalCommunity/v1", Span<const unsigned char>{
                         reinterpret_cast<const unsigned char*>(hex.data()), hex.size()});
}

void RememberStoppedPreservation(UniValue& store, const std::string& id)
{
    UniValue stopped = store.exists("stopped_preservation") ? store["stopped_preservation"] : UniValue(UniValue::VARR);
    bool have = false;
    for (const auto& x : stopped.getValues()) {
        if (x.isStr() && x.get_str() == id) have = true;
    }
    if (!have) stopped.push_back(id);
    store.pushKV("stopped_preservation", stopped);
}

bool IssueAndStoreRecord(ModelCatalog& cat, uint8_t kind, const UniValue& extra, int64_t ttl_s, SignedRecordHint& h, std::string& err)
{
    std::vector<unsigned char> pk, sk;
    Digest48 signer;
    if (!LoadOrCreateResearchIdentity(HelperDir(cat), pk, sk, signer, err)) return false;
    UniValue body(UniValue::VOBJ);
    const uint8_t role = (kind == RECORD_FREE_GRANT || kind == RECORD_SERVICE_RECEIPT) ? 0 : 1;
    FillRecordCommon(body, role, signer, static_cast<int64_t>(std::time(nullptr)), ttl_s);
    if (extra.isObject()) {
        for (const auto& k : extra.getKeys()) body.pushKV(k, extra[k]);
    }
    std::vector<unsigned char> payload, sig;
    Digest48 rid;
    if (!SignTypedRecord(kind, body, sk, payload, sig, rid, err)) return false;
    h = {};
    h.kind = kind;
    h.record_id = rid;
    h.payload = std::move(payload);
    h.signature = std::move(sig);
    h.pubkey = pk;
    h.signed_ok = true;
    h.expiry = body["expires_at"].getInt<int64_t>();
    h.provider_id = signer.Hex();
    std::lock_guard<std::mutex> lock(g_ext_mu);
    if (!RecordsFor(cat).Insert(h, static_cast<int64_t>(std::time(nullptr)), err)) return false;
    PersistRecords(cat, RecordsFor(cat));
    return true;
}

bool JsonBody(const NativeRequest& req, size_t cap, UniValue& body, NativeResponse& resp)
{
    if (req.body.size() > cap) {
        resp.status = 400;
        resp.body = JsonError("TOO_LARGE", "request exceeds bound");
        return false;
    }
    if (req.body.empty()) {
        body = UniValue(UniValue::VOBJ);
        return true;
    }
    if (!body.read(req.body) || !body.isObject()) {
        resp.status = 400;
        resp.body = JsonError("BAD_JSON", "object body required");
        return false;
    }
    return true;
}

int ListenTcp(const std::string& bind, std::string& err)
{
    std::string host;
    uint16_t port = 0;
    if (!SplitHostPort(bind, host, port)) {
        err = "invalid -modelbind";
        return -1;
    }
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        err = "socket";
        return -1;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (host == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        err = "bind host";
        close(fd);
        return -1;
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || listen(fd, 16) != 0) {
        err = "bind/listen failed";
        close(fd);
        return -1;
    }
    SetListenOpts(fd);
    return fd;
}

int ListenUnix(fs::path& path, std::string& err)
{
    std::string p = fs::PathToString(path);
    if (p.size() >= sizeof(sockaddr_un::sun_path)) {
        unsigned char digest[32];
        CSHA256()
            .Write(UCharCast(p.data()), p.size())
            .Finalize(digest);
        p = strprintf("/tmp/btx-md-%s.sock", HexStr(std::vector<unsigned char>(digest, digest + 8)));
        path = fs::PathFromString(p);
    }
    ::unlink(p.c_str());
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        err = "unix socket";
        return -1;
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (p.size() >= sizeof(addr.sun_path)) {
        err = "unix path too long";
        close(fd);
        return -1;
    }
    std::strncpy(addr.sun_path, p.c_str(), sizeof(addr.sun_path) - 1);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || listen(fd, 16) != 0) {
        err = "unix bind/listen failed";
        close(fd);
        return -1;
    }
    return fd;
}

std::string RecvUntil(int fd, size_t cap, std::atomic<bool>* stop)
{
    std::string out;
    char buf[4096];
    while (out.size() < cap) {
        if (stop && stop->load()) break;
        std::string werr;
        if (!WaitFd(fd, false, PQ1_IDLE_MS, stop, werr)) break;
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (n < 0 && errno == EAGAIN) continue;
            break;
        }
        out.append(buf, static_cast<size_t>(n));
        if (out.find('\n') != std::string::npos) break;
        if (out.find("\r\n\r\n") != std::string::npos) break;
    }
    return out;
}

bool ParseHttpResponse(const std::string& raw, NativeResponse& resp, std::string& err)
{
    const auto pos = raw.find("\r\n\r\n");
    if (pos == std::string::npos) {
        err = "truncated http";
        return false;
    }
    resp.headers.clear();
    std::istringstream hs(raw.substr(0, pos));
    std::string version;
    hs >> version >> resp.status;
    std::string line;
    std::getline(hs, line);
    while (std::getline(hs, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        auto key = TrimCopy(line.substr(0, colon));
        auto val = TrimCopy(line.substr(colon + 1));
        if (ToLower(key) == "content-type") resp.content_type = val;
        resp.headers.emplace_back(std::move(key), std::move(val));
    }
    resp.body = raw.substr(pos + 4);
    resp.raw.assign(resp.body.begin(), resp.body.end());
    resp.binary = resp.content_type.find("octet-stream") != std::string::npos;
    auto cl = raw.find("Content-Length:");
    if (cl == std::string::npos) cl = raw.find("content-length:");
    if (cl != std::string::npos && cl < pos) {
        const size_t want = std::strtoul(raw.c_str() + cl + 15, nullptr, 10);
        if (resp.body.size() < want) {
            err = "truncated http";
            return false;
        }
        if (resp.body.size() > want) resp.body.resize(want);
    }
    return true;
}

struct Pq1Session {
    Pq1Context* pq{nullptr};
    SSL* ssl{nullptr};
    int fd{-1};
    uint64_t transferred{0};
    std::string host;
    uint16_t port{0};
    fs::path pinfile;
    std::atomic<bool>* stop{nullptr};
    bool outbound_held{false};

    ~Pq1Session() { Close(); }

    void Close()
    {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
        transferred = 0;
        if (outbound_held) {
            GlobalConnLimits().ReleaseOutbound();
            outbound_held = false;
        }
    }

    bool Connect(Pq1Context& ctx, const std::string& h, uint16_t p, std::string& err)
    {
        Close();
        pq = &ctx;
        host = h;
        port = p;
        if (!ctx.Ready()) {
            err = "PQ1 not ready";
            return false;
        }
        if (!GlobalConnLimits().TryOutbound()) {
            err = "outbound connection ceiling";
            return false;
        }
        outbound_held = true;
        addrinfo hints{};
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = AF_INET;
        addrinfo* res = nullptr;
        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) {
            err = "resolve failed";
            return false;
        }
        fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0) {
            freeaddrinfo(res);
            err = "socket";
            return false;
        }
        SetPq1SocketOpts(fd, true);
        const int cr = connect(fd, res->ai_addr, res->ai_addrlen);
        if (cr != 0 && errno != EINPROGRESS) {
            close(fd);
            fd = -1;
            freeaddrinfo(res);
            err = "connect failed";
            return false;
        }
        if (!WaitFd(fd, true, PQ1_HANDSHAKE_MS, stop, err)) {
            close(fd);
            fd = -1;
            freeaddrinfo(res);
            return false;
        }
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen);
        if (soerr != 0) {
            close(fd);
            fd = -1;
            freeaddrinfo(res);
            err = "connect failed";
            return false;
        }
        freeaddrinfo(res);
        ssl = SSL_new(static_cast<SSL_CTX*>(ctx.SslCtx()));
        if (!ssl) {
            close(fd);
            fd = -1;
            err = "SSL_new";
            return false;
        }
        SSL_set_fd(ssl, fd);
        SSL_set_connect_state(ssl);
        if (!SslHandshake(ssl, fd, /*accept=*/false, PQ1_HANDSHAKE_MS, stop, err)) {
            err = err.empty() ? "PQ1 handshake failed" : err;
            Close();
            return false;
        }
        NegotiatedPq1 n;
        InspectNegotiated(ssl, n);
        if (!IsStrictPq1(n)) {
            err = "negotiated parameters are not strict PQ1";
            Close();
            return false;
        }
        Digest48 pin;
        if (!ExtractPeerTransportPin(ssl, pin, err)) {
            Close();
            return false;
        }
        const std::string endpoint = host + ":" + std::to_string(port);
        if (!pinfile.empty() && !CheckOrStorePin(pinfile, endpoint, pin, err)) {
            Close();
            return false;
        }
        return true;
    }

    bool Ensure(std::string& err)
    {
        if (ssl && transferred >= PQ1_RECONNECT_BYTES) Close();
        if (ssl) return true;
        if (!pq) {
            err = "PQ1 session has no context";
            return false;
        }
        return Connect(*pq, host, port, err);
    }

    bool Request(const NativeRequest& req, NativeResponse& resp, std::string& err)
    {
        if (!Ensure(err)) return false;
        std::string wire = req.method + " " + req.path + " HTTP/1.1\r\nHost: " + host + "\r\n";
        for (const auto& h : req.headers) {
            if (!h.first.empty()) wire += h.first + ": " + h.second + "\r\n";
        }
        wire += "Content-Length: " + std::to_string(req.body.size()) + "\r\nConnection: keep-alive\r\n\r\n";
        wire += req.body;
        const int wto = req.path.find("/pieces/") != std::string::npos ? PQ1_TRANSFER_MS : PQ1_IDLE_MS;
        if (!SslWriteAll(ssl, fd, wire, wto, stop, err)) {
            if (err.empty()) err = "write failed";
            Close();
            return false;
        }
        const size_t cap = req.path.find("/pieces/") != std::string::npos ? MAX_PIECE_HTTP : MAX_RPC_BODY + 8192;
        const std::string raw = SslReadHttp(ssl, fd, cap, wto, stop);
        if (!ParseHttpResponse(raw, resp, err)) {
            Close();
            return false;
        }
        transferred += raw.size();
        return true;
    }
};

Digest48 IdFromUser(const std::string& s, std::string& err)
{
    Resource r;
    std::string decode_err;
    if (DecodeResource(s, r, decode_err)) {
        err.clear();
        return r.digest;
    }
    Digest48 id;
    Digest48::FromHex(s, id, err);
    return id;
}

} // namespace

bool ParseHttpRequest(const std::string& raw, NativeRequest& req, std::string& err)
{
    req = {};
    const auto pos = raw.find("\r\n\r\n");
    if (pos == std::string::npos) {
        err = "truncated http";
        return false;
    }
    if (pos > MAX_HTTP_HEADERS) {
        err = "headers too large";
        return false;
    }
    std::istringstream hs(raw.substr(0, pos));
    std::string ver;
    hs >> req.method >> req.path >> ver;
    if (req.method.empty() || req.path.empty()) {
        err = "bad request line";
        return false;
    }
    std::string line;
    std::getline(hs, line);
    while (std::getline(hs, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        req.headers.emplace_back(TrimCopy(line.substr(0, colon)), TrimCopy(line.substr(colon + 1)));
    }
    req.body = raw.substr(pos + 4);
    auto cl = raw.find("Content-Length:");
    if (cl == std::string::npos) cl = raw.find("content-length:");
    if (cl != std::string::npos && cl < pos) {
        const size_t v = std::strtoul(raw.c_str() + cl + 15, nullptr, 10);
        if (v > MAX_RPC_BODY && req.method != "GET") {
            err = "body too large";
            return false;
        }
        if (req.body.size() > v) req.body.resize(v);
    }
    return true;
}

std::string FormatHttpResponse(const NativeResponse& resp)
{
    std::ostringstream o;
    o << "HTTP/1.1 " << resp.status << (resp.status == 200 ? " OK" : " ERR") << "\r\n";
    o << "Content-Type: " << resp.content_type << "\r\n";
    o << "Content-Length: " << resp.body.size() << "\r\n";
    for (const auto& h : resp.headers) {
        o << h.first << ": " << h.second << "\r\n";
    }
    o << "Connection: keep-alive\r\n\r\n";
    o << resp.body;
    return o.str();
}

bool HandleNativeRequest(ModelCatalog& cat, const NativeRequest& req, NativeResponse& resp)
{
    resp = {};
    resp.content_type = "application/json";
    const std::string root{MODEL_HTTP_ROOT};
    if (req.path == root + "hello") {
        UniValue o(UniValue::VOBJ);
        o.pushKV("schema_version", 2);
        o.pushKV("protocol", 2);
        o.pushKV("suite", "pq1");
        o.pushKV("group", "MLKEM768");
        o.pushKV("cipher", "TLS_AES_256_GCM_SHA384");
        o.pushKV("sigalg", "mldsa44");
        o.pushKV("automatic_spend_atoms", 0);
        o.pushKV("note", "A BTX node already has compute. BTX gives it models and money.");
        resp.body = o.write();
        resp.status = 200;
        return true;
    }
    const std::string man = root + "manifests/";
    if (req.method == "GET" && req.path.rfind(man, 0) == 0) {
        Digest48 id;
        std::string err;
        UniValue manij;
        if (!Digest48::FromHex(req.path.substr(man.size()), id, err) || !cat.GetManifest(id, manij, err)) {
            resp.status = 404;
            resp.body = JsonError("NOT_FOUND", err);
            return true;
        }
        CatalogEntry served;
        if (!cat.Find(id, served) || !served.seeded) {
            resp.status = 404;
            resp.body = JsonError("NOT_FOUND", "not seeded");
            return true;
        }
        resp.body = manij.write();
        resp.status = 200;
        return true;
    }
    const std::string pieces_pfx = root + "transfers/";
    if (req.method == "GET" && req.path.rfind(pieces_pfx, 0) == 0) {
        std::string rest = req.path.substr(pieces_pfx.size());
        const auto p1 = rest.find("/pieces/");
        if (p1 == std::string::npos) {
            resp.status = 400;
            resp.body = JsonError("BAD_PATH", "expected /pieces/");
            return true;
        }
        const std::string xfer = rest.substr(0, p1);
        const std::string fp = rest.substr(p1 + 8);
        const auto slash = fp.find('/');
        if (slash == std::string::npos) {
            resp.status = 400;
            resp.body = JsonError("BAD_PATH", "file/piece");
            return true;
        }
        const uint32_t file_index = static_cast<uint32_t>(std::strtoul(fp.c_str(), nullptr, 10));
        const uint32_t piece_index = static_cast<uint32_t>(std::strtoul(fp.c_str() + slash + 1, nullptr, 10));
        CatalogEntry entry;
        std::string err;
        Digest48 artifact;
        bool found = Digest48::FromHex(xfer, artifact, err) && cat.Find(artifact, entry);
        if (!found) {
            UniValue listed;
            cat.List(listed);
            if (listed.exists("models") && !listed["models"].getValues().empty()) {
                found = Digest48::FromHex(listed["models"][0]["artifact_id"].get_str(), artifact, err) &&
                        cat.Find(artifact, entry);
            }
        }
        if (!found) {
            resp.status = 404;
            resp.body = JsonError("NOT_FOUND", "no artifact");
            return true;
        }
        if (!entry.seeded) {
            resp.status = 404;
            resp.body = JsonError("NOT_FOUND", "not seeded");
            return true;
        }
        const std::string gp = RequestHeader(req, "X-BTX-Grant-Payload");
        const std::string gs = RequestHeader(req, "X-BTX-Grant-Sig");
        const std::string gpk = RequestHeader(req, "X-BTX-Grant-Pubkey");
        if (gp.empty() || gs.empty() || gpk.empty()) {
            resp.status = 403;
            resp.body = JsonError("ENTITLEMENT", "FreeGrant required");
            return true;
        }
        {
            const auto payload = TryParseHex<unsigned char>(gp);
            const auto sig = TryParseHex<unsigned char>(gs);
            const auto pk = TryParseHex<unsigned char>(gpk);
            UniValue gbody;
            std::string gerr;
            const int64_t now = static_cast<int64_t>(std::time(nullptr));
            if (!payload || !sig || !pk ||
                !VerifyFreeGrant(*payload, *sig, *pk, now, {}, gbody, gerr)) {
                resp.status = 403;
                resp.body = JsonError("ENTITLEMENT", gerr.empty() ? "invalid FreeGrant" : gerr);
                return true;
            }
            const std::string grant_art = gbody.exists("artifact_id") ? gbody["artifact_id"].get_str() : "";
            const std::string grant_model = gbody.exists("model_id") ? gbody["model_id"].get_str() : "";
            if (grant_art != entry.artifact_id.Hex() && grant_model != entry.model_id.Hex()) {
                resp.status = 403;
                resp.body = JsonError("ENTITLEMENT", "grant object mismatch");
                return true;
            }
            const uint32_t gfile = gbody.exists("file_index") ? gbody["file_index"].getInt<uint32_t>() : 0;
            const uint32_t first = gbody.exists("first_piece") ? gbody["first_piece"].getInt<uint32_t>() : 0;
            const uint32_t count = gbody.exists("piece_count") ? gbody["piece_count"].getInt<uint32_t>() : 0;
            if (gfile != file_index || count == 0 || piece_index < first || piece_index >= first + count) {
                resp.status = 403;
                resp.body = JsonError("ENTITLEMENT", "piece not in grant range");
                return true;
            }
        }
        std::vector<unsigned char> bytes;
        std::vector<Digest48> proof;
        uint64_t file_size = 0;
        if (!cat.GetVerifiedPiece(entry.artifact_id, file_index, piece_index, bytes, proof, file_size, err)) {
            resp.status = 404;
            resp.body = JsonError("MISSING_PIECE", err);
            return true;
        }
        std::string proof_csv;
        for (size_t i = 0; i < proof.size(); ++i) {
            if (i) proof_csv += ",";
            proof_csv += proof[i].Hex();
        }
        const std::string pieces_root = file_index < entry.core.files.size() ? entry.core.files[file_index].pieces_root.Hex() : "";
        resp.status = 200;
        resp.binary = true;
        resp.content_type = "application/octet-stream";
        resp.body.assign(bytes.begin(), bytes.end());
        resp.headers.emplace_back("X-BTX-Artifact-Id", entry.artifact_id.Hex());
        resp.headers.emplace_back("X-BTX-File-Index", std::to_string(file_index));
        resp.headers.emplace_back("X-BTX-Piece-Index", std::to_string(piece_index));
        resp.headers.emplace_back("X-BTX-File-Size", std::to_string(file_size));
        resp.headers.emplace_back("X-BTX-Pieces-Root", pieces_root);
        resp.headers.emplace_back("X-BTX-Proof", proof_csv);
        return true;
    }
    if (req.path == root + "availability" && req.method == "POST") {
        UniValue o(UniValue::VOBJ);
        o.pushKV("schema_version", 2);
        UniValue listed;
        cat.List(listed);
        UniValue pub(UniValue::VOBJ);
        pub.pushKV("schema_version", 2);
        pub.pushKV("coverage", "incomplete");
        UniValue models(UniValue::VARR);
        if (listed.exists("models")) {
            for (const auto& m : listed["models"].getValues()) {
                if (!m.exists("seeded") || !m["seeded"].get_bool()) continue;
                UniValue one = m;
                if (!one.exists("observed_sources") || one["observed_sources"].getInt<int>() == 0) {
                    one.pushKV("observed_sources", 1);
                }
                models.push_back(one);
            }
        }
        pub.pushKV("models", models);
        pub.pushKV("local_count", static_cast<int>(models.size()));
        o.pushKV("local", pub);
        resp.body = o.write();
        return true;
    }
    if ((req.path == root + "quotes" || req.path == std::string(MODEL_HTTP_ROOT) + "quotes") && req.method == "POST") {
        UniValue body;
        if (!body.read(req.body) || !body.isObject()) {
            resp.status = 400;
            resp.body = JsonError("BAD_JSON", "quote body");
            return true;
        }
        Digest48 model_id, artifact_id;
        std::string err;
        if (!body.exists("model_id") || !Digest48::FromHex(body["model_id"].get_str(), model_id, err)) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", err);
            return true;
        }
        if (body.exists("artifact_id") && !body["artifact_id"].get_str().empty()) {
            if (!Digest48::FromHex(body["artifact_id"].get_str(), artifact_id, err)) {
                resp.status = 400;
                resp.body = JsonError("INVALID_PARAMETER", err);
                return true;
            }
        }
        const int64_t price = body.exists("price_atoms") ? body["price_atoms"].getInt<int64_t>() : 0;
        Quote q;
        if (!MakePrepaidQuote(q, model_id, artifact_id, 0, body.exists("piece_count") ? body["piece_count"].getInt<uint32_t>() : 0, price, err)) {
            resp.status = 500;
            resp.body = JsonError("QUOTE", err);
            return true;
        }
        std::vector<Quote> quotes;
        std::vector<PaymentJournal> journal;
        const fs::path dir = cat.Store().Root().parent_path();
        LoadPaymentState(dir, quotes, journal, err);
        quotes.push_back(q);
        SavePaymentState(dir, quotes, journal, err);
        resp.status = 200;
        resp.body = QuoteToJson(q).write();
        return true;
    }
    if (req.method == "POST" && req.path.find("/payment") != std::string::npos) {
        UniValue body;
        if (!body.read(req.body) || !body.isObject() || !body.exists("txid") || !body.exists("quote_id")) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", "quote_id and txid required");
            return true;
        }
        std::vector<Quote> quotes;
        std::vector<PaymentJournal> journal;
        std::string err;
        const fs::path dir = cat.Store().Root().parent_path();
        LoadPaymentState(dir, quotes, journal, err);
        const std::string txid = body["txid"].get_str();
        if (DuplicatePayment(journal, txid)) {
            resp.status = 409;
            resp.body = JsonError("DUPLICATE_PAYMENT", "txid already recorded; retry does not pay again");
            return true;
        }
        PaymentJournal e;
        e.quote_id = body["quote_id"].get_str();
        e.txid = txid;
        e.accepted = false;
        e.file_index = body.exists("file_index") ? body["file_index"].getInt<uint32_t>() : 0;
        e.first_piece = body.exists("first_piece") ? body["first_piece"].getInt<uint32_t>() : 0;
        e.piece_count = body.exists("piece_count") ? body["piece_count"].getInt<uint32_t>() : 0;
        if (e.piece_count > 0 && DuplicateReservedRange(journal, e.file_index, e.first_piece, e.piece_count)) {
            resp.status = 409;
            resp.body = JsonError("DUPLICATE_PAYMENT", "range already reserved; restart does not pay again");
            return true;
        }
        journal.push_back(e);
        SavePaymentState(dir, quotes, journal, err);
        UniValue o(UniValue::VOBJ);
        o.pushKV("schema_version", 2);
        o.pushKV("recorded", true);
        o.pushKV("accepted", false);
        o.pushKV("note", "Journal records intent. Chain settlement is 0.34.6 wallet RPCs; helper does not verify the chain.");
        resp.body = o.write();
        return true;
    }
    if ((req.path == root + "query") && req.method == "POST") {
        UniValue body;
        if (!JsonBody(req, 512, body, resp)) return true;
        UniValue ids(UniValue::VARR);
        UniValue listed;
        cat.List(listed);
        std::string qerr;
        if (body.exists("root") && body["root"].isStr()) {
            Digest48 id;
            if (Digest48::FromHex(body["root"].get_str(), id, qerr)) {
                CatalogEntry e;
                if (cat.Find(id, e) && e.seeded) ids.push_back(e.model_id.Hex());
                std::lock_guard<std::mutex> lock(g_ext_mu);
                for (const auto& h : RecordsFor(cat).LookupExact(id, static_cast<int64_t>(std::time(nullptr)))) {
                    ids.push_back(h.record_id.Hex());
                }
            }
        } else if (body.exists("text") && body["text"].isStr()) {
            const std::string q = ToLower(body["text"].get_str());
            int limit = 32;
            if (body.exists("limit")) limit = std::min(32, body["limit"].getInt<int>());
            if (listed.exists("models")) {
                for (const auto& m : listed["models"].getValues()) {
                    if (static_cast<int>(ids.size()) >= limit) break;
                    if (!m.exists("seeded") || !m["seeded"].get_bool()) continue;
                    const std::string hay = ToLower(m.write());
                    if (hay.find(q) != std::string::npos) ids.push_back(m["model_id"].get_str());
                }
            }
        }
        UniValue qo(UniValue::VOBJ);
        qo.pushKV("schema_version", 2);
        qo.pushKV("coverage", "incomplete");
        qo.pushKV("ids", ids);
        qo.pushKV("local_count", listed.exists("local_count") ? listed["local_count"] : 0);
        resp.body = qo.write();
        return true;
    }
    if (req.path == root + "records/get" && req.method == "POST") {
        UniValue body;
        if (!JsonBody(req, 16 * 1024, body, resp)) return true;
        UniValue recs(UniValue::VARR);
        std::lock_guard<std::mutex> lock(g_ext_mu);
        auto& cache = RecordsFor(cat);
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        UniValue want = body.exists("ids") ? body["ids"] : UniValue(UniValue::VARR);
        size_t n = 0;
        for (const auto& idv : want.getValues()) {
            if (n >= 16) break;
            Digest48 id;
            std::string e;
            if (!idv.isStr() || !Digest48::FromHex(idv.get_str(), id, e)) continue;
            for (const auto& h : cache.LookupExact(id, now)) {
                recs.push_back(HintJson(h));
                ++n;
            }
        }
        UniValue orec(UniValue::VOBJ);
        orec.pushKV("schema_version", 2);
        orec.pushKV("records", recs);
        resp.body = orec.write();
        return true;
    }
    if (req.path == root + "records/announce" && req.method == "POST") {
        UniValue body;
        if (!JsonBody(req, 16 * 1024, body, resp)) return true;
        SignedRecordHint h;
        std::string err;
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (!AcceptSignedAnnounce(body, now, h, err)) {
            resp.status = 400;
            resp.body = JsonError("UNSIGNED", err);
            return true;
        }
        std::lock_guard<std::mutex> lock(g_ext_mu);
        if (!RecordsFor(cat).Insert(h, now, err)) {
            resp.status = 400;
            resp.body = JsonError("RECORD", err);
            return true;
        }
        PersistRecords(cat, RecordsFor(cat));
        UniValue oann(UniValue::VOBJ);
        oann.pushKV("schema_version", 2);
        oann.pushKV("accepted", true);
        oann.pushKV("signed", true);
        oann.pushKV("record_id", h.record_id.Hex());
        resp.body = oann.write();
        return true;
    }
    if (req.method == "POST" && req.path.rfind(root + "releases/", 0) == 0) {
        const std::string rest = req.path.substr((root + "releases/").size());
        const auto slash = rest.find('/');
        if (slash == std::string::npos) {
            resp.status = 400;
            resp.body = JsonError("BAD_PATH", "releases/{id}/{pledges|rounds|signatures}");
            return true;
        }
        const std::string idhex = rest.substr(0, slash);
        const std::string action = rest.substr(slash + 1);
        Digest48 id;
        std::string err;
        if (!Digest48::FromHex(idhex, id, err)) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", err);
            return true;
        }
        UniValue body;
        const size_t cap = (action == "pledges") ? 16 * 1024 : 512 * 1024;
        if (!JsonBody(req, cap, body, resp)) return true;
        if (action == "pledges") {
            std::vector<ReleaseCampaign> campaigns;
            LoadCampaigns(HelperDir(cat), campaigns, err);
            bool found = false;
            const int64_t atoms = body.exists("amount_atoms") ? body["amount_atoms"].getInt<int64_t>() : 0;
            for (auto& c : campaigns) {
                if (c.release_id == id) {
                    c.pledged_atoms += atoms;
                    found = true;
                    resp.body = CampaignToJson(c).write();
                }
            }
            if (!found) {
                resp.status = 404;
                resp.body = JsonError("NOT_FOUND", "unknown release");
                return true;
            }
            SaveCampaigns(HelperDir(cat), campaigns, err);
            return true;
        }
        UniValue store;
        ReadJsonFile(HelperDir(cat) / "release-coord.json", store);
        if (!store.isObject()) store = UniValue(UniValue::VOBJ);
        UniValue one = store.exists(idhex) ? store[idhex] : UniValue(UniValue::VOBJ);
        if (action == "rounds") {
            one.pushKV("round", body);
            one.pushKV("frozen", true);
        } else if (action == "signatures") {
            UniValue sigs = one.exists("signatures") ? one["signatures"] : UniValue(UniValue::VARR);
            sigs.push_back(body);
            one.pushKV("signatures", sigs);
        } else {
            resp.status = 404;
            resp.body = JsonError("NOT_FOUND", "unknown release action");
            return true;
        }
        store.pushKV(idhex, one);
        WriteJsonFile(HelperDir(cat) / "release-coord.json", store, err);
        UniValue orel(UniValue::VOBJ);
        orel.pushKV("schema_version", 2);
        orel.pushKV("release_id", idhex);
        orel.pushKV("action", action);
        orel.pushKV("note", "coordination only; broadcast funding with btxd; claim via buildhtlcclaim");
        resp.body = orel.write();
        return true;
    }
    if ((req.path == root + "ext/caps") && (req.method == "POST" || req.method == "GET")) {
        UniValue oc(UniValue::VOBJ);
        oc.pushKV("extension_version", static_cast<int>(EXT_VERSION));
        oc.pushKV("features", static_cast<int>(EXT_FEATURES));
        oc.pushKV("max_envelope_bytes", 81920);
        oc.pushKV("schema_version", 2);
        resp.body = oc.write();
        return true;
    }
    if (req.path == root + "ext/resolve" && req.method == "POST") {
        UniValue body;
        if (!JsonBody(req, 512, body, resp)) return true;
        uint8_t kind = static_cast<uint8_t>(ResourceKind::MODEL);
        std::string kerr;
        if (body.exists("kind") && !KindFromJson(body["kind"], kind, kerr)) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", kerr);
            return true;
        }
        std::string digest;
        if (body.exists("digest48") && body["digest48"].isStr()) digest = body["digest48"].get_str();
        else if (body.exists("id") && body["id"].isStr()) digest = body["id"].get_str();
        resp.body = TypedResolveJson(cat, kind, digest).write();
        return true;
    }
    if (req.path == root + "ext/objects/get" && req.method == "POST") {
        UniValue body;
        if (!JsonBody(req, 1024, body, resp)) return true;
        UniValue objs(UniValue::VARR);
        std::lock_guard<std::mutex> lock(g_ext_mu);
        auto& cache = RecordsFor(cat);
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        size_t n = 0;
        UniValue want = body.exists("ids") ? body["ids"] : UniValue(UniValue::VARR);
        for (const auto& idv : want.getValues()) {
            if (n >= 8) break;
            Digest48 id;
            std::string e;
            if (!idv.isStr() || !Digest48::FromHex(idv.get_str(), id, e)) continue;
            for (const auto& h : cache.LookupExact(id, now)) {
                objs.push_back(HintJson(h));
                ++n;
            }
        }
        UniValue oobj(UniValue::VOBJ);
        oobj.pushKV("schema_version", 2);
        oobj.pushKV("objects", objs);
        oobj.pushKV("coverage", "incomplete");
        resp.body = oobj.write();
        return true;
    }
    if (req.path == root + "ext/objects/announce" && req.method == "POST") {
        if (req.body.size() > 80 * 1024) {
            resp.status = 400;
            resp.body = JsonError("TOO_LARGE", "envelope exceeds 80 KiB");
            return true;
        }
        UniValue body;
        SignedRecordHint h;
        std::string err;
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (req.body.empty() || req.body[0] != '{') {
            resp.status = 400;
            resp.body = JsonError("UNSIGNED", "unsigned envelope rejected");
            return true;
        }
        if (!JsonBody(req, 80 * 1024, body, resp)) return true;
        if (!AcceptSignedAnnounce(body, now, h, err)) {
            resp.status = 400;
            resp.body = JsonError("UNSIGNED", err);
            return true;
        }
        std::lock_guard<std::mutex> lock(g_ext_mu);
        if (!RecordsFor(cat).Insert(h, now, err)) {
            resp.status = 400;
            resp.body = JsonError("RECORD", err);
            return true;
        }
        PersistRecords(cat, RecordsFor(cat));
        UniValue oann(UniValue::VOBJ);
        oann.pushKV("schema_version", 2);
        oann.pushKV("accepted", true);
        oann.pushKV("signed", true);
        oann.pushKV("record_id", h.record_id.Hex());
        resp.body = oann.write();
        return true;
    }
    if (req.path == root + "ext/free/grant" && req.method == "POST") {
        UniValue body;
        if (!JsonBody(req, 16 * 1024, body, resp)) return true;
        if (GrantHasPaymentFields(body)) {
            resp.status = 400;
            resp.body = JsonError("PAYMENT_FIELD", "FreeGrant has no payment script, address, amount, fee, or confirmation field");
            return true;
        }
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (body.exists("expires_at")) {
            const int64_t exp = body["expires_at"].getInt<int64_t>();
            if (exp <= now) {
                resp.status = 400;
                resp.body = JsonError("EXPIRED", "grant expired");
                return true;
            }
        }
        Digest48 model_id;
        std::string err;
        if (!body.exists("model_id") || !Digest48::FromHex(body["model_id"].get_str(), model_id, err)) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", "model_id");
            return true;
        }
        CatalogEntry e;
        if (!cat.Find(model_id, e) || !e.seeded) {
            resp.status = 404;
            resp.body = JsonError("NOT_FOUND", "no seeded local grant");
            return true;
        }
        const uint32_t file_index = body.exists("file_index") ? body["file_index"].getInt<uint32_t>() : 0;
        if (file_index >= e.core.files.size() && !e.core.files.empty()) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", "file_index");
            return true;
        }
        const uint64_t file_size = e.core.files.empty() ? 1 : e.core.files[file_index].size;
        const uint32_t n_pieces = file_size == 0 ? 1u : static_cast<uint32_t>((file_size + PIECE_SIZE - 1) / PIECE_SIZE);
        const uint32_t first_piece = body.exists("first_piece") ? body["first_piece"].getInt<uint32_t>() : 0;
        uint32_t piece_count = body.exists("piece_count") ? body["piece_count"].getInt<uint32_t>() : 0;
        if (piece_count == 0) piece_count = n_pieces > first_piece ? n_pieces - first_piece : 0;
        if (piece_count == 0 || first_piece >= n_pieces || first_piece > n_pieces - piece_count) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", "piece range");
            return true;
        }
        const uint64_t start = uint64_t{first_piece} * PIECE_SIZE;
        const uint64_t end = std::min(file_size == 0 ? uint64_t{1} : file_size, start + uint64_t{piece_count} * PIECE_SIZE);
        const uint64_t maximum_bytes = body.exists("maximum_bytes") ? body["maximum_bytes"].getInt<uint64_t>() : (end > start ? end - start : 1);

        Digest48 buyer_id{};
        if (body.exists("buyer_id") && !body["buyer_id"].get_str().empty()) {
            if (!Digest48::FromHex(body["buyer_id"].get_str(), buyer_id, err)) {
                resp.status = 400;
                resp.body = JsonError("INVALID_PARAMETER", "buyer_id");
                return true;
            }
        }
        Hash32 grant_nonce{};
        if (body.exists("grant_nonce")) {
            if (!Hash32::FromHex(body["grant_nonce"].get_str(), grant_nonce, err)) {
                resp.status = 400;
                resp.body = JsonError("INVALID_PARAMETER", "grant_nonce");
                return true;
            }
        } else {
            GetStrongRandBytes(Span<unsigned char>{grant_nonce.data.data(), grant_nonce.data.size()});
        }
        uint64_t sequence = 1;
        if (!ConsumeGrantNonce(HelperDir(cat), grant_nonce.Hex(), sequence, err)) {
            resp.status = err == "replay" ? 409 : 400;
            resp.body = JsonError(err == "replay" ? "REPLAY" : "GRANT", err);
            return true;
        }
        std::vector<unsigned char> pk, sk;
        Digest48 signer_id;
        if (!LoadOrCreateServiceIdentity(HelperDir(cat), pk, sk, signer_id, err)) {
            resp.status = 500;
            resp.body = JsonError("CRYPTO", err);
            return true;
        }
        FreeGrantParams gp;
        gp.sequence = sequence;
        gp.issued_at = now;
        gp.expires_at = now + FREE_GRANT_LIFETIME_S;
        if (body.exists("issued_at")) gp.issued_at = body["issued_at"].getInt<int64_t>();
        if (body.exists("expires_at")) gp.expires_at = body["expires_at"].getInt<int64_t>();
        gp.buyer_id = buyer_id;
        gp.model_id = e.model_id;
        gp.artifact_id = e.artifact_id;
        if (body.exists("artifact_id") && !body["artifact_id"].get_str().empty()) {
            if (!Digest48::FromHex(body["artifact_id"].get_str(), gp.artifact_id, err)) {
                resp.status = 400;
                resp.body = JsonError("INVALID_PARAMETER", "artifact_id");
                return true;
            }
            if (gp.artifact_id != e.artifact_id) {
                resp.status = 400;
                resp.body = JsonError("OBJECT_MISMATCH", "artifact_id");
                return true;
            }
        }
        gp.file_index = file_index;
        gp.first_piece = first_piece;
        gp.piece_count = piece_count;
        gp.maximum_bytes = maximum_bytes;
        gp.grant_nonce = grant_nonce;
        gp.queue_class = body.exists("queue_class") ? static_cast<uint8_t>(body["queue_class"].getInt<uint64_t>()) : 0;
        if (body.exists("transfer_id")) {
            if (!Hash32::FromHex(body["transfer_id"].get_str(), gp.transfer_id, err)) {
                resp.status = 400;
                resp.body = JsonError("INVALID_PARAMETER", "transfer_id");
                return true;
            }
        }
        SignedFreeGrant issued;
        if (!IssueFreeGrant(gp, sk, pk, issued, err)) {
            resp.status = 400;
            resp.body = JsonError("GRANT", err);
            return true;
        }
        if (issued.body["signer_id"].get_str() != signer_id.Hex()) {
            resp.status = 500;
            resp.body = JsonError("CRYPTO", "signer_id");
            return true;
        }
        const bool octet = (body.exists("octet_stream") && body["octet_stream"].get_bool()) ||
                            (body.exists("format") && body["format"].isStr() && body["format"].get_str() == "octet-stream");
        if (octet) {
            std::vector<unsigned char> env;
            if (!EncodeGrantEnvelope(issued, env, err)) {
                resp.status = 500;
                resp.body = JsonError("GRANT", err);
                return true;
            }
            resp.content_type = "application/octet-stream";
            resp.binary = true;
            resp.body.assign(env.begin(), env.end());
            return true;
        }
        resp.body = SignedGrantToJson(issued).write();
        return true;
    }
    if (req.path == root + "ext/receipts" && req.method == "POST") {
        UniValue body;
        if (!JsonBody(req, 16 * 1024, body, resp)) return true;
        std::string err;
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (!body.exists("payload_hex") || !body.exists("sig_hex") || !body.exists("pubkey_hex")) {
            resp.status = 400;
            resp.body = JsonError("UNSIGNED", "ServiceReceipt must be signed");
            return true;
        }
        const auto payload = TryParseHex<unsigned char>(body["payload_hex"].get_str());
        const auto sig = TryParseHex<unsigned char>(body["sig_hex"].get_str());
        const auto pk = TryParseHex<unsigned char>(body["pubkey_hex"].get_str());
        UniValue decoded;
        Digest48 rid;
        if (!payload || !sig || !pk ||
            !VerifyTypedRecord(RECORD_SERVICE_RECEIPT, *payload, *sig, *pk, now, decoded, rid, err)) {
            resp.status = 400;
            resp.body = JsonError("RECEIPT", err.empty() ? "invalid ServiceReceipt" : err);
            return true;
        }
        UniValue store;
        ReadJsonFile(HelperDir(cat) / "receipts.json", store);
        UniValue arr = store.exists("receipts") ? store["receipts"] : UniValue(UniValue::VARR);
        UniValue rec(UniValue::VOBJ);
        rec.pushKV("record_id", rid.Hex());
        rec.pushKV("received_at", now);
        rec.pushKV("payload_hex", body["payload_hex"].get_str());
        rec.pushKV("signed", true);
        arr.push_back(rec);
        store.pushKV("schema_version", 2);
        store.pushKV("receipts", arr);
        WriteJsonFile(HelperDir(cat) / "receipts.json", store, err);
        UniValue orc(UniValue::VOBJ);
        orc.pushKV("schema_version", 2);
        orc.pushKV("recorded", true);
        orc.pushKV("broadcast", false);
        orc.pushKV("record_id", rid.Hex());
        resp.body = orc.write();
        return true;
    }
    resp.status = 404;
    resp.body = JsonError("NOT_FOUND", "unknown /btx-model/2/ path");
    return true;
}

bool NativeHttpRequiresVerifiedPq1()
{
    // HandleNativeRequest is only invoked from HandlePq1Fd after IsStrictPq1.
    // Unix JSON-RPC is a local socket, not a native HTTP endpoint.
    return true;
}

std::vector<std::string> AdvertisedNativeHttpPaths()
{
    std::vector<std::string> out;
    const UniValue caps = CapabilitiesObject();
    if (!caps.exists("http") || !caps["http"].isArray()) return out;
    for (const auto& p : caps["http"].getValues()) {
        if (p.isStr()) out.push_back(p.get_str());
    }
    return out;
}

namespace {

struct RetrieveJob {
    std::string id;
    std::string status{"queued"};
    UniValue result;
    std::string err;
    std::atomic<bool> cancel{false};
    std::thread worker;

    RetrieveJob() = default;
    RetrieveJob(const RetrieveJob&) = delete;
    RetrieveJob& operator=(const RetrieveJob&) = delete;
    ~RetrieveJob()
    {
        cancel.store(true);
        if (worker.joinable()) worker.join();
    }
};

std::mutex g_retrieve_mu;
std::map<std::string, std::shared_ptr<RetrieveJob>> g_retrieve_jobs;

std::string NewRetrieveJobId()
{
    unsigned char b[16];
    GetStrongRandBytes(Span<unsigned char>{b, sizeof(b)});
    return HexStr(Span<const unsigned char>{b, sizeof(b)});
}

UniValue RetrieveJobJson(const RetrieveJob& j)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("job_id", j.id);
    o.pushKV("status", j.status);
    if (j.result.isObject() && !j.result.getKeys().empty()) o.pushKV("result", j.result);
    if (!j.err.empty()) o.pushKV("error", j.err);
    return o;
}

std::string EnqueueRetrieve(ModelCatalog& cat, const Digest48& model_id, std::atomic<bool>* stop)
{
    (void)stop;
    auto job = std::make_shared<RetrieveJob>();
    job->id = NewRetrieveJobId();
    job->status = "running";
    {
        std::lock_guard<std::mutex> lock(g_retrieve_mu);
        g_retrieve_jobs[job->id] = job;
    }
    // DISC-05: re-read catalog peers after a contact dies. Committed pieces
    // stay on disk; RetrieveFreeFromPeer skips them via GetPiece.
    job->worker = std::thread([job, &cat, model_id]() {
        auto failed = [&](const std::string& e) {
            job->err = e;
            job->status = "failed";
            UniValue r(UniValue::VOBJ);
            r.pushKV("schema_version", 2);
            r.pushKV("status", "failed");
            r.pushKV("error", e);
            job->result = std::move(r);
        };
        Pq1Context pq;
        std::string tls_err;
        if (!LoadPq1Identity(pq, cat.Store().Root().parent_path(), tls_err)) {
            failed(tls_err);
            return;
        }
        const fs::path pinfile = cat.Store().Root().parent_path() / "tls" / "pins.json";
        std::set<std::string> failed_peers;
        std::string last_err;
        while (true) {
            if (job->cancel.load()) {
                failed("cancelled");
                return;
            }
            std::string peer;
            for (const auto& p : cat.Peers()) {
                if (failed_peers.count(p) == 0) {
                    peer = p;
                    break;
                }
            }
            if (peer.empty()) {
                failed(last_err.empty() ? "retrieve failed" : last_err);
                return;
            }
            std::string host;
            uint16_t port = 0;
            if (!SplitHostPort(peer, host, port)) {
                failed_peers.insert(peer);
                last_err = "peer host:port";
                continue;
            }
            std::string rerr;
            try {
                if (RetrieveFreeFromPeer(cat, pq, host, port, model_id, rerr, &job->cancel, pinfile)) {
                    std::string seed_err;
                    cat.ApplyDemandSeed(model_id, seed_err);
                    CatalogEntry got;
                    UniValue r(UniValue::VOBJ);
                    r.pushKV("schema_version", 2);
                    r.pushKV("plan", "FREE");
                    r.pushKV("status", "retrieved");
                    r.pushKV("seeded", cat.Find(model_id, got) && got.seeded);
                    r.pushKV("propagation", "demand");
                    r.pushKV("model_id", model_id.Hex());
                    r.pushKV("failed_contacts", static_cast<int>(failed_peers.size()));
                    r.pushKV("last_peer", peer);
                    job->result = std::move(r);
                    job->status = "done";
                    return;
                }
            } catch (const std::exception& e) {
                rerr = std::string("retrieve exception: ") + e.what();
            } catch (...) {
                rerr = "retrieve exception";
            }
            last_err = rerr.empty() ? "retrieve failed" : rerr;
            failed_peers.insert(peer);
        }
    });
    return job->id;
}

void JoinRetrieveJobs()
{
    std::vector<std::shared_ptr<RetrieveJob>> copy;
    {
        std::lock_guard<std::mutex> lock(g_retrieve_mu);
        for (auto& kv : g_retrieve_jobs) copy.push_back(kv.second);
        g_retrieve_jobs.clear();
    }
    for (auto& j : copy) {
        j->cancel.store(true);
        if (j->worker.joinable()) j->worker.join();
    }
}

} // namespace

bool DispatchHelperRpc(ModelCatalog& cat, const UniValue& request, UniValue& result, std::string& err_code, std::string& err, std::atomic<bool>* stop)
{
    result = UniValue(UniValue::VOBJ);
    const std::string method = request.exists("method") ? request["method"].get_str() : "";
    const UniValue params = request.exists("params") ? request["params"] : UniValue(UniValue::VARR);
    auto Arg = [&](size_t i) -> const UniValue& {
        if (params.isArray() && params.size() > i) return params[i];
        static const UniValue none;
        return none;
    };

    if (method == "getmodelnetworkinfo" || method == "getmodelcryptoinfo") {
        result.pushKV("schema_version", 2);
        result.pushKV("enabled", true);
        result.pushKV("helper_ready", true);
        Pq1Context pq;
        result.pushKV("pq1_ready", pq.Ready());
        result.pushKV("error", pq.Ready() ? "" : pq.Error());
        result.pushKV("openssl", OpenSSL_version(OPENSSL_VERSION));
        result.pushKV("transport", "pq1");
        result.pushKV("group", "MLKEM768");
        result.pushKV("cipher", "TLS_AES_256_GCM_SHA384");
        result.pushKV("sigalg", "mldsa44");
        result.pushKV("max_send_fragment", 512);
        result.pushKV("resumption", false);
        result.pushKV("early_data", false);
        result.pushKV("retrieval_default", "FREE_ONLY");
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("quota_bytes", cat.QuotaBytes());
        result.pushKV("used_bytes", cat.UsedBytes());
        result.pushKV("propagation", PolicyToJson(cat.Policy()));
        result.pushKV("capabilities", CapabilitiesObject());
        result.pushKV("http_workers", PQ1_HTTP_WORKERS);
        result.pushKV("http_queue", PQ1_HTTP_QUEUE);
        result.pushKV("inbound_connections", GlobalConnLimits().Inbound());
        result.pushKV("outbound_connections", GlobalConnLimits().Outbound());
        result.pushKV("peer_pin", "TOFU tls_spki_hash D384(BTX/TransportKey/v2, DER_SPKI)");
        result.pushKV("htlc", "reuses final 0.34.6 htlc_sha256 / buildhtlcclaim / buildhtlcrefund");
        return true;
    }
    if (method == "decoderesource" || method == "decoderesourceuri" || method == "openbtxuri") {
        Resource r;
        if (!DecodeResource(Arg(0).get_str(), r, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("uri", r.Uri());
        result.pushKV("kind", ResourceKindName(r.kind));
        result.pushKV("digest", r.digest.Hex());
        if (method == "openbtxuri") {
            UniValue actions(UniValue::VARR);
            actions.push_back("getmodelmanifest");
            actions.push_back("getmodel FREE_ONLY");
            actions.push_back("exportmodelpath");
            result.pushKV("proposed_actions", actions);
            result.pushKV("network", false);
            result.pushKV("inference", false);
            result.pushKV("wallet", false);
            result.pushKV("note", "Preview only. Opening a URI never runs inference, mining, or spend.");
        }
        return true;
    }
    if (method == "encoderesource" || method == "encoderesourceuri") {
        ResourceKind kind = ResourceKind::MODEL;
        bool found = false;
        for (int i = 0; i <= 8; ++i) {
            ResourceKind k;
            if (ResourceKindFromInt(i, k) && Arg(0).get_str() == ResourceKindName(k)) {
                kind = k;
                found = true;
                break;
            }
        }
        if (!found) {
            err_code = "INVALID_PARAMETER";
            err = "unknown resource kind";
            return false;
        }
        Digest48 d;
        if (!Digest48::FromHex(Arg(1).get_str(), d, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        std::string uri;
        if (!EncodeResource(kind, d, uri, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        result = uri;
        return true;
    }
    if (method == "importmodel") {
        const std::string path = Arg(0).get_str();
        bool pin = true;
        if (params.isArray() && params.size() > 1 && params[1].isObject() && params[1].exists("pin")) {
            pin = params[1]["pin"].get_bool();
        }
        CatalogEntry e;
        if (!cat.ImportPath(path, pin, e, err)) {
            err_code = "IMPORT_FAILED";
            return false;
        }
        std::string uri;
        EncodeResource(ResourceKind::MODEL, e.model_id, uri, err);
        result.pushKV("schema_version", 2);
        result.pushKV("uri", uri);
        result.pushKV("model_id", e.model_id.Hex());
        result.pushKV("artifact_id", e.artifact_id.Hex());
        result.pushKV("admission", AdmissionLevelName(e.admission));
        result.pushKV("qualification", "structure only; not usefulness, safety, or alignment");
        result.pushKV("seeded", e.seeded);
        result.pushKV("propagation", ShouldDemandSeed(cat.Policy(), e.admission) || e.seeded ? "demand" : "local_only");
        return true;
    }
    if (method == "listmodels") {
        cat.List(result);
        return true;
    }
    if (method == "searchmodels") {
        cat.List(result);
        result.pushKV("remote_count", 0);
        result.pushKV("coverage", "incomplete");
        std::string text;
        if (params.isArray() && params.size() > 0) {
            if (Arg(0).isStr()) text = Arg(0).get_str();
            else if (Arg(0).isObject() && Arg(0).exists("text")) text = Arg(0)["text"].get_str();
            else if (Arg(0).isObject() && Arg(0).exists("query")) text = Arg(0)["query"].get_str();
        }
        if (!text.empty() && result.exists("models")) {
            const std::string q = ToLower(text);
            UniValue filtered(UniValue::VARR);
            for (const auto& m : result["models"].getValues()) {
                if (ToLower(m.write()).find(q) != std::string::npos) filtered.push_back(m);
            }
            result.pushKV("models", filtered);
            result.pushKV("local_count", static_cast<int>(filtered.size()));
        }
        return true;
    }
    if (method == "getmodelmanifest") {
        const Digest48 id = IdFromUser(Arg(0).get_str(), err);
        if (!err.empty() && id.IsNull()) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        err.clear();
        if (!cat.GetManifest(id, result, err)) {
            err_code = "NOT_FOUND";
            return false;
        }
        return true;
    }
    if (method == "seedmodel" || method == "unseedmodel") {
        std::string derr;
        const Digest48 id = IdFromUser(Arg(0).get_str(), derr);
        if (id.IsNull()) {
            err_code = "INVALID_PARAMETER";
            err = derr;
            return false;
        }
        if (!cat.Seed(id, method == "seedmodel", err)) {
            err_code = "NOT_FOUND";
            return false;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("seeded", method == "seedmodel");
        return true;
    }
    if (method == "qualifymodel") {
        QualReport report;
        const auto qr = QualifyFile(Arg(0).get_str(), report);
        result.pushKV("schema_version", 2);
        result.pushKV("result", QualResultName(qr));
        result.pushKV("admission", AdmissionLevelName(report.level));
        result.pushKV("detail", report.detail);
        result.pushKV("tensor_count", report.tensor_count);
        result.pushKV("note", "not a claim of usefulness, safety, or alignment");
        return true;
    }
    if (method == "getmodel") {
        Resource r;
        std::string hexerr;
        if (!DecodeResource(Arg(0).get_str(), r, err)) {
            const Digest48 id = IdFromUser(Arg(0).get_str(), hexerr);
            if (id.IsNull()) {
                err_code = "INVALID_PARAMETER";
                return false;
            }
            CatalogEntry found;
            if (cat.Find(id, found)) {
                r.kind = ResourceKind::MODEL;
                r.digest = found.model_id;
            } else {
                r.kind = ResourceKind::MODEL;
                r.digest = id;
            }
            err.clear();
        }
        if (r.kind != ResourceKind::MODEL) {
            err_code = "INVALID_PARAMETER";
            err = "resource is not a MODEL";
            return false;
        }
        RetrievalMode mode = RetrievalMode::FREE_ONLY;
        int64_t budget_atoms = 0;
        bool approved = false;
        UniValue requester(UniValue::VOBJ);
        if (params.isArray() && params.size() > 1) {
            if (params[1].isStr()) {
                if (!RetrievalModeFromName(params[1].get_str(), mode)) {
                    err_code = "INVALID_PARAMETER";
                    err = "unknown retrieval mode";
                    return false;
                }
            } else if (params[1].isObject()) {
                requester = params[1];
                std::string pol;
                if (requester.exists("retrieval_policy") && requester["retrieval_policy"].isStr()) {
                    pol = requester["retrieval_policy"].get_str();
                } else if (requester.exists("mode") && requester["mode"].isStr()) {
                    const std::string m = requester["mode"].get_str();
                    if (m != "plan" && m != "approve") pol = m;
                }
                if (!pol.empty() && !RetrievalModeFromName(pol, mode)) {
                    err_code = "INVALID_PARAMETER";
                    err = "unknown retrieval mode";
                    return false;
                }
                if (requester.exists("max_atoms")) budget_atoms = requester["max_atoms"].getInt<int64_t>();
                approved = requester.exists("approved") && requester["approved"].get_bool();
                if (requester.exists("mode") && requester["mode"].isStr() && requester["mode"].get_str() == "approve") {
                    approved = true;
                }
            }
        }
        if (mode == RetrievalMode::EXPLICIT_PAID) {
            err_code = "WALLET_REQUIRED";
            err = "paid retrieval requires a configured monetary wallet; free functionality continues";
            return false;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("uri", r.Uri());
        result.pushKV("automatic_spend_atoms", 0);

        CatalogEntry local_probe;
        const bool have_local = cat.Find(r.digest, local_probe);
        std::vector<PieceNeed> missing;
        if (have_local && !local_probe.core.files.empty()) {
            const auto& f = local_probe.core.files[0];
            const uint32_t n = f.size == 0 ? 1u : static_cast<uint32_t>((f.size + PIECE_SIZE - 1) / PIECE_SIZE);
            for (uint32_t i = 0; i < n; ++i) {
                PieceNeed p;
                p.file_index = 0;
                p.piece_index = i;
                missing.push_back(p);
            }
        } else {
            PieceNeed p;
            missing.push_back(p);
        }
        std::vector<SourceOffer> sources;
        if (have_local) {
            SourceOffer s;
            s.peer = "local";
            s.available = true;
            sources.push_back(s);
        }
        if (!cat.Peers().empty()) {
            SourceOffer s;
            s.peer = "peer";
            s.available = true;
            sources.push_back(s);
        }
        std::vector<Quote> quotes;
        std::vector<PaymentJournal> journal;
        const fs::path dir = cat.Store().Root().parent_path();
        LoadPaymentState(dir, quotes, journal, err);
        for (auto& p : missing) {
            if (DuplicateReservedRange(journal, p.file_index, p.piece_index, 1)) p.reserved_paid = true;
        }
        int64_t outstanding = 0;
        for (const auto& q : quotes) {
            if (!(q.model_id == r.digest) || q.price_atoms <= 0) continue;
            bool delivered = false;
            for (const auto& j : journal) {
                if (j.delivered && j.quote_id == q.offer_id.Hex()) delivered = true;
            }
            if (delivered) continue;
            outstanding += q.price_atoms;
            if (q.fee_cap_atoms > 0) outstanding += q.fee_cap_atoms;
        }
        if (mode != RetrievalMode::FREE_ONLY) {
            Quote q;
            MakePrepaidQuote(q, r.digest, have_local ? local_probe.artifact_id : Digest48{}, 0, 0, 0, err);
            quotes.push_back(q);
            SavePaymentState(dir, quotes, journal, err);
            result.pushKV("quote", QuoteToJson(q));
        }
        bool paid_binding = false;
        for (const auto& q : quotes) {
            if (!(q.model_id == r.digest)) continue;
            if (QuoteMayBeTakenAsFree(q, requester)) continue;
            paid_binding = true;
            SourceOffer s;
            s.peer = "quote";
            s.paid = true;
            s.price_atoms = q.price_atoms;
            s.fee_atoms = q.fee_cap_atoms;
            s.file_index = q.file_index;
            s.first_piece = q.first_piece;
            s.piece_count = q.piece_count;
            s.available = true;
            sources.push_back(s);
        }
        if (paid_binding && requester.exists("price_atoms") && requester["price_atoms"].getInt<int64_t>() == 0) {
            result.pushKV("plan", "APPROVAL_REQUIRED");
            result.pushKV("bypass_rejected", true);
            result.pushKV("note", "price=0 in requester JSON cannot bypass an accepted paid quote");
            return true;
        }
        const HybridPlan hp = PlanRetrieval(missing, sources, mode, budget_atoms, approved, outstanding);
        result.pushKV("paid_atoms", mode == RetrievalMode::FREE_ONLY ? 0 : hp.paid_atoms);
        result.pushKV("free_piece_count", static_cast<int>(hp.free_pieces.size()));
        result.pushKV("paid_piece_count", static_cast<int>(hp.paid_pieces.size()));
        result.pushKV("eta_s", EtaWithFees(/*queue_s=*/0,
                                            hp.paid_atoms > 0 ? 600 : 0,
                                            hp.paid_atoms,
                                            hp.paid_atoms > 0 ? 30 : 0));
        if (hp.unknown_eta) result.pushKV("eta", "unknown");
        if (mode != RetrievalMode::FREE_ONLY && !hp.paid_pieces.empty()) {
            result.pushKV("plan", (approved || mode == RetrievalMode::FREE_FIRST_BUDGET) ? "PAID" : "APPROVAL_REQUIRED");
            result.pushKV("note", "automatic spend remains 0; FREE_ONLY never becomes paid because a timer expired");
            return true;
        }
        CatalogEntry local;
        if (cat.Find(r.digest, local)) {
            cat.ApplyDemandSeed(local.model_id, err);
            cat.Find(r.digest, local);
            result.pushKV("plan", "FREE");
            result.pushKV("status", "local");
            result.pushKV("model_id", local.model_id.Hex());
            result.pushKV("artifact_id", local.artifact_id.Hex());
            result.pushKV("seeded", local.seeded);
            return true;
        }
        auto peers = cat.Peers();
        ResolveQueryPlan rplan;
        PlanRouterQueries(peers, peers.size() >= 2 ? std::vector<std::string>{peers.back()} : std::vector<std::string>{}, rplan);
        if (rplan.contacts.empty()) {
            result.pushKV("plan", "WAIT_FREE");
            result.pushKV("status", "not_local");
            result.pushKV("peers", 0);
            result.pushKV("unknown_eta", true);
            return true;
        }
        if (stop) {
            const std::string job_id = EnqueueRetrieve(cat, r.digest, stop);
            result.pushKV("plan", "WAIT_FREE");
            result.pushKV("status", "running");
            result.pushKV("async", true);
            result.pushKV("job_id", job_id);
            result.pushKV("peers", static_cast<int>(rplan.contacts.size()));
            result.pushKV("max_routers", MAX_ROUTER_CONTACTS);
            result.pushKV("note", "poll getmodeljob; helper unix RPC does not wait for WAN retrieve");
            return true;
        }
        Pq1Context pq;
        std::string tls_err;
        if (!LoadPq1Identity(pq, cat.Store().Root().parent_path(), tls_err)) {
            result.pushKV("retrieve_error", tls_err);
            result.pushKV("plan", "WAIT_FREE");
            result.pushKV("status", "not_local");
            result.pushKV("peers", static_cast<int>(rplan.contacts.size()));
            return true;
        }
        for (const auto& ep : rplan.contacts) {
            std::string host;
            uint16_t port = 0;
            if (pq.Ready() && SplitHostPort(ep, host, port) &&
                RetrieveFreeFromPeer(cat, pq, host, port, r.digest, err, stop,
                                     cat.Store().Root().parent_path() / "tls" / "pins.json")) {
                cat.ApplyDemandSeed(r.digest, err);
                CatalogEntry got;
                result.pushKV("plan", "FREE");
                result.pushKV("status", "retrieved");
                result.pushKV("seeded", cat.Find(r.digest, got) && got.seeded);
                result.pushKV("propagation", "demand");
                return true;
            }
        }
        result.pushKV("retrieve_error", err.empty() ? tls_err : err);
        result.pushKV("plan", "WAIT_FREE");
        result.pushKV("status", "not_local");
        result.pushKV("peers", static_cast<int>(rplan.contacts.size()));
        return true;
    }
    if (method == "addmodelnode") {
        cat.AddPeer(Arg(0).get_str());
        result = true;
        return true;
    }
    if (method == "getmodelpeers") {
        result.pushKV("schema_version", 2);
        UniValue arr(UniValue::VARR);
        for (const auto& p : cat.Peers()) arr.push_back(p);
        result.pushKV("peers", arr);
        result.pushKV("note", "model-plane contacts; not AddrMan; not monetary addnode");
        return true;
    }
    if (method == "getmodeljob" || method == "cancelmodeljob") {
        result.pushKV("schema_version", 2);
        std::string want;
        if (params.isArray() && params.size() > 0 && Arg(0).isStr()) want = Arg(0).get_str();
        UniValue arr(UniValue::VARR);
        std::lock_guard<std::mutex> lock(g_retrieve_mu);
        if (method == "cancelmodeljob" && !want.empty()) {
            const auto it = g_retrieve_jobs.find(want);
            if (it != g_retrieve_jobs.end()) {
                it->second->cancel.store(true);
                if (it->second->status == "running" || it->second->status == "queued") {
                    it->second->status = "cancelled";
                }
                result.pushKV("cancelled", true);
                result.pushKV("job_id", want);
            } else {
                result.pushKV("cancelled", false);
                result.pushKV("job_id", want);
            }
        }
        for (auto& kv : g_retrieve_jobs) {
            if (!want.empty() && kv.first != want) continue;
            arr.push_back(RetrieveJobJson(*kv.second));
        }
        result.pushKV("jobs", arr);
        result.pushKV("job_count", static_cast<int>(arr.size()));
        return true;
    }
    if (method == "createmodelrelease") {
        Resource r;
        if (!DecodeResource(Arg(0).get_str(), r, err) || r.kind != ResourceKind::MODEL) {
            err_code = "INVALID_PARAMETER";
            err = "model uri required";
            return false;
        }
        if (params.isArray() && params.size() < 3) {
            err_code = "INVALID_PARAMETER";
            err = "createmodelrelease(uri, secret32_hex, refund_height)";
            return false;
        }
        const auto secret = TryParseHex<unsigned char>(Arg(1).get_str());
        if (!secret || secret->size() != 32) {
            err_code = "INVALID_PARAMETER";
            err = "secret must be 32 bytes hex (stored as SHA-256 only)";
            return false;
        }
        ReleaseCampaign c;
        unsigned char nonce[32];
        GetStrongRandBytes(Span<unsigned char>{nonce, 32});
        c.release_id = DomainHash("BTX/ReleaseCampaign/v1", Span<const unsigned char>{nonce, 32});
        c.model_id = r.digest;
        CatalogEntry local;
        if (cat.Find(r.digest, local)) c.artifact_id = local.artifact_id;
        c.key_hash = ReleaseHash(*secret);
        c.refund_height = Arg(2).getInt<uint32_t>();
        c.target_atoms = (params.isArray() && params.size() > 3) ? Arg(3).getInt<int64_t>() : 0;
        if (!ValidRefundWindow(1, 1, 1, c.refund_height) && c.refund_height < 10) {
            err_code = "INVALID_PARAMETER";
            err = "refund_height too low";
            return false;
        }
        std::vector<ReleaseCampaign> campaigns;
        const fs::path dir = cat.Store().Root().parent_path();
        if (!LoadCampaigns(dir, campaigns, err)) {
            err_code = "IO";
            return false;
        }
        campaigns.push_back(c);
        if (!SaveCampaigns(dir, campaigns, err)) {
            err_code = "IO";
            return false;
        }
        result = CampaignToJson(c);
        result.pushKV("secret_retained", false);
        return true;
    }
    if (method == "getmodelrelease") {
        std::vector<ReleaseCampaign> campaigns;
        const fs::path dir = cat.Store().Root().parent_path();
        LoadCampaigns(dir, campaigns, err);
        result.pushKV("schema_version", 2);
        UniValue arr(UniValue::VARR);
        if (params.isArray() && params.size() > 0 && Arg(0).isStr() && !Arg(0).get_str().empty()) {
            Digest48 id;
            if (!Digest48::FromHex(Arg(0).get_str(), id, err)) {
                err_code = "INVALID_PARAMETER";
                return false;
            }
            for (const auto& c : campaigns) {
                if (c.release_id == id) arr.push_back(CampaignToJson(c));
            }
        } else {
            for (const auto& c : campaigns) arr.push_back(CampaignToJson(c));
        }
        result.pushKV("campaigns", arr);
        return true;
    }
    if (method == "pledgemodelrelease") {
        Digest48 id;
        if (!Digest48::FromHex(Arg(0).get_str(), id, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        const int64_t atoms = Arg(1).getInt<int64_t>();
        std::vector<ReleaseCampaign> campaigns;
        const fs::path dir = cat.Store().Root().parent_path();
        LoadCampaigns(dir, campaigns, err);
        bool found = false;
        for (auto& c : campaigns) {
            if (c.release_id == id) {
                c.pledged_atoms += atoms;
                found = true;
                result = CampaignToJson(c);
            }
        }
        if (!found) {
            err_code = "NOT_FOUND";
            err = "unknown release";
            return false;
        }
        SaveCampaigns(dir, campaigns, err);
        result.pushKV("note", "pledge is local accounting; send BTX with 0.34.6 HTLC separately");
        return true;
    }
    if (method == "claimmodelrelease" || method == "refundmodelrelease") {
        result.pushKV("schema_version", 2);
        result.pushKV("use", method == "claimmodelrelease" ? "buildhtlcclaim" : "buildhtlcrefund");
        result.pushKV("template", "htlc_sha256");
        result.pushKV("note", "No buildmodelhtlcclaim. HASH160 htlc_tx is recovery-only. After local decrypt of a qualified public artifact, demand-seed advertises the plaintext identity within the storage budget.");
        if (params.isArray() && params.size() > 0 && Arg(0).isStr()) {
            CatalogEntry e;
            const Digest48 id = IdFromUser(Arg(0).get_str(), err);
            if (!id.IsNull() && cat.Find(id, e)) {
                cat.ApplyDemandSeed(e.model_id, err);
                result.pushKV("seeded", cat.Find(id, e) && e.seeded);
                result.pushKV("propagation", "release");
            }
        }
        return true;
    }
    if (method == "resolveresource") {
        uint8_t kind = static_cast<uint8_t>(ResourceKind::MODEL);
        std::string digest;
        const UniValue& q = Arg(0);
        if (q.isObject()) {
            if (q.exists("kind") && !KindFromJson(q["kind"], kind, err)) {
                err_code = "INVALID_PARAMETER";
                return false;
            }
            if (q.exists("digest48") && q["digest48"].isStr()) digest = q["digest48"].get_str();
            else if (q.exists("id") && q["id"].isStr()) digest = q["id"].get_str();
            else if (q.exists("uri") && q["uri"].isStr()) {
                Resource parsed;
                if (DecodeResource(q["uri"].get_str(), parsed, err)) {
                    kind = static_cast<uint8_t>(parsed.kind);
                    digest = parsed.digest.Hex();
                } else {
                    err_code = "INVALID_PARAMETER";
                    return false;
                }
            }
        } else if (q.isStr()) {
            Resource parsed;
            if (DecodeResource(q.get_str(), parsed, err)) {
                kind = static_cast<uint8_t>(parsed.kind);
                digest = parsed.digest.Hex();
            } else {
                digest = q.get_str();
                err.clear();
            }
        }
        result = TypedResolveJson(cat, kind, digest);
        return true;
    }
    if (method == "exportmodelpath") {
        const Digest48 id = IdFromUser(Arg(0).get_str(), err);
        CatalogEntry e;
        if (id.IsNull() || !cat.Find(id, e)) {
            err_code = "NOT_FOUND";
            return false;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("model_id", e.model_id.Hex());
        result.pushKV("artifact_id", e.artifact_id.Hex());
        result.pushKV("store_root", fs::PathToString(cat.Store().Root()));
        result.pushKV("source_path", e.source_path);
        result.pushKV("inference", false);
        result.pushKV("runtime_started", false);
        result.pushKV("runtime_exec", false);
        UniValue files(UniValue::VARR);
        for (const auto& f : e.core.files) {
            UniValue one(UniValue::VOBJ);
            one.pushKV("path", f.path);
            one.pushKV("size", f.size);
            one.pushKV("sha384", f.sha384.Hex());
            files.push_back(one);
        }
        result.pushKV("files", files);
        result.pushKV("note", "Verified local files. This RPC never starts a runtime.");
        return true;
    }
    if (method == "getmodelpolicy" || method == "setmodelpolicy") {
        PreservationPolicy live = cat.Policy();
        if (method == "setmodelpolicy") {
            UniValue patch = Arg(0);
            if (!patch.isObject()) {
                err_code = "INVALID_PARAMETER";
                err = "policy object required";
                return false;
            }
            if (patch.exists("automatic_spend_atoms") && patch["automatic_spend_atoms"].getInt<int64_t>() != 0) {
                err_code = "INVALID_PARAMETER";
                err = "automatic spend remains 0; use EXPLICIT_PAID getmodel for a quote";
                return false;
            }
            if (patch.exists("auto_pay") && patch["auto_pay"].get_bool()) {
                err_code = "INVALID_PARAMETER";
                err = "auto_pay is refused; automatic spend is 0";
                return false;
            }
            if (!PolicyFromJson(patch, live, err)) {
                err_code = "INVALID_PARAMETER";
                return false;
            }
            cat.SetPolicy(live);
            const UniValue dumped = PolicyToJson(cat.Policy());
            if (!WriteJsonFile(HelperDir(cat) / "policy.json", dumped, err)) {
                err_code = "IO";
                return false;
            }
        }
        result = PolicyToJson(cat.Policy());
        result.pushKV("auto_pay", false);
        return true;
    }
    if (method == "listmodelidentities" || method == "createmodelidentity") {
        UniValue store;
        ReadJsonFile(HelperDir(cat) / "identities.json", store);
        UniValue arr = store.exists("identities") ? store["identities"] : UniValue(UniValue::VARR);
        if (method == "createmodelidentity") {
            std::vector<unsigned char> pk, sk;
            if (!GenerateMlDsa44(pk, sk, err)) {
                err_code = "CRYPTO";
                return false;
            }
            UniValue id(UniValue::VOBJ);
            id.pushKV("id", PublisherId(pk).Hex());
            id.pushKV("label", Arg(0).isStr() ? Arg(0).get_str() : "");
            id.pushKV("pubkey_hex", HexStr(pk));
            id.pushKV("class", "RESEARCH_PUBLISHER");
            id.pushKV("trusted", false);
            arr.push_back(id);
            store.pushKV("identities", arr);
            if (!WriteJsonFile(HelperDir(cat) / "identities.json", store, err)) {
                err_code = "IO";
                return false;
            }
            const fs::path skpath = HelperDir(cat) / "tls" / fs::PathFromString("identity-" + PublisherId(pk).Hex().substr(0, 16) + ".sk");
            fs::create_directories(skpath.parent_path());
            std::ofstream skf(skpath, std::ios::binary);
            skf.write(reinterpret_cast<const char*>(sk.data()), static_cast<std::streamsize>(sk.size()));
            result = id;
            result.pushKV("schema_version", 2);
            result.pushKV("secret_path", fs::PathToString(skpath));
            result.pushKV("wallet_backed", false);
            result.pushKV("contains_wallet_material", false);
            result.pushKV("note", "identity-only; never a wallet key");
            return true;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("identities", arr);
        return true;
    }
    if (method == "getmodelreciprocity") {
        ReciprocityLedger led;
        UniValue snap;
        UniValue raw;
        ReadJsonFile(HelperDir(cat) / "reciprocity.json", raw);
        if (raw.isObject()) led.Load(raw, err);
        result = led.Snapshot();
        result.pushKV("schema_version", 2);
        result.pushKV("note", "local observations only; not money and not consensus");
        return true;
    }
    if (method == "exportmodelcontacts" || method == "exportmodelpeers") {
        result.pushKV("schema_version", 2);
        UniValue arr(UniValue::VARR);
        for (const auto& p : cat.Peers()) arr.push_back(p);
        result.pushKV("peers", arr);
        result.pushKV("note", "public endpoints only; no secret keys");
        return true;
    }
    if (method == "importmodelcontacts" || method == "importmodelpeers" || method == "importmodeltrust") {
        if (!Arg(0).isArray() && !Arg(0).isStr()) {
            err_code = "INVALID_PARAMETER";
            err = "peer list required";
            return false;
        }
        if (Arg(0).isStr()) cat.AddPeer(Arg(0).get_str());
        else {
            for (const auto& p : Arg(0).getValues()) {
                if (p.isStr()) cat.AddPeer(p.get_str());
            }
        }
        result.pushKV("schema_version", 2);
        result.pushKV("peers", static_cast<int>(cat.Peers().size()));
        return true;
    }
    if (method == "listmodelrules" || method == "setmodelrule" || method == "removemodelrule") {
        UniValue rules;
        ReadJsonFile(HelperDir(cat) / "acl.json", rules);
        if (!rules.isObject()) rules = UniValue(UniValue::VOBJ);
        if (method == "setmodelrule") {
            if (!Arg(0).isObject()) {
                err_code = "INVALID_PARAMETER";
                err = "rule object required";
                return false;
            }
            UniValue arr = rules.exists("rules") ? rules["rules"] : UniValue(UniValue::VARR);
            arr.push_back(Arg(0));
            rules.pushKV("rules", arr);
            WriteJsonFile(HelperDir(cat) / "acl.json", rules, err);
        } else if (method == "removemodelrule" && Arg(0).isNum()) {
            UniValue arr(UniValue::VARR);
            const int idx = Arg(0).getInt<int>();
            int i = 0;
            for (const auto& r : rules["rules"].getValues()) {
                if (i++ != idx) arr.push_back(r);
            }
            rules.pushKV("rules", arr);
            WriteJsonFile(HelperDir(cat) / "acl.json", rules, err);
        }
        result = rules;
        result.pushKV("schema_version", 2);
        result.pushKV("affects_banman", false);
        return true;
    }
    if (method == "joinmodelcircle" || method == "leavemodelcircle" || method == "subscribemodelcollection" ||
        method == "subscribemodelpolicy" || method == "unsubscribemodelcollection" || method == "unsubscribemodelpolicy") {
        UniValue store;
        ReadJsonFile(HelperDir(cat) / "community.json", store);
        const std::string key = (method.find("circle") != std::string::npos) ? "circles" : "subscriptions";
        UniValue arr = store.exists(key) ? store[key] : UniValue(UniValue::VARR);
        if (method.rfind("leave", 0) == 0 || method.rfind("unsub", 0) == 0) {
            UniValue keep(UniValue::VARR);
            const std::string id = Arg(0).get_str();
            for (const auto& x : arr.getValues()) {
                if (!x.isStr() || x.get_str() != id) keep.push_back(x);
            }
            arr = keep;
            RememberStoppedPreservation(store, id);
        } else if (Arg(0).isStr()) {
            arr.push_back(Arg(0).get_str());
            uint8_t kind = RECORD_PRESERVATION_CIRCLE;
            if (method.find("collection") != std::string::npos) kind = RECORD_COLLECTION;
            else if (method.find("policy") != std::string::npos) kind = RECORD_POLICY_BUNDLE;
            Digest48 mid = CommunityLocalId(Arg(0).get_str());
            std::string hex = mid.Hex();
            UniValue extra(UniValue::VOBJ);
            int64_t ttl = 0;
            if (kind == RECORD_COLLECTION) {
                extra.pushKV("title", "collection");
                extra.pushKV("description", "local");
                UniValue entries(UniValue::VARR);
                UniValue e(UniValue::VOBJ);
                e.pushKV("model_id", hex);
                e.pushKV("priority", 1);
                e.pushKV("retention_days", 7);
                entries.push_back(e);
                extra.pushKV("entries", entries);
            } else if (kind == RECORD_POLICY_BUNDLE) {
                extra.pushKV("title", "policy");
                UniValue recs(UniValue::VARR);
                UniValue rec(UniValue::VOBJ);
                rec.pushKV("target_kind", 0);
                rec.pushKV("target_id", hex);
                rec.pushKV("action", 3);
                rec.pushKV("ttl_seconds", DAY_SECONDS);
                rec.pushKV("reason", "preview");
                recs.push_back(rec);
                extra.pushKV("recommendations", recs);
                ttl = DAY_SECONDS;
            } else {
                extra.pushKV("title", "circle");
                extra.pushKV("description", "local");
                extra.pushKV("collection_id", hex);
                extra.pushKV("target_observed_groups", 2);
                extra.pushKV("suggested_storage_bytes", 0);
                extra.pushKV("suggested_lease_seconds", 300);
            }
            SignedRecordHint h;
            if (!IssueAndStoreRecord(cat, kind, extra, ttl, h, err)) {
                err_code = "RECORD";
                return false;
            }
            result.pushKV("signed_record_id", h.record_id.Hex());
            result.pushKV("kind", kind);
            result.pushKV("recorded", true);
        }
        store.pushKV(key, arr);
        WriteJsonFile(HelperDir(cat) / "community.json", store, err);
        result.pushKV("schema_version", 2);
        result.pushKV("on_chain_membership", false);
        result.pushKV("automatic_preservation", method.rfind("unsub", 0) != 0 && method.rfind("leave", 0) != 0);
        if (method.find("collection") != std::string::npos || method.find("policy") != std::string::npos) {
            uint64_t est_disk = 0;
            if (result.exists("kind") && result["kind"].getInt<int>() == RECORD_COLLECTION) {
                UniValue listed;
                cat.List(listed);
                if (listed.exists("models")) {
                    for (const auto& m : listed["models"].getValues()) {
                        if (m.exists("bytes")) est_disk += m["bytes"].getInt<uint64_t>();
                    }
                }
            }
            result.pushKV("impact", CollectionFollowImpactPreview(cat.QuotaBytes(), cat.UsedBytes(), est_disk, /*egress=*/0));
        }
        if (store.exists("circles")) result.pushKV("circles", store["circles"]);
        if (store.exists("subscriptions")) result.pushKV("subscriptions", store["subscriptions"]);
        return true;
    }
    if (method == "delegatemodelservice" || method == "revokemodelservice") {
        UniValue extra(UniValue::VOBJ);
        uint8_t kind = RECORD_SERVICE_DELEGATION;
        int64_t ttl = 7 * DAY_SECONDS;
        if (method == "revokemodelservice") {
            kind = RECORD_REVOCATION;
            ttl = 0;
            extra.pushKV("target_kind", 1);
            Digest48 tid;
            if (Arg(0).isStr() && Digest48::FromHex(Arg(0).get_str(), tid, err)) extra.pushKV("target_id", tid.Hex());
            else extra.pushKV("target_id", std::string(96, '0'));
            extra.pushKV("reason_code", 1);
        } else {
            std::vector<unsigned char> pk, sk;
            Digest48 sid;
            if (!LoadOrCreateResearchIdentity(HelperDir(cat), pk, sk, sid, err)) {
                err_code = "CRYPTO";
                return false;
            }
            const UniValue& body = Arg(0);
            std::string dhex = HexStr(pk);
            uint32_t scopes = DELEGATE_ANNOUNCE | DELEGATE_SERVE;
            bool all_models = true;
            UniValue model_scope(UniValue::VARR);
            if (body.isObject()) {
                if (body.exists("delegate_pubkey") && body["delegate_pubkey"].isStr()) {
                    dhex = body["delegate_pubkey"].get_str();
                } else if (body.exists("service_pubkey") && body["service_pubkey"].isStr()) {
                    dhex = body["service_pubkey"].get_str();
                }
                if (body.exists("scopes") && body["scopes"].isNum()) {
                    scopes = static_cast<uint32_t>(body["scopes"].getInt<int64_t>());
                }
                if (body.exists("ttl") && body["ttl"].isNum()) {
                    ttl = body["ttl"].getInt<int64_t>();
                } else if (body.exists("expiry") && body["expiry"].isNum()) {
                    const int64_t exp = body["expiry"].getInt<int64_t>();
                    const int64_t now = static_cast<int64_t>(std::time(nullptr));
                    ttl = exp > now ? exp - now : 0;
                }
                if (body.exists("all_models") && body["all_models"].isBool()) {
                    all_models = body["all_models"].get_bool();
                }
                if (body.exists("model_scope") && body["model_scope"].isArray()) {
                    model_scope = body["model_scope"];
                    all_models = false;
                }
            } else if (body.isStr() && body.get_str().size() == MLDSA44_PK * 2) {
                dhex = body.get_str();
            }
            if ((scopes & ~DELEGATE_KNOWN_MASK) != 0) {
                err_code = "INVALID_PARAMETER";
                err = "delegation cannot authorize money, root actions, or unknown scopes";
                return false;
            }
            if (ttl <= 0 || ttl > MAX_DELEGATION_SECONDS) ttl = MAX_DELEGATION_SECONDS;
            extra.pushKV("delegate_pubkey", dhex);
            extra.pushKV("scopes", static_cast<int>(scopes));
            extra.pushKV("all_models", all_models);
            extra.pushKV("model_scope", model_scope);
        }
        SignedRecordHint h;
        if (!IssueAndStoreRecord(cat, kind, extra, ttl, h, err)) {
            err_code = "RECORD";
            return false;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("recorded", true);
        result.pushKV("record_id", h.record_id.Hex());
        result.pushKV("note", "typed root-authorized operation; never a money signature");
        return true;
    }
    if (method == "preparemodelfunding" || method == "signmodelfunding" || method == "submitmodelfunding" ||
        method == "exportmodelrecovery" || method == "buildmodelhtlcclaim" || method == "buildmodelhtlcrefund") {
        err_code = "NOT_IMPLEMENTED";
        err = "wallet funding RPCs stay on btxd; reuse 0.34.6 buildhtlcclaim / buildhtlcrefund. HASH160 htlc_tx is recovery-only.";
        return false;
    }
    err_code = "METHOD_NOT_FOUND";
    err = "unknown model RPC";
    return false;
}

bool EnsureMlDsaTlsFiles(const fs::path& cert, const fs::path& key, std::string& err)
{
    if (fs::exists(cert) && fs::exists(key)) return true;
    fs::create_directories(cert.parent_path());
    const std::string cmd = strprintf(
        "%s req -x509 -new -newkey mldsa44 -keyout '%s' -out '%s' -nodes -subj '/CN=btx-modeld' -days 3650 >/dev/null 2>&1",
        OpensslBin(), fs::PathToString(key), fs::PathToString(cert));
    const int rc = std::system(cmd.c_str());
    if (rc != 0 || !fs::exists(cert) || !fs::exists(key)) {
        err = "openssl mldsa44 certificate generation failed";
        return false;
    }
    return true;
}

bool LoadPq1Identity(Pq1Context& pq, const fs::path& modeldir, std::string& err)
{
    const fs::path cert = modeldir / "tls" / "cert.pem";
    const fs::path key = modeldir / "tls" / "key.pem";
    if (!EnsureMlDsaTlsFiles(cert, key, err)) return false;
    std::ifstream cf(cert), kf(key);
    const std::string cert_pem((std::istreambuf_iterator<char>(cf)), std::istreambuf_iterator<char>());
    const std::string key_pem((std::istreambuf_iterator<char>(kf)), std::istreambuf_iterator<char>());
    return pq.LoadSelfSignedMlDsa(cert_pem, key_pem, err);
}

bool RetrieveFreeFromPeer(ModelCatalog& cat, Pq1Context& pq, const std::string& host, uint16_t port,
                          const Digest48& model_id, std::string& err, std::atomic<bool>* stop, const fs::path& pinfile)
{
    auto init_sess = [&](Pq1Session& sess) -> bool {
        sess.stop = stop;
        sess.pinfile = pinfile;
        return sess.Connect(pq, host, port, err);
    };
    Pq1Session sess;
    if (!init_sess(sess)) return false;
    NativeRequest req;
    NativeResponse resp;
    req.method = "POST";
    req.path = std::string(MODEL_HTTP_ROOT) + "hello";
    if (!sess.Request(req, resp, err) || resp.status != 200) {
        if (err.empty()) err = "hello failed";
        return false;
    }
    req.method = "GET";
    req.path = std::string(MODEL_HTTP_ROOT) + "manifests/" + model_id.Hex();
    req.body.clear();
    if (!sess.Request(req, resp, err) || resp.status != 200) {
        if (err.empty()) err = "manifest failed";
        return false;
    }
    UniValue man;
    if (!man.read(resp.body) || !man.isObject()) {
        err = "manifest json";
        return false;
    }
    Digest48 artifact;
    if (!Digest48::FromHex(man["artifact_id"].get_str(), artifact, err)) return false;

    std::vector<std::pair<std::string, std::string>> grant_headers;
    std::mutex grant_mu;
    auto issue_grant = [&](Pq1Session& s, uint32_t file_index, std::string& gerr) -> bool {
        NativeRequest grant_req;
        NativeResponse grant_resp;
        grant_req.method = "POST";
        grant_req.path = std::string(MODEL_HTTP_ROOT) + "ext/free/grant";
        UniValue gb(UniValue::VOBJ);
        gb.pushKV("model_id", model_id.Hex());
        gb.pushKV("artifact_id", artifact.Hex());
        gb.pushKV("file_index", static_cast<int>(file_index));
        grant_req.body = gb.write();
        if (!(s.Request(grant_req, grant_resp, gerr) && grant_resp.status == 200)) {
            if (gerr.empty()) gerr = "missing FreeGrant";
            if (grant_resp.status != 0 && grant_resp.status != 200) {
                gerr += " HTTP " + std::to_string(grant_resp.status);
            }
            return false;
        }
        UniValue gj;
        if (!gj.read(grant_resp.body) || !gj.isObject() || !gj.exists("payload_hex") ||
            !gj.exists("sig_hex") || !gj.exists("pubkey_hex")) {
            gerr = "missing FreeGrant";
            return false;
        }
        std::lock_guard<std::mutex> lock(grant_mu);
        grant_headers.clear();
        grant_headers.emplace_back("X-BTX-Grant-Payload", gj["payload_hex"].get_str());
        grant_headers.emplace_back("X-BTX-Grant-Sig", gj["sig_hex"].get_str());
        grant_headers.emplace_back("X-BTX-Grant-Pubkey", gj["pubkey_hex"].get_str());
        return true;
    };
    err.clear();

    auto parse_piece = [&](const NativeResponse& presp, uint64_t size, const Digest48& pieces_root,
                            std::vector<unsigned char>& raw, std::vector<Digest48>& proof, uint64_t& hdr_size,
                            Digest48& hdr_root, std::string& local_err) -> bool {
        if (!(presp.binary || presp.content_type.find("octet-stream") != std::string::npos)) {
            local_err = "piece is not application/octet-stream (hex JSON is not a legal 4 MiB piece body)";
            return false;
        }
        raw.assign(presp.body.begin(), presp.body.end());
        hdr_size = size;
        hdr_root = pieces_root;
        const auto szs = HeaderGet(presp, "X-BTX-File-Size");
        if (!szs.empty()) hdr_size = std::strtoull(szs.c_str(), nullptr, 10);
        const auto rs = HeaderGet(presp, "X-BTX-Pieces-Root");
        if (!rs.empty() && !Digest48::FromHex(rs, hdr_root, local_err)) return false;
        const auto ps = HeaderGet(presp, "X-BTX-Proof");
        proof.clear();
        if (!ps.empty()) {
            size_t start = 0;
            while (start < ps.size()) {
                const auto comma = ps.find(',', start);
                const std::string part = TrimCopy(ps.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
                Digest48 d;
                if (!Digest48::FromHex(part, d, local_err)) return false;
                proof.push_back(d);
                if (comma == std::string::npos) break;
                start = comma + 1;
            }
        }
        return true;
    };

    std::mutex store_mu;
    auto fetch_one = [&](Pq1Session& s, uint32_t file_index, uint64_t i, uint64_t size, const Digest48& pieces_root,
                          std::vector<unsigned char>& raw, std::vector<Digest48>& proof, uint64_t& hdr_size,
                          Digest48& hdr_root, std::string& local_err) -> bool {
        std::string skip_err;
        if (cat.Store().GetPiece(artifact, file_index, static_cast<uint32_t>(i), raw, skip_err)) {
            return true;
        }
        NativeRequest preq;
        NativeResponse presp;
        preq.method = "GET";
        preq.path = std::string(MODEL_HTTP_ROOT) + "transfers/" + artifact.Hex() + "/pieces/" +
                    std::to_string(file_index) + "/" + std::to_string(i);
        {
            std::lock_guard<std::mutex> lock(grant_mu);
            preq.headers = grant_headers;
        }
        int grant_refreshes = 0;
        for (int attempt = 0; attempt < PQ1_PIECE_RETRIES; ++attempt) {
            if (stop && stop->load()) {
                local_err = "stopped";
                return false;
            }
            if (ModelWorkMayStarveExactReplay()) {
                local_err = "model work must not starve ExactReplay";
                return false;
            }
            std::this_thread::yield();
            if (s.Request(preq, presp, local_err)) {
                if (presp.status == 200 &&
                    parse_piece(presp, size, pieces_root, raw, proof, hdr_size, hdr_root, local_err)) {
                    std::lock_guard<std::mutex> lock(store_mu);
                    if (cat.PutFetchedPiece(artifact, file_index, static_cast<uint32_t>(i), raw, proof, hdr_size, hdr_root, local_err)) {
                        return true;
                    }
                } else if (presp.status == 403 && presp.body.find("expired") != std::string::npos) {
                    // FreeGrant TTL is 600s (spec cap). A 4 GiB file on a slow WAN outlives one grant.
                    if (++grant_refreshes > 64) {
                        local_err = "grant refresh limit";
                        return false;
                    }
                    if (!issue_grant(s, file_index, local_err)) return false;
                    {
                        std::lock_guard<std::mutex> lock(grant_mu);
                        preq.headers = grant_headers;
                    }
                    --attempt;
                    continue;
                } else if (presp.status != 200) {
                    const std::string body = presp.body.size() > 240 ? presp.body.substr(0, 240) : presp.body;
                    local_err = "piece HTTP " + std::to_string(presp.status) + " " + body;
                }
            }
            if (attempt + 1 == PQ1_PIECE_RETRIES) break;
            s.Close();
            s.stop = stop;
            s.pinfile = pinfile;
            if (!s.Connect(pq, host, port, local_err)) return false;
            {
                std::lock_guard<std::mutex> lock(grant_mu);
                preq.headers = grant_headers;
            }
        }
        if (local_err.empty()) local_err = "piece fetch failed";
        return false;
    };

    uint32_t file_index = 0;
    for (const auto& f : man["files"].getValues()) {
        const uint64_t size = f["size"].getInt<uint64_t>();
        Digest48 pieces_root, sha;
        if (!Digest48::FromHex(f["pieces_root"].get_str(), pieces_root, err)) return false;
        if (!Digest48::FromHex(f["sha384"].get_str(), sha, err)) return false;
        const uint64_t n = size == 0 ? 0 : (size + PIECE_SIZE - 1) / PIECE_SIZE;
        if (!issue_grant(sess, file_index, err)) return false;
        sess.Close();
        if (!init_sess(sess)) return false;
        std::vector<Digest48> leaves(n);
        Pq1Session sess2;
        if (n > 1) {
            sess2.stop = stop;
            sess2.pinfile = pinfile;
            sess2.Connect(pq, host, port, err);
        }
        for (uint64_t i = 0; i < n; i += 2) {
            if (stop && stop->load()) {
                err = "stopped";
                return false;
            }
            std::vector<unsigned char> raw0, raw1;
            std::vector<Digest48> proof0, proof1;
            uint64_t hs0 = size, hs1 = size;
            Digest48 hr0 = pieces_root, hr1 = pieces_root;
            std::string e0, e1;
            bool ok1 = true;
            std::thread t;
            if (i + 1 < n && sess2.ssl) {
                t = std::thread([&] {
                    try {
                        ok1 = fetch_one(sess2, file_index, i + 1, size, pieces_root, raw1, proof1, hs1, hr1, e1);
                    } catch (const std::exception& ex) {
                        ok1 = false;
                        e1 = ex.what();
                    } catch (...) {
                        ok1 = false;
                        e1 = "piece thread exception";
                    }
                });
            }
            if (!fetch_one(sess, file_index, i, size, pieces_root, raw0, proof0, hs0, hr0, e0)) {
                if (t.joinable()) t.join();
                err = e0;
                return false;
            }
            leaves[i] = ChunkLeaf(i, raw0);
            if (t.joinable()) {
                t.join();
                if (!ok1) {
                    err = e1;
                    return false;
                }
                leaves[i + 1] = ChunkLeaf(i + 1, raw1);
            } else if (i + 1 < n) {
                if (!fetch_one(sess, file_index, i + 1, size, pieces_root, raw1, proof1, hs1, hr1, e1)) {
                    err = e1;
                    return false;
                }
                leaves[i + 1] = ChunkLeaf(i + 1, raw1);
            }
        }
        if (size > 0) {
            size_t width = 1;
            while (width < n) width <<= 1;
            for (size_t i = n; i < width; ++i) leaves.push_back(ChunkPad(i));
            PieceIndex idx;
            idx.file_size = size;
            idx.pieces_root = pieces_root;
            idx.leaves = std::move(leaves);
            if (!cat.Store().SavePieceIndex(artifact, file_index, idx, err)) return false;
            if (!cat.VerifyFileDigest(artifact, file_index, sha, err)) return false;
        }
        ++file_index;
    }
    return cat.InstallFromManifest(man, err);
}

bool CallUnixRpc(const fs::path& socket_path, const std::string& method, const UniValue& params, UniValue& result, std::string& err)
{
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        err = "unix socket";
        return false;
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    const std::string p = fs::PathToString(socket_path);
    if (p.size() >= sizeof(addr.sun_path)) {
        err = "unix path too long";
        close(fd);
        return false;
    }
    std::strncpy(addr.sun_path, p.c_str(), sizeof(addr.sun_path) - 1);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        err = "helper unix connect failed (btx-modeld not running)";
        close(fd);
        return false;
    }
    UniValue req(UniValue::VOBJ);
    req.pushKV("jsonrpc", "1.0");
    req.pushKV("id", "model");
    req.pushKV("method", method);
    req.pushKV("params", params);
    const std::string wire = req.write() + "\n";
    if (::send(fd, wire.data(), wire.size(), 0) < 0) {
        err = "unix write";
        close(fd);
        return false;
    }
    ::shutdown(fd, SHUT_WR);
    const std::string raw = RecvUntil(fd, MAX_RPC_BODY, nullptr);
    close(fd);
    UniValue reply;
    if (!reply.read(raw) || !reply.isObject()) {
        err = "helper reply json";
        return false;
    }
    if (reply.exists("error") && !reply["error"].isNull()) {
        err = reply["error"].write();
        return false;
    }
    result = reply["result"];
    return true;
}

namespace {

void HandleUnixFd(int cfd, ModelCatalog& cat, std::atomic<bool>* stop)
{
    const std::string raw = RecvUntil(cfd, MAX_RPC_BODY, stop);
    std::string body = raw;
    NativeRequest http;
    std::string perr;
    if (raw.rfind("POST", 0) == 0 || raw.rfind("GET", 0) == 0) {
        if (ParseHttpRequest(raw, http, perr)) body = http.body;
    }
    UniValue req;
    UniValue reply(UniValue::VOBJ);
    reply.pushKV("jsonrpc", "1.0");
    if (!req.read(body)) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("code", "PARSE");
        e.pushKV("message", "invalid json");
        reply.pushKV("result", UniValue::VNULL);
        reply.pushKV("error", e);
    } else {
        if (req.exists("id")) reply.pushKV("id", req["id"]);
        if (req.exists("method") && req["method"].get_str() == "stop") {
            if (stop) stop->store(true);
            reply.pushKV("result", "stopping");
            reply.pushKV("error", UniValue::VNULL);
        } else {
            UniValue result;
            std::string code, emsg;
            if (DispatchHelperRpc(cat, req, result, code, emsg, stop)) {
                reply.pushKV("result", result);
                reply.pushKV("error", UniValue::VNULL);
            } else {
                UniValue e(UniValue::VOBJ);
                e.pushKV("code", code);
                e.pushKV("message", emsg);
                e.pushKV("schema_version", 2);
                reply.pushKV("result", UniValue::VNULL);
                reply.pushKV("error", e);
            }
        }
    }
    const std::string out = reply.write() + "\n";
    ::send(cfd, out.data(), out.size(), 0);
    close(cfd);
}

void HandlePq1Fd(int cfd, ModelCatalog& cat, Pq1Context& pq, std::atomic<bool>* stop, const fs::path& pinfile, uint32_t netgroup)
{
    SetPq1SocketOpts(cfd, true);
    SSL* ssl = SSL_new(static_cast<SSL_CTX*>(pq.SslCtx()));
    if (!ssl) {
        close(cfd);
        return;
    }
    SSL_set_fd(ssl, cfd);
    SSL_set_accept_state(ssl);
    std::string err;
    if (!SslHandshake(ssl, cfd, /*accept=*/true, PQ1_HANDSHAKE_MS, stop, err)) {
        CountUnauthAndBump(netgroup);
        SSL_free(ssl);
        close(cfd);
        return;
    }
    NegotiatedPq1 n;
    InspectNegotiated(ssl, n);
    if (!IsStrictPq1(n)) {
        CountUnauthAndBump(netgroup);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cfd);
        return;
    }
    Digest48 pin;
    if (!ExtractPeerTransportPin(ssl, pin, err)) {
        CountUnauthAndBump(netgroup);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cfd);
        return;
    }
    (void)pin;
    (void)pinfile;
    // Inbound TOFU must not be keyed by IPv4 netgroup: every researcher
    // behind one NAT would collide and the server would close after
    // handshake (client sees truncated HTTP). Outbound clients still pin
    // host:port in Pq1Session::Connect.
    ClearUnauth(netgroup);
    for (;;) {
        if (stop && stop->load()) break;
        const std::string raw = SslReadHttp(ssl, cfd, MAX_RPC_BODY + 8192, PQ1_IDLE_MS, stop);
        if (raw.empty()) break;
        NativeRequest nreq;
        NativeResponse nresp;
        if (!ParseHttpRequest(raw, nreq, err)) {
            nresp.status = 400;
            nresp.body = JsonError("BAD_HTTP", err);
        } else {
            HandleNativeRequest(cat, nreq, nresp);
        }
        const int wto = nreq.path.find("/pieces/") != std::string::npos ? PQ1_TRANSFER_MS : PQ1_IDLE_MS;
        if (!SslWriteAll(ssl, cfd, FormatHttpResponse(nresp), wto, stop, err)) break;
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(cfd);
}

struct WorkerJob {
    int fd{-1};
    bool unix_rpc{false};
    uint32_t netgroup{0};
};

} // namespace

static PreservationPolicy PolicyFromConfig(const HelperConfig& cfg)
{
    PreservationPolicy p;
    p.storage_quota_bytes = cfg.quota_bytes;
    if (!SeedModeFromName(cfg.seed, p.seed_mode)) p.seed_mode = SeedMode::AUTO;
    p.seed_upon_download = p.seed_mode == SeedMode::AUTO;
    p.preserve_rare = cfg.preserve_rare;
    p.allow_encrypted = cfg.allow_encrypted;
    p.upload_bps = cfg.upload_bps;
    return p;
}

static void TryPreserveRareTick(ModelCatalog& cat, Pq1Context& pq, const fs::path& pinfile, std::atomic<bool>* stop)
{
    const auto pol = cat.Policy();
    if (!pol.preserve_rare || pol.storage_quota_bytes == 0) return;
    const uint64_t spare = pol.storage_quota_bytes > cat.UsedBytes() ? pol.storage_quota_bytes - cat.UsedBytes() : 0;
    if (spare < 64 * MIB) return;
    std::set<Digest48> local;
    UniValue listed;
    cat.List(listed);
    if (listed.exists("models")) {
        for (const auto& m : listed["models"].getValues()) {
            Digest48 id;
            std::string e;
            if (m.exists("model_id") && Digest48::FromHex(m["model_id"].get_str(), id, e)) local.insert(id);
        }
    }
    {
        UniValue comm;
        ReadJsonFile(HelperDir(cat) / "community.json", comm);
        if (comm.exists("stopped_preservation")) {
            for (const auto& x : comm["stopped_preservation"].getValues()) {
                if (!x.isStr()) continue;
                local.insert(CommunityLocalId(x.get_str()));
            }
        }
    }
    std::map<std::string, PreserveCandidate> seen;
    for (const auto& endpoint : cat.Peers()) {
        if (stop && stop->load()) return;
        std::string host;
        uint16_t port = 0;
        if (!SplitHostPort(endpoint, host, port)) continue;
        Pq1Session sess;
        std::string err;
        sess.stop = stop;
        sess.pinfile = pinfile;
        if (!sess.Connect(pq, host, port, err)) continue;
        NativeRequest req;
        NativeResponse resp;
        req.method = "POST";
        req.path = std::string(MODEL_HTTP_ROOT) + "availability";
        req.body = "{}";
        if (!sess.Request(req, resp, err) || resp.status != 200) continue;
        UniValue body;
        if (!body.read(resp.body) || !body.isObject()) continue;
        const UniValue models = (body.exists("local") && body["local"].exists("models")) ? body["local"]["models"] : UniValue(UniValue::VARR);
        for (const auto& m : models.getValues()) {
            if (!m.exists("model_id") || !m.exists("seeded") || !m["seeded"].get_bool()) continue;
            Digest48 id;
            std::string e;
            if (!Digest48::FromHex(m["model_id"].get_str(), id, e)) continue;
            const std::string key = id.Hex();
            if (seen.count(key)) {
                seen[key].observed_sources += 1;
                continue;
            }
            PreserveCandidate c;
            c.model_id = id;
            c.bytes = m.exists("bytes") ? m["bytes"].getInt<uint64_t>() : 0;
            c.observed_sources = 1;
            c.peer = endpoint;
            c.admission = AdmissionLevel::BYTES_VERIFIED;
            c.encrypted = false;
            seen[key] = c;
        }
    }
    std::vector<PreserveCandidate> observed;
    observed.reserve(seen.size());
    for (auto& kv : seen) observed.push_back(kv.second);
    PreserveCandidate pick;
    if (!SelectPreserveRare(observed, local, spare, pol, pick, static_cast<int64_t>(std::time(nullptr)))) return;
    std::string host;
    uint16_t port = 0;
    std::string err;
    if (!SplitHostPort(pick.peer, host, port)) return;
    if (!cat.EnforceQuota(pick.bytes, err)) return;
    if (RetrieveFreeFromPeer(cat, pq, host, port, pick.model_id, err, stop, pinfile)) {
        cat.ApplyDemandSeed(pick.model_id, err);
    }
}

int RunModelDaemon(HelperConfig cfg, std::atomic<bool>* stop)
{
    std::signal(SIGPIPE, SIG_IGN);
    std::atomic<bool> local_stop{false};
    if (!stop) stop = &local_stop;
    fs::create_directories(cfg.modeldir);
    if (cfg.rpc_socket.empty()) cfg.rpc_socket = cfg.modeldir / "modeld.sock";
    if (cfg.tls_cert.empty()) cfg.tls_cert = cfg.modeldir / "tls" / "cert.pem";
    if (cfg.tls_key.empty()) cfg.tls_key = cfg.modeldir / "tls" / "key.pem";

    Pq1Context pq;
    if (!pq.Ready()) {
        std::cerr << "model subsystem fail-closed: strict PQ1 unavailable: " << pq.Error() << "\n";
        std::cerr << "monetary BTX remains independently operational.\n";
        return 2;
    }
    std::string err;
    if (!EnsureMlDsaTlsFiles(cfg.tls_cert, cfg.tls_key, err)) {
        std::cerr << "model subsystem fail-closed: " << err << "\n";
        return 2;
    }
    std::ifstream cf(cfg.tls_cert), kf(cfg.tls_key);
    const std::string cert_pem((std::istreambuf_iterator<char>(cf)), std::istreambuf_iterator<char>());
    const std::string key_pem((std::istreambuf_iterator<char>(kf)), std::istreambuf_iterator<char>());
    if (!pq.LoadSelfSignedMlDsa(cert_pem, key_pem, err)) {
        std::cerr << "model subsystem fail-closed: " << err << "\n";
        return 2;
    }

    ModelCatalog cat(cfg.modeldir, cfg.quota_bytes);
    for (const auto& p : cfg.peers) cat.AddPeer(p);
    cat.SetPolicy(PolicyFromConfig(cfg));
    {
        std::string perr;
        WriteJsonFile(cfg.modeldir / "policy.json", PolicyToJson(cat.Policy()), perr);
    }
    const int unix_fd = ListenUnix(cfg.rpc_socket, err);
    if (unix_fd < 0) {
        std::cerr << err << "\n";
        return 2;
    }
    int tcp_fd = -1;
    if (!cfg.bind.empty()) {
        tcp_fd = ListenTcp(cfg.bind, err);
        if (tcp_fd < 0) {
            close(unix_fd);
            std::cerr << err << "\n";
            return 2;
        }
    }
    const fs::path pinfile = cfg.modeldir / "tls" / "pins.json";
    std::mutex qmu;
    std::condition_variable qcv;
    std::queue<WorkerJob> jobs;
    auto enqueue = [&](WorkerJob job) -> bool {
        std::unique_lock<std::mutex> lock(qmu);
        if (jobs.size() >= static_cast<size_t>(PQ1_HTTP_QUEUE)) return false;
        jobs.push(job);
        qcv.notify_one();
        return true;
    };
    std::vector<std::thread> workers;
    workers.reserve(PQ1_HTTP_WORKERS);
    for (int i = 0; i < PQ1_HTTP_WORKERS; ++i) {
        workers.emplace_back([&] {
            while (!stop->load()) {
                WorkerJob job;
                {
                    std::unique_lock<std::mutex> lock(qmu);
                    qcv.wait_for(lock, std::chrono::milliseconds(250), [&] { return !jobs.empty() || stop->load(); });
                    if (jobs.empty()) continue;
                    job = jobs.front();
                    jobs.pop();
                }
                if (job.fd < 0) continue;
                if (job.unix_rpc) HandleUnixFd(job.fd, cat, stop);
                else {
                    HandlePq1Fd(job.fd, cat, pq, stop, pinfile, job.netgroup);
                    GlobalConnLimits().ReleaseInbound(job.netgroup);
                }
            }
        });
    }
    std::cout << "btx-modeld: PQ1 ready; unix=" << fs::PathToString(cfg.rpc_socket)
              << " quota=" << cfg.quota_bytes
              << " seed=" << cfg.seed
              << " preserve_rare=" << (cfg.preserve_rare ? "1" : "0")
              << " automatic_spend=0"
              << " workers=" << PQ1_HTTP_WORKERS
              << (cfg.bind.empty() ? "" : " bind=" + cfg.bind)
              << (cfg.relay ? " relay" : "")
              << (cfg.host ? " host" : "")
              << "\n";
    std::cout.flush();

    // Preserve-rare: first tick immediately, then every 5s (fail-fast e2e; not a 60s stall).
    auto last_preserve = std::chrono::steady_clock::now() - std::chrono::seconds(5);
    while (!stop->load()) {
        pollfd fds[2]{};
        nfds_t nf = 1;
        fds[0].fd = unix_fd;
        fds[0].events = POLLIN;
        if (tcp_fd >= 0) {
            fds[1].fd = tcp_fd;
            fds[1].events = POLLIN;
            nf = 2;
        }
        const int pr = poll(fds, nf, 250);
        if (cfg.preserve_rare &&
            std::chrono::steady_clock::now() - last_preserve >= std::chrono::seconds(5)) {
            TryPreserveRareTick(cat, pq, pinfile, stop);
            last_preserve = std::chrono::steady_clock::now();
        }
        if (pr <= 0) continue;
        if (fds[0].revents & POLLIN) {
            const int c = accept(unix_fd, nullptr, nullptr);
            if (c >= 0) {
                WorkerJob job;
                job.fd = c;
                job.unix_rpc = true;
                if (!enqueue(job)) close(c);
            }
        }
        if (tcp_fd >= 0 && (fds[1].revents & POLLIN)) {
            sockaddr_in peer{};
            socklen_t plen = sizeof(peer);
            const int c = accept(tcp_fd, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (c >= 0) {
                const uint32_t ng = Ipv4Netgroup(reinterpret_cast<sockaddr*>(&peer), plen);
                if (UnauthCount(ng) >= PQ1_UNAUTH_HANDSHAKE_LIMIT) {
                    close(c);
                    continue;
                }
                if (!GlobalConnLimits().TryInbound(ng)) {
                    close(c);
                    continue;
                }
                WorkerJob job;
                job.fd = c;
                job.unix_rpc = false;
                job.netgroup = ng;
                if (!enqueue(job)) {
                    GlobalConnLimits().ReleaseInbound(ng);
                    close(c);
                }
            }
        }
    }
    qcv.notify_all();
    for (auto& w : workers) w.join();
    JoinRetrieveJobs();
    close(unix_fd);
    if (tcp_fd >= 0) close(tcp_fd);
    ::unlink(fs::PathToString(cfg.rpc_socket).c_str());
    return 0;
}

} // namespace modelnet
