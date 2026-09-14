// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/pq1_runtime.h>

#include <modelnet/crypto.h>
#include <modelnet/transport_pq.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>

#include <cstdlib>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/time.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>

namespace modelnet {
namespace {

struct UnauthState {
    int count{0};
    std::chrono::steady_clock::time_point window{};
};

std::mutex g_unauth_mu;
std::map<uint32_t, UnauthState> g_unauth;
std::mutex g_netgroup_mu;
std::map<uint32_t, int> g_inbound_netgroup;
ConnLimits g_limits;

void DecayUnauthLocked(UnauthState& e)
{
    const auto now = std::chrono::steady_clock::now();
    if (e.window.time_since_epoch().count() == 0 ||
        now - e.window >= std::chrono::seconds(PQ1_UNAUTH_WINDOW_S)) {
        e.count = 0;
        e.window = now;
    }
}

} // namespace

ConnLimits& GlobalConnLimits() { return g_limits; }

void SetPq1SocketOpts(int fd, bool nonblock)
{
    int mss = 800;
    setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
    int disc = IP_PMTUDISC_DONT;
    setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &disc, sizeof(disc));
    int nodelay = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    if (nonblock) {
        const int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

bool WaitFd(int fd, bool want_write, int timeout_ms, std::atomic<bool>* stop, std::string& err)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (!stop || !stop->load()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            err = "timeout";
            return false;
        }
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        int slice = 250;
        if (left < slice) slice = static_cast<int>(left);
        if (slice <= 0) {
            err = "timeout";
            return false;
        }
        pollfd p{};
        p.fd = fd;
        p.events = want_write ? POLLOUT : POLLIN;
        const int r = poll(&p, 1, slice);
        if (r < 0) {
            if (errno == EINTR) continue;
            err = "poll";
            return false;
        }
        if (r > 0) {
            if (p.revents & POLLNVAL) {
                err = "socket closed";
                return false;
            }
            if (want_write) {
                if (p.revents & POLLOUT) return true;
                if (p.revents & (POLLERR | POLLHUP)) {
                    err = "socket closed";
                    return false;
                }
                continue;
            }
            // POLLIN|POLLHUP is the normal unix-RPC close: peer wrote the
            // reply and closed. Drain via recv(); do not fail the wait.
            if (p.revents & (POLLIN | POLLHUP | POLLERR)) return true;
            continue;
        }
    }
    err = "stopped";
    return false;
}

static bool SslWantWait(SSL* ssl, int rc, int fd, int timeout_ms, std::atomic<bool>* stop, std::string& err)
{
    const int w = SSL_get_error(ssl, rc);
    if (w == SSL_ERROR_WANT_READ) return WaitFd(fd, false, timeout_ms, stop, err);
    if (w == SSL_ERROR_WANT_WRITE) return WaitFd(fd, true, timeout_ms, stop, err);
    if (w == SSL_ERROR_ZERO_RETURN) {
        err = "tls closed";
        return false;
    }
    err = "tls io";
    return false;
}

bool SslHandshake(void* ssl_void, int fd, bool accept, int timeout_ms, std::atomic<bool>* stop, std::string& err)
{
    auto* ssl = static_cast<SSL*>(ssl_void);
    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_clear_mode(ssl, SSL_MODE_AUTO_RETRY);
    SSL_set_max_send_fragment(ssl, 512);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (!stop || !stop->load()) {
        const int rc = accept ? SSL_accept(ssl) : SSL_connect(ssl);
        if (rc == 1) return true;
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) {
            err = "handshake timeout";
            return false;
        }
        if (!SslWantWait(ssl, rc, fd, static_cast<int>(left), stop, err)) return false;
    }
    err = "stopped";
    return false;
}

bool SslWriteAll(void* ssl_void, int fd, const std::string& data, int timeout_ms, std::atomic<bool>* stop, std::string& err)
{
    auto* ssl = static_cast<SSL*>(ssl_void);
    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_clear_mode(ssl, SSL_MODE_AUTO_RETRY);
    size_t off = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (off < data.size()) {
        if (stop && stop->load()) {
            err = "stopped";
            return false;
        }
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) {
            err = "write timeout";
            return false;
        }
        const int n = SSL_write(ssl, data.data() + off, static_cast<int>(data.size() - off));
        if (n > 0) {
            off += static_cast<size_t>(n);
            continue;
        }
        if (!SslWantWait(ssl, n, fd, static_cast<int>(left), stop, err)) return false;
    }
    return true;
}

std::string SslReadHttp(void* ssl_void, int fd, size_t cap, int timeout_ms, std::atomic<bool>* stop)
{
    auto* ssl = static_cast<SSL*>(ssl_void);
    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_clear_mode(ssl, SSL_MODE_AUTO_RETRY);
    std::string out;
    char buf[4096];
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (out.size() < cap) {
        if (stop && stop->load()) break;
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) break;
        const int n = SSL_read(ssl, buf, sizeof(buf));
        if (n > 0) {
            out.append(buf, static_cast<size_t>(n));
            const auto pos = out.find("\r\n\r\n");
            if (pos == std::string::npos) {
                if (out.size() > PQ1_HTTP_HEADER_CAP) break;
                continue;
            }
            size_t clen = 0;
            auto cl = out.find("Content-Length:");
            if (cl == std::string::npos) cl = out.find("content-length:");
            if (cl != std::string::npos && cl < pos) {
                clen = std::strtoul(out.c_str() + cl + 15, nullptr, 10);
            }
            if (out.size() >= pos + 4 + clen) break;
            continue;
        }
        if (n == 0) break;
        std::string err;
        if (!SslWantWait(ssl, n, fd, static_cast<int>(left), stop, err)) break;
    }
    return out;
}

bool ExtractPeerTransportPin(void* ssl_void, Digest48& out, std::string& err)
{
    auto* ssl = static_cast<SSL*>(ssl_void);
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        err = "no peer certificate";
        return false;
    }
    unsigned char* der = nullptr;
    const int len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &der);
    X509_free(cert);
    if (len <= 0 || !der) {
        err = "peer SPKI encode failed";
        return false;
    }
    out = DomainHash("BTX/TransportKey/v2", Span<const unsigned char>{der, static_cast<size_t>(len)});
    OPENSSL_free(der);
    return true;
}

bool CheckOrStorePin(const fs::path& pinfile, const std::string& endpoint, const Digest48& pin, std::string& err)
{
    UniValue obj(UniValue::VOBJ);
    if (fs::exists(pinfile)) {
        std::ifstream in(pinfile);
        std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        if (!raw.empty() && !obj.read(raw)) {
            err = "pin file corrupt";
            return false;
        }
    }
    if (obj.exists(endpoint)) {
        Digest48 stored;
        if (!Digest48::FromHex(obj[endpoint].get_str(), stored, err)) return false;
        if (stored != pin) {
            err = "peer cert pin mismatch (TOFU)";
            return false;
        }
        return true;
    }
    obj.pushKV(endpoint, pin.Hex());
    fs::create_directories(pinfile.parent_path());
    std::ofstream out(pinfile, std::ios::trunc);
    if (!out) {
        err = "pin file write";
        return false;
    }
    out << obj.write() << "\n";
    return true;
}

uint32_t Ipv4Netgroup(const sockaddr* sa, socklen_t len)
{
    if (!sa || len < static_cast<socklen_t>(sizeof(sockaddr_in))) return 0;
    if (sa->sa_family != AF_INET) return 0;
    return ntohl(reinterpret_cast<const sockaddr_in*>(sa)->sin_addr.s_addr);
}

int CountUnauthAndBump(uint32_t netgroup)
{
    std::lock_guard<std::mutex> lock(g_unauth_mu);
    auto& e = g_unauth[netgroup];
    DecayUnauthLocked(e);
    return ++e.count;
}

int UnauthCount(uint32_t netgroup)
{
    std::lock_guard<std::mutex> lock(g_unauth_mu);
    auto it = g_unauth.find(netgroup);
    if (it == g_unauth.end()) return 0;
    DecayUnauthLocked(it->second);
    return it->second.count;
}

void ClearUnauth(uint32_t netgroup)
{
    std::lock_guard<std::mutex> lock(g_unauth_mu);
    g_unauth.erase(netgroup);
}

bool ConnLimits::TryInbound(uint32_t netgroup)
{
    std::lock_guard<std::mutex> lock(g_netgroup_mu);
    if (inbound.load() >= PQ1_MAX_INBOUND) return false;
    if (g_inbound_netgroup[netgroup] >= PQ1_MAX_INBOUND_PER_NETGROUP) return false;
    ++g_inbound_netgroup[netgroup];
    inbound.fetch_add(1);
    return true;
}

void ConnLimits::ReleaseInbound(uint32_t netgroup)
{
    std::lock_guard<std::mutex> lock(g_netgroup_mu);
    auto it = g_inbound_netgroup.find(netgroup);
    if (it != g_inbound_netgroup.end() && it->second > 0) --it->second;
    inbound.fetch_sub(1);
}

bool ConnLimits::TryOutbound()
{
    int cur = outbound.load();
    while (cur < PQ1_MAX_OUTBOUND) {
        if (outbound.compare_exchange_weak(cur, cur + 1)) return true;
    }
    return false;
}

void ConnLimits::ReleaseOutbound()
{
    outbound.fetch_sub(1);
}

void Pq1SanitizeOpenSslEnv()
{
    unsetenv("OPENSSL_CONF");
    unsetenv("OPENSSL_CONF_INCLUDE");
    unsetenv("OPENSSL_MODULES");
    unsetenv("OPENSSL_ENGINES");
}

void Pq1InitOpenSsl()
{
    Pq1SanitizeOpenSslEnv();
    OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr);
}

bool Pq1OpenSslEnvIsClean()
{
    static const char* kKeys[] = {"OPENSSL_CONF", "OPENSSL_CONF_INCLUDE", "OPENSSL_MODULES", "OPENSSL_ENGINES"};
    for (const char* k : kKeys) {
        const char* v = std::getenv(k);
        if (v && v[0] != '\0') return false;
    }
    return true;
}

namespace {

bool ApplyHostileSslConf(SSL_CTX* ctx)
{
    SSL_CONF_CTX* cctx = SSL_CONF_CTX_new();
    if (!cctx) return false;
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_CLIENT |
                                     SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_CERTIFICATE);
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    SSL_CONF_cmd(cctx, "MinProtocol", "TLSv1.2");
    SSL_CONF_cmd(cctx, "MaxProtocol", "TLSv1.3");
    SSL_CONF_cmd(cctx, "Groups", "X25519:X25519MLKEM768:MLKEM768");
    SSL_CONF_cmd(cctx, "Ciphersuites", "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384");
    SSL_CONF_cmd(cctx, "SignatureAlgorithms", "ECDSA+SHA256:ed25519:mldsa44");
    SSL_CONF_CTX_finish(cctx);
    SSL_CONF_CTX_free(cctx);
    return true;
}

} // namespace

bool Pq1HostileConfCannotWeaken(std::string& err)
{
    Pq1InitOpenSsl();
    if (!Pq1OpenSslEnvIsClean()) {
        err = "OPENSSL_* env still set after sanitize";
        return false;
    }
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        err = "SSL_CTX_new failed";
        return false;
    }
    ApplyHostileSslConf(ctx);
    if (!PinPq1SslCtx(ctx, err)) {
        SSL_CTX_free(ctx);
        // Fail-closed: no live weaker profile.
        return true;
    }
    const long minv = SSL_CTX_get_min_proto_version(ctx);
    const long maxv = SSL_CTX_get_max_proto_version(ctx);
    SSL_CTX_free(ctx);
    if (minv != TLS1_3_VERSION || maxv != TLS1_3_VERSION) {
        err = "protocol bounds not TLS1.3 after pin";
        return false;
    }
    return true;
}

} // namespace modelnet
