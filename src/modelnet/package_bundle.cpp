// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/package_bundle.h>

#include <crypto/common.h>
#include <crypto/sha384.h>
#include <span.h>
#include <univalue.h>

#include <cstring>

namespace modelnet {
namespace {

constexpr size_t MAX_BUNDLE_PAYLOAD = 4 * 1024 * 1024;

bool RejectFloats(const UniValue& v, std::string& err, int depth = 0)
{
    if (depth > 32) {
        err = "nesting";
        return false;
    }
    if (v.isNum()) {
        const std::string s = v.getValStr();
        if (s.find('.') != std::string::npos || s.find('e') != std::string::npos ||
            s.find('E') != std::string::npos) {
            err = "floats prohibited";
            return false;
        }
    }
    if (v.isArray()) {
        for (const auto& e : v.getValues()) {
            if (!RejectFloats(e, err, depth + 1)) return false;
        }
    } else if (v.isObject()) {
        for (const auto& k : v.getKeys()) {
            if (!RejectFloats(v[k], err, depth + 1)) return false;
        }
    }
    return true;
}

} // namespace

bool EncodeBtxBundle(const UniValue& value, std::vector<unsigned char>& out, std::string& err)
{
    out.clear();
    if (!value.isObject()) {
        err = "package must be object";
        return false;
    }
    if (!RejectFloats(value, err)) return false;
    const std::string payload = value.write();
    if (payload.size() > MAX_BUNDLE_PAYLOAD) {
        err = "oversize";
        return false;
    }
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
    unsigned char digest[48];
    hasher.Finalize(digest);
    out.resize(8 + 4 + 8 + 48 + payload.size());
    std::memcpy(out.data(), BTXPKG_MAGIC, 8);
    WriteLE32(out.data() + 8, 0);
    WriteLE64(out.data() + 12, payload.size());
    std::memcpy(out.data() + 20, digest, 48);
    std::memcpy(out.data() + 68, payload.data(), payload.size());
    return true;
}

bool DecodeBtxBundle(Span<const unsigned char> data, UniValue& out, std::string& err)
{
    out = UniValue(UniValue::VOBJ);
    if (data.size() < 68) {
        err = "invalid header";
        return false;
    }
    if (std::memcmp(data.data(), BTXPKG_MAGIC, 8) != 0) {
        err = "invalid header";
        return false;
    }
    const uint32_t flags = ReadLE32(data.data() + 8);
    const uint64_t n = ReadLE64(data.data() + 12);
    if (flags != 0 || n > MAX_BUNDLE_PAYLOAD || data.size() != 68 + n) {
        err = "flags/size/trailing";
        return false;
    }
    CSHA384 hasher;
    hasher.Write(data.data() + 68, n);
    unsigned char digest[48];
    hasher.Finalize(digest);
    if (std::memcmp(digest, data.data() + 20, 48) != 0) {
        err = "payload digest";
        return false;
    }
    const std::string payload(reinterpret_cast<const char*>(data.data() + 68), n);
    if (!out.read(payload) || !out.isObject()) {
        err = "package must be object";
        return false;
    }
    if (!RejectFloats(out, err)) return false;
    return true;
}

} // namespace modelnet
