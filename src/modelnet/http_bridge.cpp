// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/http_bridge.h>

#include <univalue.h>

namespace modelnet {

bool HandleBridgeGet(const std::string& path, BrowserBridgeResponse& out)
{
    out = {};
    std::string token = path;
    if (!token.empty() && token[0] == '/') token.erase(0, 1);
    Resource r;
    std::string err;
    if (!DecodeResource(token, r, err) && !DecodeResource("btx://" + token, r, err)) {
        out.http_status = 400;
        out.content_type = "text/plain";
        out.body = "malformed token";
        return true;
    }
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("canonical", r.Uri());
    obj.pushKV("kind", ResourceKindName(r.kind));
    obj.pushKV("digest", r.digest.Hex());
    obj.pushKV("open_in_btx", r.Uri());
    obj.pushKV("note", "HTTP bridge is not the identity authority; verify native hash.");
    out.ok = true;
    out.http_status = 200;
    out.content_type = "application/json";
    out.body = obj.write();
    out.canonical_btx = r.Uri();
    return true;
}

} // namespace modelnet
