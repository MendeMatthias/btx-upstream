// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_HTTP_BRIDGE_H
#define BITCOIN_MODELNET_HTTP_BRIDGE_H

#include <modelnet/resource_uri.h>

#include <string>

namespace modelnet {

struct BrowserBridgeResponse {
    bool ok{false};
    int http_status{404};
    std::string content_type;
    std::string body;
    std::string canonical_btx;
};

/** Loopback-only browser compatibility. Not a native trust root. No wallet secrets. */
bool HandleBridgeGet(const std::string& path, BrowserBridgeResponse& out);

} // namespace modelnet

#endif // BITCOIN_MODELNET_HTTP_BRIDGE_H
