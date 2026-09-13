// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ACL_H
#define BITCOIN_MODELNET_ACL_H

#include <modelnet/policy.h>

#include <string>
#include <unordered_map>
#include <unordered_set>

namespace modelnet {

enum class PolicyDim : uint8_t {
    CONNECT = 0,
    DISCOVER = 1,
    RETRIEVE = 2,
    SERVE = 3,
    TRUST_METADATA = 4,
    AUTO_SEED = 5,
    AUTO_PAY = 6,
};

struct ModelAcl {
    std::unordered_set<std::string> deny_endpoint;
    std::unordered_set<std::string> deny_subnet;
    std::unordered_set<std::string> deny_service_id;
    std::unordered_set<std::string> deny_publisher;
    std::unordered_set<std::string> deny_artifact;
    std::unordered_set<std::string> deny_model;
    std::unordered_set<std::string> deny_collection;
    std::unordered_set<std::string> allow_prefer;
    bool auto_seed{false};
    bool auto_pay{false};
    bool trust_metadata{false};

    bool Denied(PolicyDim dim, const std::string& subject) const;
    /** Model ACLs never map to monetary BanMan / NoBan / ForceRelay. */
    bool AffectsMonetaryBan() const { return false; }
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_ACL_H
