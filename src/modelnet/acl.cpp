// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acl.h>

namespace modelnet {

bool ModelAcl::Denied(PolicyDim dim, const std::string& subject) const
{
    (void)dim;
    if (deny_endpoint.count(subject) || deny_subnet.count(subject) ||
        deny_service_id.count(subject) || deny_publisher.count(subject) ||
        deny_artifact.count(subject) || deny_model.count(subject) ||
        deny_collection.count(subject)) {
        return true;
    }
    return false;
}

} // namespace modelnet
