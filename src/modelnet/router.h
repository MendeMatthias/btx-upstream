// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ROUTER_H
#define BITCOIN_MODELNET_ROUTER_H

#include <modelnet/types.h>

#include <map>
#include <string>
#include <vector>

namespace modelnet {

struct SignedRecordHint {
    Digest48 record_id;
    uint8_t kind{0};
    int64_t expiry{0};
    std::string provider_id;
    std::vector<unsigned char> payload;
};

/** CPU-only discovery cache. No GPU, no wallet, no consensus authority. */
class RouterCache {
    std::map<std::string, SignedRecordHint> m_by_id;
    size_t m_max{4096};

public:
    bool Insert(const SignedRecordHint& rec, int64_t now, std::string& err);
    std::vector<SignedRecordHint> LookupExact(const Digest48& id, int64_t now) const;
    void Expire(int64_t now);
    size_t Size() const { return m_by_id.size(); }
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_ROUTER_H
