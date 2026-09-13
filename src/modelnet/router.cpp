// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/router.h>

namespace modelnet {

bool RouterCache::Insert(const SignedRecordHint& rec, int64_t now, std::string& err)
{
    if (rec.expiry && rec.expiry < now) {
        err = "expired record";
        return false;
    }
    if (m_by_id.size() >= m_max) {
        Expire(now);
        if (m_by_id.size() >= m_max) {
            err = "router cache full";
            return false;
        }
    }
    m_by_id[rec.record_id.Hex()] = rec;
    return true;
}

std::vector<SignedRecordHint> RouterCache::LookupExact(const Digest48& id, int64_t now) const
{
    std::vector<SignedRecordHint> out;
    const auto it = m_by_id.find(id.Hex());
    if (it == m_by_id.end()) return out;
    if (it->second.expiry && it->second.expiry < now) return out;
    out.push_back(it->second);
    return out;
}

void RouterCache::Expire(int64_t now)
{
    for (auto it = m_by_id.begin(); it != m_by_id.end();) {
        if (it->second.expiry && it->second.expiry < now) it = m_by_id.erase(it);
        else ++it;
    }
}

} // namespace modelnet
