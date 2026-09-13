// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/release.h>

#include <modelnet/crypto.h>

namespace modelnet {

Hash32 ReleaseHash(Span<const unsigned char> secret32)
{
    return Sha256(secret32);
}

bool ValidRefundWindow(uint32_t latest_funding, uint32_t min_conf, uint32_t claim_margin, uint32_t refund_height)
{
    if (!(latest_funding > 0 && latest_funding < refund_height && refund_height < 500000000u)) return false;
    return latest_funding + min_conf + claim_margin < refund_height;
}

} // namespace modelnet
