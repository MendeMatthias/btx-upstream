// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RELEASE_H
#define BITCOIN_MODELNET_RELEASE_H

#include <modelnet/types.h>
#include <span.h>

#include <string>
#include <vector>

namespace modelnet {

/** Campaign coordination only. Monetary claim/refund uses 0.34.6 htlc_sha256 + buildhtlcclaim/buildhtlcrefund. */
struct ReleaseCampaign {
    Digest48 release_id;
    Digest48 model_id;
    Digest48 artifact_id;
    Hash32 key_hash; // SHA256(secret), never HASH160
    int64_t target_atoms{0};
    int64_t pledged_atoms{0};
    uint32_t refund_height{0};
    uint32_t latest_funding_height{0};
    bool frozen{false};
    bool secret_disclosed{false};
    bool plaintext_verified{false};
};

Hash32 ReleaseHash(Span<const unsigned char> secret32);
bool ValidRefundWindow(uint32_t latest_funding, uint32_t min_conf, uint32_t claim_margin, uint32_t refund_height);

} // namespace modelnet

#endif // BITCOIN_MODELNET_RELEASE_H
