// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_TRANSFER_H
#define BITCOIN_MODELNET_TRANSFER_H

#include <modelnet/types.h>

#include <string>
#include <vector>

namespace modelnet {

struct Quote {
    Digest48 offer_id;
    Digest48 provider_id;
    Digest48 buyer_id;
    Digest48 model_id;
    Digest48 artifact_id;
    uint32_t file_index{0};
    uint32_t first_piece{0};
    uint32_t piece_count{0};
    uint64_t maximum_bytes{0};
    int64_t price_atoms{0};
    int64_t fee_cap_atoms{0};
    int64_t expires_at{0};
};

struct PaymentJournal {
    std::string quote_id;
    std::string txid;
    bool accepted{false};
    bool delivered{false};
};

bool DuplicatePayment(const std::vector<PaymentJournal>& journal, const std::string& txid);

} // namespace modelnet

#endif // BITCOIN_MODELNET_TRANSFER_H
