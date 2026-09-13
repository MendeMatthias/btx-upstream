// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/transfer.h>

namespace modelnet {

bool DuplicatePayment(const std::vector<PaymentJournal>& journal, const std::string& txid)
{
    for (const auto& e : journal) {
        if (e.txid == txid) return true;
    }
    return false;
}

} // namespace modelnet
