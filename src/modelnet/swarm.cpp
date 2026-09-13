// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm.h>

namespace modelnet {

HybridPlan PlanRetrieval(const std::vector<PieceNeed>& missing,
                          const std::vector<SourceOffer>& sources,
                          RetrievalMode mode,
                          int64_t budget_atoms,
                          bool approved)
{
    HybridPlan plan;
    bool have_free = false;
    bool have_paid = false;
    for (const auto& s : sources) {
        if (!s.available) continue;
        if (!s.paid) have_free = true;
        else have_paid = true;
    }
    for (const auto& p : missing) {
        if (p.verified) continue;
        if (have_free) {
            plan.free_pieces.push_back(p);
        } else if (have_paid && mode != RetrievalMode::FREE_ONLY &&
                   (approved || mode == RetrievalMode::FREE_FIRST_BUDGET) && budget_atoms > 0) {
            plan.paid_pieces.push_back(p);
        } else {
            plan.free_pieces.push_back(p);
        }
    }
    if (!approved && mode != RetrievalMode::FREE_FIRST_BUDGET) {
        plan.paid_pieces.clear();
        plan.paid_atoms = 0;
    }
    for (const auto& s : sources) {
        if (s.paid && s.available) plan.paid_atoms += s.price_atoms;
    }
    if (plan.paid_atoms > budget_atoms) {
        plan.paid_pieces.clear();
        plan.paid_atoms = 0;
    }
    return plan;
}

} // namespace modelnet
