// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_POLICY_H
#define BITCOIN_MODELNET_POLICY_H

#include <modelnet/types.h>

#include <univalue.h>

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace modelnet {

struct PaidPlan {
    int64_t price_atoms{0};
    int64_t fee_atoms{0};
    std::optional<int> total_eta_s;
    bool safe{true};
    bool deliverable{true};
    bool requires_release{false};
};

bool ChoosePlan(RetrievalMode mode,
                const std::optional<int>& free_eta_s,
                const PaidPlan* paid,
                int64_t budget_atoms,
                bool exposure_ok,
                const std::optional<int>& deadline_s,
                int64_t value_per_second_atoms,
                bool approved,
                PlanChoice& out,
                std::string& err);

AclDecision DecideAcl(bool crypto_ok,
                       bool hard_limit_ok,
                       bool local_deny,
                       bool quarantined,
                       bool exact_allow,
                       bool subscribed_deny,
                       bool needs_spend,
                       bool budget_approved);

/** Local reciprocity ledger. Not money, not consensus, not transferable. */
class ReciprocityLedger {
    struct Event {
        std::string peer;
        int64_t bytes{0};
        int64_t when{0};
    };
    std::vector<Event> m_events;
    std::set<std::tuple<std::string, int, int>> m_seen; // artifact,file,piece

public:
    bool Received(const std::string& peer,
                  const std::string& artifact,
                  int file,
                  int piece,
                  int64_t nbytes,
                  int64_t when,
                  bool verified,
                  bool needed,
                  bool paid,
                  int observed_sources);
    int64_t Effective(const std::string& peer, int64_t now) const;
    int Weight(const std::string& peer, int64_t now) const;
    UniValue Snapshot() const;
    bool Load(const UniValue& obj, std::string& err);
};

std::vector<std::string> LaneSequence(const std::map<std::string, int>& backlogs, int quanta);

struct ReciprocityStatus {
    TrustLabel label{TrustLabel::NEW};
    int weight{1};
    int64_t effective_bytes{0};
};

TrustLabel ClassifyPeer(int64_t effective_bytes, int successful_sessions, int invalid_pieces, bool blocked, bool preferred, bool trusted);

struct PreservationPolicy {
    bool seed_upon_download{false};
    double giveback_ratio{1.0};
    int64_t retain_seconds{7 * DAY_SECONDS};
    uint64_t storage_quota_bytes{0};
    uint64_t upload_bps{0};
    bool preserve_rare{false};
};

enum class EvictClass : uint8_t {
    EXPIRED_CIPHERTEXT = 0,
    UNPINNED_LRU = 1,
    PINNED = 2,
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_POLICY_H
