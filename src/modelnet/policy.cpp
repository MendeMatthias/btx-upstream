// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/policy.h>

#include <algorithm>
#include <stdexcept>

namespace modelnet {

bool ChoosePlan(RetrievalMode mode,
                const std::optional<int>& free_eta_s,
                const PaidPlan* paid,
                int64_t budget_atoms,
                bool exposure_ok,
                const std::optional<int>& deadline_s,
                int64_t value_per_second_atoms,
                bool approved,
                PlanChoice& out,
                std::string& err)
{
    if (budget_atoms < 0 || value_per_second_atoms < 0) {
        err = "invalid policy amount";
        return false;
    }
    auto check_dur = [&](const std::optional<int>& d) {
        return !d || *d >= 0;
    };
    if (!check_dur(free_eta_s) || !check_dur(deadline_s) || (paid && paid->total_eta_s && *paid->total_eta_s < 0)) {
        err = "invalid ETA/deadline";
        return false;
    }
    if (mode == RetrievalMode::FREE_ONLY) {
        out = free_eta_s ? PlanChoice::FREE : PlanChoice::WAIT_FREE;
        return true;
    }
    if (!paid || !paid->safe || !paid->deliverable || paid->requires_release) {
        out = free_eta_s ? PlanChoice::FREE : PlanChoice::WAIT_FREE;
        return true;
    }
    if (paid->price_atoms < 0 || paid->fee_atoms < 0) {
        err = "bad price";
        return false;
    }
    const int64_t cost = paid->price_atoms + paid->fee_atoms;
    if (cost > MAX_MONEY_ATOMS || !exposure_ok) {
        out = free_eta_s ? PlanChoice::FREE : PlanChoice::WAIT_FREE;
        return true;
    }
    if (mode == RetrievalMode::EXPLICIT_PAID) {
        out = (approved && cost <= budget_atoms) ? PlanChoice::PAID : PlanChoice::APPROVAL_REQUIRED;
        return true;
    }
    const auto t = paid->total_eta_s;
    const bool saves = free_eta_s && t && *free_eta_s > *t;
    const bool missing = !free_eta_s && t;
    const bool deadline_gain = deadline_s && t && *t <= *deadline_s && (!free_eta_s || *free_eta_s > *deadline_s);
    const bool economical = saves && value_per_second_atoms * static_cast<int64_t>(*free_eta_s - *t) >= cost;
    const bool worthwhile = missing || deadline_gain || economical;
    if (!worthwhile) {
        out = free_eta_s ? PlanChoice::FREE : PlanChoice::WAIT_FREE;
        return true;
    }
    if (mode == RetrievalMode::FREE_FIRST_APPROVAL) {
        out = (approved && cost <= budget_atoms) ? PlanChoice::PAID : PlanChoice::APPROVAL_REQUIRED;
        return true;
    }
    if (cost <= budget_atoms) out = PlanChoice::PAID;
    else out = free_eta_s ? PlanChoice::FREE : PlanChoice::WAIT_FREE;
    return true;
}

AclDecision DecideAcl(bool crypto_ok,
                       bool hard_limit_ok,
                       bool local_deny,
                       bool quarantined,
                       bool exact_allow,
                       bool subscribed_deny,
                       bool needs_spend,
                       bool budget_approved)
{
    if (!crypto_ok) return AclDecision::REJECT_CRYPTO;
    if (!hard_limit_ok) return AclDecision::RETRY_RESOURCE;
    if (local_deny) return AclDecision::DENY_LOCAL;
    if (quarantined) return AclDecision::QUARANTINE;
    if (subscribed_deny && !exact_allow) return AclDecision::DENY_SUBSCRIBED;
    if (needs_spend && !budget_approved) return AclDecision::REQUIRE_SPEND_APPROVAL;
    return AclDecision::ALLOW;
}

bool ReciprocityLedger::Received(const std::string& peer,
                                  const std::string& artifact,
                                  int file,
                                  int piece,
                                  int64_t nbytes,
                                  int64_t when,
                                  bool verified,
                                  bool needed,
                                  bool paid,
                                  int observed_sources)
{
    if (nbytes <= 0 || when < 0) throw std::runtime_error("invalid observation");
    const auto key = std::tuple<std::string, int, int>{artifact, file, piece};
    if (!verified || !needed || paid || m_seen.count(key)) return false;
    m_seen.insert(key);
    const int64_t bonus = (observed_sources == 1 || observed_sources == 2) ? 2 : 1;
    m_events.push_back({peer, nbytes * bonus, when});
    return true;
}

int64_t ReciprocityLedger::Effective(const std::string& peer, int64_t now) const
{
    int64_t total = 0;
    for (const auto& e : m_events) {
        const int64_t age = std::max<int64_t>(0, now - e.when);
        if (e.peer == peer && age < 28 * DAY_SECONDS) {
            total += e.bytes >> (age / (7 * DAY_SECONDS));
        }
    }
    return std::min<int64_t>(total, int64_t{4} << 30);
}

int ReciprocityLedger::Weight(const std::string& peer, int64_t now) const
{
    const int64_t units = std::min<int64_t>(64, Effective(peer, now) / static_cast<int64_t>(64 * MIB));
    return static_cast<int>(1 + (3 * units) / 64);
}

UniValue ReciprocityLedger::Snapshot() const
{
    UniValue obj(UniValue::VOBJ);
    UniValue events(UniValue::VARR);
    for (const auto& e : m_events) {
        UniValue ev(UniValue::VOBJ);
        ev.pushKV("peer", e.peer);
        ev.pushKV("bytes", e.bytes);
        ev.pushKV("when", e.when);
        events.push_back(ev);
    }
    obj.pushKV("events", events);
    return obj;
}

bool ReciprocityLedger::Load(const UniValue& obj, std::string& err)
{
    if (!obj.isObject() || !obj.exists("events") || !obj["events"].isArray()) {
        err = "invalid ledger snapshot";
        return false;
    }
    m_events.clear();
    m_seen.clear();
    for (const auto& ev : obj["events"].getValues()) {
        m_events.push_back({ev["peer"].get_str(), ev["bytes"].getInt<int64_t>(), ev["when"].getInt<int64_t>()});
    }
    return true;
}

std::vector<std::string> LaneSequence(const std::map<std::string, int>& backlogs, int quanta)
{
    std::map<std::string, int> b = backlogs;
    std::vector<std::string> out;
    static const std::vector<std::string> order{"bootstrap", "reciprocal", "reciprocal", "preservation", "reciprocal"};
    for (int i = 0; i < quanta; ++i) {
        const std::string& wanted = order[i % order.size()];
        std::vector<std::string> eligible;
        for (const auto& k : order) {
            if (b[k] > 0) eligible.push_back(k);
        }
        if (eligible.empty()) break;
        const std::string k = (b[wanted] > 0) ? wanted : eligible.front();
        out.push_back(k);
        b[k] -= 1;
    }
    return out;
}

TrustLabel ClassifyPeer(int64_t effective_bytes, int successful_sessions, int invalid_pieces, bool blocked, bool preferred, bool trusted)
{
    if (blocked) return TrustLabel::BLOCKED;
    if (trusted) return TrustLabel::TRUSTED;
    if (preferred) return TrustLabel::PREFERRED;
    if (invalid_pieces > 0 && successful_sessions == 0) return TrustLabel::OBSERVED;
    if (effective_bytes >= static_cast<int64_t>(64 * MIB) && successful_sessions >= 3) return TrustLabel::RELIABLE;
    if (effective_bytes > 0) return TrustLabel::RECIPROCAL;
    if (successful_sessions > 0) return TrustLabel::OBSERVED;
    return TrustLabel::NEW;
}

} // namespace modelnet
