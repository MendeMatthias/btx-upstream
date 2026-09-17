// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Cognitive Reserve Layer v1.2 helpers. Same HcpEngine; not a second product.

#include <modelnet/hcp.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>

namespace modelnet {

bool Crl12BrandDispatch(const std::string& s)
{
    std::string l;
    l.reserve(s.size());
    for (unsigned char c : s) l.push_back(static_cast<char>(std::tolower(c)));
    static const char* k[] = {"goldman", "blackrock", "coinbase", "binance", "kraken", "fidelity",
                              "jpmorgan", "j.p. morgan", "morgan stanley", "citadel", "bridgewater"};
    for (const char* b : k) {
        if (l.find(b) != std::string::npos) return true;
    }
    return false;
}

bool Crl12FiniteDecimal(const std::string& s, std::string& err)
{
    err.clear();
    if (s.empty()) {
        err = HCP_ERR_NONFINITE;
        return false;
    }
    std::string l;
    for (unsigned char c : s) l.push_back(static_cast<char>(std::tolower(c)));
    if (l.find("nan") != std::string::npos || l.find("inf") != std::string::npos) {
        err = HCP_ERR_NONFINITE;
        return false;
    }
    size_t i = 0;
    if (s[i] == '+' || s[i] == '-') ++i;
    if (i >= s.size()) {
        err = HCP_ERR_NONFINITE;
        return false;
    }
    bool digit = false, dot = false;
    for (; i < s.size(); ++i) {
        if (s[i] >= '0' && s[i] <= '9') {
            digit = true;
            continue;
        }
        if (s[i] == '.' && !dot) {
            dot = true;
            continue;
        }
        err = HCP_ERR_NONFINITE;
        return false;
    }
    if (!digit) {
        err = HCP_ERR_NONFINITE;
        return false;
    }
    return true;
}

bool Crl12MetricEligible(const std::string& metric_kind, const std::string& mandate, const std::string& asset_kind)
{
    if (asset_kind == "CAPABILITY" || asset_kind == "UTILITY") {
        return metric_kind == "CAPABILITY_COUNT" || metric_kind == "SCENARIO_VALUE";
    }
    if (metric_kind == "AUM") return mandate == "MANAGED";
    if (metric_kind == "AUC") return mandate == "CUSTODY";
    if (metric_kind == "AUA") return mandate == "ADMIN";
    if (metric_kind == "PLATFORM_ASSETS") return mandate == "ADMIN" || mandate == "PLATFORM";
    if (metric_kind == "FINANCIAL_NAV") return mandate == "MANAGED" || mandate == "CUSTODY" || mandate == "OWNER";
    if (metric_kind == "ACTUAL_COST") return mandate == "MANAGED" || mandate == "OWNER";
    if (metric_kind == "CAPABILITY_COUNT") return asset_kind == "CAPABILITY";
    return false;
}

bool Crl12CsvSafe(const std::string& cell, std::string& out)
{
    out = cell;
    if (cell.empty()) return true;
    const char c = cell[0];
    if (c == '=' || c == '+' || c == '-' || c == '@' || c == '\t') {
        out = "'" + cell;
    }
    return true;
}

} // namespace modelnet
