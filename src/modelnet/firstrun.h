// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_FIRSTRUN_H
#define BITCOIN_MODELNET_FIRSTRUN_H

#include <modelnet/policy.h>
#include <util/fs.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Operator-consented first-run storage policy. Missing or zero budget stores no payload. */
struct FirstRunConsent {
    uint64_t storage_bytes{0};
    SeedMode seed{SeedMode::AUTO};
    bool preserve_rare{false};
    int64_t consented_unix{0};
};

/** `<datadir>/modelnet/firstrun.json`. Never under wallet/chainstate. */
fs::path FirstRunConsentPath(const fs::path& datadir);

bool LoadFirstRunConsent(const fs::path& path, FirstRunConsent& out, std::string& err);
bool SaveFirstRunConsent(const fs::path& path, const FirstRunConsent& in, std::string& err);

/** False when storage_bytes == 0 (fresh install / explicit no-payload). */
bool AllowPayloadStorage(const FirstRunConsent& in);
bool AllowPayloadStorageFile(const fs::path& path);

/** Same parser as -modelstorage / -modelcache (`80GiB`, raw bytes). */
bool ParseStorageBudget(const std::string& in, uint64_t& out, std::string& err);

/** `BTX_MODEL_STORAGE`. False if unset, empty, zero, or unparsable. */
bool EnvHasPositiveStorageBudget(uint64_t& bytes, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_FIRSTRUN_H
