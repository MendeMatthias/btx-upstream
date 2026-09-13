// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_QUALIFICATION_H
#define BITCOIN_MODELNET_QUALIFICATION_H

#include <modelnet/types.h>
#include <span.h>

#include <string>
#include <vector>

namespace modelnet {

enum class QualResult : uint8_t {
    STRUCTURE_VERIFIED = 0,
    PROFILE_VERIFIED = 1,
    RUNTIME_OBSERVED = 2,
    INVALID_MODEL = 3,
    NOT_RUN_RESOURCE_LIMIT = 4,
    REJECTED_UNSAFE_FORMAT = 5,
    ENCRYPTED_UNQUALIFIED = 6,
};

const char* QualResultName(QualResult r);

struct QualReport {
    QualResult result{QualResult::INVALID_MODEL};
    std::string detail;
    AdmissionLevel level{AdmissionLevel::FAILED};
    uint64_t header_bytes{0};
    uint64_t tensor_count{0};
};

/** Static SafeTensors / GGUF checks. Never executes Pickle, .pt, Python, or CUDA kernels. */
QualResult QualifyBytes(const std::string& filename_hint, Span<const unsigned char> bytes, QualReport& report);

bool LooksLikePickle(Span<const unsigned char> bytes);
bool LooksLikeExecutable(const std::string& filename_hint, Span<const unsigned char> bytes);

} // namespace modelnet

#endif // BITCOIN_MODELNET_QUALIFICATION_H
