// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/qualification.h>

#include <crypto/common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstring>
#include <set>

namespace modelnet {

const char* QualResultName(QualResult r)
{
    switch (r) {
    case QualResult::STRUCTURE_VERIFIED: return "STRUCTURE_VERIFIED";
    case QualResult::PROFILE_VERIFIED: return "PROFILE_VERIFIED";
    case QualResult::RUNTIME_OBSERVED: return "RUNTIME_OBSERVED";
    case QualResult::INVALID_MODEL: return "INVALID_MODEL";
    case QualResult::NOT_RUN_RESOURCE_LIMIT: return "NOT_RUN_RESOURCE_LIMIT";
    case QualResult::REJECTED_UNSAFE_FORMAT: return "REJECTED_UNSAFE_FORMAT";
    case QualResult::ENCRYPTED_UNQUALIFIED: return "ENCRYPTED_UNQUALIFIED";
    }
    return "UNKNOWN";
}

bool LooksLikePickle(Span<const unsigned char> bytes)
{
    if (bytes.size() < 2) return false;
    // Protocol 2/3/4 pickle opcodes start with 0x80 then a version byte.
    return bytes[0] == 0x80 && bytes[1] <= 5;
}

bool LooksLikeExecutable(const std::string& filename_hint, Span<const unsigned char> bytes)
{
    const auto lower = ToLower(filename_hint);
    if (lower.ends_with(".pt") || lower.ends_with(".pth") || lower.ends_with(".pkl") ||
        lower.ends_with(".py") || lower.ends_with(".so") || lower.ends_with(".dll") ||
        lower.ends_with(".ipynb") || lower.ends_with(".sh") || lower.ends_with(".cu")) {
        return true;
    }
    if (bytes.size() >= 4 && bytes[0] == 0x7f && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F') return true;
    if (bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z') return true;
    return LooksLikePickle(bytes);
}

namespace {

constexpr uint64_t MAX_ST_HEADER = 8ULL << 20;
constexpr uint64_t MAX_TENSORS = 200000;

QualResult QualifySafeTensors(Span<const unsigned char> bytes, QualReport& report)
{
    if (bytes.size() < 8) {
        report.detail = "truncated safetensors";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    const uint64_t hlen = ReadLE64(bytes.data());
    report.header_bytes = hlen;
    if (hlen == 0 || hlen > MAX_ST_HEADER || 8 + hlen > bytes.size()) {
        report.detail = "safetensors header size";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    std::string json(reinterpret_cast<const char*>(bytes.data() + 8), hlen);
    if (json.find('\0') != std::string::npos) {
        report.detail = "NUL in header";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    UniValue header;
    if (!header.read(json) || !header.isObject()) {
        report.detail = "safetensors header json";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    uint64_t tensors = 0;
    uint64_t max_end = 8 + hlen;
    static const std::set<std::string> dtypes{"F32", "F16", "BF16", "F64", "I8", "I16", "I32", "I64", "U8", "U16", "U32", "U64", "BOOL", "F8_E4M3", "F8_E5M2"};
    for (const auto& key : header.getKeys()) {
        if (key == "__metadata__") continue;
        ++tensors;
        const UniValue& t = header[key];
        if (!t.isObject() || !t.exists("dtype") || !t.exists("shape") || !t.exists("data_offsets")) {
            report.detail = "tensor missing fields";
            report.result = QualResult::INVALID_MODEL;
            return report.result;
        }
        if (!t["dtype"].isStr() || !dtypes.count(t["dtype"].get_str())) {
            report.detail = "unsupported dtype";
            report.result = QualResult::INVALID_MODEL;
            return report.result;
        }
        if (!t["shape"].isArray() || t["data_offsets"].size() != 2) {
            report.detail = "tensor geometry";
            report.result = QualResult::INVALID_MODEL;
            return report.result;
        }
        uint64_t numel = 1;
        for (const auto& d : t["shape"].getValues()) {
            const uint64_t dim = d.getInt<uint64_t>();
            if (dim > 0 && numel > (UINT64_MAX / dim)) {
                report.detail = "shape overflow";
                report.result = QualResult::INVALID_MODEL;
                return report.result;
            }
            numel *= dim;
        }
        const uint64_t begin = t["data_offsets"][0].getInt<uint64_t>();
        const uint64_t end = t["data_offsets"][1].getInt<uint64_t>();
        if (end < begin || 8 + hlen + end > bytes.size()) {
            report.detail = "tensor offset";
            report.result = QualResult::INVALID_MODEL;
            return report.result;
        }
        max_end = std::max(max_end, 8 + hlen + end);
    }
    report.tensor_count = tensors;
    if (tensors > MAX_TENSORS) {
        report.detail = "too many tensors";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    if (max_end != bytes.size()) {
        report.detail = "trailing or missing tensor bytes";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    report.result = QualResult::STRUCTURE_VERIFIED;
    report.level = AdmissionLevel::STRUCTURE_VERIFIED;
    report.detail = "safetensors structure ok; not a claim of safety or usefulness";
    return report.result;
}

QualResult QualifyGGUF(Span<const unsigned char> bytes, QualReport& report)
{
    if (bytes.size() < 24) {
        report.detail = "truncated gguf";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    if (std::memcmp(bytes.data(), "GGUF", 4) != 0) {
        report.detail = "not gguf";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    const uint32_t version = ReadLE32(bytes.data() + 4);
    if (version < 1 || version > 3) {
        report.detail = "unsupported gguf version";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    const uint64_t n_tensors = ReadLE64(bytes.data() + 8);
    const uint64_t n_kv = ReadLE64(bytes.data() + 16);
    report.tensor_count = n_tensors;
    if (n_tensors > MAX_TENSORS || n_kv > 1024) {
        report.detail = "gguf counts";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    report.result = QualResult::STRUCTURE_VERIFIED;
    report.level = AdmissionLevel::STRUCTURE_VERIFIED;
    report.detail = "gguf magic/version/counts ok; tensor inventory not profile-matched";
    return report.result;
}

} // namespace

QualResult QualifyBytes(const std::string& filename_hint, Span<const unsigned char> bytes, QualReport& report)
{
    report = {};
    if (LooksLikeExecutable(filename_hint, bytes)) {
        report.result = QualResult::REJECTED_UNSAFE_FORMAT;
        report.detail = "rejected pickle/executable/script format";
        report.level = AdmissionLevel::FAILED;
        return report.result;
    }
    const auto lower = ToLower(filename_hint);
    if (bytes.size() >= 8 && std::memcmp(bytes.data(), "BTXENC2", 7) == 0) {
        report.result = QualResult::ENCRYPTED_UNQUALIFIED;
        report.level = AdmissionLevel::ENCRYPTED_UNQUALIFIED;
        report.detail = "ciphertext only; not a plaintext model check";
        return report.result;
    }
    if (lower.ends_with(".safetensors") || (bytes.size() >= 8 && bytes[0] < 8 && bytes[1] == 0)) {
        return QualifySafeTensors(bytes, report);
    }
    if (lower.ends_with(".gguf") || (bytes.size() >= 4 && std::memcmp(bytes.data(), "GGUF", 4) == 0)) {
        return QualifyGGUF(bytes, report);
    }
    report.result = QualResult::REJECTED_UNSAFE_FORMAT;
    report.detail = "unsupported model container";
    report.level = AdmissionLevel::FAILED;
    return report.result;
}

} // namespace modelnet
