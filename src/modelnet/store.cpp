// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/store.h>

#include <modelnet/crypto.h>
#include <crypto/common.h>
#include <crypto/sha384.h>
#include <util/fs.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>
#include <regex>
#include <stdexcept>
#include <system_error>

namespace modelnet {
namespace {

fs::path ArtifactDir(const fs::path& root, const Digest48& artifact)
{
    return root / "artifacts" / artifact.Hex().c_str();
}

} // namespace

bool IsPortableRelPath(const std::string& path, std::string& err)
{
    static const std::regex re{R"(^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$)"};
    if (!std::regex_match(path, re) || path.size() > 240) {
        err = "unsafe path";
        return false;
    }
    static const std::set<std::string> reserved{"CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"};
    size_t start = 0;
    while (start < path.size()) {
        const size_t slash = path.find('/', start);
        const std::string part = path.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
        if (part == "." || part == ".." || (!part.empty() && part.back() == '.')) {
            err = "unsafe path";
            return false;
        }
        std::string stem = part;
        const auto dot = stem.find('.');
        if (dot != std::string::npos) stem = stem.substr(0, dot);
        for (char& c : stem) {
            if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
        }
        if (reserved.count(stem)) {
            err = "unsafe path";
            return false;
        }
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    return true;
}

Digest48 ChunkLeaf(uint64_t index, Span<const unsigned char> piece)
{
    std::vector<unsigned char> body(8 + 4 + piece.size());
    WriteLE64(body.data(), index);
    WriteLE32(body.data() + 8, static_cast<uint32_t>(piece.size()));
    if (!piece.empty()) memcpy(body.data() + 12, piece.data(), piece.size());
    return DomainHash("BTX/ModelChunk/v2", body);
}

Digest48 ChunkPad(uint64_t index)
{
    unsigned char buf[8];
    WriteLE64(buf, index);
    return DomainHash("BTX/ModelChunkPad/v2", Span<const unsigned char>{buf, 8});
}

Digest48 ChunkNode(const Digest48& left, const Digest48& right)
{
    unsigned char body[96];
    memcpy(body, left.data.data(), 48);
    memcpy(body + 48, right.data.data(), 48);
    return DomainHash("BTX/ModelChunkNode/v2", Span<const unsigned char>{body, 96});
}

Digest48 EmptyFileRoot()
{
    return DomainHash("BTX/ModelEmpty/v2", Span<const unsigned char>{});
}

std::vector<std::vector<Digest48>> BuildChunkTree(Span<const unsigned char> file)
{
    if (file.empty()) return {{EmptyFileRoot()}};
    const size_t n = (file.size() + PIECE_SIZE - 1) / PIECE_SIZE;
    size_t width = 1;
    while (width < n) width <<= 1;
    std::vector<Digest48> leaves;
    leaves.reserve(width);
    for (size_t i = 0; i < n; ++i) {
        const size_t off = i * PIECE_SIZE;
        const size_t len = std::min(PIECE_SIZE, file.size() - off);
        leaves.push_back(ChunkLeaf(i, Span<const unsigned char>{file.data() + off, len}));
    }
    for (size_t i = n; i < width; ++i) leaves.push_back(ChunkPad(i));
    std::vector<std::vector<Digest48>> rows;
    rows.push_back(std::move(leaves));
    while (rows.back().size() > 1) {
        const auto& r = rows.back();
        std::vector<Digest48> next;
        next.reserve(r.size() / 2);
        for (size_t i = 0; i < r.size(); i += 2) {
            next.push_back(ChunkNode(r[i], r[i + 1]));
        }
        rows.push_back(std::move(next));
    }
    return rows;
}

std::vector<Digest48> PieceProof(const std::vector<std::vector<Digest48>>& rows, uint64_t index)
{
    std::vector<Digest48> result;
    uint64_t i = index;
    for (size_t level = 0; level + 1 < rows.size(); ++level) {
        result.push_back(rows[level][i ^ 1]);
        i /= 2;
    }
    return result;
}

bool VerifyPiece(const Digest48& root, uint64_t file_size, uint64_t index,
                  Span<const unsigned char> piece,
                  const std::vector<Digest48>& siblings)
{
    if (file_size == 0 || file_size > MAX_FILE_BYTES) return false;
    const uint64_t n = (file_size + PIECE_SIZE - 1) / PIECE_SIZE;
    if (index >= n) return false;
    const uint64_t expected_len = std::min<uint64_t>(PIECE_SIZE, file_size - index * PIECE_SIZE);
    if (piece.size() != expected_len) return false;
    size_t width_bits = 0;
    uint64_t tmp = n - 1;
    while (tmp) {
        ++width_bits;
        tmp >>= 1;
    }
    if (siblings.size() != width_bits) return false;
    Digest48 v = ChunkLeaf(index, piece);
    for (size_t level = 0; level < siblings.size(); ++level) {
        if ((index >> level) & 1) {
            v = ChunkNode(siblings[level], v);
        } else {
            v = ChunkNode(v, siblings[level]);
        }
    }
    return v == root;
}

ModelStore::ModelStore(fs::path root, uint64_t quota_bytes) : m_root(std::move(root))
{
    m_quota.max_bytes = quota_bytes;
    fs::create_directories(m_root / "artifacts");
    fs::create_directories(m_root / "tmp");
}

bool ModelStore::PutVerifiedPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                     Span<const unsigned char> bytes, const Digest48& expected_leaf, std::string& err)
{
    if (ChunkLeaf(piece_index, bytes) != expected_leaf) {
        err = "corrupt chunk";
        return false;
    }
    if (m_quota.max_bytes && m_quota.used_bytes + bytes.size() > m_quota.max_bytes) {
        err = "disk quota";
        return false;
    }
    const fs::path dir = ArtifactDir(m_root, artifact) / std::to_string(file_index).c_str();
    fs::create_directories(dir);
    const fs::path final_path = dir / (std::to_string(piece_index) + ".piece").c_str();
    const fs::path tmp = m_root / "tmp" / (artifact.Hex() + "-" + std::to_string(file_index) + "-" + std::to_string(piece_index) + ".tmp").c_str();
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            err = "tmp write failed";
            return false;
        }
        if (!bytes.empty()) out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        out.flush();
        if (!out) {
            err = "tmp write failed";
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, final_path, ec);
    if (ec) {
        err = "atomic rename failed";
        return false;
    }
    m_quota.used_bytes += bytes.size();
    return true;
}

bool ModelStore::GetPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                            std::vector<unsigned char>& out, std::string& err) const
{
    const fs::path path = ArtifactDir(m_root, artifact) / std::to_string(file_index).c_str() /
                           (std::to_string(piece_index) + ".piece").c_str();
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "missing piece";
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

bool ModelStore::Pin(const Digest48& model_id, std::string& err)
{
    (void)err;
    m_pinned.insert(model_id.Hex());
    return true;
}

bool ModelStore::Unpin(const Digest48& model_id)
{
    return m_pinned.erase(model_id.Hex()) > 0;
}

void ModelStore::EvictUnpinned()
{
    // Pinned models are never deleted here. Unpinned LRU is a follow-up journal.
}

} // namespace modelnet
