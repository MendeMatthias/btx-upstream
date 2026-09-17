// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PACKAGE_BUNDLE_H
#define BITCOIN_MODELNET_PACKAGE_BUNDLE_H

#include <span.h>
#include <univalue.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Binary .btxbundle framing. exportmodellink remains the JSON magnet analog. */
inline constexpr unsigned char BTXPKG_MAGIC[8] = {'B', 'T', 'X', 'P', 'K', 'G', 0x00, 0x01};

/**
 * This magic and the 68-byte header (magic[8] | flags LE32 | len LE64 |
 * SHA-384 of body[48]) are shared with EncodeBtxPackage/DecodeBtxPackage in
 * package_core.h. The bodies are NOT interchangeable: this pair writes
 * UniValue::write() JSON text, the package_core pair writes canonical
 * BTX-PJSON1. flags is 0 in both, so the header alone does not identify the
 * body encoding -- a caller must already know which framing it expects.
 * Do not "unify" by pointing one decoder at the other's bytes.
 */
bool EncodeBtxBundle(const UniValue& value, std::vector<unsigned char>& out, std::string& err);
bool DecodeBtxBundle(Span<const unsigned char> data, UniValue& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PACKAGE_BUNDLE_H
