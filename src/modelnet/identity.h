// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_IDENTITY_H
#define BITCOIN_MODELNET_IDENTITY_H

#include <modelnet/types.h>
#include <span.h>

#include <array>
#include <string>
#include <vector>

namespace modelnet {

constexpr size_t MLDSA44_PK = 1312;
constexpr size_t MLDSA44_SK = 2560;
constexpr size_t MLDSA44_SIG = 2420;

enum class IdentityClass : uint8_t {
    RESEARCH_PUBLISHER = 1,
    SERVICE_PROVIDER = 2,
    TRANSPORT_EPHEMERAL = 3,
    MONETARY_WALLET = 4, // never used as model identity material
    RELEASE_SECRET = 5,
};

struct ModelIdentity {
    IdentityClass cls{IdentityClass::RESEARCH_PUBLISHER};
    std::vector<unsigned char> pubkey; // 1312
    Digest48 id;
    std::string local_label;
    bool explicitly_trusted{false};
};

bool GenerateMlDsa44(std::vector<unsigned char>& pk, std::vector<unsigned char>& sk, std::string& err);
bool SignMlDsa44(Span<const unsigned char> sk, Span<const unsigned char> msg, std::vector<unsigned char>& sig, std::string& err);
bool VerifyMlDsa44(Span<const unsigned char> pk, Span<const unsigned char> msg, Span<const unsigned char> sig);
Digest48 PublisherId(Span<const unsigned char> pubkey);

} // namespace modelnet

#endif // BITCOIN_MODELNET_IDENTITY_H
