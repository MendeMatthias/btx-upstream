// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/identity.h>

#include <modelnet/crypto.h>
extern "C" {
#include <libbitcoinpqc/ml_dsa.h>
}
#include <random.h>
#include <support/cleanse.h>

#include <algorithm>

namespace modelnet {

namespace {
void FillStrong(unsigned char* out, size_t n)
{
    while (n > 0) {
        const size_t chunk = std::min(n, size_t{32});
        GetStrongRandBytes(Span<unsigned char>{out, chunk});
        out += chunk;
        n -= chunk;
    }
}
} // namespace

bool GenerateMlDsa44(std::vector<unsigned char>& pk, std::vector<unsigned char>& sk, std::string& err)
{
    pk.assign(ML_DSA_44_PUBLIC_KEY_SIZE, 0);
    sk.assign(ML_DSA_44_SECRET_KEY_SIZE, 0);
    unsigned char rnd[128];
    FillStrong(rnd, sizeof(rnd));
    if (ml_dsa_44_keygen(pk.data(), sk.data(), rnd, sizeof(rnd)) != 0) {
        err = "ml-dsa-44 keygen failed";
        memory_cleanse(rnd, sizeof(rnd));
        return false;
    }
    memory_cleanse(rnd, sizeof(rnd));
    return true;
}

bool SignMlDsa44(Span<const unsigned char> sk, Span<const unsigned char> msg, std::vector<unsigned char>& sig, std::string& err)
{
    if (sk.size() != ML_DSA_44_SECRET_KEY_SIZE) {
        err = "bad secret key";
        return false;
    }
    sig.assign(ML_DSA_44_SIGNATURE_SIZE, 0);
    size_t siglen = sig.size();
    if (ml_dsa_44_sign(sig.data(), &siglen, msg.data(), msg.size(), sk.data()) != 0) {
        err = "ml-dsa-44 sign failed";
        return false;
    }
    sig.resize(siglen);
    return true;
}

bool VerifyMlDsa44(Span<const unsigned char> pk, Span<const unsigned char> msg, Span<const unsigned char> sig)
{
    if (pk.size() != ML_DSA_44_PUBLIC_KEY_SIZE) return false;
    return ml_dsa_44_verify(sig.data(), sig.size(), msg.data(), msg.size(), pk.data()) == 0;
}

Digest48 PublisherId(Span<const unsigned char> pubkey)
{
    return DomainHash("BTX/ModelPublisherId/v1.1", pubkey);
}

} // namespace modelnet
