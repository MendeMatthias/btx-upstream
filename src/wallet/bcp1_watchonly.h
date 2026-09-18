// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_BCP1_WATCHONLY_H
#define BITCOIN_WALLET_BCP1_WATCHONLY_H

#include <cstdint>

class ArgsManager;
class UniValue;
struct bilingual_str;

namespace wallet {
class CWallet;

/**
 * BCP/1 exchange watch-only helpers.
 *
 * No new wallet-flag bit is added. Upper-section flags (bit 32+) are
 * mandatory: an unknown bit makes LoadWalletFlags fail, and InitWalletFlags
 * asserts every high bit is in KNOWN_WALLET_FLAGS (wallet.h). A new bit
 * would break serialization/load unless wallet.h is updated in lockstep.
 *
 * The persisted profile is the existing pair
 * WALLET_FLAG_DISABLE_PRIVATE_KEYS + WALLET_FLAG_EXTERNAL_SIGNER (plus
 * WALLET_FLAG_DESCRIPTORS). A disable_private_keys descriptor wallet
 * without EXTERNAL_SIGNER is the imported-deposit-pool path.
 *
 * Node arg (already registered in wallet/init.cpp): -exchange-watchonly
 */

inline constexpr const char* EXCHANGE_WATCHONLY_ARG = "-exchange-watchonly";

bool ExchangeWatchOnlyNodeEnabled(const ArgsManager& args);

/**
 * Create-wallet flags implied by -exchange-watchonly.
 * Always: DISABLE_PRIVATE_KEYS | DESCRIPTORS | BLANK_WALLET.
 * If -signer is set: also EXTERNAL_SIGNER (signer descriptors replace blank).
 */
uint64_t ExchangeWatchOnlyCreateFlags(const ArgsManager& args);

/** OR ExchangeWatchOnlyCreateFlags into create_flags. */
void ApplyExchangeWatchOnlyCreateFlags(uint64_t& create_flags, const ArgsManager& args);

/**
 * ParameterInteraction helper. Returns false (with err) if -exchange-watchonly
 * is combined with -disablewallet. No-op success when the arg is unset.
 */
bool ApplyExchangeWatchOnlyArgs(const ArgsManager& args, bilingual_str& err);

/**
 * Call after CWallet::Create when -exchange-watchonly is set.
 * Requires descriptor + disable_private_keys and no embedded PQ master seeds.
 */
bool EnsureExchangeWatchOnly(const CWallet& wallet, bilingual_str& err);
bool EnsureExchangeWatchOnly(const CWallet& wallet, const ArgsManager& args, bilingual_str& err);

/** True if this wallet is in the BCP/1 exchange watch-only profile, or the node arg is set. */
bool ExchangeWatchOnlyActive(const CWallet& wallet);

/**
 * True if signing (or dumping) with wallet-resident keys must fail.
 * Callers throw RPC_WALLET_ERROR with err.original.
 */
bool RefusePrivateSign(const CWallet& wallet, bilingual_str& err);

/**
 * Import a pre-generated P2MR address / pubkey pool into a watch-only
 * descriptor wallet. ML-DSA cannot do non-hardened public children, so
 * this is the watch-only deposit path (not a fake xpub).
 *
 * `addresses_or_pubkeys` is an array of:
 *   - P2MR address strings
 *   - ML-DSA-44 or SLH-DSA pubkey hex (SLH may be pk_slh(hex))
 *   - public descriptors (addr(...) / mr(...) with explicit pubkeys)
 *   - objects: {address|pubkey|desc, label?, index?}
 *
 * Refuses any private material (WIF, xprv, PQ seed, secret-key hex,
 * pqhd(seed)). Does not rescan; the RPC layer does.
 */
bool ImportDepositPool(CWallet& wallet, const UniValue& addresses_or_pubkeys, bilingual_str& err);
bool ImportDepositPool(CWallet& wallet, const UniValue& addresses_or_pubkeys, bilingual_str& err, UniValue& details);

} // namespace wallet

#endif // BITCOIN_WALLET_BCP1_WATCHONLY_H
