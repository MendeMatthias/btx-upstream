// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_HELLO_CAPS_H
#define BITCOIN_MODELNET_HELLO_CAPS_H

#include <univalue.h>

#include <string>

namespace modelnet {

UniValue HelloCapabilityArray();
bool HelloHasCapability(const UniValue& hello, const std::string& name);

} // namespace modelnet

#endif // BITCOIN_MODELNET_HELLO_CAPS_H
