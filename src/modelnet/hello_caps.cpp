// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/hello_caps.h>

#include <modelnet/file_stream.h>
#include <modelnet/subpiece.h>

namespace modelnet {

UniValue HelloCapabilityArray()
{
    UniValue a(UniValue::VARR);
    for (const char* c : {
             FULL_FILE_STREAM_V1,
             SUBPIECE_V1,
             "SELECTIVE_FILES_V1",
             "ORIGIN_OFFER_V1",
             "FULL_ORIGIN_INGEST_V1",
             "ERASURE_PRESERVATION_V1",
             "QUERY_SUMMARY_V1",
             "INDEX_RECONCILE_V1",
             "METADATA_GOSSIP_V1",
             "PACKAGE_V1",
             "BTXPKG_CORE_V2",
             "AGENT_HANDOFF_V1",
             "BTXPKG_CORE_V3",
             "CAPABILITY_HANDOFF_V1",
             "LAN_DISCOVERY_V1",
         }) {
        a.push_back(c);
    }
    return a;
}

bool HelloHasCapability(const UniValue& hello, const std::string& name)
{
    if (!hello.isObject()) return false;
    if (name == FULL_FILE_STREAM_V1 && hello.exists("full_file_stream_v1") && hello["full_file_stream_v1"].isTrue()) {
        return true;
    }
    if (hello.exists("capability") && hello["capability"].isStr() && hello["capability"].get_str() == name) {
        return true;
    }
    if (hello.exists("capabilities") && hello["capabilities"].isArray()) {
        for (const auto& c : hello["capabilities"].getValues()) {
            if (c.isStr() && c.get_str() == name) return true;
        }
    }
    return false;
}

} // namespace modelnet
