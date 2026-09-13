// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/http_bridge.h>
#include <modelnet/qualification.h>
#include <modelnet/resource_uri.h>
#include <modelnet/transport_pq.h>

#include <iostream>
#include <string>

static void Usage()
{
    std::cerr <<
        "btx-modeld — BTX Native Model Network helper (0.34.7)\n"
        "\n"
        "Inference is local after a model is acquired. This process is not a remote\n"
        "inference marketplace and has no monetary consensus authority.\n"
        "\n"
        "  -decode=<uri>   decode a btx:// resource and exit\n"
        "  -modelrelay      CPU-only discovery relay (no GPU, no wallet)\n"
        "  -help            print this message\n";
}

int main(int argc, char* argv[])
{
    bool relay = false;
    std::string decode;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "-help" || a == "-h" || a == "--help") {
            Usage();
            return 0;
        }
        if (a == "-modelrelay") relay = true;
        else if (a.rfind("-decode=", 0) == 0) decode = a.substr(8);
        else if (a == "-decode" && i + 1 < argc) decode = argv[++i];
        else {
            std::cerr << "unknown argument: " << a << "\n";
            Usage();
            return 1;
        }
    }
    if (!decode.empty()) {
        modelnet::Resource r;
        std::string err;
        if (!modelnet::DecodeResource(decode, r, err)) {
            std::cerr << err << "\n";
            return 1;
        }
        std::cout << r.Uri() << " " << modelnet::ResourceKindName(r.kind) << " " << r.digest.Hex() << "\n";
        return 0;
    }

    modelnet::Pq1Context pq;
    if (!pq.Ready()) {
        std::cerr << "model subsystem fail-closed: strict PQ1 unavailable: " << pq.Error() << "\n";
        std::cerr << "monetary BTX remains independently operational.\n";
        return 2;
    }
    std::cout << "btx-modeld: PQ1 context ready; default automatic spend is 0; store quota 0 until allocated.\n";
    if (relay) {
        std::cout << "relay mode: CPU-only introduction; no GPU qualification; no wallet; coverage=incomplete.\n";
    }
    return 0;
}
