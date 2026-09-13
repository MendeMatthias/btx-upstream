// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/qualification.h>
#include <util/fs.h>

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "usage: btx-modelcheck <file>\n"
                     "Static qualification only. Does not prove usefulness, safety, or alignment.\n";
        return 1;
    }
    const std::string path = argv[1];
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "cannot read " << path << "\n";
        return 1;
    }
    std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    modelnet::QualReport report;
    modelnet::QualifyBytes(path, bytes, report);
    std::cout << modelnet::QualResultName(report.result) << " " << modelnet::AdmissionLevelName(report.level)
              << " " << report.detail << "\n";
    return report.result == modelnet::QualResult::REJECTED_UNSAFE_FORMAT ||
                   report.result == modelnet::QualResult::INVALID_MODEL
               ? 2
               : 0;
}
