// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/common.h>
#include <crypto/sha384.h>
#include <modelnet/firstrun.h>
#include <modelnet/package_bundle.h>
#include <modelnet/package_core.h>
#include <modelnet/package_documents.h>
#include <modelnet/package_export.h>
#include <modelnet/resource_uri.h>
#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>
#include <util/translation.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

/** BTXPKG1 payload cap plus 68-byte frame; refuse unbounded reads. */
constexpr size_t kMaxInspectBytes = 68 + 4 * 1024 * 1024;
constexpr size_t kAgentsSnippetChars = 200;

bool StartsWithBtxUri(const std::string& s)
{
    return s.size() >= 6 && s.compare(0, 6, "btx://") == 0;
}

bool HasWhitespace(const std::string& s)
{
    return s.find_first_of(" \t\n\r") != std::string::npos;
}

bool EndsWithBtx(const std::string& s)
{
    if (s.size() < 4) return false;
    return s[s.size() - 4] == '.' &&
           (s[s.size() - 3] == 'b' || s[s.size() - 3] == 'B') &&
           (s[s.size() - 2] == 't' || s[s.size() - 2] == 'T') &&
           (s[s.size() - 1] == 'x' || s[s.size() - 1] == 'X');
}

/** argc remains 2: one argv that mixes a URI with a file path is rejected. */
bool MixedUriAndFile(const std::string& s)
{
    if (StartsWithBtxUri(s)) return HasWhitespace(s);
    return s.find("btx://") != std::string::npos;
}

bool ReadBoundedFile(const std::string& path, std::vector<unsigned char>& bytes, std::string& err)
{
    bytes.clear();
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "cannot open path for local inspect";
        return false;
    }
    bytes.reserve(4096);
    char buf[4096];
    while (in) {
        in.read(buf, sizeof(buf));
        const std::streamsize n = in.gcount();
        if (n <= 0) break;
        if (bytes.size() + static_cast<size_t>(n) > kMaxInspectBytes) {
            err = "PACKAGE_TOO_LARGE";
            bytes.clear();
            return false;
        }
        bytes.insert(bytes.end(), buf, buf + n);
    }
    return true;
}

bool FileLooksLikeBtxBundle(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    unsigned char mag[8] = {};
    in.read(reinterpret_cast<char*>(mag), 8);
    if (in.gcount() < 8) return false;
    return modelnet::LooksLikeBtxBundle(Span<const unsigned char>{mag, 8});
}

bool TryPackageCoreId(const UniValue& core, modelnet::Digest48& out)
{
    std::string err;
    return modelnet::PackageCoreId(core, out, err);
}

const UniValue* DocumentsArray(const UniValue& decoded, const UniValue* core)
{
    if (core && core->exists("documents") && (*core)["documents"].isArray()) {
        return &(*core)["documents"];
    }
    if (decoded.exists("documents") && decoded["documents"].isArray()) {
        return &decoded["documents"];
    }
    return nullptr;
}

std::string DocumentPaths(const UniValue& docs)
{
    std::string list;
    for (const auto& d : docs.getValues()) {
        if (!d.isObject() || !d.exists("path") || !d["path"].isStr()) continue;
        if (!list.empty()) list += ",";
        list += modelnet::EscapeForTerminal(d["path"].get_str());
    }
    return list;
}

std::string AgentsSnippet(const UniValue& docs)
{
    for (const auto& d : docs.getValues()) {
        if (!d.isObject() || !d.exists("path") || !d["path"].isStr()) continue;
        if (d["path"].get_str() != "AGENTS.md") continue;
        if (!d.exists("text") || !d["text"].isStr()) return {};
        const std::string& text = d["text"].get_str();
        const size_t n = text.size() < kAgentsSnippetChars ? text.size() : kAgentsSnippetChars;
        return modelnet::EscapeForTerminal(text.substr(0, n));
    }
    return {};
}

int PrintUriPreview(const char* arg)
{
    modelnet::Resource r;
    std::string err;
    if (!modelnet::DecodeResource(arg, r, err)) {
        std::cerr << err << "\n";
        return 1;
    }
    uint64_t storage_bytes = 0;
    std::string storage_err;
    const bool have_budget = modelnet::EnvHasPositiveStorageBudget(storage_bytes, storage_err);
    (void)storage_err;
    std::cout << "canonical=" << r.Uri() << "\n"
              << "display=" << modelnet::ShortDisplayUri(r.Uri()) << "\n"
              << "copy=" << modelnet::CopyUri(r.Uri()) << "\n"
              << "kind=" << modelnet::ResourceKindName(r.kind) << "\n"
              << "digest=" << r.digest.Hex() << "\n"
              << "action=preview-only\n"
              << "storage_consent_required=" << (have_budget ? "false" : "true") << "\n"
              << "storage_bytes=" << storage_bytes << "\n"
              << "wallet=not-opened\n"
              << "note=download, seed, payment and local execution require separate approval\n";
    return 0;
}

void PrintInspectFooter()
{
    std::cout << "action=preview-only\n"
              << "wallet=not-opened\n"
              << "install=false\n"
              << "network=false\n"
              << "agents_md_write=false\n"
              << "note=local inspect only; does not install, open the wallet, use the network, or write AGENTS.md\n";
}

int InspectLocalPackage(const std::string& path)
{
    std::vector<unsigned char> bytes;
    std::string err;
    if (!ReadBoundedFile(path, bytes, err)) {
        std::cerr << err << "\n";
        return 1;
    }
    const bool magic = modelnet::LooksLikeBtxBundle(Span<const unsigned char>{bytes.data(), bytes.size()});
    UniValue decoded(UniValue::VOBJ);
    bool parsed = false;
    modelnet::DecodedBtxPackage pkg;
    if (magic && modelnet::DecodeBtxPackage(Span<const unsigned char>{bytes.data(), bytes.size()}, pkg, err)) {
        decoded = pkg.payload;
        parsed = true;
        err.clear();
    } else if (magic) {
        parsed = modelnet::DecodeBtxBundle(Span<const unsigned char>{bytes.data(), bytes.size()}, decoded, err);
    }
    if (!parsed) {
        decoded = UniValue(UniValue::VOBJ);
        const std::string raw(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        if (!decoded.read(raw) || !decoded.isObject()) {
            std::cerr << (err.empty() ? "unreadable package" : err) << "\n";
            return 1;
        }
        parsed = true;
    }

    std::cout << "path=" << modelnet::EscapeForTerminal(path) << "\n"
              << "looks_like_btxbundle=" << (magic ? "true" : "false") << "\n";

    const UniValue* core = nullptr;
    if (decoded.exists("core") && decoded["core"].isObject()) {
        core = &decoded["core"];
    }

    if (core && core->exists("version") && (*core)["version"].isNum()) {
        const int ver = (*core)["version"].getInt<int>();
        std::cout << "core_version=" << ver << "\n";
        modelnet::Digest48 id;
        if (TryPackageCoreId(*core, id)) {
            std::cout << "package_core_id=" << id.Hex() << "\n";
        }
    } else {
        std::cout << "core_version=unparseable\n";
    }

    const UniValue* docs = DocumentsArray(decoded, core);
    std::cout << "documents=" << (docs ? DocumentPaths(*docs) : "") << "\n";
    if (docs) {
        const std::string snippet = AgentsSnippet(*docs);
        if (!snippet.empty()) {
            std::cout << "agents_snippet=" << snippet << "\n";
        }
    }
    PrintInspectFooter();
    return 0;
}

} // namespace

int main(int argc, char* argv[])
{
    if (argc < 2 || std::string(argv[1]) == "-help" || std::string(argv[1]) == "-h") {
        std::cerr <<
            "btx-open — bounded BTX resource URI dispatcher (0.34.7)\n"
            "Opens an inspection preview only. Does not run inference, mine,\n"
            "open the spending wallet, import trust, or upload files.\n"
            "Usage: btx-open <btx://resource>\n"
            "       btx-open <path.btx>\n";
        return argc < 2 ? 1 : 0;
    }
    if (argc != 2) {
        std::cerr << "btx-open accepts exactly one URI or .btx path argument and does not invoke a shell\n";
        return 1;
    }
    const std::string arg{argv[1]};
    if (MixedUriAndFile(arg)) {
        std::cerr << "btx-open rejects mixed URI and file arguments; pass exactly one btx:// URI or one path\n";
        return 1;
    }
    if (StartsWithBtxUri(arg)) {
        return PrintUriPreview(argv[1]);
    }
    if (EndsWithBtx(arg) || FileLooksLikeBtxBundle(arg)) {
        return InspectLocalPackage(arg);
    }
    return PrintUriPreview(argv[1]);
}
