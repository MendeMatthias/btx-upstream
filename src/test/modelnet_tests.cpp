// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/sha256.h>
#include <modelnet/acl.h>
#include <modelnet/crypto.h>
#include <modelnet/http_bridge.h>
#include <modelnet/identity.h>
#include <modelnet/policy.h>
#include <modelnet/protocol.h>
#include <modelnet/qualification.h>
#include <modelnet/records.h>
#include <modelnet/release.h>
#include <modelnet/resource_uri.h>
#include <modelnet/router.h>
#include <modelnet/store.h>
#include <modelnet/swarm.h>
#include <modelnet/transfer.h>
#include <modelnet/transport_pq.h>
#include <protocol.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <crypto/common.h>
#include <crypto/sha384.h>
#include <fstream>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <tinyformat.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <iterator>

BOOST_FIXTURE_TEST_SUITE(modelnet_tests, BasicTestingSetup)

static UniValue LoadVectors()
{
    std::ifstream in{MODELNET_V11_VECTORS_PATH};
    BOOST_REQUIRE(in);
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue v;
    BOOST_REQUIRE(v.read(raw));
    return v;
}

BOOST_AUTO_TEST_CASE(sha384_nist_abc)
{
    CSHA384 hasher;
    hasher.Write(UCharCast("abc"), 3);
    unsigned char out[48];
    hasher.Finalize(out);
    BOOST_CHECK_EQUAL(HexStr(Span{out, 48}),
                      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
}

BOOST_AUTO_TEST_CASE(resource_vectors)
{
    const UniValue vectors = LoadVectors();
    for (const auto& v : vectors["resource_vectors"].getValues()) {
        modelnet::Digest48 d;
        std::string err;
        BOOST_REQUIRE(modelnet::Digest48::FromHex(v["digest"].get_str(), d, err));
        modelnet::ResourceKind kind;
        BOOST_REQUIRE(modelnet::ResourceKindFromInt(v["kind"].getInt<int>(), kind));
        std::string uri;
        BOOST_REQUIRE(modelnet::EncodeResource(kind, d, uri, err));
        BOOST_CHECK_EQUAL(uri, v["uri"].get_str());
        BOOST_CHECK_EQUAL(uri.size(), 91U);
        BOOST_CHECK_EQUAL(uri.substr(6).size(), 85U);
        modelnet::Resource r;
        BOOST_REQUIRE(modelnet::DecodeResource(uri, r, err));
        BOOST_CHECK_EQUAL(r.Uri(), uri);
        BOOST_CHECK(r.digest == d);
        BOOST_CHECK(r.kind == kind);
        std::string path, host;
        BOOST_REQUIRE(modelnet::BridgePath(uri, "https://bridge.example.org", path, err));
        BOOST_CHECK_EQUAL(path, v["bridge_path"].get_str());
        BOOST_REQUIRE(modelnet::SplitBridgeHost(uri, "bridge.example.org", host, err));
        BOOST_CHECK_EQUAL(host, v["split_bridge_hostname"].get_str());
    }
}

BOOST_AUTO_TEST_CASE(resource_mutations_and_forms)
{
    std::vector<unsigned char> digest(48);
    for (int i = 0; i < 48; ++i) digest[i] = static_cast<unsigned char>(i);
    modelnet::Digest48 d;
    std::copy(digest.begin(), digest.end(), d.data.begin());
    std::string uri, err;
    BOOST_REQUIRE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, d, uri, err));
    BOOST_CHECK_EQUAL(uri.size(), 91U);
    const std::string token = uri.substr(6);
    static const std::string alphabet{"qpzry9x8gf2tvdw0s3jn54khce6mua7l"};
    modelnet::Resource r;
    for (size_t i = 0; i < token.size(); ++i) {
        for (char c : alphabet) {
            if (c == token[i]) continue;
            std::string mut = token;
            mut[i] = c;
            BOOST_CHECK(!modelnet::DecodeResource("btx://" + mut, r, err));
        }
    }
    BOOST_REQUIRE(modelnet::DecodeResource(uri, r, err));
    BOOST_REQUIRE(modelnet::DecodeResource(token, r, err));
    BOOST_REQUIRE(modelnet::DecodeResource("btx:" + token, r, err));
    BOOST_REQUIRE(modelnet::DecodeResource(uri + "/", r, err));
    std::string upper = uri;
    for (char& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    BOOST_REQUIRE(modelnet::DecodeResource(upper, r, err));
    std::string mixed = token;
    for (size_t i = 0; i < mixed.size(); ++i) {
        if (std::isalpha(static_cast<unsigned char>(mixed[i]))) {
            mixed[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(mixed[i])));
            break;
        }
    }
    BOOST_CHECK(!modelnet::DecodeResource(mixed, r, err));
    BOOST_CHECK(!modelnet::DecodeResource(uri + "?pay=1", r, err));
    BOOST_CHECK(!modelnet::DecodeResource(uri + "#run", r, err));
    BOOST_CHECK(!modelnet::DecodeResource("btx://m/" + token, r, err));
    BOOST_CHECK(!modelnet::DecodeResource("btx1" + token, r, err));
    std::string origin_err;
    std::string dummy;
    BOOST_CHECK(!modelnet::BridgePath(uri, "http://example.org", dummy, origin_err));
}

BOOST_AUTO_TEST_CASE(record_vectors)
{
    const UniValue vectors = LoadVectors();
    for (const auto& v : vectors["record_vectors"].getValues()) {
        const uint8_t kind = static_cast<uint8_t>(v["kind"].getInt<int>());
        std::vector<unsigned char> encoded;
        std::string err;
        BOOST_REQUIRE(modelnet::EncodeRecord(kind, v["body"], encoded, err));
        BOOST_CHECK_EQUAL(HexStr(encoded), v["encoded_hex"].get_str());
        UniValue decoded;
        BOOST_REQUIRE(modelnet::DecodeRecord(kind, encoded, decoded, err));
        modelnet::Digest48 id, msg;
        BOOST_REQUIRE(modelnet::RecordId(kind, v["body"], id, err));
        BOOST_CHECK_EQUAL(id.Hex(), v["object_id"].get_str());
        BOOST_REQUIRE(modelnet::SigningMessage(kind, v["body"], msg, err));
        BOOST_CHECK_EQUAL(msg.Hex(), v["signing_message"].get_str());
        auto extra = encoded;
        extra.push_back(0);
        BOOST_CHECK(!modelnet::DecodeRecord(kind, extra, decoded, err));
        if (!encoded.empty()) {
            std::vector<unsigned char> trunc(encoded.begin(), encoded.end() - 1);
            BOOST_CHECK(!modelnet::DecodeRecord(kind, trunc, decoded, err));
        }
    }
}

BOOST_AUTO_TEST_CASE(free_first_and_reciprocity)
{
    modelnet::PaidPlan paid;
    paid.price_atoms = 100;
    paid.fee_atoms = 1;
    paid.total_eta_s = 10;
    modelnet::PlanChoice choice;
    std::string err;
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_ONLY, 50, &paid, 0, true, std::nullopt, 0, false, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::FREE);
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_ONLY, std::nullopt, &paid, 0, true, std::nullopt, 0, false, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::WAIT_FREE);
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_FIRST_APPROVAL, 50, &paid, 1000, true, std::nullopt, 100, false, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::APPROVAL_REQUIRED);
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_FIRST_BUDGET, std::nullopt, &paid, 1000, true, std::nullopt, 0, false, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::PAID);

    modelnet::ReciprocityLedger ledger;
    BOOST_CHECK(ledger.Received("p1", "art", 0, 0, 64 * 1024 * 1024, 0, true, true, false, 1));
    BOOST_CHECK(!ledger.Received("p2", "art", 0, 0, 64 * 1024 * 1024, 0, true, true, false, 1)); // cross-peer dedupe
    BOOST_CHECK(ledger.Weight("p1", 0) >= 1);
    BOOST_CHECK(ledger.Received("new", "art2", 0, 1, 1024, 0, true, true, false, 8));
    BOOST_CHECK(modelnet::DecideAcl(false, true, false, false, false, false, false, false) == modelnet::AclDecision::REJECT_CRYPTO);
    BOOST_CHECK(modelnet::DecideAcl(true, true, false, false, false, false, true, false) == modelnet::AclDecision::REQUIRE_SPEND_APPROVAL);
    BOOST_CHECK(modelnet::DecideAcl(true, true, false, false, false, false, false, false) == modelnet::AclDecision::ALLOW);
    auto lanes = modelnet::LaneSequence({{"bootstrap", 2}, {"reciprocal", 3}, {"preservation", 1}}, 10);
    BOOST_CHECK(!lanes.empty());
}

BOOST_AUTO_TEST_CASE(store_and_paths)
{
    std::string err;
    BOOST_CHECK(!modelnet::IsPortableRelPath("../etc/passwd", err));
    BOOST_CHECK(!modelnet::IsPortableRelPath("/abs", err));
    BOOST_CHECK(modelnet::IsPortableRelPath("model.safetensors", err));
    const std::string payload = "hello-modelnet-piece";
    std::vector<unsigned char> file(payload.begin(), payload.end());
    const auto rows = modelnet::BuildChunkTree(file);
    BOOST_REQUIRE(!rows.empty());
    const auto proof = modelnet::PieceProof(rows, 0);
    BOOST_CHECK(modelnet::VerifyPiece(rows.back()[0], file.size(), 0, file, proof));
    std::vector<unsigned char> corrupt = file;
    corrupt[0] ^= 0xff;
    BOOST_CHECK(!modelnet::VerifyPiece(rows.back()[0], file.size(), 0, corrupt, proof));

    const fs::path tmp = m_args.GetDataDirBase() / "modelstore";
    modelnet::ModelStore store{tmp, /*quota*/ 1024};
    modelnet::Digest48 art{};
    art.data[0] = 1;
    const auto leaf = modelnet::ChunkLeaf(0, file);
    BOOST_REQUIRE(store.PutVerifiedPiece(art, 0, 0, file, leaf, err));
    std::vector<unsigned char> got;
    BOOST_REQUIRE(store.GetPiece(art, 0, 0, got, err));
    BOOST_CHECK(got == file);
    std::vector<unsigned char> big(2000, 'x');
    const auto leaf2 = modelnet::ChunkLeaf(1, big);
    BOOST_CHECK(!store.PutVerifiedPiece(art, 0, 1, big, leaf2, err));
}

BOOST_AUTO_TEST_CASE(qualification_rejects_unsafe)
{
    modelnet::QualReport report;
    const unsigned char pickle[] = {0x80, 0x04, 0x95};
    BOOST_CHECK(modelnet::QualifyBytes("model.pkl", Span<const unsigned char>{pickle, sizeof(pickle)}, report) == modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
    const unsigned char junk[] = {1, 2, 3};
    BOOST_CHECK(modelnet::QualifyBytes("model.pt", Span<const unsigned char>{junk, sizeof(junk)}, report) == modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
    const unsigned char encmagic[] = {'B', 'T', 'X', 'E', 'N', 'C', '2', 0};
    BOOST_CHECK(modelnet::QualifyBytes("x.btxenc", Span<const unsigned char>{encmagic, sizeof(encmagic)}, report) == modelnet::QualResult::ENCRYPTED_UNQUALIFIED);

    // Minimal SafeTensors: 8-byte header length + "{}" + no tensors, file size must match 8+2.
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    BOOST_CHECK(modelnet::QualifyBytes("x.safetensors", st, report) == modelnet::QualResult::STRUCTURE_VERIFIED);

    std::vector<unsigned char> gguf(24, 0);
    std::memcpy(gguf.data(), "GGUF", 4);
    WriteLE32(gguf.data() + 4, 3);
    BOOST_CHECK(modelnet::QualifyBytes("x.gguf", gguf, report) == modelnet::QualResult::STRUCTURE_VERIFIED);
}

BOOST_AUTO_TEST_CASE(acl_does_not_ban_monetary)
{
    modelnet::ModelAcl acl;
    acl.deny_model.insert("abc");
    BOOST_CHECK(acl.Denied(modelnet::PolicyDim::RETRIEVE, "abc"));
    BOOST_CHECK(!acl.AffectsMonetaryBan());
}

BOOST_AUTO_TEST_CASE(release_hash_is_sha256_not_hash160)
{
    unsigned char secret[32];
    for (int i = 0; i < 32; ++i) secret[i] = static_cast<unsigned char>(i + 1);
    const auto h = modelnet::ReleaseHash(secret);
    BOOST_CHECK_EQUAL(h.Hex().size(), 64U);
    BOOST_CHECK(modelnet::ValidRefundWindow(100, 1, 10, 200));
    BOOST_CHECK(!modelnet::ValidRefundWindow(100, 50, 60, 150));
}

BOOST_AUTO_TEST_CASE(http_bridge_and_protocol)
{
    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/not-a-token", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
    const UniValue vectors = LoadVectors();
    const std::string uri = vectors["resource_vectors"][0]["uri"].get_str();
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/" + uri.substr(6), br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    BOOST_CHECK_EQUAL(br.canonical_btx, uri);

    modelnet::SendModels sm;
    std::vector<unsigned char> bytes;
    std::string err;
    BOOST_REQUIRE(modelnet::SerializeSendModels(sm, bytes, err));
    BOOST_CHECK_EQUAL(bytes.size(), 18U);
    modelnet::SendModels parsed;
    BOOST_REQUIRE(modelnet::ParseSendModels(bytes, parsed, err));
}

BOOST_AUTO_TEST_CASE(hybrid_free_first_scheduler)
{
    std::vector<modelnet::PieceNeed> missing(3);
    missing[0].piece_index = 0;
    missing[1].piece_index = 1;
    missing[2].piece_index = 2;
    std::vector<modelnet::SourceOffer> src{{"free", false, 0, 10, true}, {"paid", true, 50, 1, true}};
    auto plan = modelnet::PlanRetrieval(missing, src, modelnet::RetrievalMode::FREE_ONLY, 0, false);
    BOOST_CHECK(plan.paid_pieces.empty());
    BOOST_CHECK_EQUAL(plan.free_pieces.size(), 3U);
}

BOOST_AUTO_TEST_CASE(router_cpu_only)
{
    modelnet::RouterCache cache;
    modelnet::SignedRecordHint rec;
    rec.record_id.data[0] = 9;
    rec.expiry = 100;
    std::string err;
    BOOST_REQUIRE(cache.Insert(rec, 50, err));
    BOOST_CHECK_EQUAL(cache.LookupExact(rec.record_id, 50).size(), 1U);
    cache.Expire(200);
    BOOST_CHECK(cache.LookupExact(rec.record_id, 200).empty());
}

BOOST_AUTO_TEST_CASE(xchacha_roundtrip)
{
    unsigned char key[32];
    unsigned char nonce[24];
    for (int i = 0; i < 32; ++i) key[i] = static_cast<unsigned char>(i);
    for (int i = 0; i < 24; ++i) nonce[i] = static_cast<unsigned char>(100 + i);
    const std::vector<unsigned char> pt{'a', 'r', 't', 'i', 'f', 'a', 'c', 't'};
    std::vector<unsigned char> ct, recovered;
    BOOST_REQUIRE(modelnet::XChaCha20Poly1305Encrypt(key, nonce, {}, pt, ct));
    BOOST_REQUIRE(modelnet::XChaCha20Poly1305Decrypt(key, nonce, {}, ct, recovered));
    BOOST_CHECK(recovered == pt);
    ct[0] ^= 0x01;
    BOOST_CHECK(!modelnet::XChaCha20Poly1305Decrypt(key, nonce, {}, ct, recovered));
}

static std::string ReadAll(const fs::path& p)
{
    std::ifstream in(p);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

BOOST_AUTO_TEST_CASE(pq1_handshake_mlkem768)
{
    const fs::path dir = m_path_root / "pq1";
    fs::create_directories(dir);
    const fs::path key = dir / "key.pem";
    const fs::path cert = dir / "cert.pem";
    const fs::path openssl_err = dir / "openssl.err";
    const std::string cmd = strprintf(
        "/usr/bin/openssl req -x509 -new -newkey mldsa44 -keyout '%s' -out '%s' -nodes -subj '/CN=btx-model-test' -days 1 >'%s' 2>&1",
        fs::PathToString(key), fs::PathToString(cert), fs::PathToString(openssl_err));
    const int rc = std::system(cmd.c_str());
    BOOST_REQUIRE_MESSAGE(rc == 0, "openssl mldsa44 cert failed rc=" + std::to_string(rc) + " " + ReadAll(openssl_err));
    const std::string cert_pem = ReadAll(cert);
    const std::string key_pem = ReadAll(key);
    modelnet::Pq1Context server;
    modelnet::Pq1Context client;
    BOOST_REQUIRE_MESSAGE(server.Ready(), server.Error());
    BOOST_REQUIRE_MESSAGE(client.Ready(), client.Error());
    std::string err;
    BOOST_REQUIRE(server.LoadSelfSignedMlDsa(cert_pem, key_pem, err));
    BOOST_REQUIRE(client.LoadSelfSignedMlDsa(cert_pem, key_pem, err));
    modelnet::NegotiatedPq1 n;
    BOOST_REQUIRE_MESSAGE(modelnet::HandshakePair(server, client, n, err), err);
    BOOST_CHECK(modelnet::IsStrictPq1(n));
    BOOST_TEST_MESSAGE("PQ1 group=" + n.group + " cipher=" + n.ciphersuite + " ver=" + n.tls_version);
}

BOOST_AUTO_TEST_CASE(pq1_rejects_hybrid_peer)
{
    modelnet::Pq1Context client;
    BOOST_REQUIRE(client.Ready());
    SSL_CTX* rogue = SSL_CTX_new(TLS_method());
    BOOST_REQUIRE(rogue);
    SSL_CTX_set_min_proto_version(rogue, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(rogue, TLS1_3_VERSION);
    BOOST_REQUIRE_EQUAL(SSL_CTX_set1_groups_list(rogue, "X25519MLKEM768"), 1);
    SSL* ssl_s = SSL_new(rogue);
    SSL* ssl_c = SSL_new(static_cast<SSL_CTX*>(client.SslCtx()));
    BIO *b1 = nullptr, *b2 = nullptr;
    BOOST_REQUIRE_EQUAL(BIO_new_bio_pair(&b1, 0, &b2, 0), 1);
    SSL_set_bio(ssl_s, b1, b1);
    SSL_set_bio(ssl_c, b2, b2);
    SSL_set_accept_state(ssl_s);
    SSL_set_connect_state(ssl_c);
    int rc_c = 0, rc_s = 0;
    for (int i = 0; i < 32; ++i) {
        rc_c = SSL_do_handshake(ssl_c);
        rc_s = SSL_do_handshake(ssl_s);
        if (rc_c == 1 && rc_s == 1) break;
    }
    BOOST_CHECK(!(rc_c == 1 && rc_s == 1));
    SSL_free(ssl_c);
    SSL_free(ssl_s);
    SSL_CTX_free(rogue);
}

BOOST_AUTO_TEST_CASE(identity_is_not_wallet_and_release_is_sha256)
{
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    BOOST_CHECK_EQUAL(pk.size(), modelnet::MLDSA44_PK);
    BOOST_CHECK_EQUAL(sk.size(), modelnet::MLDSA44_SK);
    const std::vector<unsigned char> msg{'m', 'o', 'd', 'e', 'l'};
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(modelnet::SignMlDsa44(sk, msg, sig, err));
    BOOST_CHECK(modelnet::VerifyMlDsa44(pk, msg, sig));
    auto bad = msg;
    bad[0] ^= 0x01;
    BOOST_CHECK(!modelnet::VerifyMlDsa44(pk, bad, sig));
    const auto pid = modelnet::PublisherId(pk);
    BOOST_CHECK(!pid.IsNull());

    unsigned char secret[32];
    for (int i = 0; i < 32; ++i) secret[i] = static_cast<unsigned char>(i + 1);
    const auto h = modelnet::ReleaseHash(secret);
    unsigned char sha[32];
    CSHA256().Write(secret, 32).Finalize(sha);
    BOOST_CHECK(std::equal(h.data.begin(), h.data.end(), sha));
    BOOST_CHECK((SeedsServiceFlags() & NODE_MODEL_RELAY) == 0);
    BOOST_CHECK((SeedsServiceFlags() & NODE_MODEL_HOST) == 0);
    BOOST_CHECK(!MayHaveUsefulAddressDB(NODE_MODEL_RELAY));
    BOOST_CHECK(!MayHaveUsefulAddressDB(NODE_MODEL_HOST));
}

BOOST_AUTO_TEST_SUITE_END()
