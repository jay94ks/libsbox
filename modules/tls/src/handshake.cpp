#include "session.hpp"
#include "verifyimpl.hpp"
#include "keyschedule.hpp"
#include "wire.hpp"
#include <certpp/x509/chain.hpp>
#include <certpp/x509/chain/pem.hpp>
#include <cerrno>

namespace sbox {
namespace tls {

    namespace {

        // --> SHA-256("HelloRetryRequest"), the ServerHello.random of a HelloRetryRequest.
        const uint8_t HRR_RANDOM[32] = {
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
            0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
        };

        // --> RFC 8446 4.1.3 downgrade sentinel of a TLS 1.3 server negotiating TLS 1.2.
        const uint8_t DOWNGRADE_TLS12[8] = { 0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01 };

        const uint16_t SUITES13[] = { TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 };

        const uint16_t SUITES12[] = {
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        };

        const uint16_t GROUPS[] = { GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1 };

        const uint16_t SCHEMES[] = {
            SIG_ECDSA_SECP256R1_SHA256, SIG_ECDSA_SECP384R1_SHA384, SIG_ECDSA_SECP521R1_SHA512,
            SIG_ED25519,
            SIG_RSA_PSS_RSAE_SHA256, SIG_RSA_PSS_RSAE_SHA384, SIG_RSA_PSS_RSAE_SHA512,
            SIG_RSA_PKCS1_SHA256, SIG_RSA_PKCS1_SHA384, SIG_RSA_PKCS1_SHA512,
        };

        /* Lower-cases a host name and drops a trailing dot (SNI carries neither). */
        std::string sniForm(std::string_view host) {
            if (!host.empty() && host.back() == '.') {
                host.remove_suffix(1);
            }

            std::string out(host);
            for (char& c : out) {
                if (c >= 'A' && c <= 'Z') {
                    c = char(c - 'A' + 'a');
                }
            }

            return out;
        }

    }

    /* Loads the client certificate chain and key. */
    int32_t CTlsStream::SImpl::loadClientIdentity() {
        std::string text = options.clientCertificatePem + "\n" + options.clientKeyPem;
        certpp::x509::CPemChainFormat format(true);
        certpp::x509::CCertCollection collection;

        if (format.load(certpp::SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text.data()), text.size()),
                        certpp::SReadOnlyByteSpan(), collection) != certpp::ERET_OK) {
            return -EINVAL;
        }

        std::vector<std::vector<uint8_t>> others;
        for (size_t i = 0; i < collection.count(); ++i) {
            certpp::x509::SCertEntry entry;
            if (collection.at(i, entry) != certpp::ERET_OK) {
                return -EINVAL;
            }

            const certpp::COctet& raw = entry.cert.rawData();
            std::vector<uint8_t> der(raw.toPtr(), raw.toPtr() + raw.size());
            certpp::crypto::IPrivateKeyPtr key = entry.privateKey ? entry.privateKey : entry.cert.privateKey();

            if (key && !clientKey) {
                clientKey = key;
                clientLeaf = entry.cert;
                clientChain.insert(clientChain.begin(), std::move(der));
            }
            else {
                others.push_back(std::move(der));
            }
        }

        if (!clientKey) {
            return -EINVAL;
        }

        for (auto& der : others) {
            clientChain.push_back(std::move(der));
        }

        return SBOX_OK;
    }

    /* Builds the ClientHello body. */
    std::vector<uint8_t> CTlsStream::SImpl::buildClientHello(const std::vector<uint8_t>& cookie) {
        bool offer13 = options.maxVersion >= ETLSV_1_3;
        bool offer12 = options.minVersion <= ETLSV_1_2;

        std::vector<uint8_t> body;
        Writer w(body);
        offeredExtensions.clear();
        offeredSuites.clear();
        offeredSchemes.assign(std::begin(SCHEMES), std::end(SCHEMES));

        w.u16(VER_TLS12);
        w.bytes(clientRandom);
        w.begin(1);
        w.bytes(sessionId);
        w.end();

        w.begin(2);
        if (offer13) {
            for (uint16_t s : SUITES13) {
                w.u16(s);
                offeredSuites.push_back(s);
            }
        }

        if (offer12) {
            for (uint16_t s : SUITES12) {
                w.u16(s);
                offeredSuites.push_back(s);
            }
        }
        w.end();

        w.u8(1);    // --> compression_methods: null only.
        w.u8(0);

        w.begin(2);

        auto ext = [&](uint16_t type) {
            offeredExtensions.insert(type);
            w.u16(type);
            w.begin(2);
        };

        if (!sniName.empty()) {
            ext(EXT_SERVER_NAME);
            w.begin(2);
            w.u8(0);    // --> host_name
            w.begin(2);
            w.bytes(BytesOf(sniName));
            w.end();
            w.end();
            w.end();
        }

        if (offer12) {
            ext(EXT_EC_POINT_FORMATS);
            w.begin(1);
            w.u8(0);    // --> uncompressed
            w.end();
            w.end();
        }

        ext(EXT_SUPPORTED_GROUPS);
        w.begin(2);
        for (uint16_t g : GROUPS) {
            w.u16(g);
        }
        w.end();
        w.end();

        ext(EXT_SIGNATURE_ALGORITHMS);
        w.begin(2);
        for (uint16_t s : SCHEMES) {
            w.u16(s);
        }
        w.end();
        w.end();

        if (!options.alpn.empty()) {
            ext(EXT_ALPN);
            w.begin(2);
            for (const std::string& p : options.alpn) {
                w.begin(1);
                w.bytes(BytesOf(p));
                w.end();
            }
            w.end();
            w.end();
        }

        if (offer12) {
            ext(EXT_EXTENDED_MASTER_SECRET);
            w.end();

            ext(EXT_RENEGOTIATION_INFO);
            w.u8(0);    // --> Empty renegotiated_connection: initial handshake (RFC 5746).
            w.end();
        }

        if (offer13) {
            ext(EXT_SUPPORTED_VERSIONS);
            w.begin(1);
            w.u16(VER_TLS13);
            if (offer12) {
                w.u16(VER_TLS12);
            }
            w.end();
            w.end();

            ext(EXT_KEY_SHARE);
            w.begin(2);
            for (const KeyShare& ks : shares) {
                w.u16(ks.group());
                w.begin(2);
                w.bytes(ks.publicValue());
                w.end();
            }
            w.end();
            w.end();

            if (!cookie.empty()) {
                ext(EXT_COOKIE);
                w.begin(2);
                w.bytes(cookie);
                w.end();
                w.end();
            }
        }

        w.end();
        return body;
    }

    /* ALPN acceptance. */
    bool CTlsStream::SImpl::alpnAcceptable(const std::string& proto) const {
        for (const std::string& p : options.alpn) {
            if (p == proto) {
                return true;
            }
        }

        return false;
    }

    /* Parses a ServerHello / HelloRetryRequest. */
    int32_t CTlsStream::SImpl::parseServerHello(const std::vector<uint8_t>& body, ServerHello& out, int32_t& alert, std::string& why) {
        Reader r(BytesOf(body));
        out.legacyVersion = uint16_t(r.u16());
        out.random = ToVector(r.bytes(32));
        out.sessionId = ToVector(r.block(1).rest());
        out.suite = uint16_t(r.u16());
        uint32_t compression = r.u8();

        std::set<uint16_t> seen;
        if (r.left() > 0) {
            Reader exts = r.block(2);
            while (exts.ok() && exts.left() > 0) {
                uint16_t type = uint16_t(exts.u16());
                Reader data = exts.block(2);
                if (!exts.ok()) {
                    break;
                }

                if (!seen.insert(type).second) {
                    alert = AD_ILLEGAL_PARAMETER;
                    why = "the ServerHello repeats an extension";
                    return -EPROTO;
                }

                if (!offeredExtensions.count(type)) {
                    alert = AD_UNSUPPORTED_EXTENSION;
                    why = "the ServerHello carries an extension that was not offered (" + std::to_string(type) + ")";
                    return -EPROTO;
                }

                switch (type) {
                case EXT_SUPPORTED_VERSIONS:
                    out.selectedVersion = uint16_t(data.u16());
                    break;

                case EXT_KEY_SHARE:
                    out.hasKeyShare = true;
                    out.keyShareGroup = uint16_t(data.u16());
                    if (data.left() > 0) {
                        out.keyShare = ToVector(data.block(2).rest());
                    }
                    break;

                case EXT_COOKIE:
                    out.cookie = ToVector(data.block(2).rest());
                    if (out.cookie.empty()) {
                        data.fail();
                    }
                    break;

                case EXT_EXTENDED_MASTER_SECRET:
                    out.extendedMasterSecret = true;
                    break;

                case EXT_RENEGOTIATION_INFO:
                    if (data.block(1).left() != 0) {
                        alert = AD_HANDSHAKE_FAILURE;
                        why = "the server's renegotiation_info is not empty on an initial handshake";
                        return -EPROTO;
                    }
                    break;

                case EXT_ALPN: {
                    Reader list = data.block(2);
                    std::string proto(TextOf(list.block(1).rest()));
                    if (!list.done() || proto.empty()) {
                        data.fail();
                        break;
                    }

                    out.hasAlpn = true;
                    out.alpn = proto;
                    break;
                }

                case EXT_EC_POINT_FORMATS: {
                    Reader formats = data.block(1);
                    bool uncompressed = false;
                    while (formats.ok() && formats.left() > 0) {
                        uint32_t format = formats.u8();
                        uncompressed = uncompressed || format == 0;
                    }

                    if (!uncompressed) {
                        alert = AD_ILLEGAL_PARAMETER;
                        why = "the server does not accept uncompressed EC points";
                        return -EPROTO;
                    }
                    break;
                }

                case EXT_SERVER_NAME:
                    break;

                default:
                    alert = AD_ILLEGAL_PARAMETER;
                    why = "the ServerHello carries an extension not allowed there (" + std::to_string(type) + ")";
                    return -EPROTO;
                }

                if (!data.done()) {
                    alert = AD_DECODE_ERROR;
                    why = "malformed ServerHello extension " + std::to_string(type);
                    return -EPROTO;
                }
            }

            if (!exts.done()) {
                r.fail();
            }
        }

        if (!r.done() || out.random.size() != 32 || out.sessionId.size() > 32) {
            alert = AD_DECODE_ERROR;
            why = "malformed ServerHello";
            return -EPROTO;
        }

        out.helloRetry = std::memcmp(out.random.data(), HRR_RANDOM, 32) == 0;

        if (compression != 0) {
            alert = AD_ILLEGAL_PARAMETER;
            why = "the server selected a compression method";
            return -EPROTO;
        }

        auto offeredSuite = [&](bool want13) {
            const SuiteInfo* s = FindSuite(out.suite);
            if (!s || s->tls13 != want13) {
                return false;
            }

            for (uint16_t o : offeredSuites) {
                if (o == out.suite) {
                    return true;
                }
            }

            return false;
        };

        if (out.selectedVersion != 0) {
            if (out.selectedVersion != VER_TLS13 || out.legacyVersion != VER_TLS12) {
                alert = AD_ILLEGAL_PARAMETER;
                why = "the server selected an invalid version in supported_versions";
                return -EPROTO;
            }

            if (out.extendedMasterSecret || out.hasAlpn || seen.count(EXT_RENEGOTIATION_INFO) || seen.count(EXT_EC_POINT_FORMATS)
                || seen.count(EXT_SERVER_NAME)) {
                alert = AD_ILLEGAL_PARAMETER;
                why = "the TLS 1.3 ServerHello carries a TLS 1.2 extension";
                return -EPROTO;
            }

            if (out.sessionId != sessionId) {
                alert = AD_ILLEGAL_PARAMETER;
                why = "the server did not echo the legacy session id";
                return -EPROTO;
            }

            if (!offeredSuite(true)) {
                alert = AD_ILLEGAL_PARAMETER;
                why = "the server selected a cipher suite that was not offered (" + SuiteName(out.suite) + ")";
                return -EPROTO;
            }

            if (out.helloRetry) {
                if (out.cookie.empty() && !out.hasKeyShare) {
                    alert = AD_ILLEGAL_PARAMETER;
                    why = "the HelloRetryRequest would not change the ClientHello";
                    return -EPROTO;
                }

                if (out.hasKeyShare && !out.keyShare.empty()) {
                    alert = AD_DECODE_ERROR;
                    why = "malformed HelloRetryRequest key_share";
                    return -EPROTO;
                }
            }
            else {
                if (!out.cookie.empty()) {
                    alert = AD_ILLEGAL_PARAMETER;
                    why = "the ServerHello carries a cookie";
                    return -EPROTO;
                }

                if (!out.hasKeyShare || out.keyShare.empty()) {
                    alert = AD_MISSING_EXTENSION;
                    why = "the ServerHello has no key_share (PSK-only modes are not offered)";
                    return -EPROTO;
                }
            }

            return SBOX_OK;
        }

        if (out.helloRetry) {
            alert = AD_ILLEGAL_PARAMETER;
            why = "HelloRetryRequest without TLS 1.3";
            return -EPROTO;
        }

        if (out.legacyVersion < VER_TLS12 || options.minVersion > ETLSV_1_2) {
            alert = AD_PROTOCOL_VERSION;
            why = out.legacyVersion < VER_TLS12 ? "the server only supports TLS versions older than 1.2"
                                                : "the server does not support TLS 1.3 (minimum version is 1.3)";
            return -EPROTONOSUPPORT;
        }

        if (out.legacyVersion != VER_TLS12) {
            alert = AD_ILLEGAL_PARAMETER;
            why = "the server selected an invalid legacy version";
            return -EPROTO;
        }

        if (options.maxVersion >= ETLSV_1_3 && std::memcmp(out.random.data() + 24, DOWNGRADE_TLS12, 8) == 0) {
            alert = AD_ILLEGAL_PARAMETER;
            why = "the server signals a TLS 1.3 downgrade (possible attack)";
            return -EPROTO;
        }

        if (out.hasKeyShare || !out.cookie.empty()) {
            alert = AD_ILLEGAL_PARAMETER;
            why = "the TLS 1.2 ServerHello carries a TLS 1.3 extension";
            return -EPROTO;
        }

        if (!offeredSuite(false)) {
            alert = AD_ILLEGAL_PARAMETER;
            why = "the server selected a cipher suite that was not offered (" + SuiteName(out.suite) + ")";
            return -EPROTO;
        }

        if (!out.sessionId.empty() && out.sessionId == sessionId) {
            alert = AD_ILLEGAL_PARAMETER;
            why = "the server attempts to resume a session that was never offered";
            return -EPROTO;
        }

        return SBOX_OK;
    }

    /* Verifies the server chain. */
    TTask<int32_t> CTlsStream::SImpl::verifyServerCertificates(const std::vector<std::vector<uint8_t>>& chain) {
        report.peerCertificates = chain;

        if (chain.empty()) {
            co_return co_await fail(-EPROTO, AD_DECODE_ERROR, "the server sent an empty certificate list");
        }

        if (leaf.importDer(certpp::COctet(chain[0].data(), chain[0].size())) != certpp::ERET_OK || !leaf.publicKey()) {
            co_return co_await fail(-EKEYREJECTED, AD_BAD_CERTIFICATE, "the server certificate cannot be parsed or has an unsupported key");
        }

        if (options.insecure) {
            co_return SBOX_OK;
        }

        std::string why;
        uint8_t alert = AD_BAD_CERTIFICATE;
        STlsVerifyParams params;
        params.host = options.serverName;
        params.nowSeconds = options.verifyTimeSeconds;

        int32_t rc = VerifyChainWithAlert(chain, *options.trustStore, params, why, alert);
        if (rc != SBOX_OK) {
            co_return co_await fail(-EKEYREJECTED, alert, "certificate verification failed: " + why);
        }

        co_return SBOX_OK;
    }

    /* Picks our client signature scheme. */
    uint16_t CTlsStream::SImpl::pickClientScheme(const std::vector<uint16_t>& serverSchemes, bool is13) const {
        if (!clientKey) {
            return 0;
        }

        for (uint16_t ours : SCHEMES) {
            bool listed = false;
            for (uint16_t s : serverSchemes) {
                listed = listed || s == ours;
            }

            if (listed && SchemeFitsKey(clientLeaf, ours, is13)) {
                return ours;
            }
        }

        return 0;
    }

    /* Fills the report on success. */
    void CTlsStream::SImpl::finishReport() {
        report.error = SBOX_OK;
        report.reason.clear();
        report.version = ETlsVersion(version);
        report.cipherSuite = suite ? suite->id : 0;
        report.cipherSuiteName = suite ? suite->name : "";
    }

    /* Runs the handshake. */
    TTask<int32_t> CTlsStream::SImpl::handshake() {
        if (phase != PHASE_HANDSHAKE || !transcript.empty()) {
            co_return -EALREADY;
        }

        deadline = options.handshakeTimeoutMs >= 0 ? CEventLoop::nowMs() + options.handshakeTimeoutMs : -1;

        bool versionsValid = (options.minVersion == ETLSV_1_2 || options.minVersion == ETLSV_1_3)
            && (options.maxVersion == ETLSV_1_2 || options.maxVersion == ETLSV_1_3)
            && options.minVersion <= options.maxVersion;
        if (!versionsValid) {
            co_return failQuiet(-EINVAL, "invalid TLS version range");
        }

        if (!options.insecure && options.serverName.empty()) {
            co_return failQuiet(-EINVAL, "a server name is required to verify the certificate");
        }

        for (const std::string& p : options.alpn) {
            if (p.empty() || p.size() > 255) {
                co_return failQuiet(-EINVAL, "invalid ALPN protocol name");
            }
        }

        std::vector<uint8_t> ip;
        if (!options.serverName.empty() && !ParseIpLiteral(options.serverName, ip)) {
            sniName = sniForm(options.serverName);
        }

        if (!options.clientCertificatePem.empty() && loadClientIdentity() != SBOX_OK) {
            co_return failQuiet(-EINVAL, "the client certificate or key cannot be loaded (or they do not match)");
        }

        if (!options.insecure && !options.trustStore) {
            options.trustStore = CTrustStore::system();
        }

        clientRandom.assign(32, 0);
        sessionId.assign(32, 0);
        if (!RandomBytes(BytesOf(clientRandom)) || !RandomBytes(BytesOf(sessionId))) {
            co_return failQuiet(-EIO, "the system random generator failed");
        }

        if (options.maxVersion >= ETLSV_1_3) {
            KeyShare ks;
            if (ks.generate(GROUP_X25519) != SBOX_OK) {
                co_return failQuiet(-EIO, "key share generation failed");
            }

            shares.push_back(std::move(ks));
        }

        int32_t rc = co_await sendHandshake(HS_CLIENT_HELLO, buildClientHello({}), VER_TLS10);
        if (rc != SBOX_OK) {
            co_return rc;
        }

        HsMessage msg;
        rc = co_await readHandshake(msg);
        if (rc != SBOX_OK) {
            co_return rc;
        }

        if (msg.type != HS_SERVER_HELLO) {
            co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "expected ServerHello, got message " + std::to_string(msg.type));
        }

        ServerHello sh;
        int32_t alert = AD_DECODE_ERROR;
        std::string why;
        rc = parseServerHello(msg.body, sh, alert, why);
        if (rc != SBOX_OK) {
            co_return co_await fail(rc, alert, why);
        }

        if (sh.selectedVersion == VER_TLS13) {
            rc = co_await handshake13(std::move(sh), std::move(msg));
        }
        else {
            rc = co_await handshake12(std::move(sh), std::move(msg));
        }

        if (rc != SBOX_OK) {
            co_return phase == PHASE_FAILED ? error : failQuiet(rc, "handshake failed");
        }

        finishReport();
        phase = PHASE_OPEN;
        Wipe(transcript);
        co_return SBOX_OK;
    }

}
}
