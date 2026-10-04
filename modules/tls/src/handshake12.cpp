#include "session.hpp"
#include "keyschedule.hpp"
#include "wire.hpp"
#include <cerrno>

namespace sbox {
namespace tls {

    /* TLS 1.2 handshake: ECDHE key exchange with AEAD suites (RFC 5246, 8422, 7627). */
    TTask<int32_t> CTlsStream::SImpl::handshake12(ServerHello sh, HsMessage shMsg) {
        version = VER_TLS12;
        suite = FindSuite(sh.suite);
        HashAlg hash = suite->hash;
        int32_t rc;

        // --> RFC 7627: without the extended master secret the session is not bound to the
        // handshake (triple handshake attack); this client insists on it.
        if (!sh.extendedMasterSecret) {
            co_return co_await fail(-EPROTO, AD_HANDSHAKE_FAILURE, "the server does not support the extended master secret (RFC 7627)");
        }

        if (sh.hasAlpn) {
            if (!alpnAcceptable(sh.alpn)) {
                co_return co_await fail(-EPROTO, AD_ILLEGAL_PARAMETER, "the server selected an ALPN protocol that was not offered");
            }

            report.alpn = sh.alpn;
        }

        addTranscript(shMsg.raw);

        // -- Certificate.

        HsMessage msg;
        rc = co_await readHandshake(msg);
        if (rc != SBOX_OK) {
            co_return rc;
        }

        if (msg.type != HS_CERTIFICATE) {
            co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "expected the server Certificate (anonymous suites are not offered)");
        }

        std::vector<std::vector<uint8_t>> chain;
        {
            Reader r(BytesOf(msg.body));
            Reader list = r.block(3);
            while (list.ok() && list.left() > 0) {
                Reader data = list.block(3);
                if (!list.ok() || data.left() == 0) {
                    list.fail();
                    break;
                }

                chain.push_back(ToVector(data.rest()));
            }

            if (!list.done() || !r.done()) {
                co_return co_await fail(-EPROTO, AD_DECODE_ERROR, "malformed Certificate message");
            }
        }

        addTranscript(msg.raw);

        rc = co_await verifyServerCertificates(chain);
        if (rc != SBOX_OK) {
            co_return rc;
        }

        {
            certpp::crypto::EAsymmetrics which = leaf.publicKey()->algorithm();
            bool ecKey = which == certpp::crypto::EASYM_P256 || which == certpp::crypto::EASYM_P384
                || which == certpp::crypto::EASYM_P521 || which == certpp::crypto::EASYM_ED25519;
            if (suite->ecdsa ? !ecKey : which != certpp::crypto::EASYM_RSA) {
                co_return co_await fail(-EPROTO, AD_UNSUPPORTED_CERTIFICATE, "the server certificate key does not match the cipher suite");
            }

            auto ku = leaf.extension<certpp::x509::CKeyUsagesExtension>();
            if (ku && !options.insecure && !(ku->bits() & certpp::x509::EKUSE_DIGITAL_SIGNATURE)) {
                co_return co_await fail(-EKEYREJECTED, AD_UNSUPPORTED_CERTIFICATE, "the server certificate key usage does not allow signatures");
            }
        }

        // -- ServerKeyExchange.

        rc = co_await readHandshake(msg);
        if (rc != SBOX_OK) {
            co_return rc;
        }

        if (msg.type != HS_SERVER_KEY_EXCHANGE) {
            co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "expected ServerKeyExchange");
        }

        uint16_t group = 0;
        std::vector<uint8_t> serverPoint;
        {
            Reader r(BytesOf(msg.body));
            uint32_t curveType = r.u8();
            group = uint16_t(r.u16());
            serverPoint = ToVector(r.block(1).rest());
            size_t paramsLength = msg.body.size() - r.left();
            uint16_t scheme = uint16_t(r.u16());
            SReadOnlyByteSpan signature = r.block(2).rest();

            if (!r.done() || serverPoint.empty()) {
                co_return co_await fail(-EPROTO, AD_DECODE_ERROR, "malformed ServerKeyExchange");
            }

            if (curveType != 3 || !KeyShare::supported(group)) {
                co_return co_await fail(-EPROTO, AD_ILLEGAL_PARAMETER, "ServerKeyExchange uses a curve that was not offered");
            }

            bool offered = false;
            for (uint16_t s : offeredSchemes) {
                offered = offered || s == scheme;
            }

            if (!offered || !SchemeFitsKey(leaf, scheme, false)) {
                co_return co_await fail(-EPROTO, AD_ILLEGAL_PARAMETER, "ServerKeyExchange uses a signature scheme that was not offered or does not fit the key");
            }

            // --> Signed: client_random || server_random || ServerECDHParams.
            std::vector<uint8_t> signedData = clientRandom;
            signedData.insert(signedData.end(), sh.random.begin(), sh.random.end());
            signedData.insert(signedData.end(), msg.body.begin(), msg.body.begin() + long(paramsLength));

            if (VerifySignature(leaf, scheme, false, BytesOf(signedData), signature) != SBOX_OK) {
                co_return co_await fail(-EKEYREJECTED, AD_DECRYPT_ERROR, "the ServerKeyExchange signature does not verify");
            }

            report.signatureScheme = scheme;
            report.group = group;
        }

        addTranscript(msg.raw);

        // -- CertificateRequest (optional) and ServerHelloDone.

        rc = co_await readHandshake(msg);
        if (rc != SBOX_OK) {
            co_return rc;
        }

        bool certRequested = false;
        std::vector<uint16_t> requestSchemes;

        if (msg.type == HS_CERTIFICATE_REQUEST) {
            certRequested = true;
            Reader r(BytesOf(msg.body));
            r.block(1);     // --> certificate_types
            Reader list = r.block(2);
            while (list.ok() && list.left() >= 2) {
                requestSchemes.push_back(uint16_t(list.u16()));
            }

            r.block(2);     // --> certificate_authorities
            if (!list.done() || !r.done()) {
                co_return co_await fail(-EPROTO, AD_DECODE_ERROR, "malformed CertificateRequest");
            }

            addTranscript(msg.raw);

            rc = co_await readHandshake(msg);
            if (rc != SBOX_OK) {
                co_return rc;
            }
        }

        if (msg.type != HS_SERVER_HELLO_DONE || !msg.body.empty()) {
            co_return co_await fail(-EPROTO, msg.type == HS_SERVER_HELLO_DONE ? AD_DECODE_ERROR : AD_UNEXPECTED_MESSAGE,
                                    "expected ServerHelloDone");
        }

        addTranscript(msg.raw);

        if (!hsBuf.empty()) {
            co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "data follows ServerHelloDone");
        }

        // -- Key agreement.

        KeyShare ks;
        if (ks.generate(group) != SBOX_OK) {
            co_return co_await fail(-EIO, AD_INTERNAL_ERROR, "key share generation failed");
        }

        std::vector<uint8_t> preMaster;
        if (ks.agree(BytesOf(serverPoint), preMaster) != SBOX_OK) {
            co_return co_await fail(-EPROTO, AD_ILLEGAL_PARAMETER, "the server ECDHE public value is invalid");
        }

        // -- Client flight.

        uint16_t clientScheme = certRequested ? pickClientScheme(requestSchemes, false) : 0;
        bool sendCert = certRequested && clientKey && clientScheme != 0;

        if (certRequested) {
            std::vector<uint8_t> body;
            Writer w(body);
            w.begin(3);
            if (sendCert) {
                for (const auto& der : clientChain) {
                    w.begin(3);
                    w.bytes(der);
                    w.end();
                }
            }
            w.end();

            rc = co_await sendHandshake(HS_CERTIFICATE, body);
            if (rc != SBOX_OK) {
                Wipe(preMaster);
                co_return rc;
            }
        }

        {
            std::vector<uint8_t> body;
            Writer w(body);
            w.begin(1);
            w.bytes(ks.publicValue());
            w.end();

            rc = co_await sendHandshake(HS_CLIENT_KEY_EXCHANGE, body);
            if (rc != SBOX_OK) {
                Wipe(preMaster);
                co_return rc;
            }
        }

        // --> RFC 7627 4: the session hash covers the transcript through ClientKeyExchange.
        std::vector<uint8_t> sessionHash = transcriptHash();
        std::vector<uint8_t> master = Tls12ExtendedMasterSecret(hash, BytesOf(preMaster), BytesOf(sessionHash));
        Wipe(preMaster);

        if (master.size() != 48) {
            co_return co_await fail(-EIO, AD_INTERNAL_ERROR, "key derivation failed");
        }

        if (sendCert) {
            // --> TLS 1.2 CertificateVerify signs the handshake messages themselves.
            std::vector<uint8_t> signature;
            if (SignMessage(clientLeaf, clientKey, clientScheme, BytesOf(transcript), signature) != SBOX_OK) {
                Wipe(master);
                co_return co_await fail(-EIO, AD_INTERNAL_ERROR, "signing the client CertificateVerify failed");
            }

            std::vector<uint8_t> cv;
            Writer w(cv);
            w.u16(clientScheme);
            w.begin(2);
            w.bytes(signature);
            w.end();

            rc = co_await sendHandshake(HS_CERTIFICATE_VERIFY, cv);
            if (rc != SBOX_OK) {
                Wipe(master);
                co_return rc;
            }

            report.clientCertificateSent = true;
        }

        rc = co_await writeCcs(remaining(-1));
        if (rc != SBOX_OK) {
            Wipe(master);
            co_return failQuiet(rc, "failed to send change_cipher_spec");
        }

        RecordCipher serverWrite;
        if (!Tls12InstallKeys(*suite, BytesOf(master), BytesOf(clientRandom), BytesOf(sh.random), writeCipher, serverWrite)) {
            Wipe(master);
            co_return co_await fail(-EIO, AD_INTERNAL_ERROR, "key derivation failed");
        }

        {
            std::vector<uint8_t> th = transcriptHash();
            std::vector<uint8_t> verify = Tls12Finished(hash, BytesOf(master), true, BytesOf(th));
            rc = co_await sendHandshake(HS_FINISHED, verify);
            if (rc != SBOX_OK) {
                Wipe(master);
                co_return rc;
            }
        }

        // -- Server ChangeCipherSpec and Finished.

        rc = co_await readHandshake(msg);
        if (rc != SBOX_OK) {
            Wipe(master);
            co_return rc;
        }

        if (msg.type != MSG_CCS) {
            Wipe(master);
            co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE,
                                    msg.type == HS_NEW_SESSION_TICKET ? "unexpected NewSessionTicket (tickets were not offered)"
                                                                      : "expected the server change_cipher_spec");
        }

        readCipher = std::move(serverWrite);

        std::vector<uint8_t> th = transcriptHash();
        rc = co_await readHandshake(msg);
        if (rc != SBOX_OK) {
            Wipe(master);
            co_return rc;
        }

        if (msg.type != HS_FINISHED) {
            Wipe(master);
            co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "expected the server Finished");
        }

        std::vector<uint8_t> expected = Tls12Finished(hash, BytesOf(master), false, BytesOf(th));
        Wipe(master);

        // --> Constant-time comparison (certpp CSecure).
        if (expected.empty() || !SecureEquals(BytesOf(msg.body), BytesOf(expected))) {
            co_return co_await fail(-EPROTO, AD_DECRYPT_ERROR, "the server Finished does not verify");
        }

        serverFinished = true;
        if (!hsBuf.empty()) {
            co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "handshake data follows the server Finished");
        }

        co_return SBOX_OK;
    }

}
}
