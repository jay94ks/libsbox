#include "session.hpp"
#include "keyschedule.hpp"
#include "wire.hpp"
#include <cerrno>

namespace sbox {
namespace tls {

    namespace {

        /* Wipes several secrets. */
        void wipeAll(std::initializer_list<std::vector<uint8_t>*> list) {
            for (std::vector<uint8_t>* v : list) {
                Wipe(*v);
            }
        }

    }

    /* TLS 1.3 handshake (RFC 8446 2, 4). */
    TTask<int32_t> CTlsStream::SImpl::handshake13(ServerHello sh, HsMessage shMsg) {
        version = VER_TLS13;
        suite = FindSuite(sh.suite);
        HashAlg hash = suite->hash;
        int32_t rc;

        if (sh.helloRetry) {
            report.helloRetry = true;

            if (sh.hasKeyShare) {
                if (!KeyShare::supported(sh.keyShareGroup)) {
                    co_return co_await fail(-EPROTO, AD_ILLEGAL_PARAMETER, "HelloRetryRequest selects a group that was not offered");
                }

                for (const KeyShare& ks : shares) {
                    if (ks.group() == sh.keyShareGroup) {
                        co_return co_await fail(-EPROTO, AD_ILLEGAL_PARAMETER, "HelloRetryRequest selects a group whose share was already sent");
                    }
                }
            }

            // --> RFC 8446 4.4.1: ClientHello1 is replaced by a synthetic message_hash.
            std::vector<uint8_t> ch1 = Hash(hash, BytesOf(transcript));
            transcript.clear();
            Writer w(transcript);
            w.u8(HS_MESSAGE_HASH);
            w.u24(uint32_t(ch1.size()));
            w.bytes(ch1);
            addTranscript(shMsg.raw);

            if (!hsBuf.empty()) {
                co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "data follows the HelloRetryRequest");
            }

            if (sh.hasKeyShare) {
                shares.clear();
                KeyShare ks;
                if (ks.generate(sh.keyShareGroup) != SBOX_OK) {
                    co_return co_await fail(-EIO, AD_INTERNAL_ERROR, "key share generation failed");
                }

                shares.push_back(std::move(ks));
            }

            // --> Middlebox compatibility (RFC 8446 D.4): CCS right before the second flight.
            rc = co_await writeCcs(remaining(-1));
            if (rc != SBOX_OK) {
                co_return failQuiet(rc, "failed to send change_cipher_spec");
            }

            compatCcsSent = true;

            rc = co_await sendHandshake(HS_CLIENT_HELLO, buildClientHello(sh.cookie));
            if (rc != SBOX_OK) {
                co_return rc;
            }

            HsMessage msg;
            rc = co_await readHandshake(msg);
            if (rc != SBOX_OK) {
                co_return rc;
            }

            if (msg.type != HS_SERVER_HELLO) {
                co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "expected ServerHello after HelloRetryRequest");
            }

            ServerHello sh2;
            int32_t alert = AD_DECODE_ERROR;
            std::string why;
            rc = parseServerHello(msg.body, sh2, alert, why);
            if (rc != SBOX_OK) {
                co_return co_await fail(rc, alert, why);
            }

            if (sh2.helloRetry) {
                co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "received a second HelloRetryRequest");
            }

            if (sh2.selectedVersion != VER_TLS13 || sh2.suite != sh.suite) {
                co_return co_await fail(-EPROTO, AD_ILLEGAL_PARAMETER, "the ServerHello does not match the HelloRetryRequest");
            }

            if (sh.hasKeyShare && sh2.keyShareGroup != sh.keyShareGroup) {
                co_return co_await fail(-EPROTO, AD_ILLEGAL_PARAMETER, "the ServerHello key share is not the requested group");
            }

            sh = std::move(sh2);
            shMsg = std::move(msg);
        }

        // -- Key exchange.

        const KeyShare* mine = nullptr;
        for (const KeyShare& ks : shares) {
            if (ks.group() == sh.keyShareGroup) {
                mine = &ks;
            }
        }

        if (!mine) {
            co_return co_await fail(-EPROTO, AD_ILLEGAL_PARAMETER, "the server key share is for a group that was not offered");
        }

        std::vector<uint8_t> ecdhe;
        if (mine->agree(BytesOf(sh.keyShare), ecdhe) != SBOX_OK) {
            co_return co_await fail(-EPROTO, AD_ILLEGAL_PARAMETER, "the server key share is invalid");
        }

        report.group = sh.keyShareGroup;
        addTranscript(shMsg.raw);

        if (!hsBuf.empty()) {
            co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "handshake data follows the ServerHello across a key change");
        }

        std::vector<uint8_t> hs = Tls13HandshakeSecret(hash, BytesOf(ecdhe));
        Wipe(ecdhe);

        std::vector<uint8_t> th = transcriptHash();
        std::vector<uint8_t> chts = DeriveSecret(hash, BytesOf(hs), "c hs traffic", BytesOf(th));
        std::vector<uint8_t> shts = DeriveSecret(hash, BytesOf(hs), "s hs traffic", BytesOf(th));

        if (!Tls13InstallKeys(readCipher, *suite, BytesOf(shts)) || !Tls13InstallKeys(writeCipher, *suite, BytesOf(chts))) {
            wipeAll({ &hs, &chts, &shts });
            co_return co_await fail(-EIO, AD_INTERNAL_ERROR, "key derivation failed");
        }

        // -- EncryptedExtensions.

        HsMessage msg;
        rc = co_await readHandshake(msg);
        if (rc != SBOX_OK) {
            wipeAll({ &hs, &chts, &shts });
            co_return rc;
        }

        auto bail = [&](int32_t err, int32_t alert, std::string why) -> TTask<int32_t> {
            wipeAll({ &hs, &chts, &shts });
            co_return co_await fail(err, alert, std::move(why));
        };

        if (msg.type != HS_ENCRYPTED_EXTENSIONS) {
            co_return co_await bail(-EPROTO, AD_UNEXPECTED_MESSAGE, "expected EncryptedExtensions");
        }

        {
            Reader r(BytesOf(msg.body));
            Reader exts = r.block(2);
            std::set<uint16_t> seen;

            while (exts.ok() && exts.left() > 0) {
                uint16_t type = uint16_t(exts.u16());
                Reader data = exts.block(2);
                if (!exts.ok()) {
                    break;
                }

                if (!seen.insert(type).second) {
                    co_return co_await bail(-EPROTO, AD_ILLEGAL_PARAMETER, "EncryptedExtensions repeats an extension");
                }

                if (!offeredExtensions.count(type)) {
                    co_return co_await bail(-EPROTO, AD_UNSUPPORTED_EXTENSION, "EncryptedExtensions carries an extension that was not offered (" + std::to_string(type) + ")");
                }

                if (type == EXT_ALPN) {
                    Reader list = data.block(2);
                    std::string proto(TextOf(list.block(1).rest()));
                    if (!list.done() || proto.empty() || !data.done()) {
                        co_return co_await bail(-EPROTO, AD_DECODE_ERROR, "malformed ALPN extension");
                    }

                    if (!alpnAcceptable(proto)) {
                        co_return co_await bail(-EPROTO, AD_ILLEGAL_PARAMETER, "the server selected an ALPN protocol that was not offered");
                    }

                    report.alpn = proto;
                }
                else if (type == EXT_SERVER_NAME) {
                    if (data.left() != 0) {
                        co_return co_await bail(-EPROTO, AD_DECODE_ERROR, "malformed server_name acknowledgement");
                    }
                }
                else if (type != EXT_SUPPORTED_GROUPS) {
                    co_return co_await bail(-EPROTO, AD_ILLEGAL_PARAMETER, "EncryptedExtensions carries an extension not allowed there (" + std::to_string(type) + ")");
                }
            }

            if (!exts.done() || !r.done()) {
                co_return co_await bail(-EPROTO, AD_DECODE_ERROR, "malformed EncryptedExtensions");
            }
        }

        addTranscript(msg.raw);

        // -- CertificateRequest (optional) and Certificate.

        rc = co_await readHandshake(msg);
        if (rc != SBOX_OK) {
            wipeAll({ &hs, &chts, &shts });
            co_return rc;
        }

        bool certRequested = false;
        std::vector<uint8_t> requestContext;
        std::vector<uint16_t> requestSchemes;

        if (msg.type == HS_CERTIFICATE_REQUEST) {
            certRequested = true;
            Reader r(BytesOf(msg.body));
            requestContext = ToVector(r.block(1).rest());
            Reader exts = r.block(2);
            bool haveSchemes = false;

            while (exts.ok() && exts.left() > 0) {
                uint16_t type = uint16_t(exts.u16());
                Reader data = exts.block(2);
                if (type == EXT_SIGNATURE_ALGORITHMS) {
                    Reader list = data.block(2);
                    while (list.ok() && list.left() >= 2) {
                        requestSchemes.push_back(uint16_t(list.u16()));
                    }

                    haveSchemes = list.done() && data.done();
                }
            }

            if (!exts.done() || !r.done()) {
                co_return co_await bail(-EPROTO, AD_DECODE_ERROR, "malformed CertificateRequest");
            }

            if (!requestContext.empty()) {
                co_return co_await bail(-EPROTO, AD_ILLEGAL_PARAMETER, "CertificateRequest in the handshake has a non-empty context");
            }

            if (!haveSchemes) {
                co_return co_await bail(-EPROTO, AD_MISSING_EXTENSION, "CertificateRequest lacks signature_algorithms");
            }

            addTranscript(msg.raw);

            rc = co_await readHandshake(msg);
            if (rc != SBOX_OK) {
                wipeAll({ &hs, &chts, &shts });
                co_return rc;
            }
        }

        if (msg.type != HS_CERTIFICATE) {
            co_return co_await bail(-EPROTO, AD_UNEXPECTED_MESSAGE, "expected the server Certificate");
        }

        std::vector<std::vector<uint8_t>> chain;
        {
            Reader r(BytesOf(msg.body));
            Reader context = r.block(1);
            Reader list = r.block(3);

            while (list.ok() && list.left() > 0) {
                Reader data = list.block(3);
                Reader exts = list.block(2);
                if (!list.ok()) {
                    break;
                }

                if (data.left() == 0) {
                    co_return co_await bail(-EPROTO, AD_DECODE_ERROR, "empty certificate entry");
                }

                if (exts.left() != 0) {
                    // --> No status_request / SCT was offered, so none may come back.
                    co_return co_await bail(-EPROTO, AD_UNSUPPORTED_EXTENSION, "certificate entry carries an extension that was not requested");
                }

                chain.push_back(ToVector(data.rest()));
            }

            if (!list.done() || !r.done() || context.left() != 0) {
                co_return co_await bail(-EPROTO, AD_DECODE_ERROR, "malformed Certificate message");
            }
        }

        addTranscript(msg.raw);

        rc = co_await verifyServerCertificates(chain);
        if (rc != SBOX_OK) {
            wipeAll({ &hs, &chts, &shts });
            co_return rc;
        }

        // -- CertificateVerify.

        th = transcriptHash();
        rc = co_await readHandshake(msg);
        if (rc != SBOX_OK) {
            wipeAll({ &hs, &chts, &shts });
            co_return rc;
        }

        if (msg.type != HS_CERTIFICATE_VERIFY) {
            co_return co_await bail(-EPROTO, AD_UNEXPECTED_MESSAGE, "expected CertificateVerify");
        }

        {
            Reader r(BytesOf(msg.body));
            uint16_t scheme = uint16_t(r.u16());
            SReadOnlyByteSpan signature = r.block(2).rest();
            if (!r.done()) {
                co_return co_await bail(-EPROTO, AD_DECODE_ERROR, "malformed CertificateVerify");
            }

            bool offered = false;
            for (uint16_t s : offeredSchemes) {
                offered = offered || s == scheme;
            }

            if (!offered || !SchemeFitsKey(leaf, scheme, true)) {
                co_return co_await bail(-EPROTO, AD_ILLEGAL_PARAMETER, "CertificateVerify uses a signature scheme that was not offered or does not fit the key");
            }

            std::vector<uint8_t> content = Tls13SignedContent(true, BytesOf(th));
            if (VerifySignature(leaf, scheme, true, BytesOf(content), signature) != SBOX_OK) {
                co_return co_await bail(-EKEYREJECTED, AD_DECRYPT_ERROR, "the server CertificateVerify signature does not verify");
            }

            report.signatureScheme = scheme;
        }

        addTranscript(msg.raw);

        // -- Server Finished.

        th = transcriptHash();
        rc = co_await readHandshake(msg);
        if (rc != SBOX_OK) {
            wipeAll({ &hs, &chts, &shts });
            co_return rc;
        }

        if (msg.type != HS_FINISHED) {
            co_return co_await bail(-EPROTO, AD_UNEXPECTED_MESSAGE, "expected the server Finished");
        }

        {
            std::vector<uint8_t> expected = Tls13Finished(hash, BytesOf(shts), BytesOf(th));
            // --> Constant-time comparison (certpp CSecure).
            if (expected.empty() || !SecureEquals(BytesOf(msg.body), BytesOf(expected))) {
                co_return co_await bail(-EPROTO, AD_DECRYPT_ERROR, "the server Finished does not verify");
            }
        }

        addTranscript(msg.raw);
        serverFinished = true;

        if (!hsBuf.empty()) {
            co_return co_await bail(-EPROTO, AD_UNEXPECTED_MESSAGE, "handshake data follows the server Finished across a key change");
        }

        // -- Application secrets (transcript through the server Finished).

        th = transcriptHash();
        std::vector<uint8_t> master = Tls13MasterSecret(hash, BytesOf(hs));
        clientAppSecret = DeriveSecret(hash, BytesOf(master), "c ap traffic", BytesOf(th));
        serverAppSecret = DeriveSecret(hash, BytesOf(master), "s ap traffic", BytesOf(th));
        Wipe(master);

        if (clientAppSecret.empty() || serverAppSecret.empty()) {
            co_return co_await bail(-EIO, AD_INTERNAL_ERROR, "key derivation failed");
        }

        // -- Client flight.

        if (!compatCcsSent) {
            rc = co_await writeCcs(remaining(-1));
            if (rc != SBOX_OK) {
                wipeAll({ &hs, &chts, &shts });
                co_return failQuiet(rc, "failed to send change_cipher_spec");
            }

            compatCcsSent = true;
        }

        if (certRequested) {
            uint16_t scheme = pickClientScheme(requestSchemes, true);
            bool sendCert = clientKey && scheme != 0;

            std::vector<uint8_t> body;
            Writer w(body);
            w.begin(1);
            w.bytes(requestContext);
            w.end();
            w.begin(3);
            if (sendCert) {
                for (const auto& der : clientChain) {
                    w.begin(3);
                    w.bytes(der);
                    w.end();
                    w.begin(2);
                    w.end();
                }
            }
            w.end();

            rc = co_await sendHandshake(HS_CERTIFICATE, body);
            if (rc != SBOX_OK) {
                wipeAll({ &hs, &chts, &shts });
                co_return rc;
            }

            if (sendCert) {
                std::vector<uint8_t> cth = transcriptHash();
                std::vector<uint8_t> content = Tls13SignedContent(false, BytesOf(cth));
                std::vector<uint8_t> signature;
                if (SignMessage(clientLeaf, clientKey, scheme, BytesOf(content), signature) != SBOX_OK) {
                    co_return co_await bail(-EIO, AD_INTERNAL_ERROR, "signing the client CertificateVerify failed");
                }

                std::vector<uint8_t> cv;
                Writer cw(cv);
                cw.u16(scheme);
                cw.begin(2);
                cw.bytes(signature);
                cw.end();

                rc = co_await sendHandshake(HS_CERTIFICATE_VERIFY, cv);
                if (rc != SBOX_OK) {
                    wipeAll({ &hs, &chts, &shts });
                    co_return rc;
                }

                report.clientCertificateSent = true;
            }
        }

        th = transcriptHash();
        std::vector<uint8_t> finished = Tls13Finished(hash, BytesOf(chts), BytesOf(th));
        rc = co_await sendHandshake(HS_FINISHED, finished);
        wipeAll({ &hs, &chts, &shts });
        if (rc != SBOX_OK) {
            co_return rc;
        }

        if (!Tls13InstallKeys(readCipher, *suite, BytesOf(serverAppSecret))
            || !Tls13InstallKeys(writeCipher, *suite, BytesOf(clientAppSecret))) {
            co_return co_await fail(-EIO, AD_INTERNAL_ERROR, "key derivation failed");
        }

        co_return SBOX_OK;
    }

}
}
