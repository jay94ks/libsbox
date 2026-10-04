#include "keyschedule.hpp"
#include <cstring>

namespace sbox {
namespace tls {

    /* TLS 1.3 handshake secret. */
    std::vector<uint8_t> Tls13HandshakeSecret(HashAlg hash, const SReadOnlyByteSpan& ecdhe) {
        std::vector<uint8_t> early = HkdfExtract(hash, SReadOnlyByteSpan(), SReadOnlyByteSpan());
        std::vector<uint8_t> empty = Hash(hash, SReadOnlyByteSpan());
        std::vector<uint8_t> derived = DeriveSecret(hash, BytesOf(early), "derived", BytesOf(empty));
        std::vector<uint8_t> out = HkdfExtract(hash, BytesOf(derived), ecdhe);
        Wipe(early);
        Wipe(derived);
        return out;
    }

    /* TLS 1.3 master secret. */
    std::vector<uint8_t> Tls13MasterSecret(HashAlg hash, const SReadOnlyByteSpan& handshakeSecret) {
        std::vector<uint8_t> empty = Hash(hash, SReadOnlyByteSpan());
        std::vector<uint8_t> derived = DeriveSecret(hash, handshakeSecret, "derived", BytesOf(empty));
        std::vector<uint8_t> out = HkdfExtract(hash, BytesOf(derived), SReadOnlyByteSpan());
        Wipe(derived);
        return out;
    }

    /* Traffic key and IV. */
    bool Tls13TrafficKeys(const SuiteInfo& suite, const SReadOnlyByteSpan& secret,
                          std::vector<uint8_t>& key, std::vector<uint8_t>& iv) {
        key = HkdfExpandLabel(suite.hash, secret, "key", SReadOnlyByteSpan(), suite.keyLength);
        iv = HkdfExpandLabel(suite.hash, secret, "iv", SReadOnlyByteSpan(), 12);
        return key.size() == suite.keyLength && iv.size() == 12;
    }

    /* Keys a cipher from a traffic secret. */
    bool Tls13InstallKeys(RecordCipher& cipher, const SuiteInfo& suite, const SReadOnlyByteSpan& secret) {
        std::vector<uint8_t> key, iv;
        bool ok = Tls13TrafficKeys(suite, secret, key, iv) && cipher.init(suite, BytesOf(key), BytesOf(iv));
        Wipe(key);
        Wipe(iv);
        return ok;
    }

    /* Finished verify_data. */
    std::vector<uint8_t> Tls13Finished(HashAlg hash, const SReadOnlyByteSpan& baseSecret,
                                       const SReadOnlyByteSpan& transcriptHash) {
        std::vector<uint8_t> finishedKey = HkdfExpandLabel(hash, baseSecret, "finished", SReadOnlyByteSpan(), HashSize(hash));
        std::vector<uint8_t> out = Hmac(hash, BytesOf(finishedKey), transcriptHash);
        Wipe(finishedKey);
        return out;
    }

    /* KeyUpdate secret. */
    std::vector<uint8_t> Tls13NextSecret(HashAlg hash, const SReadOnlyByteSpan& secret) {
        return HkdfExpandLabel(hash, secret, "traffic upd", SReadOnlyByteSpan(), HashSize(hash));
    }

    /* CertificateVerify content. */
    std::vector<uint8_t> Tls13SignedContent(bool server, const SReadOnlyByteSpan& transcriptHash) {
        std::vector<uint8_t> out(64, 0x20);
        std::string_view label = server ? "TLS 1.3, server CertificateVerify" : "TLS 1.3, client CertificateVerify";
        out.insert(out.end(), label.begin(), label.end());
        out.push_back(0);
        out.insert(out.end(), transcriptHash.data, transcriptHash.data + transcriptHash.size);
        return out;
    }

    /* Extended master secret. */
    std::vector<uint8_t> Tls12ExtendedMasterSecret(HashAlg hash, const SReadOnlyByteSpan& preMaster,
                                                   const SReadOnlyByteSpan& sessionHash) {
        return Prf12(hash, preMaster, "extended master secret", sessionHash, 48);
    }

    /* TLS 1.2 key block. */
    bool Tls12InstallKeys(const SuiteInfo& suite, const SReadOnlyByteSpan& master,
                          const SReadOnlyByteSpan& clientRandom, const SReadOnlyByteSpan& serverRandom,
                          RecordCipher& clientWrite, RecordCipher& serverWrite) {
        std::vector<uint8_t> seed;
        seed.insert(seed.end(), serverRandom.data, serverRandom.data + serverRandom.size);
        seed.insert(seed.end(), clientRandom.data, clientRandom.data + clientRandom.size);

        size_t k = suite.keyLength, v = suite.ivLength;
        std::vector<uint8_t> block = Prf12(suite.hash, master, "key expansion", BytesOf(seed), 2 * k + 2 * v);
        if (block.size() != 2 * k + 2 * v) {
            return false;
        }

        const uint8_t* p = block.data();
        bool ok = clientWrite.init(suite, SReadOnlyByteSpan(p, k), SReadOnlyByteSpan(p + 2 * k, v))
            && serverWrite.init(suite, SReadOnlyByteSpan(p + k, k), SReadOnlyByteSpan(p + 2 * k + v, v));
        Wipe(block);
        return ok;
    }

    /* TLS 1.2 Finished. */
    std::vector<uint8_t> Tls12Finished(HashAlg hash, const SReadOnlyByteSpan& master, bool client,
                                       const SReadOnlyByteSpan& transcriptHash) {
        return Prf12(hash, master, client ? "client finished" : "server finished", transcriptHash, 12);
    }

}
}
