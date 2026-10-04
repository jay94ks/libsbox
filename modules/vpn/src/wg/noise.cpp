#include "noise.hpp"

#include <certpp/crypto/aeads/chacha20poly1305.hpp>
#include <certpp/crypto/aeads/xchacha20poly1305.hpp>
#include <certpp/crypto/blake2smac.hpp>
#include <certpp/crypto/hashers/blake2s.hpp>
#include <certpp/crypto/hkdf.hpp>
#include <certpp/crypto/rng.hpp>
#include <certpp/utils/secure.hpp>
#include <ctime>

namespace sbox {
namespace vpn {

    namespace {

        constexpr char CONSTRUCTION[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
        constexpr char IDENTIFIER[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";

        /* Views a libsbox span as a libcertpp span (same layout). */
        inline certpp::SReadOnlyByteSpan cs(const SReadOnlyByteSpan& s) noexcept {
            return certpp::SReadOnlyByteSpan(s.data, s.size);
        }

        /* Views raw bytes as a libcertpp span. */
        inline certpp::SReadOnlyByteSpan cs(const uint8_t* p, size_t n) noexcept {
            return certpp::SReadOnlyByteSpan(p, n);
        }

        /* Views raw bytes as a mutable libcertpp span. */
        inline certpp::SByteSpan cm(uint8_t* p, size_t n) noexcept {
            return certpp::SByteSpan(p, n);
        }

        /* Builds the 96-bit AEAD nonce 0^32 || le64(counter). */
        inline void makeNonce(uint8_t nonce[12], uint64_t counter) noexcept {
            std::memset(nonce, 0, 4);
            StoreLe64(nonce + 4, counter);
        }

        /* Returns the initial chaining key HASH(CONSTRUCTION) (computed once). */
        const uint8_t* initialChainingKey() noexcept {
            static uint8_t ck[NOISE_HASH_BYTES];
            static bool done = false;
            if (!done) {
                NoiseHash(ck, BytesOf(std::string_view(CONSTRUCTION)));
                done = true;
            }

            return ck;
        }

        /* Returns the initial hash HASH(ck || IDENTIFIER) (computed once). */
        const uint8_t* initialHash() noexcept {
            static uint8_t h[NOISE_HASH_BYTES];
            static bool done = false;
            if (!done) {
                NoiseHash(h, SReadOnlyByteSpan(initialChainingKey(), NOISE_HASH_BYTES), BytesOf(std::string_view(IDENTIFIER)));
                done = true;
            }

            return h;
        }

        /* h = HASH(h || data). */
        inline void mixHash(uint8_t h[NOISE_HASH_BYTES], const uint8_t* data, size_t length) noexcept {
            NoiseHash(h, SReadOnlyByteSpan(h, NOISE_HASH_BYTES), SReadOnlyByteSpan(data, length));
        }

        /* X25519 over raw bytes. */
        bool dh(const uint8_t* priv, const uint8_t* pub, uint8_t out[32]) noexcept {
            return WgSharedSecret(SWgKey::fromBytes(priv), SWgKey::fromBytes(pub), out) == SBOX_OK;
        }

        /* Derives a public key from raw private bytes. */
        bool publicOf(const uint8_t* priv, uint8_t out[32]) noexcept {
            SWgKey pub;
            if (DeriveWgPublicKey(SWgKey::fromBytes(priv), pub) != SBOX_OK) {
                return false;
            }

            std::memcpy(out, pub.bytes, 32);
            return true;
        }

        /* Wipes several 32-byte temporaries on scope exit. */
        struct Wiper {
            uint8_t* items[4];
            size_t count;

            ~Wiper() {
                for (size_t i = 0; i < count; ++i) {
                    NoiseWipe(items[i], 32);
                }
            }
        };

    }

    /* Zeroes the handshake state. */
    void NoiseHandshake::clear() noexcept {
        NoiseWipe(this, sizeof(*this));
    }

    /* HASH over up to three parts. */
    void NoiseHash(uint8_t out[NOISE_HASH_BYTES], const SReadOnlyByteSpan& a, const SReadOnlyByteSpan& b,
        const SReadOnlyByteSpan& c) noexcept
    {
        certpp::crypto::BLAKE2s h;
        if (!a.empty()) {
            h.push(cs(a));
        }

        if (!b.empty()) {
            h.push(cs(b));
        }

        if (!c.empty()) {
            h.push(cs(c));
        }

        h.finish(cm(out, NOISE_HASH_BYTES));
    }

    /* Keyed BLAKE2s-128. */
    void NoiseMac(uint8_t out[NOISE_MAC_BYTES], const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& input) noexcept {
        certpp::crypto::CBlake2sMac::compute(cs(key), cs(input), cm(out, NOISE_MAC_BYTES));
    }

    /* KDF1..3 via HKDF-BLAKE2s. */
    void NoiseKdf(const uint8_t key[NOISE_HASH_BYTES], const SReadOnlyByteSpan& input, uint8_t* out1, uint8_t* out2,
        uint8_t* out3) noexcept
    {
        uint8_t prk[NOISE_HASH_BYTES];
        uint8_t okm[3 * NOISE_HASH_BYTES];
        size_t n = out3 ? 3 : (out2 ? 2 : 1);

        // --> HKDF-Extract(salt = key, ikm = input) is tau0 = HMAC(key, input); Expand with an
        // empty info string yields tau1 = HMAC(tau0, 0x1), tau2 = HMAC(tau0, tau1 || 0x2), ...
        // which is exactly the whitepaper's KDF_n.
        certpp::crypto::CHkdf::extract(certpp::crypto::EHASH_BLAKE2S, cs(key, NOISE_HASH_BYTES), cs(input), cm(prk, sizeof(prk)));
        certpp::crypto::CHkdf::expand(certpp::crypto::EHASH_BLAKE2S, cs(prk, sizeof(prk)), certpp::SReadOnlyByteSpan(),
            cm(okm, n * NOISE_HASH_BYTES));

        std::memcpy(out1, okm, NOISE_HASH_BYTES);
        if (out2) {
            std::memcpy(out2, okm + NOISE_HASH_BYTES, NOISE_HASH_BYTES);
        }

        if (out3) {
            std::memcpy(out3, okm + 2 * NOISE_HASH_BYTES, NOISE_HASH_BYTES);
        }

        NoiseWipe(prk, sizeof(prk));
        NoiseWipe(okm, sizeof(okm));
    }

    /* AEAD seal with a counter nonce. */
    bool NoiseSeal(const uint8_t key[32], uint64_t counter, const SReadOnlyByteSpan& plain, const SReadOnlyByteSpan& aad,
        uint8_t* out) noexcept
    {
        certpp::crypto::CChaCha20Poly1305 aead;
        uint8_t nonce[12];
        makeNonce(nonce, counter);

        if (!aead.reset(cs(key, 32))) {
            return false;
        }

        return aead.seal(cs(nonce, 12), cs(aad), cs(plain), cm(out, plain.size), cm(out + plain.size, NOISE_TAG_BYTES));
    }

    /* AEAD open with a counter nonce. */
    bool NoiseOpen(const uint8_t key[32], uint64_t counter, const uint8_t* box, size_t boxLength, const SReadOnlyByteSpan& aad,
        uint8_t* out) noexcept
    {
        if (boxLength < NOISE_TAG_BYTES) {
            return false;
        }

        certpp::crypto::CChaCha20Poly1305 aead;
        uint8_t nonce[12];
        makeNonce(nonce, counter);

        if (!aead.reset(cs(key, 32))) {
            return false;
        }

        size_t n = boxLength - NOISE_TAG_BYTES;
        return aead.open(cs(nonce, 12), cs(aad), cs(box, n), cs(box + n, NOISE_TAG_BYTES), cm(out, n));
    }

    /* Current TAI64N with reduced precision. */
    void NoiseTai64n(uint8_t out[NOISE_TIMESTAMP_BYTES]) noexcept {
        timespec ts;
        ::clock_gettime(CLOCK_REALTIME, &ts);

        // --> TAI64 label: 2^62 + seconds (+10 for the TAI-UTC offset at the epoch, as the
        // reference implementations do); big-endian. The nanoseconds are rounded down to a
        // multiple of 2^24 (~16.7 ms) so the timestamp is no fingerprint of the clock.
        uint64_t secs = 0x400000000000000aull + uint64_t(ts.tv_sec);
        uint32_t nsec = uint32_t(ts.tv_nsec) & ~((1u << 24) - 1u);

        for (int i = 7; i >= 0; --i) {
            out[i] = uint8_t(secs);
            secs >>= 8;
        }

        out[8] = uint8_t(nsec >> 24);
        out[9] = uint8_t(nsec >> 16);
        out[10] = uint8_t(nsec >> 8);
        out[11] = uint8_t(nsec);
    }

    /* Big-endian comparison of two timestamps. */
    bool NoiseTimestampAfter(const uint8_t a[NOISE_TIMESTAMP_BYTES], const uint8_t b[NOISE_TIMESTAMP_BYTES]) noexcept {
        return std::memcmp(a, b, NOISE_TIMESTAMP_BYTES) > 0;
    }

    /* HASH(label || key). */
    void NoiseLabelKey(const char* label, const SWgKey& publicKey, uint8_t out[NOISE_HASH_BYTES]) noexcept {
        NoiseHash(out, SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(label), 8), publicKey.span());
    }

    /* Initiator: builds the first message. */
    bool NoiseCreateInitiation(const SWgKey& localPublic, const SWgKey& remotePublic, const uint8_t staticStatic[32],
        const uint8_t ephemeralPrivate[32], const uint8_t timestamp[NOISE_TIMESTAMP_BYTES], uint32_t senderIndex,
        NoiseHandshake& hs, uint8_t* msg) noexcept
    {
        uint8_t ck[32], h[32], key[32], shared[32];
        Wiper wipe{ { ck, key, shared, nullptr }, 3 };

        std::memcpy(ck, initialChainingKey(), 32);
        std::memcpy(h, initialHash(), 32);
        mixHash(h, remotePublic.bytes, 32);

        std::memset(msg, 0, MSG_INITIATION_BYTES);
        StoreLe32(msg, MSG_INITIATION);
        StoreLe32(msg + OFF_SENDER, senderIndex);

        uint8_t* ephemeral = msg + OFF_INIT_EPHEMERAL;
        if (!publicOf(ephemeralPrivate, ephemeral)) {
            return false;
        }

        NoiseKdf(ck, SReadOnlyByteSpan(ephemeral, 32), ck);
        mixHash(h, ephemeral, 32);

        if (!dh(ephemeralPrivate, remotePublic.bytes, shared)) {
            return false;
        }

        NoiseKdf(ck, SReadOnlyByteSpan(shared, 32), ck, key);
        if (!NoiseSeal(key, 0, localPublic.span(), SReadOnlyByteSpan(h, 32), msg + OFF_INIT_STATIC)) {
            return false;
        }

        mixHash(h, msg + OFF_INIT_STATIC, 32 + NOISE_TAG_BYTES);

        NoiseKdf(ck, SReadOnlyByteSpan(staticStatic, 32), ck, key);
        if (!NoiseSeal(key, 0, SReadOnlyByteSpan(timestamp, NOISE_TIMESTAMP_BYTES), SReadOnlyByteSpan(h, 32), msg + OFF_INIT_TIMESTAMP)) {
            return false;
        }

        mixHash(h, msg + OFF_INIT_TIMESTAMP, NOISE_TIMESTAMP_BYTES + NOISE_TAG_BYTES);

        std::memcpy(hs.chainingKey, ck, 32);
        std::memcpy(hs.hash, h, 32);
        std::memcpy(hs.ephemeralPrivate, ephemeralPrivate, 32);
        std::memset(hs.remoteEphemeral, 0, 32);
        hs.localIndex = senderIndex;
        hs.remoteIndex = 0;
        return true;
    }

    /* Responder: decrypts the initiator's static key. */
    bool NoiseConsumeInitiationStatic(const SWgKey& localPrivate, const SWgKey& localPublic, const uint8_t* msg,
        NoiseHandshake& hs, SWgKey& remoteStatic) noexcept
    {
        uint8_t ck[32], h[32], key[32], shared[32];
        Wiper wipe{ { ck, key, shared, nullptr }, 3 };

        std::memcpy(ck, initialChainingKey(), 32);
        std::memcpy(h, initialHash(), 32);
        mixHash(h, localPublic.bytes, 32);

        const uint8_t* ephemeral = msg + OFF_INIT_EPHEMERAL;
        NoiseKdf(ck, SReadOnlyByteSpan(ephemeral, 32), ck);
        mixHash(h, ephemeral, 32);

        if (!dh(localPrivate.bytes, ephemeral, shared)) {
            return false;
        }

        NoiseKdf(ck, SReadOnlyByteSpan(shared, 32), ck, key);

        uint8_t spub[32];
        if (!NoiseOpen(key, 0, msg + OFF_INIT_STATIC, 32 + NOISE_TAG_BYTES, SReadOnlyByteSpan(h, 32), spub)) {
            return false;
        }

        mixHash(h, msg + OFF_INIT_STATIC, 32 + NOISE_TAG_BYTES);

        remoteStatic = SWgKey::fromBytes(spub);
        std::memcpy(hs.chainingKey, ck, 32);
        std::memcpy(hs.hash, h, 32);
        std::memcpy(hs.remoteEphemeral, ephemeral, 32);
        std::memset(hs.ephemeralPrivate, 0, 32);
        hs.remoteIndex = LoadLe32(msg + OFF_SENDER);
        hs.localIndex = 0;
        return true;
    }

    /* Responder: decrypts the timestamp. */
    bool NoiseConsumeInitiationFinish(NoiseHandshake& hs, const uint8_t staticStatic[32], const uint8_t* msg,
        uint8_t timestamp[NOISE_TIMESTAMP_BYTES]) noexcept
    {
        uint8_t ck[32], h[32], key[32];
        Wiper wipe{ { ck, key, nullptr, nullptr }, 2 };

        std::memcpy(ck, hs.chainingKey, 32);
        std::memcpy(h, hs.hash, 32);

        NoiseKdf(ck, SReadOnlyByteSpan(staticStatic, 32), ck, key);
        if (!NoiseOpen(key, 0, msg + OFF_INIT_TIMESTAMP, NOISE_TIMESTAMP_BYTES + NOISE_TAG_BYTES, SReadOnlyByteSpan(h, 32), timestamp)) {
            return false;
        }

        mixHash(h, msg + OFF_INIT_TIMESTAMP, NOISE_TIMESTAMP_BYTES + NOISE_TAG_BYTES);
        std::memcpy(hs.chainingKey, ck, 32);
        std::memcpy(hs.hash, h, 32);
        return true;
    }

    /* Responder: builds the second message. */
    bool NoiseCreateResponse(NoiseHandshake& hs, const SWgKey& remoteStatic, const uint8_t psk[32],
        const uint8_t ephemeralPrivate[32], uint32_t senderIndex, uint8_t* msg) noexcept
    {
        uint8_t ck[32], h[32], key[32], shared[32], tau[32];
        Wiper wipe{ { ck, key, shared, tau }, 4 };

        std::memcpy(ck, hs.chainingKey, 32);
        std::memcpy(h, hs.hash, 32);

        std::memset(msg, 0, MSG_RESPONSE_BYTES);
        StoreLe32(msg, MSG_RESPONSE);
        StoreLe32(msg + OFF_SENDER, senderIndex);
        StoreLe32(msg + OFF_RESP_RECEIVER, hs.remoteIndex);

        uint8_t* ephemeral = msg + OFF_RESP_EPHEMERAL;
        if (!publicOf(ephemeralPrivate, ephemeral)) {
            return false;
        }

        NoiseKdf(ck, SReadOnlyByteSpan(ephemeral, 32), ck);
        mixHash(h, ephemeral, 32);

        if (!dh(ephemeralPrivate, hs.remoteEphemeral, shared)) {
            return false;
        }

        NoiseKdf(ck, SReadOnlyByteSpan(shared, 32), ck);

        if (!dh(ephemeralPrivate, remoteStatic.bytes, shared)) {
            return false;
        }

        NoiseKdf(ck, SReadOnlyByteSpan(shared, 32), ck);

        NoiseKdf(ck, SReadOnlyByteSpan(psk, 32), ck, tau, key);
        mixHash(h, tau, 32);

        if (!NoiseSeal(key, 0, SReadOnlyByteSpan(), SReadOnlyByteSpan(h, 32), msg + OFF_RESP_EMPTY)) {
            return false;
        }

        mixHash(h, msg + OFF_RESP_EMPTY, NOISE_TAG_BYTES);

        std::memcpy(hs.chainingKey, ck, 32);
        std::memcpy(hs.hash, h, 32);
        std::memcpy(hs.ephemeralPrivate, ephemeralPrivate, 32);
        hs.localIndex = senderIndex;
        return true;
    }

    /* Initiator: consumes the second message. */
    bool NoiseConsumeResponse(NoiseHandshake& hs, const SWgKey& localPrivate, const uint8_t psk[32], const uint8_t* msg) noexcept {
        uint8_t ck[32], h[32], key[32], shared[32], tau[32];
        Wiper wipe{ { ck, key, shared, tau }, 4 };

        std::memcpy(ck, hs.chainingKey, 32);
        std::memcpy(h, hs.hash, 32);

        const uint8_t* ephemeral = msg + OFF_RESP_EPHEMERAL;
        NoiseKdf(ck, SReadOnlyByteSpan(ephemeral, 32), ck);
        mixHash(h, ephemeral, 32);

        if (!dh(hs.ephemeralPrivate, ephemeral, shared)) {
            return false;
        }

        NoiseKdf(ck, SReadOnlyByteSpan(shared, 32), ck);

        if (!dh(localPrivate.bytes, ephemeral, shared)) {
            return false;
        }

        NoiseKdf(ck, SReadOnlyByteSpan(shared, 32), ck);

        NoiseKdf(ck, SReadOnlyByteSpan(psk, 32), ck, tau, key);
        mixHash(h, tau, 32);

        uint8_t empty[1];
        if (!NoiseOpen(key, 0, msg + OFF_RESP_EMPTY, NOISE_TAG_BYTES, SReadOnlyByteSpan(h, 32), empty)) {
            return false;
        }

        mixHash(h, msg + OFF_RESP_EMPTY, NOISE_TAG_BYTES);

        std::memcpy(hs.chainingKey, ck, 32);
        std::memcpy(hs.hash, h, 32);
        std::memcpy(hs.remoteEphemeral, ephemeral, 32);
        hs.remoteIndex = LoadLe32(msg + OFF_SENDER);
        return true;
    }

    /* Splits the chaining key into the two transport keys. */
    void NoiseDeriveKeys(const NoiseHandshake& hs, bool initiator, uint8_t sendKey[32], uint8_t recvKey[32]) noexcept {
        if (initiator) {
            NoiseKdf(hs.chainingKey, SReadOnlyByteSpan(), sendKey, recvKey);
        }
        else {
            NoiseKdf(hs.chainingKey, SReadOnlyByteSpan(), recvKey, sendKey);
        }
    }

    /* MAC(secret, ip || be16(port)). */
    void NoiseMakeCookie(const uint8_t secret[32], const uint8_t* address, size_t addressLength, uint16_t port,
        uint8_t out[NOISE_COOKIE_BYTES]) noexcept
    {
        uint8_t input[18];
        std::memcpy(input, address, addressLength);
        input[addressLength] = uint8_t(port >> 8);
        input[addressLength + 1] = uint8_t(port);
        NoiseMac(out, SReadOnlyByteSpan(secret, 32), SReadOnlyByteSpan(input, addressLength + 2));
    }

    /* Builds a cookie reply. */
    bool NoiseCreateCookieReply(const uint8_t cookieKey[32], uint32_t receiver, const uint8_t nonce[NOISE_COOKIE_NONCE_BYTES],
        const uint8_t cookie[NOISE_COOKIE_BYTES], const uint8_t mac1[NOISE_MAC_BYTES], uint8_t* msg) noexcept
    {
        std::memset(msg, 0, MSG_COOKIE_REPLY_BYTES);
        StoreLe32(msg, MSG_COOKIE_REPLY);
        StoreLe32(msg + OFF_COOKIE_RECEIVER, receiver);
        std::memcpy(msg + OFF_COOKIE_NONCE, nonce, NOISE_COOKIE_NONCE_BYTES);

        certpp::crypto::CXChaCha20Poly1305 aead;
        if (!aead.reset(cs(cookieKey, 32))) {
            return false;
        }

        return aead.seal(cs(nonce, NOISE_COOKIE_NONCE_BYTES), cs(mac1, NOISE_MAC_BYTES), cs(cookie, NOISE_COOKIE_BYTES),
            cm(msg + OFF_COOKIE_DATA, NOISE_COOKIE_BYTES), cm(msg + OFF_COOKIE_DATA + NOISE_COOKIE_BYTES, NOISE_TAG_BYTES));
    }

    /* Decrypts a cookie reply. */
    bool NoiseConsumeCookieReply(const uint8_t cookieKey[32], const uint8_t* msg, const uint8_t mac1[NOISE_MAC_BYTES],
        uint8_t cookie[NOISE_COOKIE_BYTES]) noexcept
    {
        certpp::crypto::CXChaCha20Poly1305 aead;
        if (!aead.reset(cs(cookieKey, 32))) {
            return false;
        }

        return aead.open(cs(msg + OFF_COOKIE_NONCE, NOISE_COOKIE_NONCE_BYTES), cs(mac1, NOISE_MAC_BYTES),
            cs(msg + OFF_COOKIE_DATA, NOISE_COOKIE_BYTES), cs(msg + OFF_COOKIE_DATA + NOISE_COOKIE_BYTES, NOISE_TAG_BYTES),
            cm(cookie, NOISE_COOKIE_BYTES));
    }

    /* CSPRNG bytes. */
    void NoiseRandom(uint8_t* out, size_t length) noexcept {
        certpp::crypto::CRng::fill(cm(out, length));
    }

    /* Non-elidable wipe. */
    void NoiseWipe(void* data, size_t length) noexcept {
        certpp::CSecure::zero(cm(static_cast<uint8_t*>(data), length));
    }

}
}
