#ifndef __SRC_VPN_WG_NOISE_HPP__
#define __SRC_VPN_WG_NOISE_HPP__

#include <sbox/vpn/wg/key.hpp>
#include <cstring>

namespace sbox {
namespace vpn {

    // --> Private building blocks of the WireGuard protocol (whitepaper section 5): the
    // Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s handshake as pure functions over explicit inputs, the
    // MAC/cookie machinery and the wire layout. No I/O and no clocks live here, so the known-answer
    // tests can drive every step with fixed ephemeral keys and timestamps.

    constexpr size_t NOISE_HASH_BYTES = 32;
    constexpr size_t NOISE_TAG_BYTES = 16;
    constexpr size_t NOISE_MAC_BYTES = 16;
    constexpr size_t NOISE_TIMESTAMP_BYTES = 12;
    constexpr size_t NOISE_COOKIE_BYTES = 16;
    constexpr size_t NOISE_COOKIE_NONCE_BYTES = 24;

    // -- Message types and sizes.
    constexpr uint32_t MSG_INITIATION = 1;
    constexpr uint32_t MSG_RESPONSE = 2;
    constexpr uint32_t MSG_COOKIE_REPLY = 3;
    constexpr uint32_t MSG_DATA = 4;

    constexpr size_t MSG_INITIATION_BYTES = 148;
    constexpr size_t MSG_RESPONSE_BYTES = 92;
    constexpr size_t MSG_COOKIE_REPLY_BYTES = 64;
    constexpr size_t MSG_DATA_HEADER_BYTES = 16;
    constexpr size_t MSG_DATA_MIN_BYTES = MSG_DATA_HEADER_BYTES + NOISE_TAG_BYTES;

    // -- Field offsets.
    constexpr size_t OFF_SENDER = 4;            // --> Initiation and response.
    constexpr size_t OFF_INIT_EPHEMERAL = 8;
    constexpr size_t OFF_INIT_STATIC = 40;      // --> 32 + 16 bytes.
    constexpr size_t OFF_INIT_TIMESTAMP = 88;   // --> 12 + 16 bytes.
    constexpr size_t OFF_INIT_MAC1 = 116;
    constexpr size_t OFF_INIT_MAC2 = 132;
    constexpr size_t OFF_RESP_RECEIVER = 8;
    constexpr size_t OFF_RESP_EPHEMERAL = 12;
    constexpr size_t OFF_RESP_EMPTY = 44;       // --> 0 + 16 bytes.
    constexpr size_t OFF_RESP_MAC1 = 60;
    constexpr size_t OFF_RESP_MAC2 = 76;
    constexpr size_t OFF_COOKIE_RECEIVER = 4;
    constexpr size_t OFF_COOKIE_NONCE = 8;
    constexpr size_t OFF_COOKIE_DATA = 32;      // --> 16 + 16 bytes.
    constexpr size_t OFF_DATA_RECEIVER = 4;
    constexpr size_t OFF_DATA_COUNTER = 8;

    /** Reads a little-endian u32. */
    inline uint32_t LoadLe32(const uint8_t* p) noexcept {
        return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    }

    /** Writes a little-endian u32. */
    inline void StoreLe32(uint8_t* p, uint32_t v) noexcept {
        p[0] = uint8_t(v);
        p[1] = uint8_t(v >> 8);
        p[2] = uint8_t(v >> 16);
        p[3] = uint8_t(v >> 24);
    }

    /** Reads a little-endian u64. */
    inline uint64_t LoadLe64(const uint8_t* p) noexcept {
        return uint64_t(LoadLe32(p)) | (uint64_t(LoadLe32(p + 4)) << 32);
    }

    /** Writes a little-endian u64. */
    inline void StoreLe64(uint8_t* p, uint64_t v) noexcept {
        StoreLe32(p, uint32_t(v));
        StoreLe32(p + 4, uint32_t(v >> 32));
    }

    /**
     * Symmetric handshake state of one side: chaining key, transcript hash, ephemeral keys and
     * the session indices.
     */
    struct NoiseHandshake {
        uint8_t chainingKey[NOISE_HASH_BYTES];
        uint8_t hash[NOISE_HASH_BYTES];
        uint8_t ephemeralPrivate[WG_KEY_BYTES];
        uint8_t remoteEphemeral[WG_KEY_BYTES];
        uint32_t localIndex;
        uint32_t remoteIndex;

        /** Zeroes everything. */
        void clear() noexcept;
    };

    /**
     * HASH(a || b || c): BLAKE2s-256 over the concatenation (empty parts allowed).
     */
    void NoiseHash(uint8_t out[NOISE_HASH_BYTES], const SReadOnlyByteSpan& a, const SReadOnlyByteSpan& b = SReadOnlyByteSpan(),
        const SReadOnlyByteSpan& c = SReadOnlyByteSpan()) noexcept;

    /**
     * MAC(key, input): keyed BLAKE2s with a 16-byte tag (key of 16 or 32 bytes).
     */
    void NoiseMac(uint8_t out[NOISE_MAC_BYTES], const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& input) noexcept;

    /**
     * KDF_n(key, input) for n = 1..3: HKDF over HMAC-BLAKE2s with an empty info string.
     */
    void NoiseKdf(const uint8_t key[NOISE_HASH_BYTES], const SReadOnlyByteSpan& input, uint8_t* out1, uint8_t* out2 = nullptr,
        uint8_t* out3 = nullptr) noexcept;

    /**
     * AEAD(key, counter, plain, aad): ChaCha20-Poly1305 with the nonce 0^32 || le64(counter).
     * `out` receives plain.size + 16 bytes and may alias the plaintext.
     */
    bool NoiseSeal(const uint8_t key[32], uint64_t counter, const SReadOnlyByteSpan& plain, const SReadOnlyByteSpan& aad,
        uint8_t* out) noexcept;

    /**
     * Opens an AEAD(key, counter, ...) box of `boxLength` bytes (ciphertext + tag) into `out`
     * (which may alias the box). Nothing is written when authentication fails.
     */
    bool NoiseOpen(const uint8_t key[32], uint64_t counter, const uint8_t* box, size_t boxLength, const SReadOnlyByteSpan& aad,
        uint8_t* out) noexcept;

    /**
     * Fills `out` with the current TAI64N timestamp (12 bytes), its nanoseconds rounded down to
     * a multiple of 2^24 like the kernel does, so it does not leak a precise clock.
     */
    void NoiseTai64n(uint8_t out[NOISE_TIMESTAMP_BYTES]) noexcept;

    /**
     * Returns true when the TAI64N value `a` is greater than `b`.
     */
    bool NoiseTimestampAfter(const uint8_t a[NOISE_TIMESTAMP_BYTES], const uint8_t b[NOISE_TIMESTAMP_BYTES]) noexcept;

    /**
     * Precomputes HASH(label || publicKey) (the MAC1 key with "mac1----", the cookie key with
     * "cookie--").
     */
    void NoiseLabelKey(const char* label, const SWgKey& publicKey, uint8_t out[NOISE_HASH_BYTES]) noexcept;

    /**
     * Creates a handshake initiation (all fields except MAC1/MAC2) and fills `hs`.
     * @param staticStatic The precomputed DH(local private, remote public).
     * @param ephemeralPrivate The initiator's ephemeral private key (random in production).
     * @param timestamp TAI64N timestamp.
     * @param msg Receives MSG_INITIATION_BYTES.
     */
    bool NoiseCreateInitiation(const SWgKey& localPublic, const SWgKey& remotePublic, const uint8_t staticStatic[32],
        const uint8_t ephemeralPrivate[32], const uint8_t timestamp[NOISE_TIMESTAMP_BYTES], uint32_t senderIndex,
        NoiseHandshake& hs, uint8_t* msg) noexcept;

    /**
     * First half of consuming an initiation: decrypts the initiator's static key.
     * On success `hs` holds the intermediate state for NoiseConsumeInitiationFinish().
     */
    bool NoiseConsumeInitiationStatic(const SWgKey& localPrivate, const SWgKey& localPublic, const uint8_t* msg,
        NoiseHandshake& hs, SWgKey& remoteStatic) noexcept;

    /**
     * Second half: mixes DH(static, static) and decrypts the timestamp.
     */
    bool NoiseConsumeInitiationFinish(NoiseHandshake& hs, const uint8_t staticStatic[32], const uint8_t* msg,
        uint8_t timestamp[NOISE_TIMESTAMP_BYTES]) noexcept;

    /**
     * Creates a handshake response (all fields except MAC1/MAC2) from a consumed initiation.
     * @param psk The preshared key (all zero when none).
     */
    bool NoiseCreateResponse(NoiseHandshake& hs, const SWgKey& remoteStatic, const uint8_t psk[32],
        const uint8_t ephemeralPrivate[32], uint32_t senderIndex, uint8_t* msg) noexcept;

    /**
     * Consumes a response on the initiator's state `hs` (left untouched on failure).
     */
    bool NoiseConsumeResponse(NoiseHandshake& hs, const SWgKey& localPrivate, const uint8_t psk[32], const uint8_t* msg) noexcept;

    /**
     * Derives the transport keys from a finished handshake.
     */
    void NoiseDeriveKeys(const NoiseHandshake& hs, bool initiator, uint8_t sendKey[32], uint8_t recvKey[32]) noexcept;

    /**
     * Computes the cookie of a source address: MAC(secret, ip || port).
     */
    void NoiseMakeCookie(const uint8_t secret[32], const uint8_t* address, size_t addressLength, uint16_t port,
        uint8_t out[NOISE_COOKIE_BYTES]) noexcept;

    /**
     * Builds a cookie reply message.
     * @param cookieKey HASH("cookie--" || the replier's public key).
     * @param receiver Sender index of the message being answered.
     * @param mac1 MAC1 of the message being answered (the AEAD's additional data).
     */
    bool NoiseCreateCookieReply(const uint8_t cookieKey[32], uint32_t receiver, const uint8_t nonce[NOISE_COOKIE_NONCE_BYTES],
        const uint8_t cookie[NOISE_COOKIE_BYTES], const uint8_t mac1[NOISE_MAC_BYTES], uint8_t* msg) noexcept;

    /**
     * Decrypts a cookie reply.
     * @param cookieKey HASH("cookie--" || the peer's public key).
     * @param mac1 The MAC1 we last sent to that peer.
     */
    bool NoiseConsumeCookieReply(const uint8_t cookieKey[32], const uint8_t* msg, const uint8_t mac1[NOISE_MAC_BYTES],
        uint8_t cookie[NOISE_COOKIE_BYTES]) noexcept;

    /**
     * Fills `out` with random bytes from the CSPRNG.
     */
    void NoiseRandom(uint8_t* out, size_t length) noexcept;

    /**
     * Wipes a buffer in a way the compiler cannot drop.
     */
    void NoiseWipe(void* data, size_t length) noexcept;

}
}

#endif
