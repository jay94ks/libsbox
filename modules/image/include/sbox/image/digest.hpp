#ifndef __INCLUDE_SBOX_IMAGE_DIGEST_HPP__
#define __INCLUDE_SBOX_IMAGE_DIGEST_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>

namespace sbox {
namespace image {

    /**
     * Content digest algorithms (OCI image spec "digests": sha256 is the default, sha512 is
     * registered as well).
     */
    enum EDigestAlgorithm {
        EDIGEST_SHA256 = 0,
        EDIGEST_SHA512,
        EDIGEST_INVALID,
    };

    /**
     * Checks a digest string ("sha256:<64 lower-case hex>" or "sha512:<128 lower-case hex>").
     * @return SBOX_OK, -EINVAL when malformed, -ENOTSUP for a well-formed digest of an
     *         algorithm this module cannot compute.
     */
    SBOX_API int32_t ValidateDigest(std::string_view digest) noexcept;

    /**
     * Returns the algorithm of a digest string, EDIGEST_INVALID when unknown.
     */
    SBOX_API EDigestAlgorithm DigestAlgorithm(std::string_view digest) noexcept;

    /**
     * Returns the encoded part of a digest ("sha256:abcd" -> "abcd"), or the whole text when it
     * has no algorithm prefix.
     */
    SBOX_API std::string_view DigestHex(std::string_view digest) noexcept;

    /**
     * Returns the algorithm name ("sha256").
     */
    SBOX_API const char* DigestAlgorithmName(EDigestAlgorithm algorithm) noexcept;

    /**
     * Incremental digest computation over libcertpp's SHA-256 / SHA-512.
     */
    class SBOX_API CDigester {
    private:
        struct SImpl;
        std::unique_ptr<SImpl> _impl;

    public:
        /**
         * Starts a digest of the given algorithm.
         */
        explicit CDigester(EDigestAlgorithm algorithm = EDIGEST_SHA256);

        /** Destroys the digester. */
        ~CDigester();

        CDigester(CDigester&& other) noexcept;

        CDigester& operator=(CDigester&& other) noexcept;

        CDigester(const CDigester&) = delete;

        CDigester& operator=(const CDigester&) = delete;

        /**
         * Feeds bytes.
         */
        void update(const SReadOnlyByteSpan& data);

        /**
         * Feeds text.
         */
        inline void update(std::string_view text) { update(BytesOf(text)); }

        /**
         * Returns the number of bytes fed so far.
         */
        uint64_t size() const noexcept;

        /**
         * Finishes and returns "<algorithm>:<hex>". The digester restarts afterwards.
         */
        std::string finish();
    };

    /**
     * Returns the digest of a byte buffer.
     */
    SBOX_API std::string DigestOf(const SReadOnlyByteSpan& data, EDigestAlgorithm algorithm = EDIGEST_SHA256);

    /**
     * Returns the digest of a text.
     */
    inline std::string DigestOf(std::string_view text, EDigestAlgorithm algorithm = EDIGEST_SHA256) {
        return DigestOf(BytesOf(text), algorithm);
    }

    /**
     * Computes the digest of a file.
     * @param size Receives the file size when not null.
     * @return SBOX_OK or a negated errno.
     */
    SBOX_API int32_t DigestFile(const std::string& path, std::string& digest, uint64_t* size = nullptr,
                                EDigestAlgorithm algorithm = EDIGEST_SHA256);

    /**
     * Returns the chain ID of a layer on top of `parentChainId` (OCI image spec "ChainID":
     * sha256(parent + " " + diffID); the first layer's chain ID is its diffID).
     * @param parentChainId Empty for the bottom layer.
     */
    SBOX_API std::string ChainId(std::string_view parentChainId, std::string_view diffId);

    /**
     * Returns the chain IDs of every layer of a diffID list (bottom first).
     */
    SBOX_API std::vector<std::string> ChainIds(const std::vector<std::string>& diffIds);

}
}

#endif
