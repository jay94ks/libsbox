#include <sbox/image/digest.hpp>
#include <certpp/crypto/hashers/sha256.hpp>
#include <certpp/crypto/hashers/sha512.hpp>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

namespace sbox {
namespace image {

    namespace {

        /* Returns the hex length of an algorithm's digests. */
        size_t hexLength(EDigestAlgorithm algorithm) noexcept {
            switch (algorithm) {
            case EDIGEST_SHA256: return 64;
            case EDIGEST_SHA512: return 128;
            default: return 0;
            }
        }

        /* Returns true for [a-z0-9]. */
        bool isLowerAlnum(char c) noexcept {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        }

        /* Encodes bytes as lower-case hex. */
        std::string toHex(const uint8_t* data, size_t size) {
            static const char DIGITS[] = "0123456789abcdef";
            std::string out(size * 2, '0');
            for (size_t i = 0; i < size; ++i) {
                out[i * 2] = DIGITS[data[i] >> 4];
                out[i * 2 + 1] = DIGITS[data[i] & 15];
            }

            return out;
        }

    }

    /* Checks a digest string. */
    int32_t ValidateDigest(std::string_view digest) noexcept {
        size_t colon = digest.find(':');
        if (colon == std::string_view::npos || colon == 0 || colon + 1 >= digest.size()) {
            return -EINVAL;
        }

        // --> OCI grammar: algorithm-component (separator algorithm-component)*, with
        // components [a-z0-9]+ and separators [+._-].
        std::string_view alg = digest.substr(0, colon);
        bool lastSep = true;
        for (char c : alg) {
            if (isLowerAlnum(c)) {
                lastSep = false;
            } else if (c == '+' || c == '.' || c == '_' || c == '-') {
                if (lastSep) {
                    return -EINVAL;
                }

                lastSep = true;
            } else {
                return -EINVAL;
            }
        }

        if (lastSep) {
            return -EINVAL;
        }

        std::string_view hex = digest.substr(colon + 1);
        for (char c : hex) {
            bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                      c == '=' || c == '_' || c == '-';
            if (!ok) {
                return -EINVAL;
            }
        }

        EDigestAlgorithm a = DigestAlgorithm(digest);
        if (a == EDIGEST_INVALID) {
            return -ENOTSUP;
        }

        if (hex.size() != hexLength(a)) {
            return -EINVAL;
        }

        for (char c : hex) {
            if (!((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9'))) {
                return -EINVAL;
            }
        }

        return SBOX_OK;
    }

    /* Returns the algorithm of a digest string. */
    EDigestAlgorithm DigestAlgorithm(std::string_view digest) noexcept {
        size_t colon = digest.find(':');
        if (colon == std::string_view::npos) {
            return EDIGEST_INVALID;
        }

        std::string_view alg = digest.substr(0, colon);
        if (alg == "sha256") {
            return EDIGEST_SHA256;
        }

        if (alg == "sha512") {
            return EDIGEST_SHA512;
        }

        return EDIGEST_INVALID;
    }

    /* Returns the encoded part of a digest. */
    std::string_view DigestHex(std::string_view digest) noexcept {
        size_t colon = digest.find(':');
        return colon == std::string_view::npos ? digest : digest.substr(colon + 1);
    }

    /* Returns the algorithm name. */
    const char* DigestAlgorithmName(EDigestAlgorithm algorithm) noexcept {
        switch (algorithm) {
        case EDIGEST_SHA256: return "sha256";
        case EDIGEST_SHA512: return "sha512";
        default: return "invalid";
        }
    }

    struct CDigester::SImpl {
        EDigestAlgorithm algorithm;
        certpp::crypto::SHA256 sha256;
        certpp::crypto::SHA512 sha512;
        uint64_t size = 0;
    };

    /* Starts a digest. */
    CDigester::CDigester(EDigestAlgorithm algorithm) : _impl(std::make_unique<SImpl>()) {
        _impl->algorithm = algorithm == EDIGEST_SHA512 ? EDIGEST_SHA512 : EDIGEST_SHA256;
    }

    /* Destroys the digester. */
    CDigester::~CDigester() = default;

    CDigester::CDigester(CDigester&& other) noexcept = default;

    CDigester& CDigester::operator=(CDigester&& other) noexcept = default;

    /* Feeds bytes. */
    void CDigester::update(const SReadOnlyByteSpan& data) {
        if (data.size == 0) {
            return;
        }

        certpp::SReadOnlyByteSpan span(data.data, data.size);
        if (_impl->algorithm == EDIGEST_SHA512) {
            _impl->sha512.push(span);
        } else {
            _impl->sha256.push(span);
        }

        _impl->size += data.size;
    }

    /* Returns the number of bytes fed so far. */
    uint64_t CDigester::size() const noexcept {
        return _impl->size;
    }

    /* Finishes the digest. */
    std::string CDigester::finish() {
        uint8_t out[64];
        std::string text;
        if (_impl->algorithm == EDIGEST_SHA512) {
            _impl->sha512.finish(certpp::SByteSpan(out, 64));
            _impl->sha512.reset();
            text = "sha512:" + toHex(out, 64);
        } else {
            _impl->sha256.finish(certpp::SByteSpan(out, 32));
            _impl->sha256.reset();
            text = "sha256:" + toHex(out, 32);
        }

        _impl->size = 0;
        return text;
    }

    /* Returns the digest of a byte buffer. */
    std::string DigestOf(const SReadOnlyByteSpan& data, EDigestAlgorithm algorithm) {
        CDigester d(algorithm);
        d.update(data);
        return d.finish();
    }

    /* Computes the digest of a file. */
    int32_t DigestFile(const std::string& path, std::string& digest, uint64_t* size, EDigestAlgorithm algorithm) {
        int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            return -errno;
        }

        CDigester d(algorithm);
        std::vector<uint8_t> buf(size_t(1) << 17);
        while (true) {
            ssize_t n = ::read(fd, buf.data(), buf.size());
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }

                int32_t err = -errno;
                ::close(fd);
                return err;
            }

            if (n == 0) {
                break;
            }

            d.update(SReadOnlyByteSpan(buf.data(), size_t(n)));
        }

        ::close(fd);
        if (size) {
            *size = d.size();
        }

        digest = d.finish();
        return SBOX_OK;
    }

    /* Returns the chain ID of a layer. */
    std::string ChainId(std::string_view parentChainId, std::string_view diffId) {
        if (parentChainId.empty()) {
            return std::string(diffId);
        }

        std::string text;
        text.reserve(parentChainId.size() + 1 + diffId.size());
        text.append(parentChainId);
        text.push_back(' ');
        text.append(diffId);
        return DigestOf(text);
    }

    /* Returns the chain IDs of a diffID list. */
    std::vector<std::string> ChainIds(const std::vector<std::string>& diffIds) {
        std::vector<std::string> out;
        out.reserve(diffIds.size());
        std::string parent;
        for (const std::string& d : diffIds) {
            parent = ChainId(parent, d);
            out.push_back(parent);
        }

        return out;
    }

}
}
