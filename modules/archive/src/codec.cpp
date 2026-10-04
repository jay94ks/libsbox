#include <sbox/archive/codec.hpp>
#include <sbox/archive/deflate.hpp>
#include <sbox/archive/zstd.hpp>
#include "bits.hpp"
#include <cerrno>
#include <cstring>

namespace sbox {
namespace archive {

    namespace {

        /*
         * Decoder that looks at the first bytes and then delegates to a gzip, zstd or
         * pass-through codec.
         */
        class AutoDecoder : public ICodec {
        private:
            SDecoderOptions _options;
            ICodecPtr _inner;
            uint8_t _head[4];
            size_t _headSize = 0;
            size_t _headFed = 0;

        public:
            explicit AutoDecoder(const SDecoderOptions& options) : _options(options) {}

            /* Detects the format, then forwards to the chosen codec. */
            int32_t process(const SReadOnlyByteSpan& in, size_t& consumed, const SByteSpan& out,
                            size_t& produced, bool finish) override {
                consumed = 0;
                produced = 0;
                SReadOnlyByteSpan rest = in;
                if (!_inner) {
                    if (_headSize == 0 && in.size >= 4) {
                        create(DetectCompression(in, finish));
                    } else {
                        size_t take = 4 - _headSize;
                        if (take > in.size) {
                            take = in.size;
                        }

                        if (take) {
                            std::memcpy(_head + _headSize, in.data, take);
                        }

                        _headSize += take;
                        consumed = take;
                        rest = in.slice(take);
                        bool atEof = finish && rest.size == 0;
                        ECompression c = DetectCompression(SReadOnlyByteSpan(_head, _headSize), atEof);
                        if (c == ECOMP_INVALID) {
                            return SBOX_OK;
                        }

                        create(c);
                    }
                }

                size_t outUsed = 0;
                if (_headFed < _headSize) {
                    size_t c = 0;
                    size_t p = 0;
                    int32_t rc = _inner->process(SReadOnlyByteSpan(_head + _headFed, _headSize - _headFed), c, out, p,
                                                 finish && rest.size == 0);
                    _headFed += c;
                    outUsed = p;
                    if (rc != SBOX_OK || _headFed < _headSize) {
                        produced = outUsed;
                        return rc;
                    }
                }

                size_t c = 0;
                size_t p = 0;
                int32_t rc = _inner->process(rest, c, out.slice(outUsed), p, finish);
                consumed += c;
                produced = outUsed + p;
                return rc;
            }

            /* Forgets the detected format. */
            void reset() override {
                _inner.reset();
                _headSize = 0;
                _headFed = 0;
            }

        private:
            /* Instantiates the codec for the detected format. */
            void create(ECompression c) {
                if (c == ECOMP_GZIP || c == ECOMP_ZSTD) {
                    _inner = CreateDecoder(c, _options);
                } else {
                    _inner = std::make_unique<CPassThrough>();
                }
            }
        };

    }

    /* Copies bytes unchanged. */
    int32_t CPassThrough::process(const SReadOnlyByteSpan& in, size_t& consumed, const SByteSpan& out,
                                  size_t& produced, bool finish) {
        size_t n = in.size < out.size ? in.size : out.size;
        if (n) {
            std::memcpy(out.data, in.data, n);
        }

        consumed = n;
        produced = n;
        return finish && n == in.size ? CODEC_END : SBOX_OK;
    }

    /* Sniffs the compression format. */
    ECompression DetectCompression(const SReadOnlyByteSpan& head, bool atEof) noexcept {
        if (head.size >= 3 && head[0] == 0x1F && head[1] == 0x8B && head[2] == 8) {
            return ECOMP_GZIP;
        }

        if (head.size >= 4) {
            uint32_t magic = bits::load32(head.data);
            if (magic == 0xFD2FB528u || (magic & 0xFFFFFFF0u) == 0x184D2A50u) {
                return ECOMP_ZSTD;
            }

            return ECOMP_NONE;
        }

        if (atEof) {
            return ECOMP_NONE;
        }

        // --> Too short to rule out a magic number that is still arriving.
        static const uint8_t GZ[3] = { 0x1F, 0x8B, 8 };
        static const uint8_t ZS[4] = { 0x28, 0xB5, 0x2F, 0xFD };
        if (head.size == 0) {
            return ECOMP_INVALID;
        }

        bool maybe = std::memcmp(head.data, GZ, head.size < 3 ? head.size : 3) == 0
                  || std::memcmp(head.data, ZS, head.size) == 0
                  || (head[0] & 0xF0u) == 0x50u;
        return maybe ? ECOMP_INVALID : ECOMP_NONE;
    }

    /* Creates a decoder. */
    ICodecPtr CreateDecoder(ECompression compression, const SDecoderOptions& options) {
        switch (compression) {
        case ECOMP_NONE:
            return std::make_unique<CPassThrough>();
        case ECOMP_GZIP:
            return std::make_unique<CInflater>(EDFMT_GZIP, options.gzipMultiMember);
        case ECOMP_ZLIB:
            return std::make_unique<CInflater>(EDFMT_ZLIB);
        case ECOMP_DEFLATE:
            return std::make_unique<CInflater>(EDFMT_RAW);
        case ECOMP_ZSTD:
            return std::make_unique<CZstdDecoder>(options.zstdMaxWindow);
        case ECOMP_AUTO:
            return std::make_unique<AutoDecoder>(options);
        default:
            return nullptr;
        }
    }

    /* Creates an encoder. */
    ICodecPtr CreateEncoder(ECompression compression, int32_t level) {
        switch (compression) {
        case ECOMP_NONE:
            return std::make_unique<CPassThrough>();
        case ECOMP_GZIP:
            return std::make_unique<CDeflater>(EDFMT_GZIP, level);
        case ECOMP_ZLIB:
            return std::make_unique<CDeflater>(EDFMT_ZLIB, level);
        case ECOMP_DEFLATE:
            return std::make_unique<CDeflater>(EDFMT_RAW, level);
        default:
            return nullptr;
        }
    }

    /* Name of a compression format. */
    const char* CompressionName(ECompression compression) noexcept {
        switch (compression) {
        case ECOMP_NONE:
            return "none";
        case ECOMP_GZIP:
            return "gzip";
        case ECOMP_ZLIB:
            return "zlib";
        case ECOMP_DEFLATE:
            return "deflate";
        case ECOMP_ZSTD:
            return "zstd";
        case ECOMP_AUTO:
            return "auto";
        default:
            return "invalid";
        }
    }

}
}
