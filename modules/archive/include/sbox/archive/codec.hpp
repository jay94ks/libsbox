#ifndef __INCLUDE_SBOX_ARCHIVE_CODEC_HPP__
#define __INCLUDE_SBOX_ARCHIVE_CODEC_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>

namespace sbox {
namespace archive {

    /**
     * Positive status a codec returns once its stream is complete (alongside SBOX_OK = "more to
     * do" and negated errno values for failures).
     */
    constexpr int32_t CODEC_END = 1;

    /**
     * Compression formats the archive module knows.
     */
    enum ECompression {
        ECOMP_NONE = 0,     // --> Bytes pass through unchanged.
        ECOMP_GZIP,         // --> RFC 1952 (multi-member on decode).
        ECOMP_ZLIB,         // --> RFC 1950.
        ECOMP_DEFLATE,      // --> Raw RFC 1951 stream.
        ECOMP_ZSTD,         // --> RFC 8878 (decode only).
        ECOMP_AUTO,         // --> Decode only: picks gzip, zstd or none from the first bytes.
        ECOMP_INVALID,
    };

    /**
     * Incremental, synchronous compressor or decompressor (a state machine in the style of
     * zlib's z_stream). It never blocks and never allocates per call once warmed up; the stream
     * adapters in stream.hpp drive it from descriptors or coroutine streams.
     */
    class SBOX_API ICodec {
    public:
        virtual ~ICodec() = default;

        /**
         * Moves data from `in` to `out`.
         *
         * Call repeatedly. `consumed` and `produced` report how much of each span was used.
         * When the input is complete pass `finish = true` (also on every later call) until the
         * codec reports CODEC_END.
         *
         * @param in Input bytes (may be empty).
         * @param consumed Receives the number of input bytes taken.
         * @param out Output space (may be empty).
         * @param produced Receives the number of output bytes written.
         * @param finish True when no input follows `in`.
         * @return SBOX_OK when more calls are needed (more input, more output room, or with
         *         finish set, more output to drain); CODEC_END once the stream is complete and all
         *         output was delivered; -EBADMSG for corrupt input; -ENODATA when `finish` is set
         *         but the compressed stream is truncated; -EFBIG when a limit was exceeded;
         *         -ENOTSUP for an unsupported feature. Errors are sticky until reset().
         */
        virtual int32_t process(const SReadOnlyByteSpan& in, size_t& consumed, const SByteSpan& out,
                                size_t& produced, bool finish) = 0;

        /**
         * Returns the codec to its initial state (keeping its configuration and buffers).
         */
        virtual void reset() = 0;
    };

    using ICodecPtr = std::unique_ptr<ICodec>;

    /**
     * Knobs of the decoders created by CreateDecoder.
     */
    struct SDecoderOptions {
        uint64_t zstdMaxWindow = uint64_t(128) << 20;  // --> Largest zstd window accepted (memory bound).
        bool gzipMultiMember = true;                    // --> Decode concatenated gzip members.
    };

    /**
     * Guesses the compression of a stream from its first bytes: gzip (1f 8b 08), zstd (28 b5 2f fd
     * or a skippable frame), otherwise ECOMP_NONE. zlib is not sniffed: its 2-byte header is too
     * easy to hit by chance (a tar entry named "x^..." would match). Returns ECOMP_INVALID when
     * `head` is too short to tell (fewer than 4 bytes and not at EOF).
     * @param atEof True when `head` is the whole stream.
     */
    SBOX_API ECompression DetectCompression(const SReadOnlyByteSpan& head, bool atEof = false) noexcept;

    /**
     * Creates a decoder. ECOMP_AUTO yields a decoder that sniffs gzip/zstd/plain.
     * @return The codec, or nullptr for ECOMP_INVALID.
     */
    SBOX_API ICodecPtr CreateDecoder(ECompression compression, const SDecoderOptions& options = SDecoderOptions());

    /**
     * Creates an encoder.
     * @param level 0 (stored) to 9 (best); -1 picks the default (6).
     * @return The codec, or nullptr for formats that cannot be written (zstd, auto, invalid).
     */
    SBOX_API ICodecPtr CreateEncoder(ECompression compression, int32_t level = -1);

    /**
     * Returns a lowercase name ("gzip", "zstd", ...) for logs and media types.
     */
    SBOX_API const char* CompressionName(ECompression compression) noexcept;

    /**
     * Codec that copies its input unchanged (ECOMP_NONE).
     */
    class SBOX_API CPassThrough : public ICodec {
    public:
        /**
         * Copies as much as fits; reports CODEC_END when finishing with no input left.
         */
        int32_t process(const SReadOnlyByteSpan& in, size_t& consumed, const SByteSpan& out,
                        size_t& produced, bool finish) override;

        /** Nothing to reset. */
        inline void reset() override {}
    };

}
}

#endif
