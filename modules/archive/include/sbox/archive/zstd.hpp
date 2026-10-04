#ifndef __INCLUDE_SBOX_ARCHIVE_ZSTD_HPP__
#define __INCLUDE_SBOX_ARCHIVE_ZSTD_HPP__

#include <sbox/archive/codec.hpp>

namespace sbox {
namespace archive {

    /**
     * Streaming Zstandard decoder (RFC 8878).
     *
     * Supports zstd frames (raw, RLE and compressed blocks; raw, RLE, Huffman and treeless
     * literals with 1 or 4 streams; predefined, RLE, FSE and repeat sequence tables; repeat
     * offsets), concatenated frames, skippable frames, Frame_Content_Size and XXH64 content
     * checksum verification. History lives in a window buffer of Window_Size plus one block, so
     * memory is bounded by `maxWindow`. Dictionaries (Dictionary_ID != 0) are not supported
     * (-ENOTSUP). Compression is not implemented.
     */
    class SBOX_API CZstdDecoder : public ICodec {
    private:
        struct SImpl;
        std::unique_ptr<SImpl> _impl;

    public:
        /**
         * Creates a decoder.
         * @param maxWindow Largest Window_Size accepted; larger frames fail with -EFBIG.
         *                  Defaults to 128 MiB (what `zstd --long=27` produces); at most 2 GiB.
         */
        explicit CZstdDecoder(uint64_t maxWindow = uint64_t(128) << 20);

        /** Destroys the decoder. */
        ~CZstdDecoder() override;

        CZstdDecoder(const CZstdDecoder&) = delete;

        CZstdDecoder& operator=(const CZstdDecoder&) = delete;

        /**
         * Decodes (see ICodec::process). Reports CODEC_END only with `finish` set, at a frame
         * boundary; -ENODATA when input ends inside a frame; -EBADMSG for corrupt data or a
         * checksum/content-size mismatch.
         */
        int32_t process(const SReadOnlyByteSpan& in, size_t& consumed, const SByteSpan& out,
                        size_t& produced, bool finish) override;

        /**
         * Starts over (keeps the window limit; buffers are kept for reuse).
         */
        void reset() override;

        /**
         * Returns the number of zstd frames (not counting skippable ones) finished so far.
         */
        uint64_t frames() const noexcept;
    };

}
}

#endif
