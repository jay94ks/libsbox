#ifndef __INCLUDE_SBOX_ARCHIVE_DEFLATE_HPP__
#define __INCLUDE_SBOX_ARCHIVE_DEFLATE_HPP__

#include <sbox/archive/codec.hpp>

namespace sbox {
namespace archive {

    /**
     * Container around a DEFLATE stream.
     */
    enum EDeflateFormat {
        EDFMT_RAW = 0,      // --> Bare RFC 1951 blocks.
        EDFMT_ZLIB,         // --> RFC 1950: 2-byte header, Adler-32 trailer.
        EDFMT_GZIP,         // --> RFC 1952: gzip header, CRC-32 and ISIZE trailer.
        EDFMT_AUTO,         // --> Decode only: zlib or gzip, chosen by the first bytes.
    };

    /**
     * Fields of the most recent gzip member header seen by CInflater.
     */
    struct SGzipHeader {
        uint32_t mtime = 0;
        uint8_t flags = 0;          // --> FLG byte (FTEXT, FHCRC, FEXTRA, FNAME, FCOMMENT).
        uint8_t extraFlags = 0;     // --> XFL byte.
        uint8_t os = 255;
        std::string name;           // --> FNAME (without the terminator).
        std::string comment;        // --> FCOMMENT.
        std::vector<uint8_t> extra; // --> FEXTRA payload.
    };

    /**
     * Streaming DEFLATE decoder (RFC 1951) with optional zlib or gzip container.
     *
     * Decodes stored, fixed and dynamic Huffman blocks with table-driven lookups (10-bit
     * literal/length and 8-bit distance root tables plus sub-tables), keeps only a sliding window
     * of history, and accepts input and output in pieces of any size. In gzip mode concatenated
     * members are decoded as one stream (as gzip(1) does) unless disabled; every member's CRC-32
     * and ISIZE are verified. Bytes after the last member must be another member.
     */
    class SBOX_API CInflater : public ICodec {
    private:
        struct SImpl;
        std::unique_ptr<SImpl> _impl;

    public:
        /**
         * Creates a decoder for `format` (EDFMT_AUTO accepts zlib or gzip).
         * @param multiMember In gzip mode, decode concatenated members (default true).
         */
        explicit CInflater(EDeflateFormat format = EDFMT_GZIP, bool multiMember = true);

        ~CInflater() override;

        CInflater(const CInflater&) = delete;

        CInflater& operator=(const CInflater&) = delete;

        /**
         * Decodes (see ICodec::process). Corrupt data is -EBADMSG, a truncated stream with
         * `finish` set is -ENODATA.
         */
        int32_t process(const SReadOnlyByteSpan& in, size_t& consumed, const SByteSpan& out,
                        size_t& produced, bool finish) override;

        /**
         * Starts over (keeps the format and the window buffer).
         */
        void reset() override;

        /**
         * Returns the header of the most recent gzip member.
         */
        const SGzipHeader& gzipHeader() const noexcept;

        /**
         * Returns the number of gzip members finished so far.
         */
        uint64_t members() const noexcept;

        /**
         * Returns the total number of decompressed bytes produced since the last reset.
         */
        uint64_t totalOut() const noexcept;
    };

    /**
     * Streaming DEFLATE encoder (RFC 1951) with optional zlib or gzip container.
     *
     * LZ77 over a 32 KiB window with hash chains (greedy matching for levels 1-3, lazy matching
     * for 4-9), blocks of up to 16 Ki symbols, each emitted as stored, fixed or dynamic Huffman,
     * whichever is smallest; Huffman codes are length-limited (15 bits, 7 for the code-length
     * code). Level 0 writes stored blocks only.
     */
    class SBOX_API CDeflater : public ICodec {
    private:
        struct SImpl;
        std::unique_ptr<SImpl> _impl;

    public:
        /**
         * Creates an encoder.
         * @param format EDFMT_RAW, EDFMT_ZLIB or EDFMT_GZIP (EDFMT_AUTO is treated as gzip).
         * @param level 0..9, or -1 for the default (6).
         */
        explicit CDeflater(EDeflateFormat format = EDFMT_GZIP, int32_t level = -1);

        ~CDeflater() override;

        CDeflater(const CDeflater&) = delete;

        CDeflater& operator=(const CDeflater&) = delete;

        /**
         * Encodes (see ICodec::process). With `finish` set, keep calling until CODEC_END.
         */
        int32_t process(const SReadOnlyByteSpan& in, size_t& consumed, const SByteSpan& out,
                        size_t& produced, bool finish) override;

        /**
         * Starts a new stream with the same settings.
         */
        void reset() override;

        /**
         * Sets the gzip header name (FNAME) and modification time written at the next stream
         * start. Has no effect once output was produced.
         */
        void gzipHeader(std::string_view name, uint32_t mtime) noexcept;
    };

}
}

#endif
