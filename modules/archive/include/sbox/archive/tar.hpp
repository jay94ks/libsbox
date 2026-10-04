#ifndef __INCLUDE_SBOX_ARCHIVE_TAR_HPP__
#define __INCLUDE_SBOX_ARCHIVE_TAR_HPP__

#include <sbox/archive/stream.hpp>

namespace sbox {
namespace archive {

    /**
     * Kind of a tar entry.
     */
    enum ETarEntryType {
        ETAR_FILE = 0,      // --> Regular file ('0', '\0', '7').
        ETAR_HARDLINK,      // --> '1': linkPath names an earlier entry.
        ETAR_SYMLINK,       // --> '2'
        ETAR_CHAR,          // --> '3'
        ETAR_BLOCK,         // --> '4'
        ETAR_DIR,           // --> '5'
        ETAR_FIFO,          // --> '6'
        ETAR_INVALID,
    };

    /**
     * Seconds and nanoseconds since the epoch.
     */
    struct STarTime {
        int64_t sec = 0;
        uint32_t nsec = 0;
    };

    /**
     * Metadata of one tar entry (after PAX and GNU extensions were applied).
     */
    struct STarEntry {
        ETarEntryType type = ETAR_FILE;
        std::string path;               // --> As stored (relative, may carry "./" or a trailing '/').
        std::string linkPath;           // --> Symlink target or hardlink source.
        uint32_t mode = 0644;           // --> Permission bits including setuid/setgid/sticky (07777).
        int64_t uid = 0;
        int64_t gid = 0;
        std::string uname;
        std::string gname;
        uint64_t size = 0;              // --> Data bytes (regular files only).
        STarTime mtime;
        STarTime atime;                 // --> Only meaningful when hasAtime.
        STarTime ctime;                 // --> Only meaningful when hasCtime.
        bool hasAtime = false;
        bool hasCtime = false;
        uint32_t devMajor = 0;
        uint32_t devMinor = 0;
        std::vector<std::pair<std::string, std::string>> xattrs;      // --> Name and raw value.
        std::vector<std::pair<std::string, std::string>> paxRecords;  // --> PAX records not interpreted above.
    };

    /**
     * Events produced by CTarParser::next.
     */
    enum ETarEvent {
        ETEV_NEED_INPUT = 0,    // --> All input was used; feed more.
        ETEV_ENTRY,             // --> A header was parsed: see entry().
        ETEV_DATA,              // --> `data` holds the next bytes of the current entry.
        ETEV_ENTRY_END,         // --> The current entry's data is complete.
        ETEV_END,               // --> End-of-archive marker; later input is ignored.
    };

    /**
     * Limits that keep a hostile archive from exhausting memory.
     */
    struct STarLimits {
        size_t maxMetaSize = size_t(1) << 20;   // --> Largest PAX header or GNU long name/link.
    };

    /**
     * Incremental tar parser (ustar, POSIX PAX 'x'/'g' records, GNU 'L'/'K' long names, GNU
     * base-256 numbers, old v7 headers). It never copies entry data: DATA events point into the
     * caller's input. Sparse files ('S', GNU.sparse.*) and multi-volume archives are rejected
     * with -ENOTSUP.
     */
    class SBOX_API CTarParser {
    private:
        struct SImpl;
        std::unique_ptr<SImpl> _impl;

    public:
        explicit CTarParser(const STarLimits& limits = STarLimits());

        ~CTarParser();

        CTarParser(const CTarParser&) = delete;

        CTarParser& operator=(const CTarParser&) = delete;

        /**
         * Consumes input up to the next event.
         * @param in Input bytes.
         * @param consumed Receives how many bytes of `in` were used.
         * @param event Receives the event.
         * @param data For ETEV_DATA, the bytes (a slice of `in`).
         * @return SBOX_OK, -EBADMSG for a malformed archive (bad checksum, bad number, bad PAX
         *         record), -ENOTSUP for sparse/multi-volume entries, -EFBIG when a limit is hit.
         */
        int32_t next(const SReadOnlyByteSpan& in, size_t& consumed, ETarEvent& event, SReadOnlyByteSpan& data);

        /**
         * Returns the entry of the latest ETEV_ENTRY event.
         */
        const STarEntry& entry() const noexcept;

        /**
         * Returns true once the end-of-archive marker was seen.
         */
        bool ended() const noexcept;

        /**
         * Returns true between entries: the next byte would start a header and no partial header
         * is buffered (an archive may legally stop here when its end marker is missing).
         */
        bool idle() const noexcept;

        /**
         * Starts a new archive.
         */
        void reset();
    };

    /**
     * Receiver of parsed entries, used with CTarSink.
     */
    class SBOX_API ITarHandler {
    public:
        virtual ~ITarHandler() = default;

        /**
         * A new entry starts.
         */
        virtual int32_t onEntry(const STarEntry& entry) = 0;

        /**
         * The next chunk of the current entry's data.
         */
        virtual int32_t onData(const SReadOnlyByteSpan& data) = 0;

        /**
         * The current entry is complete.
         */
        virtual int32_t onEntryEnd() = 0;

        /**
         * The archive is complete (end marker seen or input ended on a block boundary).
         */
        virtual int32_t onEnd() { return SBOX_OK; }
    };

    /**
     * Push-style tar reader: bytes written to it are parsed and dispatched to a handler. finish()
     * fails with -ENODATA when the input stops inside an entry. A missing end-of-archive marker
     * is tolerated (as GNU tar does).
     */
    class SBOX_API CTarSink : public IByteSink {
    private:
        CTarParser _parser;
        ITarHandler& _handler;
        int32_t _error = SBOX_OK;
        bool _inEntry = false;
        bool _done = false;

    public:
        explicit CTarSink(ITarHandler& handler, const STarLimits& limits = STarLimits());

        /**
         * Parses and dispatches. Handler errors stop the sink and are returned.
         */
        int32_t write(const SReadOnlyByteSpan& data) override;

        /**
         * Checks that the archive did not end mid-entry and calls onEnd().
         */
        int32_t finish() override;
    };

    /**
     * Pull-style tar reader over a source.
     */
    class SBOX_API CTarReader {
    private:
        CTarParser _parser;
        IByteSource& _source;
        std::vector<uint8_t> _buf;
        size_t _pos = 0;
        size_t _len = 0;
        bool _eof = false;
        bool _inEntry = false;
        bool _ended = false;

    public:
        explicit CTarReader(IByteSource& source, const STarLimits& limits = STarLimits());

        /**
         * Advances to the next entry, skipping unread data of the current one.
         * @return 1 with `entry` filled, 0 at the end of the archive, or a negated errno.
         */
        int32_t next(STarEntry& entry);

        /**
         * Reads data of the current entry; 0 bytes with SBOX_OK at the end of the entry.
         */
        SIoResult read(const SByteSpan& buffer);

    private:
        /**
         * Runs the parser until an event; refills from the source as needed.
         */
        int32_t pump(ETarEvent& event, SReadOnlyByteSpan& data, size_t maxData);
    };

    /**
     * Header encoding used by CTarWriter.
     */
    enum ETarFormat {
        ETFMT_PAX = 0,      // --> ustar headers plus PAX records when something does not fit (Docker/Go style).
        ETFMT_GNU,          // --> GNU 'L'/'K' long names and base-256 numbers; xattrs still use PAX records.
        ETFMT_USTAR,        // --> Strict ustar: anything that does not fit is an error.
    };

    /**
     * Streaming tar writer.
     *
     * Usage: writeHeader(entry), then writeData() exactly entry.size bytes for regular files,
     * repeat, and finish(). Padding is added automatically.
     */
    class SBOX_API CTarWriter {
    private:
        IByteSink& _sink;
        ETarFormat _format;
        uint64_t _remaining = 0;     // --> Data bytes the current entry still expects.
        uint64_t _padding = 0;       // --> Zero bytes owed once the current entry's data is complete.
        uint64_t _written = 0;
        bool _finished = false;
        int32_t _error = SBOX_OK;

    public:
        /**
         * @param sink Destination (must outlive the writer).
         */
        explicit CTarWriter(IByteSink& sink, ETarFormat format = ETFMT_PAX) noexcept
            : _sink(sink), _format(format) {}

        /**
         * Writes the header(s) of an entry.
         * @return SBOX_OK; -EINVAL when the previous entry's data is incomplete or the entry is
         *         invalid; -ENAMETOOLONG / -EOVERFLOW / -ENOTSUP when strict ustar cannot hold it.
         */
        int32_t writeHeader(const STarEntry& entry);

        /**
         * Writes data of the current entry (at most what is left of entry.size).
         */
        int32_t writeData(const SReadOnlyByteSpan& data);

        /**
         * Convenience: header plus all data at once.
         */
        int32_t writeEntry(const STarEntry& entry, const SReadOnlyByteSpan& data = SReadOnlyByteSpan());

        /**
         * Writes the end-of-archive marker (two zero blocks) and calls sink.finish().
         */
        int32_t finish();

        /**
         * Returns the number of archive bytes written so far.
         */
        inline uint64_t written() const noexcept { return _written; }

    private:
        /**
         * Writes bytes to the sink, tracking errors and the byte count.
         */
        int32_t put(const uint8_t* data, size_t size);

        /**
         * Writes a pseudo entry ('x', 'L', 'K') carrying `payload`.
         */
        int32_t writeMeta(char type, const std::string& name, const std::string& payload);
    };

    /**
     * Returns the type flag character of an entry type ('0', '1', ...).
     */
    SBOX_API char TarTypeFlag(ETarEntryType type) noexcept;

}
}

#endif
