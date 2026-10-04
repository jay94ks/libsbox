#ifndef __INCLUDE_SBOX_ARCHIVE_TREE_HPP__
#define __INCLUDE_SBOX_ARCHIVE_TREE_HPP__

#include <sbox/archive/extract.hpp>
#include <sys/stat.h>

namespace sbox {
namespace archive {

    /**
     * Options for writing a directory tree into a tar.
     */
    struct STreeOptions {
        std::string prefix;                 // --> Prepended to every entry path ("layer/" -> "layer/etc/...").
        bool includeRoot = false;           // --> Emit an entry for the root itself ("./" or the bare prefix).
        bool xattrs = true;                 // --> Record extended attributes as SCHILY.xattr PAX records.
        bool overlayWhiteouts = false;      // --> Convert overlayfs whiteouts (0/0 char devices, xwhiteout files,
                                            //     overlay.opaque=y directories) into ".wh." entries; drop
                                            //     trusted./user.overlay.* xattrs.
        bool preciseTimes = false;          // --> Keep sub-second mtimes (PAX); default truncates like Docker.
        int64_t uidShift = 0;               // --> Subtracted from on-disk uids (inverse of the extraction shift).
        int64_t gidShift = 0;               // --> Subtracted from on-disk gids.
        ETarFormat format = ETFMT_PAX;
        std::function<bool(const std::string& relPath, const struct stat& st)> filter;  // --> false skips (and prunes).
        FExtractNotice notice;              // --> Skipped sockets and unreadable xattrs are reported here.
    };

    /**
     * Writes the tree under `root` into `writer` (sorted by name, so the output is
     * deterministic; hardlinked files become hardlink entries). Does not call writer.finish().
     * Symlinks are archived as links and never followed.
     * @return SBOX_OK or a negated errno.
     */
    SBOX_API int32_t WriteTree(const std::string& root, CTarWriter& writer, const STreeOptions& options = STreeOptions());

    /**
     * Writes the tree under `root` as a complete, optionally compressed archive into `out`
     * (e.g. a CFdSink for a layer blob or a volume backup) and finishes `out`.
     * @param compression ECOMP_NONE, ECOMP_GZIP, ECOMP_ZLIB or ECOMP_DEFLATE.
     * @param level Compression level (-1 = default).
     * @param hooks `uncompressed` sees the tar bytes (diffID), `compressed` the output bytes.
     */
    SBOX_API int32_t WriteTreeArchive(const std::string& root, IByteSink& out, ECompression compression = ECOMP_GZIP,
                                      int32_t level = -1, const STreeOptions& options = STreeOptions(),
                                      const SPipelineHooks& hooks = SPipelineHooks());

    /**
     * Pull-style tar producer: reading from it walks the tree lazily and yields a complete tar
     * archive (end marker included). Wrap it in a CCodecSource to compress, and feed the result
     * to a file (Pump) or a coroutine stream (PumpSourceToStream).
     */
    class SBOX_API CTreeTarSource : public IByteSource {
    private:
        struct SImpl;
        std::unique_ptr<SImpl> _impl;

    public:
        /**
         * Prepares a walk of `root` (opened on the first read).
         */
        explicit CTreeTarSource(const std::string& root, const STreeOptions& options = STreeOptions());

        /** Destroys the producer. */
        ~CTreeTarSource() override;

        CTreeTarSource(const CTreeTarSource&) = delete;

        CTreeTarSource& operator=(const CTreeTarSource&) = delete;

        /**
         * Returns the next archive bytes; 0 at the end.
         */
        SIoResult read(const SByteSpan& buffer) override;
    };

}
}

#endif
