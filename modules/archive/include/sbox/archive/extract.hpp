#ifndef __INCLUDE_SBOX_ARCHIVE_EXTRACT_HPP__
#define __INCLUDE_SBOX_ARCHIVE_EXTRACT_HPP__

#include <sbox/archive/tar.hpp>
#include <sbox/core/fd.hpp>

namespace sbox {
namespace archive {

    /**
     * How OCI/Docker layer whiteouts (".wh.<name>", ".wh..wh..opq") are handled.
     */
    enum EWhiteoutMode {
        EWHT_NONE = 0,              // --> Extract ".wh." entries literally (plain archives, backups).
        EWHT_OVERLAY,               // --> overlayfs layer dir: 0/0 char device, trusted.overlay.opaque=y.
        EWHT_OVERLAY_USERXATTR,     // --> overlayfs "userxattr" (unprivileged): empty file with
                                    //     user.overlay.whiteout, user.overlay.opaque=y / =x on the parent.
        EWHT_APPLY,                 // --> Flatten onto a plain directory: delete the named path / clear
                                    //     what earlier layers put into an opaque directory.
    };

    /**
     * Ownership policy of the extractor.
     */
    enum EOwnership {
        EOWN_AUTO = 0,      // --> chown when euid is 0; refusals (EPERM/EINVAL, e.g. unmapped ids) are reported, not fatal.
        EOWN_PRESERVE,      // --> Always chown; any failure is an error.
        EOWN_IGNORE,        // --> Never chown: everything belongs to the extracting user.
    };

    /**
     * Kinds of non-fatal events reported to SExtractOptions::notice.
     */
    enum EExtractNotice {
        EXN_DEVICE_SKIPPED = 0,     // --> mknod was not permitted (or devices are disabled).
        EXN_XATTR_FAILED,           // --> An extended attribute could not be set.
        EXN_CHOWN_FAILED,           // --> Ownership could not be applied (EOWN_AUTO).
        EXN_UNSAFE_SKIPPED,         // --> An entry escaping the root was skipped (skipUnsafe).
        EXN_SOCKET_SKIPPED,         // --> Tree writer: sockets cannot be archived.
        EXN_IGNORED_ENTRY,          // --> An entry that has no meaning here (e.g. aufs ".wh..wh.plnk").
    };

    /**
     * A non-fatal event: what happened, to which path, and the errno behind it (if any).
     */
    struct SExtractNotice {
        EExtractNotice kind;
        std::string path;
        int32_t error;
    };

    /**
     * Receiver of non-fatal events.
     */
    using FExtractNotice = std::function<void(const SExtractNotice&)>;

    /**
     * Options of CExtractor.
     */
    struct SExtractOptions {
        EWhiteoutMode whiteouts = EWHT_NONE;
        EOwnership ownership = EOWN_AUTO;
        int64_t uidShift = 0;               // --> Added to every uid (rootless / userns-remapped storage).
        int64_t gidShift = 0;               // --> Added to every gid.
        bool xattrs = true;                 // --> Restore extended attributes (including security.capability).
        bool xattrErrorsFatal = false;      // --> Otherwise failures are reported via `notice` and skipped.
        bool devices = true;                // --> Create char/block devices (skipped with a notice when not permitted).
        bool preserveTimes = true;          // --> Apply atime/mtime from the archive.
        bool skipUnsafe = false;            // --> Skip entries escaping the root instead of failing with -EXDEV.
        bool noOpenat2 = false;             // --> Force the O_NOFOLLOW component walk instead of openat2(2).
        FExtractNotice notice;              // --> Optional receiver of non-fatal events.
    };

    /**
     * Counters of an extraction.
     */
    struct SExtractStats {
        uint64_t entries = 0;
        uint64_t files = 0;
        uint64_t dirs = 0;
        uint64_t symlinks = 0;
        uint64_t hardlinks = 0;
        uint64_t devices = 0;       // --> Char/block devices and fifos created.
        uint64_t whiteouts = 0;     // --> Whiteout and opaque markers processed.
        uint64_t skipped = 0;
        uint64_t bytes = 0;         // --> Regular file data written.
    };

    /**
     * Safe tar extractor (an ITarHandler for CTarSink).
     *
     * Every path is resolved inside the root without leaving it: entry paths are cleaned
     * lexically (".." past the root is rejected with -EXDEV, absolute paths are taken relative
     * to the root), and parent directories are opened with openat2(RESOLVE_IN_ROOT |
     * RESOLVE_NO_MAGICLINKS), or, on kernels without openat2, by an O_NOFOLLOW component walk
     * that resolves symlinks itself with the root as "/". The final component is never followed:
     * an existing entry is removed and recreated, so a symlink planted by an earlier entry can't
     * redirect a later write. Hardlink targets are resolved the same way, so they always point
     * inside the root. Directory modes and times are applied at the end (onEnd), so read-only
     * directories do not block their own contents.
     */
    class SBOX_API CExtractor : public ITarHandler {
    private:
        struct SImpl;
        std::unique_ptr<SImpl> _impl;

    public:
        /** Creates an extractor; call open() before feeding entries. */
        explicit CExtractor(const SExtractOptions& options = SExtractOptions());

        /** Destroys the extractor. */
        ~CExtractor() override;

        CExtractor(const CExtractor&) = delete;

        CExtractor& operator=(const CExtractor&) = delete;

        /**
         * Sets the target directory (must exist).
         * @return SBOX_OK or a negated errno.
         */
        int32_t open(const std::string& root);

        /**
         * Sets the target directory from a descriptor (duplicated; O_PATH is fine).
         */
        int32_t open(int rootFd);

        /** Creates or replaces the entry. */
        int32_t onEntry(const STarEntry& entry) override;

        /** Writes file data. */
        int32_t onData(const SReadOnlyByteSpan& data) override;

        /** Applies the entry's metadata. */
        int32_t onEntryEnd() override;

        /** Applies deferred directory modes and times. */
        int32_t onEnd() override;

        /**
         * Returns the counters so far.
         */
        const SExtractStats& stats() const noexcept;
    };

    /**
     * Observers for digests of a pipeline: `compressed` sees the bytes as read (e.g. the layer
     * blob, for its sha256 digest), `uncompressed` the tar stream (the layer's diffID).
     */
    struct SPipelineHooks {
        FByteHook compressed;
        FByteHook uncompressed;
    };

    /**
     * Synchronously extracts a (possibly compressed) tar from a source into `root`.
     * @param compression ECOMP_AUTO sniffs gzip / zstd / plain.
     * @param stats Optional counters.
     */
    SBOX_API int32_t ExtractArchive(IByteSource& source, const std::string& root, const SExtractOptions& options = SExtractOptions(),
                                    ECompression compression = ECOMP_AUTO, const SPipelineHooks& hooks = SPipelineHooks(),
                                    SExtractStats* stats = nullptr);

    /**
     * Extracts a (possibly compressed) tar read from a coroutine stream (socket, pipe, TLS).
     */
    SBOX_API TTask<int32_t> ExtractArchiveAsync(IStream& stream, std::string root, SExtractOptions options = SExtractOptions(),
                                                ECompression compression = ECOMP_AUTO, SPipelineHooks hooks = SPipelineHooks(),
                                                SExtractStats* stats = nullptr, int64_t timeoutMs = -1);

    /**
     * Cleans an archive path lexically: drops empty and "." components and leading slashes,
     * resolves "..". Fails with -EXDEV when ".." would leave the root and -EINVAL for an
     * embedded NUL. The result has no leading or trailing '/' ("" is the root itself).
     */
    SBOX_API int32_t CleanArchivePath(std::string_view path, std::string& out);

}
}

#endif
