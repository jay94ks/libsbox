#ifndef __INCLUDE_SBOX_VOL_BACKUP_HPP__
#define __INCLUDE_SBOX_VOL_BACKUP_HPP__

#include <sbox/archive/stream.hpp>
#include <sbox/core/stream.hpp>
#include <sbox/vol/store.hpp>

namespace sbox {
namespace vol {

    /**
     * Options of a volume backup.
     */
    struct SBackupOptions {
        int32_t level = 6;              // --> gzip level (0..9).
        bool xattrs = true;             // --> Record extended attributes (SCHILY.xattr).
        bool freeze = false;            // --> fsfreeze (FIFREEZE/FITHAW) the volume filesystem while
                                        //     reading; only for volumes backed by their own mount
                                        //     (device / nfs ...), -ENOTSUP for directory volumes.
    };

    /**
     * Options of a volume restore.
     */
    struct SRestoreOptions {
        bool overwrite = false;         // --> Clear a non-empty volume first (otherwise -ENOTEMPTY).
        bool create = true;             // --> Create the volume when missing (with `createOptions`).
        SVolumeCreate createOptions;    // --> Labels / driver options of a volume created here.
    };

    /**
     * Writes a volume as a gzip compressed tar (ownership, modes, times, xattrs, symlinks and
     * hardlinks preserved) into `out` and finishes it. Volumes that need a mount (and are not
     * in use) are mounted for the duration of the backup.
     *
     * Consistency is best effort: files changed while the volume is being read may be captured
     * mid-write. With `freeze` a volume on its own filesystem is frozen for the duration.
     * @return SBOX_OK or a negated errno.
     */
    SBOX_API TTask<int32_t> BackupVolume(CVolumeStore& store, std::string name, archive::IByteSink& out,
                                         SBackupOptions options = {});

    /**
     * Streams a volume backup (tar.gz) into a coroutine stream (socket, pipe).
     */
    SBOX_API TTask<int32_t> BackupVolumeToStream(CVolumeStore& store, std::string name, IStream& out,
                                                 SBackupOptions options = {});

    /**
     * Writes a backup to a file atomically (temporary sibling, fsync, rename).
     */
    SBOX_API TTask<int32_t> BackupVolumeToFile(CVolumeStore& store, std::string name, std::string path,
                                               SBackupOptions options = {});

    /**
     * Restores a backup (tar, tar.gz or tar.zst) read from `in` into a volume. Extraction is
     * the archive module's safe extractor: nothing can be written outside the volume.
     * @return SBOX_OK, -ENOTEMPTY (volume has content and no overwrite), or a negated errno.
     */
    SBOX_API TTask<int32_t> RestoreVolume(CVolumeStore& store, std::string name, archive::IByteSource& in,
                                          SRestoreOptions options = {});

    /**
     * Restores a backup read from a coroutine stream.
     */
    SBOX_API TTask<int32_t> RestoreVolumeFromStream(CVolumeStore& store, std::string name, IStream& in,
                                                    SRestoreOptions options = {});

    /**
     * Restores a backup from a file.
     */
    SBOX_API TTask<int32_t> RestoreVolumeFromFile(CVolumeStore& store, std::string name, std::string path,
                                                  SRestoreOptions options = {});

}
}

#endif
