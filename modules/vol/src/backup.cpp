#include <sbox/vol/backup.hpp>

#include "util.hpp"

#include <sbox/archive/extract.hpp>
#include <sbox/archive/tree.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/file.hpp>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <cstring>
#include <unistd.h>

namespace sbox {
namespace vol {

    namespace {

        /**
         * Holds a volume for the duration of a backup or restore: a private user id keeps it
         * mounted and makes `rm` refuse it meanwhile; the destructor does not release (that
         * needs a coroutine), so callers release explicitly.
         */
        struct VolumeHold {
            std::string user = "sbox-backup-" + std::to_string(::getpid()) + "-" + RandomHex(6);
            std::string mountpoint;
        };

        /* Returns tree options for a backup. */
        archive::STreeOptions treeOptions(const SBackupOptions& options) {
            archive::STreeOptions tree;
            tree.includeRoot = true;
            tree.xattrs = options.xattrs;
            tree.preciseTimes = true;
            return tree;
        }

        /* Returns extraction options for a restore. */
        archive::SExtractOptions extractOptions() {
            archive::SExtractOptions opts;
            opts.ownership = archive::EOWN_AUTO;
            opts.xattrs = true;
            opts.devices = true;
            opts.whiteouts = archive::EWHT_NONE;
            return opts;
        }

        /* Removes everything inside `dir` (not `dir` itself), without crossing mounts. */
        int32_t clearDirectory(const std::string& dir) {
            DIR* d = ::opendir(dir.c_str());
            if (d == nullptr) {
                return -errno;
            }

            std::vector<std::string> names;
            while (dirent* de = ::readdir(d)) {
                if (std::strcmp(de->d_name, ".") != 0 && std::strcmp(de->d_name, "..") != 0) {
                    names.emplace_back(de->d_name);
                }
            }

            ::closedir(d);
            for (const std::string& n : names) {
                int32_t rc = CFile::removeTree(CFile::join(dir, n));
                if (rc < 0) {
                    return rc;
                }
            }

            return SBOX_OK;
        }

        /* Acquires the volume and, when asked, freezes its filesystem. */
        TTask<int32_t> beginBackup(CVolumeStore& store, const std::string& name, const SBackupOptions& options,
                                   VolumeHold& hold, bool& frozen) {
            frozen = false;
            int32_t rc = co_await store.acquire(name, hold.user, hold.mountpoint);
            if (rc < 0) {
                co_return rc;
            }

            if (options.freeze) {
                // --> Freezing a directory volume would freeze the whole store filesystem.
                rc = IsMountPoint(hold.mountpoint) ? FreezeFs(hold.mountpoint) : -ENOTSUP;
                if (rc < 0) {
                    co_await store.release(name, hold.user);
                    co_return rc;
                }

                frozen = true;
            }

            co_return SBOX_OK;
        }

        /* Thaws and releases after a backup. */
        TTask<int32_t> endBackup(CVolumeStore& store, const std::string& name, VolumeHold& hold, bool frozen, int32_t rc) {
            if (frozen) {
                int32_t trc = ThawFs(hold.mountpoint);
                if (rc == SBOX_OK) {
                    rc = trc;
                }
            }

            int32_t rrc = co_await store.release(name, hold.user);
            co_return rc == SBOX_OK ? rrc : rc;
        }

        /* Creates (when allowed) and acquires the target volume, clearing it with overwrite. */
        TTask<int32_t> beginRestore(CVolumeStore& store, const std::string& name, SRestoreOptions& options, VolumeHold& hold) {
            SVolume v;
            int32_t rc = store.inspect(name, v);
            if (rc == -ENOENT && options.create) {
                options.createOptions.name = name;
                rc = co_await store.create(options.createOptions, v);
            }

            if (rc < 0) {
                co_return rc;
            }

            rc = co_await store.acquire(name, hold.user, hold.mountpoint);
            if (rc < 0) {
                co_return rc;
            }

            if (!IsDirectoryEmpty(hold.mountpoint)) {
                rc = options.overwrite ? clearDirectory(hold.mountpoint) : -ENOTEMPTY;
                if (rc < 0) {
                    co_await store.release(name, hold.user);
                    co_return rc;
                }
            }

            co_return SBOX_OK;
        }

    }

    /* Writes a volume as tar.gz into a sink. */
    TTask<int32_t> BackupVolume(CVolumeStore& store, std::string name, archive::IByteSink& out, SBackupOptions options) {
        VolumeHold hold;
        bool frozen = false;
        int32_t rc = co_await beginBackup(store, name, options, hold, frozen);
        if (rc < 0) {
            co_return rc;
        }

        rc = archive::WriteTreeArchive(hold.mountpoint, out, archive::ECOMP_GZIP, options.level, treeOptions(options));
        co_return co_await endBackup(store, name, hold, frozen, rc);
    }

    /* Streams a volume backup into a coroutine stream. */
    TTask<int32_t> BackupVolumeToStream(CVolumeStore& store, std::string name, IStream& out, SBackupOptions options) {
        VolumeHold hold;
        bool frozen = false;
        int32_t rc = co_await beginBackup(store, name, options, hold, frozen);
        if (rc < 0) {
            co_return rc;
        }

        {
            archive::CTreeTarSource tree(hold.mountpoint, treeOptions(options));
            archive::CCodecSource gz(archive::CreateEncoder(archive::ECOMP_GZIP, options.level), tree);
            rc = co_await archive::PumpSourceToStream(gz, out);
        }

        co_return co_await endBackup(store, name, hold, frozen, rc);
    }

    /* Writes a backup to a file atomically. */
    TTask<int32_t> BackupVolumeToFile(CVolumeStore& store, std::string name, std::string path, SBackupOptions options) {
        std::string tmp = path + ".tmp-" + RandomHex(4);
        int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) {
            co_return -errno;
        }

        CFd file(fd);
        archive::CFdSink sink(file.get());
        int32_t rc = co_await BackupVolume(store, name, sink, options);
        if (rc == SBOX_OK && ::fsync(file.get()) != 0) {
            rc = -errno;
        }

        file.reset();
        if (rc == SBOX_OK && ::rename(tmp.c_str(), path.c_str()) != 0) {
            rc = -errno;
        }

        if (rc < 0) {
            ::unlink(tmp.c_str());
        }

        co_return rc;
    }

    /* Restores a backup read from a source. */
    TTask<int32_t> RestoreVolume(CVolumeStore& store, std::string name, archive::IByteSource& in, SRestoreOptions options) {
        VolumeHold hold;
        int32_t rc = co_await beginRestore(store, name, options, hold);
        if (rc < 0) {
            co_return rc;
        }

        rc = archive::ExtractArchive(in, hold.mountpoint, extractOptions(), archive::ECOMP_AUTO);
        int32_t rrc = co_await store.release(name, hold.user);
        co_return rc == SBOX_OK ? rrc : rc;
    }

    /* Restores a backup read from a coroutine stream. */
    TTask<int32_t> RestoreVolumeFromStream(CVolumeStore& store, std::string name, IStream& in, SRestoreOptions options) {
        VolumeHold hold;
        int32_t rc = co_await beginRestore(store, name, options, hold);
        if (rc < 0) {
            co_return rc;
        }

        rc = co_await archive::ExtractArchiveAsync(in, hold.mountpoint, extractOptions(), archive::ECOMP_AUTO);
        int32_t rrc = co_await store.release(name, hold.user);
        co_return rc == SBOX_OK ? rrc : rc;
    }

    /* Restores a backup from a file. */
    TTask<int32_t> RestoreVolumeFromFile(CVolumeStore& store, std::string name, std::string path, SRestoreOptions options) {
        int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            co_return -errno;
        }

        CFd file(fd);
        archive::CFdSource source(file.get());
        co_return co_await RestoreVolume(store, name, source, std::move(options));
    }

}
}
