#ifndef __INCLUDE_SBOX_VOL_STORE_HPP__
#define __INCLUDE_SBOX_VOL_STORE_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/task.hpp>
#include <sbox/vol/local.hpp>

namespace sbox {
namespace vol {

    /**
     * Label Docker (23+) puts on anonymous volumes; prune without `all` only removes those.
     */
    constexpr const char* ANONYMOUS_LABEL = "com.docker.volume.anonymous";

    /**
     * A named volume: its metadata (Docker `volume inspect` fields) and its runtime state.
     */
    struct SBOX_API SVolume {
        std::string name;
        std::string driver = "local";
        std::string mountpoint;         // --> <root>/<name>/_data.
        std::string createdAt;          // --> RFC 3339, UTC.
        std::string scope = "local";
        TStringMap labels;
        TStringMap options;             // --> Driver options as given (type, device, o, size).
        uint32_t projectId = 0;         // --> Project quota id, 0 when the volume has no quota.
        uint64_t sizeLimit = 0;         // --> Quota limit in bytes (size=), 0 for none.
        // --
        std::vector<std::string> users; // --> Ids of the containers (or plugin mount ids) using it.
        bool mounted = false;           // --> Backing filesystem is mounted on the mountpoint.

        /** Returns true when the volume was created without a name. */
        bool isAnonymous() const noexcept;

        /**
         * Returns the Docker `volume inspect` document (CreatedAt, Driver, Labels, Mountpoint,
         * Name, Options, Scope), plus UsageData {RefCount} when `withUsage`.
         */
        CJson toJson(bool withUsage = false) const;

        /**
         * Returns the persisted metadata document (inspect fields plus ProjectId / SizeLimit).
         */
        CJson toMetadata() const;

        /**
         * Parses a metadata document.
         */
        static int32_t fromMetadata(const CJson& json, SVolume& out);
    };

    /**
     * Parameters of a volume creation.
     */
    struct SVolumeCreate {
        std::string name;               // --> Empty creates an anonymous volume (64 hex digits).
        std::string driver = "local";   // --> Only "local" is built in.
        TStringMap labels;
        TStringMap options;
    };

    /**
     * Options of CVolumeStore.
     */
    struct SVolumeStoreOptions {
        std::string root;               // --> Store directory; empty for DefaultVolumeRoot().
        uint32_t dataUid = 0;           // --> Owner of new _data directories (userns-remapped root).
        uint32_t dataGid = 0;
        uint32_t projectIdBase = 0x10000;   // --> First project id handed out for quotas.
        int64_t lockTimeoutMs = 30000;
    };

    /**
     * Filters of a prune.
     */
    struct SPruneOptions {
        bool all = false;               // --> Also remove unused named volumes (default: anonymous only).
        std::vector<std::string> labelFilters;  // --> "key", "key=value", "!key", "key!=value" (all must match).
    };

    /**
     * Result of a prune.
     */
    struct SPruneReport {
        std::vector<std::string> removed;
        uint64_t reclaimedBytes = 0;
    };

    /**
     * Disk usage of a volume.
     */
    struct SVolumeUsage {
        uint64_t bytes = 0;             // --> Allocated bytes (quota usage, else st_blocks sum).
        uint64_t limit = 0;             // --> Quota limit, 0 for none.
        size_t refCount = 0;
    };

    /**
     * Returns the default store directory: /var/lib/sbox/volumes for root, else
     * $XDG_DATA_HOME/sbox/volumes (or ~/.local/share/sbox/volumes).
     */
    SBOX_API std::string DefaultVolumeRoot();

    /**
     * Returns true for a valid local volume name: [a-zA-Z0-9][a-zA-Z0-9_.-]+ (Docker's rule),
     * at most 255 bytes.
     */
    SBOX_API bool IsValidVolumeName(std::string_view name) noexcept;

    /**
     * Returns a random anonymous volume name (64 lowercase hex digits, like Docker).
     */
    SBOX_API std::string NewAnonymousVolumeName();

    /**
     * Docker-compatible named volume store.
     *
     * Layout (like /var/lib/docker/volumes):
     *   <root>/<name>/_data          the volume content (mountpoint of tmpfs/nfs/bind/device volumes)
     *   <root>/<name>/volume.json    metadata (inspect fields, quota project id)
     *   <root>/<name>/opts.json      Docker local-driver options file (only for volumes with options)
     *   <root>/<name>/state.json     users (reference counts), mounted flag, boot id
     *   <root>/.lock                 flock guarding every mutation (shared by all processes)
     *   <root>/.quota.json           persisted project id allocation
     *
     * Every mutating call takes the store lock for its whole duration (waiting on the event loop,
     * never blocking it), so CLI invocations, the plugin daemon and runtimes can share one root.
     * Volumes with mount options are mounted on first acquire and unmounted on the last release
     * (Docker semantics). Runtime state written before a reboot (other boot id) is discarded.
     */
    class SBOX_API CVolumeStore {
    private:
        SVolumeStoreOptions _options;
        std::string _lastError;

    public:
        /**
         * Creates a store over `options.root` (created on first mutation).
         */
        explicit CVolumeStore(SVolumeStoreOptions options = {});

        /** Returns the store directory. */
        inline const std::string& root() const noexcept { return _options.root; }

        /** Returns the options. */
        inline const SVolumeStoreOptions& options() const noexcept { return _options; }

        /**
         * Returns a human readable reason for the last failed call (empty when unknown).
         */
        inline const std::string& lastError() const noexcept { return _lastError; }

        /**
         * Returns the directory of a volume (<root>/<name>).
         */
        std::string volumeDir(const std::string& name) const;

        /**
         * Creates a volume. Creating an existing name returns the existing volume unchanged
         * (Docker's behavior); a different driver is -EEXIST.
         * @return SBOX_OK, -EINVAL (bad name or options), -ENOTSUP (unknown driver, size= without
         *         project quota support), or another errno.
         */
        TTask<int32_t> create(SVolumeCreate request, SVolume& out);

        /**
         * Reads a volume (metadata plus runtime state).
         * @return SBOX_OK, -ENOENT, or another errno.
         */
        int32_t inspect(const std::string& name, SVolume& out) const;

        /**
         * Lists all volumes sorted by name. Unreadable entries are skipped.
         */
        int32_t list(std::vector<SVolume>& out) const;

        /**
         * Removes a volume. In use (users) is -EBUSY unless `force`, which unmounts and removes it
         * anyway. A missing volume is -ENOENT.
         */
        TTask<int32_t> remove(std::string name, bool force = false);

        /**
         * Registers `user` (container id / plugin mount id) on a volume, mounting its backing
         * filesystem when it is the first user. Acquiring twice with the same user counts once.
         * @param mountpoint Receives the host path to bind into the container.
         */
        TTask<int32_t> acquire(std::string name, std::string user, std::string& mountpoint);

        /**
         * Drops `user` from a volume; the last user unmounts it. An unknown user is not an error.
         */
        TTask<int32_t> release(std::string name, std::string user);

        /**
         * Releases every volume `user` holds; with `removeAnonymous`, anonymous volumes left
         * unused are removed (docker run --rm).
         * @param released Receives the names released (optional).
         */
        TTask<int32_t> releaseUser(std::string user, bool removeAnonymous, std::vector<std::string>* released = nullptr);

        /**
         * Removes unused volumes matching the filters.
         */
        TTask<int32_t> prune(SPruneOptions options, SPruneReport& report);

        /**
         * Computes disk usage of a volume (project quota usage when it has one).
         */
        int32_t usage(const std::string& name, SVolumeUsage& out) const;

        /**
         * Copies image content into the volume when it is empty (see CopyUpIfEmpty). The
         * volume must be acquired (mounted) by the caller.
         * @return 1 copied, 0 nothing to do, or a negated errno.
         */
        int32_t copyUp(const std::string& name, const std::string& source);

    private:
        /**
         * Records a failure reason and returns `code`.
         */
        int32_t fail(int32_t code, std::string message);

        /**
         * Allocates the next project id (store lock held).
         */
        int32_t allocateProjectId(uint32_t& id);

        /**
         * Reads metadata and runtime state of a volume (store lock held or not).
         */
        int32_t load(const std::string& name, SVolume& out) const;

        /**
         * Writes the runtime state of a volume.
         */
        int32_t saveState(const SVolume& volume);

        /**
         * Removes a volume's directory, unmounting first (store lock held).
         */
        int32_t destroy(const SVolume& volume);

        /**
         * Parses the driver options of a loaded volume (records the reason on failure).
         */
        int32_t localOptions(const SVolume& volume, SLocalOptions& out);

        /**
         * Registers a user on a loaded volume, mounting it when needed (store lock held).
         */
        TTask<int32_t> acquireLocked(SVolume& volume, std::string user);

        /**
         * Drops a user from a loaded volume, unmounting after the last one (store lock held).
         */
        int32_t releaseLocked(SVolume& volume, const std::string& user);
    };

}
}

#endif
