#ifndef __INCLUDE_SBOX_IMAGE_SNAPSHOT_HPP__
#define __INCLUDE_SBOX_IMAGE_SNAPSHOT_HPP__

#include <sbox/image/store.hpp>
#include <functional>

namespace sbox {
namespace image {

    /**
     * How a container root filesystem is built from image layers.
     */
    enum ESnapshotMode {
        ESNAP_AUTO = 0,     // --> overlay when the kernel supports it here, else copy.
        ESNAP_OVERLAY,      // --> overlayfs: layer snapshots as lowerdirs + per-container upper/work.
        ESNAP_COPY,         // --> Layers flattened into a plain directory (whiteouts applied).
        ESNAP_INVALID,
    };

    /**
     * Returns "overlay" / "copy" / "auto".
     */
    SBOX_API const char* SnapshotModeName(ESnapshotMode mode) noexcept;

    /**
     * Parses a snapshot mode name.
     */
    SBOX_API ESnapshotMode ParseSnapshotMode(std::string_view name) noexcept;

    /**
     * Phases reported through FImageProgress.
     */
    enum EProgressPhase {
        EPP_RESOLVING = 0,      // --> Resolving a reference to a manifest.
        EPP_RESOLVED,           // --> Manifest known (digest set).
        EPP_EXISTS,             // --> Blob already present.
        EPP_WAITING,            // --> Another process is downloading the same blob.
        EPP_DOWNLOADING,        // --> current / total bytes of a blob.
        EPP_RETRYING,           // --> A transfer failed and will be retried (message says why).
        EPP_VERIFIED,           // --> Blob downloaded and its digest verified.
        EPP_EXTRACTING,         // --> Unpacking a layer into a snapshot.
        EPP_EXTRACTED,          // --> Layer unpacked and its diffID verified.
        EPP_UPLOADING,          // --> current / total bytes of a blob being pushed.
        EPP_MOUNTED,            // --> Blob mounted from another repository on push.
        EPP_PUSHED,             // --> Blob or manifest pushed.
        EPP_DONE,               // --> The whole operation finished.
    };

    /**
     * One progress event.
     */
    struct SProgress {
        EProgressPhase phase = EPP_RESOLVING;
        std::string digest;
        std::string mediaType;
        uint64_t current = 0;
        uint64_t total = 0;
        std::string message;
    };

    /**
     * Receiver of progress events.
     */
    using FImageProgress = std::function<void(const SProgress&)>;

    /**
     * An unpacked layer: <root>/snapshots/<chainID hex>/fs plus meta.json.
     */
    struct SBOX_API SSnapshotInfo {
        std::string chainId;
        std::string diffId;
        std::string parent;         // --> Chain ID of the layer below, "" for the bottom layer.
        std::string path;           // --> The "fs" directory.
        std::string whiteouts;      // --> "overlay" (char devices, trusted.*) or "userxattr".
        uint64_t size = 0;
    };

    /**
     * Description of an overlay mount, for callers that mount it themselves (e.g. inside a
     * container's user and mount namespaces).
     */
    struct SBOX_API SMountPlan {
        std::vector<std::string> lowerDirs;     // --> Top layer first (overlayfs order).
        std::string upperDir;
        std::string workDir;
        std::string target;
        std::vector<std::string> options;       // --> Extra options ("userxattr", "index=off").

        /**
         * Returns the legacy mount(2) data string "lowerdir=...,upperdir=...,workdir=...".
         */
        std::string toMountData() const;
    };

    /**
     * A container root prepared from an image: <root>/containers/<id>/.
     */
    struct SBOX_API SContainerInfo {
        std::string id;
        std::string imageId;
        std::string imageName;
        std::string manifestDigest;
        ESnapshotMode mode = ESNAP_INVALID;
        std::string rootfs;                     // --> overlay: merged dir; copy: the flattened dir.
        std::vector<std::string> chainIds;      // --> Snapshots the container uses (lease for GC).
        std::string created;
        SMountPlan plan;                        // --> overlay only.
    };

    /**
     * Options of a CSnapshotter.
     */
    struct SBOX_API SSnapshotterOptions {
        int32_t rootless = -1;          // --> -1: decide from the process (not real root); 0 / 1 force.
        bool legacyMount = false;       // --> Use mount(2) with a lowerdir string instead of fsopen()+"lowerdir+".
        FImageProgress progress;
    };

    /**
     * Options of CSnapshotter::commit (like `docker commit`).
     */
    struct SBOX_API SCommitOptions {
        std::string reference;                  // --> Name for the new image ("" leaves it untagged).
        std::string author;
        std::string comment;
        std::string createdBy = "sbox commit";
        int32_t compressionLevel = -1;          // --> gzip level of the new layer (-1 default).
        bool hasConfigOverride = false;         // --> Replace the container defaults with `config` below.
        SImageConfig config;                    // --> Only User/Env/Entrypoint/Cmd/WorkingDir/... are used.
    };

    /**
     * Unpacks image layers into snapshots and builds container roots from them.
     *
     * Each layer is extracted once into snapshots/<chainID>/fs using the overlay whiteout
     * format (0/0 character devices and trusted.overlay.opaque; or, rootless, the "userxattr"
     * variant), and its diffID is verified against the image config while it is extracted.
     * A container root is either an overlay mount of those snapshots (top layer first) with a
     * per-container upper/work directory, or a flattened copy of all layers.
     */
    class SBOX_API CSnapshotter {
    private:
        CContentStorePtr _store;
        SSnapshotterOptions _options;
        bool _rootless;
        std::string _lastError;

    public:
        /**
         * Creates a snapshotter over a store.
         */
        explicit CSnapshotter(CContentStorePtr store, SSnapshotterOptions options = {});

        /** Returns the store. */
        inline const CContentStorePtr& store() const noexcept { return _store; }

        /** Returns true when snapshots use the unprivileged (userxattr) format. */
        inline bool rootless() const noexcept { return _rootless; }

        /** Returns a description of the last failure. */
        inline const std::string& lastError() const noexcept { return _lastError; }

        /**
         * Returns true when an overlay mount can be made by this process (probes once with a
         * tiny mount under the store).
         */
        bool overlaySupported();

        /**
         * Returns the directory of a snapshot ("<root>/snapshots/<hex>").
         */
        std::string snapshotDir(std::string_view chainId) const;

        /**
         * Returns true when the snapshot exists.
         */
        bool hasSnapshot(std::string_view chainId) const;

        /**
         * Reads a snapshot's metadata.
         */
        int32_t snapshot(std::string_view chainId, SSnapshotInfo& out) const;

        /**
         * Lists every snapshot.
         */
        int32_t listSnapshots(std::vector<SSnapshotInfo>& out) const;

        /**
         * Removes a snapshot.
         */
        int32_t removeSnapshot(std::string_view chainId);

        /**
         * Extracts one layer blob into its snapshot (no-op when it exists) and verifies the
         * diffID while extracting.
         * @param layer The layer descriptor (blob must be in the store).
         * @param diffId Expected diffID (from the config), or "" to accept and compute it.
         * @param parentChainId Chain ID of the layer below ("" for the bottom layer).
         * @param chainId Receives the chain ID of this layer.
         * @return SBOX_OK; -EBADMSG when the diffID does not match; or an extraction error.
         */
        int32_t unpackLayer(const SDescriptor& layer, const std::string& diffId, const std::string& parentChainId,
                            std::string& chainId);

        /**
         * Unpacks every layer of an image.
         */
        int32_t unpack(const SImageInfo& image);

        /**
         * Extracts every layer of an image onto `dir` (created when missing) with whiteouts
         * applied (EWHT_APPLY): the copy snapshotter, also used for bundles and exports.
         */
        int32_t flatten(const SImageInfo& image, const std::string& dir);

        /**
         * Creates a container root for an image.
         * @param id Container ID ([A-Za-z0-9_.-], unique); "" generates one.
         * @param mode ESNAP_AUTO picks overlay when supported.
         * @param mountNow For overlay: also mount it at containers/<id>/merged.
         */
        int32_t prepare(const std::string& id, const SImageInfo& image, ESnapshotMode mode, SContainerInfo& out,
                        bool mountNow = true);

        /**
         * Reads a container's metadata.
         */
        int32_t container(const std::string& id, SContainerInfo& out) const;

        /**
         * Lists every container root.
         */
        int32_t listContainers(std::vector<SContainerInfo>& out) const;

        /**
         * Mounts a prepared overlay container root (at its merged dir, or `target`).
         * A copy container needs no mount (SBOX_OK).
         */
        int32_t mount(const std::string& id, const std::string& target = std::string());

        /**
         * Mounts an overlay described by a plan.
         */
        int32_t mountPlan(const SMountPlan& plan);

        /**
         * Unmounts a container root (not mounted is not an error).
         */
        int32_t unmount(const std::string& id, const std::string& target = std::string());

        /**
         * Unmounts and deletes a container root.
         */
        int32_t remove(const std::string& id);

        /**
         * Turns a container's changes into a new image: the overlay upper directory becomes a
         * gzip layer (whiteouts converted back to ".wh." entries), the image config gets the
         * new diffID and a history entry, and a manifest of the parent's flavor (OCI or Docker)
         * is written and optionally tagged.
         * @return SBOX_OK; -ENOTSUP for copy containers.
         */
        int32_t commit(const std::string& id, const SCommitOptions& options, SImageInfo& out);
    };

}
}

#endif
