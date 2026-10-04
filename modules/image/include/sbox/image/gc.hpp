#ifndef __INCLUDE_SBOX_IMAGE_GC_HPP__
#define __INCLUDE_SBOX_IMAGE_GC_HPP__

#include <sbox/image/store.hpp>

namespace sbox {
namespace image {

    /**
     * Options of CollectGarbage.
     */
    struct SBOX_API SGcOptions {
        bool dryRun = false;                // --> Report what would be removed, change nothing.
        bool pruneDangling = false;         // --> First drop untagged images (`docker image prune`).
        bool pruneUnused = false;           // --> First drop every image no container uses (`prune -a`).
        int64_t ingestMaxAgeSec = 86400;    // --> Abandoned ingest files older than this are deleted.
    };

    /**
     * What a collection removed (or would remove).
     */
    struct SBOX_API SGcResult {
        std::vector<std::string> removedImages;     // --> Image IDs whose names were dropped by pruning.
        std::vector<std::string> removedBlobs;
        std::vector<std::string> removedSnapshots;  // --> Chain IDs.
        uint64_t reclaimedBytes = 0;
    };

    /**
     * Mark and sweep over the store: roots are the index.json entries (manifest, config,
     * layers, and the snapshots of their chain IDs), container roots (their image and chain
     * IDs) and live leases (pulls and loads in progress). Unreferenced blobs and snapshots are
     * removed, as are stale temporary files. Runs under the store lock.
     */
    SBOX_API int32_t CollectGarbage(CContentStore& store, const SGcOptions& options, SGcResult& out);

    /**
     * Result of RemoveImage.
     */
    struct SBOX_API SRemoveResult {
        std::vector<std::string> untagged;          // --> References removed.
        std::vector<std::string> deleted;           // --> Image IDs deleted (plus collected blobs).
    };

    /**
     * Removes an image name or an image, with `docker rmi` semantics: a reference that is not
     * the image's last tag is only untagged; the last tag (or an image ID) deletes the image
     * and collects its blobs and snapshots. An image ID with several tags, or an image used by
     * a container root, needs `force` (-EEXIST / -EBUSY otherwise).
     */
    SBOX_API int32_t RemoveImage(CContentStore& store, std::string_view nameOrId, bool force, SRemoveResult& out,
                                 std::string* error = nullptr);

}
}

#endif
