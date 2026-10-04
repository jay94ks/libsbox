#ifndef __INCLUDE_SBOX_IMAGE_STORE_HPP__
#define __INCLUDE_SBOX_IMAGE_STORE_HPP__

#include <sbox/common.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/span.hpp>
#include <sbox/image/digest.hpp>
#include <sbox/image/reference.hpp>
#include <sbox/image/spec.hpp>

namespace sbox {
namespace image {

    class CContentStore;

    using CContentStorePtr = std::shared_ptr<CContentStore>;

    /**
     * Returns the default store root: /var/lib/sbox/image for root, otherwise
     * $XDG_DATA_HOME/sbox/image (~/.local/share/sbox/image).
     */
    SBOX_API std::string DefaultStoreRoot();

    /**
     * One named (or dangling) image in the store: an entry of index.json.
     */
    struct SBOX_API SImageRecord {
        std::string name;           // --> Full normalized reference ("docker.io/library/alpine:latest" or
                                    //     "...@sha256:..."), empty for an untagged image.
        SDescriptor target;         // --> The platform manifest the name points to.
    };

    /**
     * Everything known about one image (one image ID).
     */
    struct SBOX_API SImageInfo {
        std::string id;                         // --> Image ID: the config digest, as in Docker.
        std::string manifestDigest;
        SDescriptor manifestDescriptor;
        SManifest manifest;
        SImageConfig config;
        std::vector<std::string> repoTags;      // --> Full references with a tag.
        std::vector<std::string> repoDigests;   // --> Full references with a digest.
        int64_t size = 0;                       // --> Sum of the layer blob sizes.
    };

    /**
     * Holds the store's metadata lock (flock on <root>/lock) for its lifetime.
     * Re-entrant within one CContentStore object.
     */
    class SBOX_API CStoreLock {
    private:
        CContentStore* _store;

    public:
        /**
         * Takes the exclusive lock (blocking: metadata sections are short).
         */
        explicit CStoreLock(CContentStore& store);

        /** Releases the lock. */
        ~CStoreLock();

        CStoreLock(const CStoreLock&) = delete;

        CStoreLock& operator=(const CStoreLock&) = delete;
    };

    /**
     * Writer of one blob: bytes go to a file under <root>/ingest while their digest is
     * computed; commit() verifies digest and size and renames the file into blobs/.
     *
     * A named ingest ("<digest hex>.partial") can be resumed: open() with `resume` keeps the
     * bytes already there (re-hashing them) so a download continues with a Range request.
     * The ingest file is flock()ed so two processes never write the same one.
     */
    class SBOX_API CBlobWriter {
    private:
        CContentStore* _store = nullptr;
        CFd _fd;
        std::string _path;
        CDigester _digester;
        uint64_t _offset = 0;
        bool _committed = false;
        bool _keep = false;         // --> Named (resumable) ingests survive the writer.

    public:
        CBlobWriter() = default;

        /** Removes an uncommitted ingest that cannot be resumed. */
        ~CBlobWriter();

        CBlobWriter(const CBlobWriter&) = delete;

        CBlobWriter& operator=(const CBlobWriter&) = delete;

        /**
         * Opens an ingest file.
         * @param name File name under ingest/ (empty for a unique temporary name).
         * @param resume Keep (and re-hash) existing content instead of truncating.
         * @return SBOX_OK, -EBUSY when another process holds this ingest, or a negated errno.
         */
        int32_t open(CContentStore& store, const std::string& name = std::string(), bool resume = false,
                     EDigestAlgorithm algorithm = EDIGEST_SHA256);

        /**
         * Appends bytes.
         */
        int32_t write(const SReadOnlyByteSpan& data);

        /**
         * Returns the number of bytes in the ingest so far.
         */
        inline uint64_t offset() const noexcept { return _offset; }

        /**
         * Restarts the ingest from zero (truncate).
         */
        int32_t truncate();

        /**
         * Verifies and moves the blob into place.
         * @param expectedDigest Digest the content must have; empty to accept any.
         * @param expectedSize Size the content must have; negative to accept any.
         * @param digest Receives the digest of the content when not null.
         * @return SBOX_OK; -EBADMSG on a digest or size mismatch (the ingest is discarded).
         */
        int32_t commit(const std::string& expectedDigest = std::string(), int64_t expectedSize = -1,
                       std::string* digest = nullptr);

        /**
         * Discards the ingest file.
         */
        void abort() noexcept;

        /**
         * Returns the path of the ingest file.
         */
        inline const std::string& path() const noexcept { return _path; }
    };

    /**
     * Protects content that is being produced (a pull in progress, an import) from garbage
     * collection before an index.json entry references it.
     *
     * A lease is a file <root>/leases/<random>.json listing blob digests and snapshot chain
     * IDs. The file is flock()ed while the lease object lives; the collector treats locked
     * lease files as roots and deletes unlocked (stale) ones.
     */
    class SBOX_API CLease {
    private:
        CFd _fd;
        std::string _path;
        std::vector<std::string> _blobs;
        std::vector<std::string> _snapshots;

    public:
        CLease() = default;

        /** Releases the lease (deletes its file). */
        ~CLease();

        CLease(const CLease&) = delete;

        CLease& operator=(const CLease&) = delete;

        /**
         * Creates the lease file.
         */
        int32_t open(CContentStore& store);

        /**
         * Adds a blob digest to the lease.
         */
        int32_t addBlob(const std::string& digest);

        /**
         * Adds a snapshot chain ID to the lease.
         */
        int32_t addSnapshot(const std::string& chainId);

        /**
         * Deletes the lease file.
         */
        void release() noexcept;

        /**
         * Reads the live (locked) leases of a store and removes stale ones.
         */
        static int32_t collect(CContentStore& store, std::vector<std::string>& blobs, std::vector<std::string>& snapshots);

    private:
        /**
         * Rewrites the lease file.
         */
        int32_t flush();
    };

    /**
     * Content-addressed image store laid out as an OCI image layout:
     *
     *     <root>/oci-layout              {"imageLayoutVersion": "1.0.0"}
     *     <root>/index.json              named images (annotations io.containerd.image.name and
     *                                    org.opencontainers.image.ref.name)
     *     <root>/blobs/sha256/<hex>      blobs (manifests, configs, layers)
     *     <root>/ingest/                 blobs being written
     *     <root>/db.json                 metadata (layer blob digest -> diffID)
     *     <root>/snapshots/, containers/ unpacked layers and container roots (see snapshot.hpp)
     *     <root>/lock                    flock for metadata updates by concurrent processes
     *
     * Blob ingestion needs no lock (content-addressed rename); metadata updates (index.json,
     * db.json) are read-modify-write under the lock, and files are replaced atomically.
     */
    class SBOX_API CContentStore {
    private:
        std::string _root;
        CFd _lockFd;
        int32_t _lockDepth = 0;

        friend class CStoreLock;

    public:
        /**
         * Use open() to create a store.
         */
        explicit CContentStore(std::string root);

        CContentStore(const CContentStore&) = delete;

        CContentStore& operator=(const CContentStore&) = delete;

        /**
         * Opens (and initializes when needed) a store at `root`.
         * @return SBOX_OK or a negated errno.
         */
        static int32_t open(const std::string& root, CContentStorePtr& out);

        /** Returns the root directory. */
        inline const std::string& root() const noexcept { return _root; }

        /** Returns the path of a directory below the root. */
        std::string path(std::string_view leaf) const;

        // -- Blobs.

        /**
         * Returns the path of a blob (whether it exists or not), or "" for an invalid digest.
         */
        std::string blobPath(std::string_view digest) const;

        /** Returns true when the blob exists. */
        bool hasBlob(std::string_view digest) const;

        /**
         * Returns the size of a blob.
         * @return The size (>= 0) or a negated errno (-ENOENT, -EINVAL).
         */
        int64_t blobSize(std::string_view digest) const;

        /**
         * Reads a whole (small) blob, verifying its digest.
         * @return SBOX_OK, -ENOENT, -EFBIG beyond `limit`, -EBADMSG when the content does not
         *         match its digest.
         */
        int32_t readBlob(std::string_view digest, std::string& out, size_t limit = size_t(64) << 20) const;

        /**
         * Reads a blob and parses it as JSON.
         */
        int32_t readJsonBlob(std::string_view digest, CJson& out) const;

        /**
         * Stores bytes as a blob.
         * @param digest Receives the digest.
         * @param expectedDigest When not empty, the content must match it (-EBADMSG).
         */
        int32_t writeBlob(const SReadOnlyByteSpan& data, std::string& digest, const std::string& expectedDigest = std::string());

        /**
         * Stores a JSON document as a blob and returns its descriptor.
         */
        int32_t writeJsonBlob(const CJson& json, std::string_view mediaType, SDescriptor& out);

        /**
         * Removes a blob (missing is not an error).
         */
        int32_t deleteBlob(std::string_view digest);

        /**
         * Lists the digests of all blobs.
         */
        std::vector<std::string> listBlobs() const;

        // -- Named images (index.json).

        /**
         * Reads every entry of index.json.
         */
        int32_t listRecords(std::vector<SImageRecord>& out) const;

        /**
         * Points a name at a manifest (adds or replaces the index.json entry). When the name
         * moves away from a manifest no other entry references, that manifest stays as an
         * untagged (dangling) entry, like Docker's "<none>" images.
         * @param name Full normalized reference; empty adds an untagged (dangling) entry.
         */
        int32_t setRecord(const std::string& name, const SDescriptor& target);

        /**
         * Removes the entry of a name.
         * @return SBOX_OK or -ENOENT.
         */
        int32_t removeRecord(const std::string& name);

        /**
         * Removes every entry whose target has the given manifest digest.
         * @return The number of entries removed.
         */
        int32_t removeRecordsForManifest(const std::string& manifestDigest);

        /**
         * Finds the image a user string means: a full image ID ("sha256:<hex>" or 64 hex), a
         * reference (normalized, ":latest" added), or a unique image ID prefix.
         * @return SBOX_OK, -ENOENT, or -EEXIST when an ID prefix is ambiguous.
         */
        int32_t resolve(std::string_view nameOrId, SImageInfo& out) const;

        /**
         * Loads the information of an image by its manifest descriptor.
         */
        int32_t loadImage(const SDescriptor& manifest, SImageInfo& out) const;

        /**
         * Lists every image (grouped by image ID; repoTags / repoDigests filled).
         */
        int32_t listImages(std::vector<SImageInfo>& out) const;

        // -- Metadata (db.json).

        /**
         * Returns the diffID recorded for a layer blob, or "".
         */
        std::string diffIdOf(std::string_view blobDigest) const;

        /**
         * Records the diffID of a layer blob.
         */
        int32_t recordDiffId(std::string_view blobDigest, std::string_view diffId);

        /**
         * Reads db.json (an empty object when missing).
         */
        int32_t readDb(CJson& out) const;

        /**
         * Replaces db.json atomically (take a CStoreLock around read-modify-write).
         */
        int32_t writeDb(const CJson& db);

    private:
        /**
         * Reads index.json.
         */
        int32_t readIndex(SIndex& out) const;

        /**
         * Writes index.json atomically.
         */
        int32_t writeIndex(const SIndex& index);
    };

}
}

#endif
