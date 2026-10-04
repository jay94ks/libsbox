#ifndef __INCLUDE_SBOX_IMAGE_SPEC_HPP__
#define __INCLUDE_SBOX_IMAGE_SPEC_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>

namespace sbox {
namespace image {

    /** OCI image index. */
    constexpr const char* MT_OCI_INDEX = "application/vnd.oci.image.index.v1+json";
    /** OCI image manifest. */
    constexpr const char* MT_OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json";
    /** OCI image configuration. */
    constexpr const char* MT_OCI_CONFIG = "application/vnd.oci.image.config.v1+json";
    /** OCI uncompressed layer. */
    constexpr const char* MT_OCI_LAYER = "application/vnd.oci.image.layer.v1.tar";
    /** OCI gzip layer. */
    constexpr const char* MT_OCI_LAYER_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip";
    /** OCI zstd layer. */
    constexpr const char* MT_OCI_LAYER_ZSTD = "application/vnd.oci.image.layer.v1.tar+zstd";
    /** OCI empty descriptor (artifacts). */
    constexpr const char* MT_OCI_EMPTY = "application/vnd.oci.empty.v1+json";
    /** Docker manifest list (fat manifest). */
    constexpr const char* MT_DOCKER_MANIFEST_LIST = "application/vnd.docker.distribution.manifest.list.v2+json";
    /** Docker image manifest, schema 2. */
    constexpr const char* MT_DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json";
    /** Docker image configuration. */
    constexpr const char* MT_DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json";
    /** Docker gzip layer. */
    constexpr const char* MT_DOCKER_LAYER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip";
    /** Docker uncompressed layer (used by some tools; Docker itself reads it as plain tar). */
    constexpr const char* MT_DOCKER_LAYER = "application/vnd.docker.image.rootfs.diff.tar";
    /** Docker foreign (non-distributable) gzip layer. */
    constexpr const char* MT_DOCKER_FOREIGN_LAYER = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip";
    /** Docker schema 1 manifest (unsupported). */
    constexpr const char* MT_DOCKER_SCHEMA1 = "application/vnd.docker.distribution.manifest.v1+json";
    /** Docker signed schema 1 manifest (unsupported). */
    constexpr const char* MT_DOCKER_SCHEMA1_SIGNED = "application/vnd.docker.distribution.manifest.v1+prettyjws";

    /** Annotation holding the tag (OCI image layout index.json). */
    constexpr const char* ANNOTATION_REF_NAME = "org.opencontainers.image.ref.name";
    /** Annotation holding the full image name (containerd / Docker 25+ archives). */
    constexpr const char* ANNOTATION_IMAGE_NAME = "io.containerd.image.name";
    /** Annotation with the creation time of an image. */
    constexpr const char* ANNOTATION_CREATED = "org.opencontainers.image.created";

    /**
     * What a manifest document is.
     */
    enum EManifestKind {
        EMK_INVALID = 0,
        EMK_INDEX,              // --> OCI index or Docker manifest list.
        EMK_MANIFEST,           // --> OCI manifest or Docker schema 2 manifest.
        EMK_SCHEMA1,            // --> Docker schema 1 (rejected by this module).
    };

    /**
     * Returns true for an index / manifest list media type.
     */
    SBOX_API bool IsIndexMediaType(std::string_view mediaType) noexcept;

    /**
     * Returns true for an image manifest media type (OCI or Docker schema 2).
     */
    SBOX_API bool IsManifestMediaType(std::string_view mediaType) noexcept;

    /**
     * Returns true for a layer media type this module can unpack (tar, tar+gzip, tar+zstd in
     * OCI or Docker spelling, including non-distributable / foreign variants).
     */
    SBOX_API bool IsLayerMediaType(std::string_view mediaType) noexcept;

    /**
     * Returns true for Docker schema 1 media types.
     */
    SBOX_API bool IsSchema1MediaType(std::string_view mediaType) noexcept;

    /**
     * Platform of an image (OCI "platform" object; also the target of platform selection).
     */
    struct SBOX_API SPlatform {
        std::string os;
        std::string architecture;
        std::string variant;
        std::string osVersion;
        std::vector<std::string> osFeatures;

        /**
         * Parses "os[/arch[/variant]]" ("linux/arm64/v8", "linux/amd64"); a single
         * architecture name ("arm64") is taken with os "linux".
         * @return SBOX_OK or -EINVAL.
         */
        static int32_t parse(std::string_view text, SPlatform& out);

        /**
         * Returns "os/arch[/variant]".
         */
        std::string toString() const;

        /**
         * Returns the platform in canonical spelling (aarch64 -> arm64, x86_64 -> amd64,
         * armhf -> arm/v7, arm64 variant "v8" -> "", ...), as containerd's Normalize does.
         */
        SPlatform normalized() const;

        /**
         * Reads an OCI platform object.
         */
        static SPlatform fromJson(const CJson& json);

        /**
         * Writes an OCI platform object.
         */
        CJson toJson() const;

        /** Returns true when nothing is set. */
        inline bool empty() const noexcept { return os.empty() && architecture.empty(); }
    };

    /**
     * Returns the platform of this machine (os "linux", architecture from uname(2), the arm
     * variant from the CPU).
     */
    SBOX_API SPlatform HostPlatform();

    /**
     * Returns how well `candidate` serves `want`: 0 = not usable, higher is better. Exact
     * (normalized) matches score highest; an arm variant older than the wanted one (v6 for a v7
     * host) is usable with a lower score, as is an amd64 image for an amd64 variant host.
     */
    SBOX_API int32_t PlatformScore(const SPlatform& want, const SPlatform& candidate);

    /**
     * Content descriptor (OCI "descriptor").
     */
    struct SBOX_API SDescriptor {
        std::string mediaType;
        std::string digest;
        int64_t size = 0;
        std::vector<std::string> urls;
        std::vector<std::pair<std::string, std::string>> annotations;
        SPlatform platform;
        bool hasPlatform = false;
        std::string artifactType;

        /**
         * Reads a descriptor; fails with -EINVAL when the digest or size is missing or invalid.
         */
        static int32_t fromJson(const CJson& json, SDescriptor& out);

        /**
         * Writes the descriptor (fields that are empty are omitted).
         */
        CJson toJson() const;

        /**
         * Returns an annotation value, or an empty string.
         */
        std::string annotation(std::string_view key) const;

        /**
         * Sets (or replaces) an annotation; an empty value removes it.
         */
        void annotation(std::string_view key, std::string_view value);
    };

    /**
     * Image manifest (OCI manifest or Docker schema 2 manifest; same structure).
     */
    struct SBOX_API SManifest {
        int32_t schemaVersion = 2;
        std::string mediaType;
        std::string artifactType;
        SDescriptor config;
        std::vector<SDescriptor> layers;
        std::vector<std::pair<std::string, std::string>> annotations;

        /**
         * Reads a manifest document.
         * @return SBOX_OK or -EINVAL.
         */
        static int32_t fromJson(const CJson& json, SManifest& out);

        /**
         * Writes the manifest document.
         */
        CJson toJson() const;
    };

    /**
     * Image index (OCI index or Docker manifest list).
     */
    struct SBOX_API SIndex {
        int32_t schemaVersion = 2;
        std::string mediaType;
        std::vector<SDescriptor> manifests;
        std::vector<std::pair<std::string, std::string>> annotations;

        /**
         * Reads an index document.
         * @return SBOX_OK or -EINVAL.
         */
        static int32_t fromJson(const CJson& json, SIndex& out);

        /**
         * Writes the index document.
         */
        CJson toJson() const;

        /**
         * Picks the manifest that best serves `want` (see PlatformScore). Entries without a
         * platform, attestation manifests ("unknown/unknown") and non-manifest entries are
         * ignored.
         * @return The position in `manifests`, or -ENOENT when none fits.
         */
        int32_t select(const SPlatform& want) const;
    };

    /**
     * Classifies a manifest document from its media type (the document's own field, or
     * `contentType` from the HTTP response) and, failing that, from its structure.
     */
    SBOX_API EManifestKind ClassifyManifest(const CJson& json, std::string_view contentType = {});

    /**
     * Image configuration (OCI image config / Docker container image JSON).
     *
     * The whole document is kept in `raw` so that fields this module does not interpret
     * (history, Docker's container_config, Healthcheck, ...) survive a round trip; toJson()
     * writes the interpreted fields back over a copy of it.
     */
    struct SBOX_API SImageConfig {
        CJson raw;
        std::string architecture;
        std::string os;
        std::string variant;
        std::string created;
        std::string author;
        std::vector<std::string> diffIds;           // --> rootfs.diff_ids, bottom layer first.

        // -- Container defaults ("config").
        std::string user;
        std::string workingDir;
        std::string stopSignal;
        std::vector<std::string> env;               // --> "NAME=value".
        std::vector<std::string> entrypoint;
        std::vector<std::string> cmd;
        std::vector<std::string> exposedPorts;      // --> "80/tcp".
        std::vector<std::string> volumes;
        std::vector<std::pair<std::string, std::string>> labels;
        bool argsEscaped = false;

        /**
         * Reads a configuration document.
         * @return SBOX_OK or -EINVAL (not an object, or rootfs.diff_ids malformed).
         */
        static int32_t fromJson(const CJson& json, SImageConfig& out);

        /**
         * Writes the configuration document.
         */
        CJson toJson() const;

        /**
         * Returns the platform recorded in the config.
         */
        SPlatform platform() const;

        /**
         * Returns a label value, or an empty string.
         */
        std::string label(std::string_view key) const;
    };

    /**
     * Returns the current UTC time in RFC 3339 form with nanoseconds, as image configs use.
     */
    SBOX_API std::string NowRfc3339();

}
}

#endif
