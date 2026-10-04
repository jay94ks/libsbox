#ifndef __INCLUDE_SBOX_IMAGE_TRANSFER_HPP__
#define __INCLUDE_SBOX_IMAGE_TRANSFER_HPP__

#include <sbox/archive/stream.hpp>
#include <sbox/image/store.hpp>

namespace sbox {
namespace image {

    /**
     * Options of LoadImageArchive.
     */
    struct SBOX_API SLoadOptions {
        std::string name;       // --> Name for OCI archive entries that carry only a tag (or none).
        SPlatform platform;     // --> Platform picked from nested indexes (empty: the host).
    };

    /**
     * What an archive load added.
     */
    struct SBOX_API SLoadResult {
        std::vector<std::string> tags;          // --> Full references that now point at loaded images.
        std::vector<std::string> imageIds;      // --> Every loaded image ID (config digest).
        std::string format;                     // --> "docker" or "oci".
    };

    /**
     * Writes images as a `docker save` archive (tar): manifest.json ([{"Config", "RepoTags",
     * "Layers"}]), repositories, and the Docker 25 layout of the same content (oci-layout,
     * index.json, blobs/sha256/(hex)). Layers are stored uncompressed (blob digest = diffID), as
     * `docker save` does; config blobs keep their digest, so image IDs survive the round trip.
     *
     * A name with a tag exports that tag; a name without a tag exports every tag of that
     * repository; an image ID exports the image without tags.
     * @return SBOX_OK, -ENOENT for an unknown image, -EBADMSG when a layer does not match its
     *         diffID, or an I/O error.
     */
    SBOX_API int32_t SaveDockerArchive(CContentStore& store, const std::vector<std::string>& images, archive::IByteSink& out,
                                       std::string* error = nullptr);

    /**
     * Writes images as an OCI image layout tar (oci-layout, index.json with
     * io.containerd.image.name and org.opencontainers.image.ref.name annotations, blobs as
     * stored, compressed layers included).
     */
    SBOX_API int32_t SaveOciArchive(CContentStore& store, const std::vector<std::string>& images, archive::IByteSink& out,
                                    std::string* error = nullptr);

    /**
     * Loads a `docker save` archive or an OCI layout archive (optionally gzip/zstd
     * compressed) into the store. Docker archives are recognized by manifest.json, OCI ones by
     * oci-layout + index.json. Every digest and every layer's diffID is verified.
     */
    SBOX_API int32_t LoadImageArchive(CContentStore& store, archive::IByteSource& in, const SLoadOptions& options,
                                      SLoadResult& out, std::string* error = nullptr);

}
}

#endif
