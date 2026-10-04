#ifndef __CLI_SBOX_IMAGE_ATTACH_HPP__
#define __CLI_SBOX_IMAGE_ATTACH_HPP__

// sbox-image bundle -v/--mount/--tmpfs/--network/--netns: wiring of the vol and net modules
// into a bundle's config.json, and the record `sbox-image rm` uses to undo it. The image
// library knows nothing about volumes or networks; only this tool links all three.

#include <sbox/core/json.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/network.hpp>
#include <sbox/vol/mount.hpp>
#include <string>
#include <vector>

namespace imagecli {

    using namespace sbox;

    /**
     * What `bundle` was asked to attach to a container.
     */
    struct AttachRequest {
        std::vector<vol::SMountRequest> mounts;     // --> -v / --mount / --tmpfs, in command line order.
        std::string volumeRoot;                     // --> Volume store (default vol::DefaultVolumeRoot()).
        // --
        std::string network;                        // --> --network NAME (connect into a new netns).
        std::vector<net::SPortMapping> ports;       // --> --publish, only with --network.
        std::string netns;                          // --> --netns PATH (join an existing namespace).
        std::string netStateDir;                    // --> Network state (default net::DefaultNetworkStateDir()).
        std::string netnsDir;                       // --> Where the container's netns is pinned.

        /** Returns true when nothing is to be attached. */
        bool empty() const noexcept;
    };

    /**
     * What was attached, persisted as `<store>/attachments/<id>.json` until `rm`.
     */
    struct AttachRecord {
        std::string id;                             // --> Container root ID (volume user, endpoint owner).
        std::string volumeRoot;                     // --> Empty when no volume was acquired.
        std::vector<std::string> volumes;           // --> Names acquired (anonymous ones included).
        std::string netStateDir;
        std::string network;                        // --> Empty when not connected by us.
        std::string netns;                          // --> Namespace pinned by us (removed on rm).
        std::vector<net::SPortMapping> ports;       // --> Published ports as assigned (host port filled).
        std::string address;                        // --> Container IPv4 address with prefix.

        /** Serializes the record. */
        CJson toJson() const;

        /** Parses a record. @return SBOX_OK or -EINVAL. */
        static int32_t fromJson(const CJson& json, AttachRecord& out);
    };

    /**
     * Parses one attach option at args[i] (advancing i past its value).
     * @return 1 when consumed, 0 when args[i] is not an attach option, -EINVAL on a bad value
     *         (`error` says why).
     */
    int32_t ParseAttachOption(const std::vector<std::string>& args, size_t& i, AttachRequest& out, std::string& error);

    /**
     * Prepares the mounts and the network of container `id` and edits `<bundle>/config.json`:
     * mounts are appended to "mounts" (volumes created, acquired for `id` and filled from
     * `rootfs`), and the network namespace path is set (a new namespace connected to the
     * network, or the given one). On failure everything done here is undone.
     */
    TTask<int32_t> AttachContainer(AttachRequest request, std::string id, std::string bundle, std::string rootfs,
                                   AttachRecord& out, std::string& error);

    /**
     * Undoes AttachContainer: disconnects the network, unpins the namespace and releases the
     * volumes (removing anonymous ones when `removeAnonymous`). Missing pieces are not errors.
     */
    TTask<int32_t> DetachContainer(AttachRecord record, bool removeAnonymous, std::string& error);

    /**
     * Returns the record path of a container in an image store.
     */
    std::string AttachRecordPath(const std::string& storeRoot, const std::string& id);

    /**
     * Writes a record (0600). @return SBOX_OK or a negated errno.
     */
    int32_t SaveAttachRecord(const std::string& storeRoot, const AttachRecord& record);

    /**
     * Reads a record. @return SBOX_OK, -ENOENT, or another negated errno.
     */
    int32_t LoadAttachRecord(const std::string& storeRoot, const std::string& id, AttachRecord& out);

}

#endif
