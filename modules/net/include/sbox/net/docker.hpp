#ifndef __INCLUDE_SBOX_NET_DOCKER_HPP__
#define __INCLUDE_SBOX_NET_DOCKER_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/network.hpp>

namespace sbox {
namespace net {

    /**
     * Docker remote network driver + IPAM driver plugin, as pure request handlers.
     *
     * The HTTP side (a UNIX socket under /run/docker/plugins/<name>.sock answering POSTs) is
     * not part of this class: a server calls handle() with the request path and the decoded JSON
     * body and writes the returned JSON back with Content-Type contentType(). Successful replies
     * use HTTP 200; replies whose "Err" member is non-empty may use 200 or 500 (Docker reads Err
     * either way, isError() tells which).
     *
     * Implemented endpoints:
     *   /Plugin.Activate
     *   /NetworkDriver.GetCapabilities, CreateNetwork, DeleteNetwork, CreateEndpoint,
     *     EndpointOperInfo, DeleteEndpoint, Join, Leave, DiscoverNew, DiscoverDelete,
     *     ProgramExternalConnectivity, RevokeExternalConnectivity
     *   /IpamDriver.GetCapabilities, GetDefaultAddressSpaces, RequestPool, ReleasePool,
     *     RequestAddress, ReleaseAddress
     *
     * Networks are created with the sbox driver named by the generic option "sbox.driver"
     * (bridge by default, or macvlan/ipvlan, or any registered driver such as the vpn module's
     * "wg-overlay", which is also implied by an "sbox.wg.overlay" / "sbox.wg.overlay.file"
     * option) and Docker's addresses (from whichever IPAM driver Docker used). Docker moves the interface into the sandbox itself (Join returns SrcName).
     */
    class SBOX_API CDockerPlugin {
    private:
        CNetworkManager& _manager;

    public:
        /**
         * Creates the handler over a manager (which owns state, drivers and IPAM).
         */
        explicit CDockerPlugin(CNetworkManager& manager) noexcept : _manager(manager) {}

        /**
         * Returns the content type of plugin replies.
         */
        static const char* contentType() noexcept;

        /**
         * Returns true when a reply carries an error.
         */
        static bool isError(const CJson& reply) noexcept;

        /**
         * Handles one plugin call.
         * @param path Request path ("/NetworkDriver.CreateNetwork").
         * @param body Decoded JSON request body (null for an empty body).
         * @return The reply object; {"Err": "..."} on failure.
         */
        TTask<CJson> handle(std::string path, CJson body);

    private:
        /** NetworkDriver.CreateNetwork. */
        TTask<CJson> createNetwork(const CJson& body);

        /** NetworkDriver.CreateEndpoint. */
        TTask<CJson> createEndpoint(const CJson& body);

        /** NetworkDriver.Join. */
        TTask<CJson> join(const CJson& body);

        /** NetworkDriver.ProgramExternalConnectivity. */
        TTask<CJson> programExternal(const CJson& body);

        /** IpamDriver.RequestPool. */
        TTask<CJson> requestPool(const CJson& body);

        /** IpamDriver.RequestAddress. */
        TTask<CJson> requestAddress(const CJson& body);
    };

}
}

#endif
