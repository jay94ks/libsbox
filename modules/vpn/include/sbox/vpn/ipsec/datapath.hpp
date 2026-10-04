#ifndef __INCLUDE_SBOX_VPN_IPSEC_DATAPATH_HPP__
#define __INCLUDE_SBOX_VPN_IPSEC_DATAPATH_HPP__

#include <sbox/common.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/address.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include <sbox/vpn/ipsec/ikemessage.hpp>
#include <sbox/vpn/ipsec/xfrm.hpp>
#include <memory>
#include <string>
#include <vector>

// --> Where negotiated CHILD SAs go. The kernel data path installs XFRM SAs and policies (with
// an xfrm interface when the kernel has one); the user-space data path runs ESP itself between
// the IKE NAT-T socket / a raw ESP socket and a TUN device. Both expose client traffic on a
// routable interface, so the rest of the system (routing into container networks, firewall)
// does not care which one runs.

namespace sbox {
namespace vpn {

    class CIkeSocket;

    /**
     * Data path implementations.
     */
    enum EIpsecDataPathKind {
        EIDP_AUTO = 0,          // --> Kernel when it can install ESP SAs, else user space.
        EIDP_KERNEL,            // --> XFRM.
        EIDP_USER,              // --> User-space ESP over TUN.
    };

    /**
     * One negotiated CHILD SA pair (both directions) as the data path needs it.
     */
    struct SIpsecChildSa {
        uint32_t reqid = 0;                 // --> Stable across rekeys of the same child.
        EXfrmMode mode = EXMODE_TUNNEL;
        net::SIpAddress local;              // --> Outer (tunnel endpoint) addresses.
        net::SIpAddress remote;
        bool encap = false;                 // --> ESP in UDP (NAT traversal).
        uint16_t localPort = 4500;
        uint16_t remotePort = 4500;
        uint32_t inboundSpi = 0;            // --> SPI the peer sends to us.
        uint32_t outboundSpi = 0;           // --> SPI we send to the peer.
        uint16_t encr = EIKE_ENCR_AES_GCM_16;
        uint16_t keyBits = 128;
        uint16_t integ = EIKE_INTEG_NONE;
        bool esn = false;
        std::vector<uint8_t> inEncKey;
        std::vector<uint8_t> inIntegKey;
        std::vector<uint8_t> outEncKey;
        std::vector<uint8_t> outIntegKey;
        std::vector<SIkeTrafficSelector> localTs;
        std::vector<SIkeTrafficSelector> remoteTs;
        uint32_t replayWindow = 64;
        SXfrmLifetime lifetime;             // --> Kernel lifetimes (IKE drives rekeying).
    };

    /**
     * Options of a data path.
     */
    struct SIpsecDataPathOptions {
        EIpsecDataPathKind kind = EIDP_AUTO;
        std::string netnsPath;              // --> Namespace of the interface and SAs.
        std::string interfaceName = "ipsec0";   // --> TUN or xfrm interface name.
        uint32_t ifId = 0;                  // --> xfrm if_id (0: derived from reqidBase).
        uint32_t mtu = 1400;
        std::vector<net::SIpPrefix> addresses;  // --> Addresses put on the interface.
        std::vector<net::SIpPrefix> routes;     // --> Prefixes routed into the interface.
        uint32_t reqidBase = 0x5b000000u;   // --> Reqids of this owner start here (flush scope).
        bool flushStale = true;             // --> Remove entries of a previous run at start().
    };

    /**
     * Counters of one installed child.
     */
    struct SIpsecChildStats {
        uint64_t inBytes = 0;
        uint64_t outBytes = 0;
        uint64_t inPackets = 0;
        uint64_t outPackets = 0;
        int64_t lastInbound = 0;            // --> Monotonic ms of the last inbound packet (user path).
    };

    /**
     * A CHILD SA data path.
     */
    class SBOX_API IIpsecDataPath {
    public:
        virtual ~IIpsecDataPath() = default;

        /** Returns "kernel" or "user". */
        virtual const char* kind() const noexcept = 0;

        /**
         * Creates the interface, removes stale entries and starts the packet loops.
         */
        virtual TTask<int32_t> start() = 0;

        /**
         * Removes every installed SA/policy and the interface.
         */
        virtual TTask<void> stop() = 0;

        /**
         * Connects the data path to the IKE sockets (ESP-in-UDP send/receive or kernel
         * decapsulation). Call before start().
         */
        virtual void attachSocket(CIkeSocket* socket) = 0;

        /**
         * Returns true when the ESP transform can be used.
         */
        virtual bool supports(uint16_t encr, uint16_t keyBits, uint16_t integ) const noexcept = 0;

        /**
         * Allocates an inbound SPI.
         */
        virtual TTask<int32_t> allocateSpi(net::SIpAddress local, net::SIpAddress remote, uint32_t reqid, uint32_t& spi) = 0;

        /**
         * Installs both SAs of a child; the policies of its reqid are installed with the first
         * child of that reqid and stay across rekeys.
         */
        virtual TTask<int32_t> installChild(SIpsecChildSa child) = 0;

        /**
         * Removes the SAs of a child (a rekeyed predecessor). With `policies`, also the policies
         * of its reqid (the child is gone for good).
         */
        virtual TTask<int32_t> removeChild(SIpsecChildSa child, bool policies) = 0;

        /**
         * Moves a child to new outer addresses/ports (MOBIKE, NAT mapping change).
         */
        virtual TTask<int32_t> updateChild(SIpsecChildSa child) = 0;

        /**
         * Reads the counters of a child.
         */
        virtual TTask<int32_t> stats(SIpsecChildSa child, SIpsecChildStats& out) = 0;

        /** Returns the interface name (empty for policy-only kernel mode). */
        virtual std::string interfaceName() const = 0;
    };

    using IIpsecDataPathPtr = std::shared_ptr<IIpsecDataPath>;

    /**
     * Creates a data path; EIDP_AUTO probes the kernel (ESP SAs) first.
     * @return SBOX_OK, -ENOTSUP when the requested kind cannot run here, or another error.
     */
    SBOX_API TTask<int32_t> CreateIpsecDataPath(SIpsecDataPathOptions options, IIpsecDataPathPtr& out);

}
}

#endif
