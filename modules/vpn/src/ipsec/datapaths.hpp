#ifndef __SRC_VPN_IPSEC_DATAPATHS_HPP__
#define __SRC_VPN_IPSEC_DATAPATHS_HPP__

#include <sbox/vpn/ipsec/datapath.hpp>

namespace sbox {
namespace vpn {
namespace ipsec {

    /** Creates the XFRM data path (the kernel was probed already). */
    IIpsecDataPathPtr MakeKernelDataPath(const SIpsecDataPathOptions& options, const SXfrmSupport& support);

    /** Creates the user-space ESP data path. */
    IIpsecDataPathPtr MakeUserDataPath(const SIpsecDataPathOptions& options);

    /** Configures an interface: MTU, addresses, up, routes (in the options' namespace). */
    TTask<int32_t> ConfigureInterface(const SIpsecDataPathOptions& options, std::string name);

    /**
     * Adds (or removes) routes into the data path interface for a child's remote selectors
     * that the interface does not already cover (site-to-site peers without a virtual IP).
     * Default routes (/0) are never installed.
     */
    TTask<void> RouteRemoteSelectors(const SIpsecDataPathOptions& options, std::string name, SIpsecChildSa child, bool add);

    /** Returns true when a packet's addresses/protocol/ports fit a selector pair. */
    bool PacketMatches(const SReadOnlyByteSpan& ipPacket, const std::vector<SIkeTrafficSelector>& srcTs,
                       const std::vector<SIkeTrafficSelector>& dstTs);

}
}
}

#endif
