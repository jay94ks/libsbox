#ifndef __INCLUDE_SBOX_VPN_L2TP_PROFILES_HPP__
#define __INCLUDE_SBOX_VPN_L2TP_PROFILES_HPP__

#include <sbox/common.hpp>
#include <sbox/vpn/l2tp/ppp.hpp>
#include <string>
#include <vector>

// --> Client setup material for L2TP/IPsec with a pre-shared key: the Windows PowerShell
// command (Add-VpnConnection -TunnelType L2tp -L2tpPsk) with the NAT registry note, an Apple
// configuration profile (VPNType L2TP) for macOS/iOS, and hints for Android.

namespace sbox {
namespace vpn {

    /**
     * What a client needs to connect.
     */
    struct SL2tpClientProfile {
        std::string name = "sbox L2TP";     // --> Connection name shown to the user.
        std::string server;                 // --> Host name or address clients dial.
        std::string psk;
        std::string user;                   // --> Optional (prompted when empty).
        std::string password;               // --> Optional; only embedded in the Apple profile when set.
        EPppAuth auth = EPPPA_MSCHAPV2;
        std::vector<std::string> routes;    // --> Split tunnel prefixes; empty: everything through the VPN.
        bool serverBehindNat = false;       // --> Adds the Windows AssumeUDPEncapsulationContextOnSendRule step.
        std::string organization = "libsbox";
    };

    /**
     * Returns a PowerShell script for Windows 10/11.
     */
    SBOX_API std::string WindowsL2tpSetup(const SL2tpClientProfile& profile);

    /**
     * Returns an Apple configuration profile (XML plist) for macOS/iOS.
     */
    SBOX_API std::string AppleL2tpMobileConfig(const SL2tpClientProfile& profile);

    /**
     * Returns setup hints for Android (and the manual macOS/iOS steps).
     */
    SBOX_API std::string AndroidL2tpSetup(const SL2tpClientProfile& profile);

}
}

#endif
