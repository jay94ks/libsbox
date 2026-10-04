#ifndef __INCLUDE_SBOX_VPN_IPSEC_PROFILES_HPP__
#define __INCLUDE_SBOX_VPN_IPSEC_PROFILES_HPP__

#include <sbox/common.hpp>
#include <sbox/vpn/ipsec/certs.hpp>
#include <string>
#include <vector>

// --> Setup material for the VPN clients built into the operating systems: a PowerShell script
// for Windows, an Apple configuration profile (.mobileconfig) for macOS/iOS, and step-by-step
// hints for Android's native IKEv2 client.

namespace sbox {
namespace vpn {

    /**
     * Authentication flavour a client profile is for.
     */
    enum EVpnProfileAuth {
        EVPA_EAP = 0,       // --> Username/password (EAP-MSCHAPv2), server certificate.
        EVPA_PSK,           // --> Pre-shared key (macOS/iOS/Android only).
        EVPA_CERT,          // --> Client certificate (PKCS#12).
    };

    /**
     * Everything a client profile needs.
     */
    struct SVpnClientProfile {
        std::string name = "sbox VPN";      // --> Connection name shown to the user.
        std::string server;                 // --> Host name or address clients dial.
        std::string remoteId;               // --> Server identity (empty: `server`).
        EVpnProfileAuth auth = EVPA_EAP;
        std::string user;                   // --> EAP user name (optional in the profile).
        std::string password;               // --> EAP password (optional; omit to prompt).
        std::string psk;
        std::string localId;                // --> Our identity for PSK/cert (Apple LocalIdentifier).
        CIkeCertificate ca;                 // --> CA to trust (installed by the profile/script).
        std::vector<uint8_t> clientPkcs12;  // --> Client certificate bundle for EVPA_CERT.
        std::string clientPkcs12Password;
        std::vector<std::string> routes;    // --> Split tunnel prefixes; empty: send everything.
        std::string organization = "libsbox";
    };

    /**
     * Returns a PowerShell script for Windows 10/11: imports the CA into LocalMachine\\Root,
     * creates an IKEv2 connection (EAP-MSCHAPv2 or machine certificate) with Add-VpnConnection
     * and sets strong IPsec parameters the responder accepts. PSK is not offered by Windows'
     * IKEv2 client and yields a script that says so.
     */
    SBOX_API std::string WindowsVpnSetup(const SVpnClientProfile& profile);

    /**
     * Returns an Apple configuration profile (XML plist) with the CA, the optional client
     * certificate and an IKEv2 VPN payload.
     */
    SBOX_API std::string AppleMobileConfig(const SVpnClientProfile& profile);

    /**
     * Returns setup hints for Android 11+ (Settings > Network > VPN, IKEv2/IPSec types).
     */
    SBOX_API std::string AndroidVpnSetup(const SVpnClientProfile& profile);

}
}

#endif
