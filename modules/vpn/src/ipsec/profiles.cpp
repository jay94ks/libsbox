#include <sbox/vpn/ipsec/profiles.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include <sbox/net/address.hpp>
#include <certpp/string.hpp>
#include <certpp/utils/base64.hpp>
#include <cstdio>

namespace sbox {
namespace vpn {

    namespace {

        /* Base64 of bytes, wrapped for plists. */
        std::string base64(const std::vector<uint8_t>& data) {
            certpp::CString out;
            if (!certpp::CBase64::encode(out, certpp::SReadOnlyByteSpan(data.data(), data.size()), true)) {
                return std::string();
            }

            return std::string(out.toPtr(), out.size());
        }

        /* Escapes XML text. */
        std::string xml(std::string_view text) {
            std::string out;
            for (char c : text) {
                switch (c) {
                case '&': out += "&amp;"; break;
                case '<': out += "&lt;"; break;
                case '>': out += "&gt;"; break;
                case '"': out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default: out += c; break;
                }
            }

            return out;
        }

        /* Quotes a PowerShell single-quoted string. */
        std::string ps(std::string_view text) {
            std::string out = "'";
            for (char c : text) {
                if (c == '\'') {
                    out += "''";
                }
                else {
                    out += c;
                }
            }

            return out + "'";
        }

        /* Random RFC 4122 version 4 UUID. */
        std::string uuid() {
            uint8_t b[16];
            IkeRandom(SByteSpan(b, sizeof(b)));
            b[6] = uint8_t((b[6] & 0x0f) | 0x40);
            b[8] = uint8_t((b[8] & 0x3f) | 0x80);
            char out[40];
            std::snprintf(out, sizeof(out), "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X", b[0], b[1], b[2],
                          b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
            return out;
        }

        /* Reverse-DNS identifier fragment from a name. */
        std::string ident(std::string_view text) {
            std::string out;
            for (char c : text) {
                bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
                out += ok ? c : '-';
            }

            return out.empty() ? std::string("vpn") : out;
        }

        /* Remote identity a profile uses. */
        std::string remoteIdOf(const SVpnClientProfile& p) {
            return p.remoteId.empty() ? p.server : p.remoteId;
        }

    }

    /* Windows PowerShell script. */
    std::string WindowsVpnSetup(const SVpnClientProfile& p) {
        std::string s;
        s += "# " + p.name + " -- IKEv2 setup for the built-in Windows 10/11 VPN client.\n";
        s += "# Run in an elevated PowerShell (Run as Administrator).\n";

        if (p.auth == EVPA_PSK) {
            s += "# Windows' IKEv2 client does not support pre-shared keys. Use EAP (username/password)\n";
            s += "# or a machine certificate instead; PSK clients are macOS/iOS and Android.\n";
            return s;
        }

        if (p.ca.isValid()) {
            s += "\n# 1. Trust the VPN CA (machine store, required for IKEv2 server validation).\n";
            s += "$ca = @'\n" + p.ca.toPem(false) + "'@\n";
            s += "$caFile = Join-Path $env:TEMP 'sbox-vpn-ca.cer'\n";
            s += "Set-Content -Path $caFile -Value $ca -Encoding ascii\n";
            s += "Import-Certificate -FilePath $caFile -CertStoreLocation Cert:\\LocalMachine\\Root | Out-Null\n";
        }

        if (p.auth == EVPA_CERT) {
            s += "\n# 2. Import the client (machine) certificate into LocalMachine\\My.\n";
            s += "#    Copy the .p12 file next to this script first.\n";
            s += "$p12Password = ConvertTo-SecureString -String " + ps(p.clientPkcs12Password) + " -AsPlainText -Force\n";
            s += "Import-PfxCertificate -FilePath .\\client.p12 -CertStoreLocation Cert:\\LocalMachine\\My -Password $p12Password | Out-Null\n";
        }

        std::string method = p.auth == EVPA_CERT ? "MachineCertificate" : "Eap";
        s += "\n# 3. Create the connection.\n";
        s += "Remove-VpnConnection -Name " + ps(p.name) + " -Force -ErrorAction SilentlyContinue\n";
        s += "Add-VpnConnection -Name " + ps(p.name) + " -ServerAddress " + ps(p.server) + " -TunnelType Ikev2 -AuthenticationMethod "
            + method + " -EncryptionLevel Required" + (p.auth == EVPA_EAP ? " -RememberCredential" : "")
            + (p.routes.empty() ? "" : " -SplitTunneling") + " -Force\n";

        s += "\n# 4. Use strong algorithms (the default would be AES-CBC/SHA-1/MODP-1024).\n";
        s += "Set-VpnConnectionIPsecConfiguration -ConnectionName " + ps(p.name)
            + " -AuthenticationTransformConstants GCMAES256 -CipherTransformConstants GCMAES256"
              " -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -DHGroup Group14 -PfsGroup None -Force\n";

        if (!p.routes.empty()) {
            s += "\n# 5. Split tunnel routes.\n";
            for (const std::string& r : p.routes) {
                s += "Add-VpnConnectionRoute -ConnectionName " + ps(p.name) + " -DestinationPrefix " + ps(r) + " -PassThru | Out-Null\n";
            }
        }

        if (p.auth == EVPA_EAP) {
            s += "\n# Connect: rasdial " + ps(p.name) + " <user> <password>   (or from the network flyout)\n";
            if (!p.user.empty()) {
                s += "# User name: " + p.user + "\n";
            }
        }
        else {
            s += "\n# Connect: rasdial " + ps(p.name) + "\n";
        }

        s += "# If the server sits behind NAT, also set (once, then reboot):\n";
        s += "#   Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\PolicyAgent' "
             "-Name AssumeUDPEncapsulationContextOnSendRule -Type DWord -Value 2\n";
        return s;
    }

    /* Apple configuration profile. */
    std::string AppleMobileConfig(const SVpnClientProfile& p) {
        std::string base = "com.libsbox.vpn." + ident(p.server);
        std::string caUuid = uuid();
        std::string certUuid = uuid();
        std::string vpnUuid = uuid();
        std::string profileUuid = uuid();

        std::string s;
        s += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        s += "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";
        s += "<plist version=\"1.0\">\n<dict>\n";
        s += "  <key>PayloadContent</key>\n  <array>\n";

        if (p.ca.isValid()) {
            s += "    <dict>\n";
            s += "      <key>PayloadType</key><string>com.apple.security.root</string>\n";
            s += "      <key>PayloadVersion</key><integer>1</integer>\n";
            s += "      <key>PayloadIdentifier</key><string>" + xml(base) + ".ca</string>\n";
            s += "      <key>PayloadUUID</key><string>" + caUuid + "</string>\n";
            s += "      <key>PayloadDisplayName</key><string>" + xml(p.name) + " CA</string>\n";
            s += "      <key>PayloadCertificateFileName</key><string>vpn-ca.cer</string>\n";
            s += "      <key>PayloadContent</key>\n      <data>\n" + base64(p.ca.der()) + "\n      </data>\n";
            s += "    </dict>\n";
        }

        if (p.auth == EVPA_CERT && !p.clientPkcs12.empty()) {
            s += "    <dict>\n";
            s += "      <key>PayloadType</key><string>com.apple.security.pkcs12</string>\n";
            s += "      <key>PayloadVersion</key><integer>1</integer>\n";
            s += "      <key>PayloadIdentifier</key><string>" + xml(base) + ".client</string>\n";
            s += "      <key>PayloadUUID</key><string>" + certUuid + "</string>\n";
            s += "      <key>PayloadDisplayName</key><string>" + xml(p.name) + " client certificate</string>\n";
            s += "      <key>PayloadCertificateFileName</key><string>client.p12</string>\n";
            if (!p.clientPkcs12Password.empty()) {
                s += "      <key>Password</key><string>" + xml(p.clientPkcs12Password) + "</string>\n";
            }

            s += "      <key>PayloadContent</key>\n      <data>\n" + base64(p.clientPkcs12) + "\n      </data>\n";
            s += "    </dict>\n";
        }

        s += "    <dict>\n";
        s += "      <key>PayloadType</key><string>com.apple.vpn.managed</string>\n";
        s += "      <key>PayloadVersion</key><integer>1</integer>\n";
        s += "      <key>PayloadIdentifier</key><string>" + xml(base) + ".vpn</string>\n";
        s += "      <key>PayloadUUID</key><string>" + vpnUuid + "</string>\n";
        s += "      <key>PayloadDisplayName</key><string>" + xml(p.name) + "</string>\n";
        s += "      <key>UserDefinedName</key><string>" + xml(p.name) + "</string>\n";
        s += "      <key>VPNType</key><string>IKEv2</string>\n";
        s += "      <key>IKEv2</key>\n      <dict>\n";
        s += "        <key>RemoteAddress</key><string>" + xml(p.server) + "</string>\n";
        s += "        <key>RemoteIdentifier</key><string>" + xml(remoteIdOf(p)) + "</string>\n";

        std::string local = p.localId;
        if (local.empty() && p.auth == EVPA_EAP) {
            local = p.user;
        }

        s += "        <key>LocalIdentifier</key><string>" + xml(local) + "</string>\n";

        if (p.auth == EVPA_PSK) {
            s += "        <key>AuthenticationMethod</key><string>SharedSecret</string>\n";
            s += "        <key>SharedSecret</key><string>" + xml(p.psk) + "</string>\n";
        }
        else if (p.auth == EVPA_CERT) {
            s += "        <key>AuthenticationMethod</key><string>Certificate</string>\n";
            s += "        <key>PayloadCertificateUUID</key><string>" + certUuid + "</string>\n";
            if (p.ca.isValid()) {
                std::string cn = p.ca.subject();
                size_t at = cn.find("CN=");
                if (at != std::string::npos) {
                    cn = cn.substr(at + 3);
                    cn = cn.substr(0, cn.find(','));
                    s += "        <key>ServerCertificateIssuerCommonName</key><string>" + xml(cn) + "</string>\n";
                }
            }
        }
        else {
            // --> EAP-MSCHAPv2: the server proves itself with its certificate, the user with a password.
            s += "        <key>AuthenticationMethod</key><string>None</string>\n";
            s += "        <key>ExtendedAuthEnabled</key><integer>1</integer>\n";
            if (!p.user.empty()) {
                s += "        <key>AuthName</key><string>" + xml(p.user) + "</string>\n";
            }

            if (!p.password.empty()) {
                s += "        <key>AuthPassword</key><string>" + xml(p.password) + "</string>\n";
            }
        }

        auto sa = [](const char* key) {
            std::string out;
            out += std::string("        <key>") + key + "</key>\n        <dict>\n";
            out += "          <key>EncryptionAlgorithm</key><string>AES-256-GCM</string>\n";
            out += "          <key>IntegrityAlgorithm</key><string>SHA2-256</string>\n";
            out += "          <key>DiffieHellmanGroup</key><integer>19</integer>\n";
            out += "          <key>LifeTimeInMinutes</key><integer>1440</integer>\n";
            out += "        </dict>\n";
            return out;
        };

        s += sa("IKESecurityAssociationParameters");
        s += sa("ChildSecurityAssociationParameters");
        s += "        <key>EnablePFS</key><integer>1</integer>\n";
        s += "        <key>DeadPeerDetectionRate</key><string>Medium</string>\n";
        s += "        <key>DisableMOBIKE</key><integer>0</integer>\n";
        s += "        <key>DisableRedirect</key><integer>1</integer>\n";
        s += "        <key>EnableCertificateRevocationCheck</key><integer>0</integer>\n";
        s += "        <key>UseConfigurationAttributeInternalIPSubnet</key><integer>0</integer>\n";
        s += "        <key>NATKeepAliveOffloadEnable</key><integer>1</integer>\n";
        s += "        <key>NATKeepAliveInterval</key><integer>20</integer>\n";
        s += "        <key>OnDemandEnabled</key><integer>0</integer>\n";
        s += "      </dict>\n";
        s += "    </dict>\n";
        s += "  </array>\n";
        s += "  <key>PayloadDisplayName</key><string>" + xml(p.name) + "</string>\n";
        s += "  <key>PayloadIdentifier</key><string>" + xml(base) + "</string>\n";
        s += "  <key>PayloadOrganization</key><string>" + xml(p.organization) + "</string>\n";
        s += "  <key>PayloadRemovalDisallowed</key><false/>\n";
        s += "  <key>PayloadType</key><string>Configuration</string>\n";
        s += "  <key>PayloadUUID</key><string>" + profileUuid + "</string>\n";
        s += "  <key>PayloadVersion</key><integer>1</integer>\n";
        s += "</dict>\n</plist>\n";
        return s;
    }

    /* Android hints. */
    std::string AndroidVpnSetup(const SVpnClientProfile& p) {
        std::string s;
        s += p.name + " -- Android 11+ built-in IKEv2 client\n";
        s += "Settings > Network & internet > VPN > + (Add VPN)\n\n";
        s += "  Name:                 " + p.name + "\n";

        switch (p.auth) {
        case EVPA_PSK:
            s += "  Type:                 IKEv2/IPSec PSK\n";
            s += "  Server address:       " + p.server + "\n";
            s += "  IPSec identifier:     " + (p.localId.empty() ? std::string("<your identity, e.g. @phone.example>") : p.localId) + "\n";
            s += "  IPSec pre-shared key: " + (p.psk.empty() ? std::string("<the PSK>") : p.psk) + "\n";
            break;

        case EVPA_CERT:
            s += "  Type:                 IKEv2/IPSec RSA\n";
            s += "  Server address:       " + p.server + "\n";
            s += "  IPSec identifier:     " + (p.localId.empty() ? std::string("<identity in your certificate>") : p.localId) + "\n";
            s += "  IPSec user cert:      install client.p12 first (Settings > Security > Encryption & credentials >\n";
            s += "                        Install a certificate > VPN & app user certificate)\n";
            s += "  IPSec CA certificate: the VPN CA (install vpn-ca.crt as a CA certificate)\n";
            s += "  IPSec server cert:    (received from server)\n";
            break;

        default:
            s += "  Type:                 IKEv2/IPSec MSCHAPv2\n";
            s += "  Server address:       " + p.server + "\n";
            s += "  IPSec identifier:     " + (p.user.empty() ? std::string("<user name>") : p.user) + "\n";
            s += "  IPSec CA certificate: the VPN CA (install vpn-ca.crt as a CA certificate first)\n";
            s += "  IPSec server cert:    (received from server)\n";
            s += "  Username / Password:  " + (p.user.empty() ? std::string("<user name>") : p.user) + " / <password>\n";
            break;
        }

        s += "\nNotes:\n";
        s += "  - The server certificate must contain '" + remoteIdOf(p) + "' in its subjectAltName; Android\n";
        s += "    checks it against the server address.\n";
        if (!p.routes.empty()) {
            s += "  - Split tunnel prefixes are pushed by the server; Android routes only those.\n";
        }

        s += "  - The strongSwan VPN Client app (Play Store / F-Droid) accepts the same settings on older Android.\n";
        return s;
    }

}
}
