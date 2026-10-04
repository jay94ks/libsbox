#ifndef __TESTS_VPN_IPSEC_TESTUTIL_HPP__
#define __TESTS_VPN_IPSEC_TESTUTIL_HPP__

#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/net/rtnl.hpp>
#include <sbox/vpn/ipsec/certs.hpp>
#include <sbox/vpn/ipsec/datapath.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <vector>

namespace ipsectest {

    using namespace sbox;
    using namespace sbox::vpn;

    /**
     * Temporary directory (with namespace pins) removed on destruction.
     */
    struct TempDir {
        std::string path;
        std::vector<std::string> pins;

        TempDir() {
            char tmpl[] = "/tmp/sbox-ipsec-test-XXXXXX";
            char* p = ::mkdtemp(tmpl);
            path = p ? p : "";
        }

        ~TempDir() {
            for (const std::string& pin : pins) {
                net::CNetns::remove(pin);
            }

            if (!path.empty()) {
                CFile::removeTree(path);
            }
        }

        std::string join(const std::string& leaf) const {
            return CFile::join(path, leaf);
        }

        /** Creates a pinned namespace with loopback up; empty string on failure. */
        std::string netns(const std::string& name) {
            std::string p = join(name);
            if (net::CNetns::create(p) != SBOX_OK) {
                return std::string();
            }

            pins.push_back(p);
            return p;
        }
    };

    /** Returns true when running as root. */
    inline bool isRoot() {
        return ::geteuid() == 0;
    }

    /**
     * Data path that records what IKE asks of it (protocol tests need no kernel features).
     */
    struct FakeDataPath : IIpsecDataPath {
        std::vector<SIpsecChildSa> installed;
        std::vector<SIpsecChildSa> active;
        std::vector<std::pair<SIpsecChildSa, bool>> removed;
        std::vector<SIpsecChildSa> updated;
        uint32_t nextSpi = 0xc0000100u;
        bool started = false;

        const char* kind() const noexcept override { return "fake"; }

        TTask<int32_t> start() override {
            started = true;
            co_return SBOX_OK;
        }

        TTask<void> stop() override {
            started = false;
            active.clear();
            co_return;
        }

        void attachSocket(CIkeSocket*) override {}

        bool supports(uint16_t encr, uint16_t keyBits, uint16_t integ) const noexcept override {
            const SIkeEncrInfo* info = IkeEncrInfo(encr);
            return info && IkeEncrKeyBitsValid(encr, keyBits) && (info->aead ? integ == 0 : integ != 0);
        }

        TTask<int32_t> allocateSpi(net::SIpAddress, net::SIpAddress, uint32_t, uint32_t& spi) override {
            spi = nextSpi++;
            co_return SBOX_OK;
        }

        TTask<int32_t> installChild(SIpsecChildSa child) override {
            installed.push_back(child);
            active.push_back(child);
            co_return SBOX_OK;
        }

        TTask<int32_t> removeChild(SIpsecChildSa child, bool policies) override {
            removed.emplace_back(child, policies);
            for (size_t i = 0; i < active.size(); ++i) {
                if (active[i].inboundSpi == child.inboundSpi) {
                    active.erase(active.begin() + long(i));
                    break;
                }
            }

            co_return SBOX_OK;
        }

        TTask<int32_t> updateChild(SIpsecChildSa child) override {
            updated.push_back(child);
            co_return SBOX_OK;
        }

        TTask<int32_t> stats(SIpsecChildSa, SIpsecChildStats& out) override {
            out = SIpsecChildStats();
            co_return SBOX_OK;
        }

        std::string interfaceName() const override { return std::string(); }
    };

    /**
     * Test PKI: an ECDSA CA, a server certificate and a client certificate (generated once).
     */
    struct Pki {
        CIkeCertificate ca;
        CIkeCertificate server;
        CIkeCertificate client;
        CIkeCertificate otherCa;
        CIkeCertificate stranger;   // --> Client certificate of an untrusted CA.

        static const Pki& get() {
            static Pki pki = [] {
                Pki p;
                SVpnCertOptions o;
                o.ecdsa = true;
                o.commonName = "Test VPN CA";
                GenerateVpnCa(o, p.ca);

                SVpnCertOptions s = o;
                s.commonName = "vpn.test";
                s.dnsNames = { "vpn.test" };
                s.ipAddresses = { "127.0.0.1" };
                IssueVpnCertificate(p.ca, s, p.server);

                SVpnCertOptions c = o;
                c.commonName = "laptop";
                c.server = false;
                c.dnsNames = { "laptop.test" };
                c.emails = { "alice@test" };
                IssueVpnCertificate(p.ca, c, p.client);

                SVpnCertOptions oc = o;
                oc.commonName = "Other CA";
                GenerateVpnCa(oc, p.otherCa);
                IssueVpnCertificate(p.otherCa, c, p.stranger);
                return p;
            }();
            return pki;
        }
    };

}

#endif
