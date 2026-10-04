#ifndef __TESTS_NET_DHCPSERVER_HPP__
#define __TESTS_NET_DHCPSERVER_HPP__

#include <sbox/core/eventloop.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/net/dhcp.hpp>
#include <sbox/net/netns.hpp>
#include <cstring>
#include <sys/socket.h>

namespace nettest {

    using namespace sbox;
    using namespace sbox::net;

    inline SIpAddress ipOf(const char* text) {
        SIpAddress a;
        SIpAddress::parse(text, a);
        return a;
    }

    /* Minimal DHCP server answering on one interface. */
    struct SMiniServer {
        CDatagramSocket socket;
        SIpAddress self = nettest::ipOf("10.123.0.1");
        SIpAddress offer = nettest::ipOf("10.123.0.50");
        int32_t naksLeft = 0;
        int32_t discovers = 0;
        int32_t requests = 0;
        int32_t renewals = 0;
        int32_t releases = 0;
        bool stop = false;

        int32_t open(const std::string& ns, const char* ifname) {
            CNetnsScope scope(ns);
            if (scope.error() != SBOX_OK) {
                return scope.error();
            }

            sbox::SEndpoint any;
            sbox::SEndpoint::fromIp("0.0.0.0", 67, any);
            int32_t r = socket.open(AF_INET, any);
            if (r != SBOX_OK) {
                return r;
            }

            int one = 1;
            ::setsockopt(socket.nativeHandle(), SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
            ::setsockopt(socket.nativeHandle(), SOL_SOCKET, SO_BINDTODEVICE, ifname, socklen_t(std::strlen(ifname)));
            return SBOX_OK;
        }

        SDhcpMessage reply(const SDhcpMessage& req, EDhcpType type) {
            SDhcpMessage m;
            m.op = 2;
            m.xid = req.xid;
            m.flags = req.flags;
            m.chaddr = req.chaddr;
            m.ciaddr = req.ciaddr;
            m.type(type);
            m.setAddress(54, self);

            if (type != EDHCP_NAK) {
                m.yiaddr = offer;
                m.setAddress(1, nettest::ipOf("255.255.255.0"));
                m.setAddress(3, self);
                std::vector<uint8_t> dns = { 10, 123, 0, 1, 9, 9, 9, 9 };
                m.setOption(6, dns.data(), dns.size());
                m.setOption(15, "example.test", 12);
                m.setU32(51, 600);
            }

            return m;
        }

        TTask<void> serve() {
            std::vector<uint8_t> buffer(1500);

            while (!stop) {
                sbox::SEndpoint from;
                SIoResult got = co_await socket.recvFrom(SByteSpan(buffer.data(), buffer.size()), from, 50);
                if (!got.ok()) {
                    continue;
                }

                SDhcpMessage req;
                if (SDhcpMessage::decode(buffer.data(), got.bytes, req) != SBOX_OK || req.op != 1) {
                    continue;
                }

                SDhcpMessage resp;
                switch (req.type()) {
                case EDHCP_DISCOVER:
                    ++discovers;
                    resp = reply(req, EDHCP_OFFER);
                    break;

                case EDHCP_REQUEST:
                    ++requests;
                    if (req.ciaddr.isV4() && !req.ciaddr.isUnspecified()) {
                        ++renewals;
                        resp = reply(req, EDHCP_ACK);
                    }
                    else if (naksLeft > 0) {
                        --naksLeft;
                        resp = reply(req, EDHCP_NAK);
                    }
                    else if (req.address(50) == offer) {
                        resp = reply(req, EDHCP_ACK);
                    }
                    else {
                        resp = reply(req, EDHCP_NAK);
                    }

                    break;

                case EDHCP_RELEASE:
                    ++releases;
                    continue;

                default:
                    continue;
                }

                sbox::SEndpoint to;
                if (req.ciaddr.isV4() && !req.ciaddr.isUnspecified()) {
                    sbox::SEndpoint::fromIp(req.ciaddr.toString(), 68, to);
                }
                else {
                    sbox::SEndpoint::fromIp("255.255.255.255", 68, to);
                }

                std::vector<uint8_t> bytes = resp.encode();
                socket.sendTo(SReadOnlyByteSpan(bytes.data(), bytes.size()), to);
            }
        }
    };

}

#endif
