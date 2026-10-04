#include <sbox/vpn/wg/kernel.hpp>
#include <cerrno>
#include <cstring>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace sbox {
namespace vpn {

    namespace {

        // --> Upper bounds of what one peer header / one allowed IP adds to a message.
        constexpr size_t PEER_HEADER_BYTES = 4 + 36 + 36 + 8 + 32 + 8 + 8 + 4 + 4;
        constexpr size_t ALLOWED_IP_BYTES = 4 + 8 + 20 + 8;

        /* Incremental builder of SET_DEVICE messages with splitting. */
        struct SetBuilder {
            uint16_t familyId;
            const std::string& ifName;
            size_t maxBytes;
            std::vector<net::CNlMessage> out;
            std::unique_ptr<net::CNlMessage> msg;
            size_t peersToken = 0;
            bool peersOpen = false;
            size_t peersInMessage = 0;

            /* Starts a message carrying only the device name. */
            void start() {
                msg.reset(new net::CNlMessage(net::CNlMessage::genl(familyId, EWGC_SET_DEVICE, WG_GENL_VERSION, 0)));
                msg->putString(EWGDA_IFNAME, ifName);
                peersOpen = false;
                peersInMessage = 0;
            }

            /* Closes the peer list and queues the message. */
            void finish() {
                if (peersOpen) {
                    msg->endNested(peersToken);
                    peersOpen = false;
                }

                out.push_back(std::move(*msg));
                msg.reset();
            }

            /* Opens the peer list if needed. */
            void openPeers() {
                if (!peersOpen) {
                    peersToken = msg->beginNested(EWGDA_PEERS);
                    peersOpen = true;
                }
            }

            /* Returns true when `more` bytes still fit. */
            bool fits(size_t more) const {
                return msg->size() + more <= maxBytes;
            }
        };

        /* Appends one allowed IP. */
        void putAllowedIp(net::CNlMessage& msg, const net::SIpPrefix& prefix) {
            net::SIpPrefix p = prefix.network();
            size_t t = msg.beginNested(0);
            msg.putU16(EWGAA_FAMILY, uint16_t(p.address.afamily()));
            msg.putAddress(EWGAA_IPADDR, p.address);
            msg.putU8(EWGAA_CIDR_MASK, p.length);
            msg.endNested(t);
        }

        /* Parses one peer entry into `peer` (merging allowed IPs). */
        void parsePeer(const net::CNlAttrs& attrs, SWgPeerStatus& peer) {
            for (const net::SNlAttr& a : attrs.items()) {
                switch (a.type) {
                    case EWGPA_PUBLIC_KEY:
                        if (a.length == WG_KEY_BYTES) {
                            peer.publicKey = SWgKey::fromBytes(a.data);
                        }
                        break;

                    case EWGPA_PRESHARED_KEY: {
                        bool any = false;
                        for (size_t i = 0; i < a.length; ++i) {
                            any = any || a.data[i] != 0;
                        }

                        peer.hasPresharedKey = any;
                        if (any && a.length == WG_KEY_BYTES) {
                            peer.presharedKey = SWgKey::fromBytes(a.data);
                        }
                        break;
                    }

                    case EWGPA_ENDPOINT:
                        if (a.length <= sizeof(sockaddr_storage) && a.length >= sizeof(sockaddr_in)) {
                            std::memcpy(&peer.endpoint.storage, a.data, a.length);
                            peer.endpoint.length = socklen_t(a.length);
                        }
                        break;

                    case EWGPA_PERSISTENT_KEEPALIVE_INTERVAL:
                        peer.persistentKeepalive = a.u16();
                        break;

                    case EWGPA_LAST_HANDSHAKE_TIME:
                        if (a.length >= 16) {
                            int64_t sec = 0, nsec = 0;
                            std::memcpy(&sec, a.data, 8);
                            std::memcpy(&nsec, a.data + 8, 8);
                            peer.lastHandshakeSec = sec;
                            peer.lastHandshakeNsec = nsec;
                        }
                        break;

                    case EWGPA_RX_BYTES:
                        peer.rxBytes = a.u64();
                        break;

                    case EWGPA_TX_BYTES:
                        peer.txBytes = a.u64();
                        break;

                    case EWGPA_PROTOCOL_VERSION:
                        peer.protocolVersion = a.u32();
                        break;

                    case EWGPA_ALLOWEDIPS: {
                        net::CNlAttrs list = net::CNlAttrs::nested(a);
                        for (const net::SNlAttr& item : list.items()) {
                            net::CNlAttrs ip = net::CNlAttrs::nested(item);
                            const net::SNlAttr* addr = ip.find(EWGAA_IPADDR);
                            const net::SNlAttr* mask = ip.find(EWGAA_CIDR_MASK);
                            if (addr && mask) {
                                net::SIpAddress address = addr->address();
                                if (address.isValid()) {
                                    peer.allowedIps.push_back(net::SIpPrefix(address, mask->u8()));
                                }
                            }
                        }

                        break;
                    }

                    default:
                        break;
                }
            }
        }

    }

    /* Encodes SET_DEVICE. */
    std::vector<net::CNlMessage> BuildWgSetDevice(uint16_t familyId, const std::string& ifName,
        const SWgDeviceConfig& config, size_t maxBytes)
    {
        SetBuilder b{ familyId, ifName, maxBytes < 1024 ? 1024 : maxBytes, {}, nullptr };
        b.start();

        if (config.privateKey.valid) {
            b.msg->put(EWGDA_PRIVATE_KEY, config.privateKey.bytes, WG_KEY_BYTES);
        }

        if (config.listenPort >= 0) {
            b.msg->putU16(EWGDA_LISTEN_PORT, uint16_t(config.listenPort));
        }

        if (config.fwmark >= 0) {
            b.msg->putU32(EWGDA_FWMARK, uint32_t(config.fwmark));
        }

        if (config.replacePeers) {
            b.msg->putU32(EWGDA_FLAGS, EWGDF_REPLACE_PEERS);
        }

        for (const SWgPeerConfig& peer : config.peers) {
            if (b.peersInMessage > 0 && !b.fits(PEER_HEADER_BYTES + ALLOWED_IP_BYTES)) {
                b.finish();
                b.start();
            }

            b.openPeers();
            size_t peerToken = b.msg->beginNested(0);
            ++b.peersInMessage;
            b.msg->put(EWGPA_PUBLIC_KEY, peer.publicKey.bytes, WG_KEY_BYTES);

            if (peer.remove) {
                b.msg->putU32(EWGPA_FLAGS, EWGPF_REMOVE_ME);
                b.msg->endNested(peerToken);
                continue;
            }

            uint32_t flags = 0;
            if (peer.replaceAllowedIps) {
                flags |= EWGPF_REPLACE_ALLOWEDIPS;
            }

            if (peer.updateOnly) {
                flags |= EWGPF_UPDATE_ONLY;
            }

            if (flags) {
                b.msg->putU32(EWGPA_FLAGS, flags);
            }

            if (peer.presharedKey.valid) {
                b.msg->put(EWGPA_PRESHARED_KEY, peer.presharedKey.bytes, WG_KEY_BYTES);
            }

            if (peer.endpoint.isValid()) {
                b.msg->put(EWGPA_ENDPOINT, &peer.endpoint.storage, peer.endpoint.length);
            }

            if (peer.persistentKeepalive >= 0) {
                b.msg->putU16(EWGPA_PERSISTENT_KEEPALIVE_INTERVAL, uint16_t(peer.persistentKeepalive));
            }

            if (!peer.allowedIps.empty()) {
                size_t ipsToken = b.msg->beginNested(EWGPA_ALLOWEDIPS);
                for (const net::SIpPrefix& ip : peer.allowedIps) {
                    if (!b.fits(ALLOWED_IP_BYTES + 16)) {
                        // --> Continue this peer in a new message, appending to what was sent.
                        b.msg->endNested(ipsToken);
                        b.msg->endNested(peerToken);
                        b.finish();
                        b.start();
                        b.openPeers();
                        peerToken = b.msg->beginNested(0);
                        ++b.peersInMessage;
                        b.msg->put(EWGPA_PUBLIC_KEY, peer.publicKey.bytes, WG_KEY_BYTES);
                        b.msg->putU32(EWGPA_FLAGS, EWGPF_UPDATE_ONLY);
                        ipsToken = b.msg->beginNested(EWGPA_ALLOWEDIPS);
                    }

                    putAllowedIp(*b.msg, ip);
                }

                b.msg->endNested(ipsToken);
            }

            b.msg->endNested(peerToken);
        }

        b.finish();
        return std::move(b.out);
    }

    /* Encodes GET_DEVICE. */
    net::CNlMessage BuildWgGetDevice(uint16_t familyId, const std::string& ifName) {
        net::CNlMessage msg = net::CNlMessage::genl(familyId, EWGC_GET_DEVICE, WG_GENL_VERSION, 0);
        msg.putString(EWGDA_IFNAME, ifName);
        return msg;
    }

    /* Decodes GET_DEVICE replies. */
    int32_t ParseWgGetDevice(const std::vector<net::SNlReply>& replies, SWgDeviceStatus& out) {
        out = SWgDeviceStatus();
        out.kernel = true;
        bool any = false;

        for (const net::SNlReply& reply : replies) {
            if (reply.payload.size() < 4) {
                continue;
            }

            any = true;
            net::CNlAttrs attrs = reply.attrs(4);
            for (const net::SNlAttr& a : attrs.items()) {
                switch (a.type) {
                    case EWGDA_IFINDEX:
                        out.ifIndex = int32_t(a.u32());
                        break;

                    case EWGDA_IFNAME:
                        out.name = a.str();
                        break;

                    case EWGDA_PRIVATE_KEY:
                        if (a.length == WG_KEY_BYTES) {
                            out.privateKey = SWgKey::fromBytes(a.data);
                            if (out.privateKey.isZero()) {
                                out.privateKey = SWgKey();
                            }
                        }
                        break;

                    case EWGDA_PUBLIC_KEY:
                        if (a.length == WG_KEY_BYTES) {
                            out.publicKey = SWgKey::fromBytes(a.data);
                            if (out.publicKey.isZero()) {
                                out.publicKey = SWgKey();
                            }
                        }
                        break;

                    case EWGDA_LISTEN_PORT:
                        out.listenPort = a.u16();
                        break;

                    case EWGDA_FWMARK:
                        out.fwmark = a.u32();
                        break;

                    case EWGDA_PEERS: {
                        net::CNlAttrs list = net::CNlAttrs::nested(a);
                        for (const net::SNlAttr& item : list.items()) {
                            net::CNlAttrs peerAttrs = net::CNlAttrs::nested(item);
                            const net::SNlAttr* key = peerAttrs.find(EWGPA_PUBLIC_KEY);
                            if (!key || key->length != WG_KEY_BYTES) {
                                return -EBADMSG;
                            }

                            // --> A peer whose allowed IPs did not fit continues in the next
                            // message under the same key.
                            SWgKey k = SWgKey::fromBytes(key->data);
                            if (out.peers.empty() || out.peers.back().publicKey != k) {
                                out.peers.emplace_back();
                            }

                            parsePeer(peerAttrs, out.peers.back());
                        }

                        break;
                    }

                    default:
                        break;
                }
            }
        }

        return any ? SBOX_OK : -EBADMSG;
    }

    /* Opens the family. */
    TTask<int32_t> CWgKernelClient::open(std::string netnsPath) {
        int32_t r = _socket.open(NETLINK_GENERIC, netnsPath);
        if (r != SBOX_OK) {
            co_return r;
        }

        co_return co_await net::ResolveGenlFamily(_socket, WG_GENL_NAME, _family);
    }

    /* Sends SET_DEVICE. */
    TTask<int32_t> CWgKernelClient::setDevice(std::string ifName, SWgDeviceConfig config) {
        if (!_socket.isValid()) {
            co_return -EBADF;
        }

        std::vector<net::CNlMessage> messages = BuildWgSetDevice(_family.id, ifName, config);
        for (net::CNlMessage& m : messages) {
            int32_t r = co_await _socket.request(m);
            if (r != SBOX_OK) {
                co_return r;
            }
        }

        co_return SBOX_OK;
    }

    /* Sends GET_DEVICE and decodes the reply. */
    TTask<int32_t> CWgKernelClient::getDevice(std::string ifName, SWgDeviceStatus& out) {
        if (!_socket.isValid()) {
            co_return -EBADF;
        }

        net::CNlMessage msg = BuildWgGetDevice(_family.id, ifName);
        std::vector<net::SNlReply> replies;
        int32_t r = co_await _socket.dump(msg, replies);
        if (r != SBOX_OK) {
            co_return r;
        }

        co_return ParseWgGetDevice(replies, out);
    }

}
}
