#include <sbox/vpn/l2tp/ikev1peer.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include <sbox/vpn/ipsec/ikemessage.hpp>
#include "ipsec/crypto.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <map>
#include <set>

namespace sbox {
namespace vpn {

    using ipsec::GetBe32;
    using ipsec::PutBe16;
    using ipsec::PutBe32;
    using ipsec::PutBe64;

    namespace {

        // ------------------------------------------------------------------------------------
        // Helpers

        /* Random non-zero 64-bit cookie. */
        uint64_t randomCookie() {
            uint64_t v = 0;
            while (v == 0) {
                IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&v), sizeof(v)));
            }

            return v;
        }

        /* Random bytes. */
        std::vector<uint8_t> randomBytes(size_t n) {
            std::vector<uint8_t> v(n);
            IkeRandom(SByteSpan(v.data(), v.size()));
            return v;
        }

        /* Address of an endpoint. */
        net::SIpAddress addressOf(const SEndpoint& ep) {
            net::SIpAddress a;
            if (ep.family() == AF_INET) {
                net::SIpAddress::fromBytes(reinterpret_cast<const uint8_t*>(&reinterpret_cast<const sockaddr_in*>(&ep.storage)->sin_addr), 4, a);
            }
            else if (ep.family() == AF_INET6) {
                net::SIpAddress::fromBytes(reinterpret_cast<const uint8_t*>(&reinterpret_cast<const sockaddr_in6*>(&ep.storage)->sin6_addr), 16, a);
            }

            return a;
        }

        /* Endpoint from an address and port. */
        SEndpoint endpointOf(const net::SIpAddress& a, uint16_t port) {
            SEndpoint ep;
            SEndpoint::fromIp(a.toString(), port, ep);
            return ep;
        }

        /* Network-order bytes of a 32-bit SPI. */
        std::vector<uint8_t> spiBytes(uint32_t spi) {
            std::vector<uint8_t> v;
            PutBe32(v, spi);
            return v;
        }

        /* Cookie pair as the 16-byte ISAKMP SPI. */
        std::vector<uint8_t> cookieBytes(uint64_t i, uint64_t r) {
            std::vector<uint8_t> v;
            PutBe64(v, i);
            PutBe64(v, r);
            return v;
        }

        /* Encryption transform name for logs. */
        std::string espName(uint16_t encr, uint16_t keyBits, uint16_t integ, bool encap) {
            std::string text = "ESP " + IkeTransformName(EIKE_TT_ENCR, encr);
            if (keyBits && encr != EIKE_ENCR_3DES) {
                text += "_" + std::to_string(keyBits);
            }

            if (integ) {
                text += "/" + IkeTransformName(EIKE_TT_INTEG, integ);
            }

            text += encap ? " udp-transport" : " transport";
            return text;
        }

        /* Phase 1 attributes of a suite (initiator proposal). */
        SIkev1Transform suiteTransform(const SIkev1Suite& s, uint8_t number, uint32_t life) {
            SIkev1Transform t;
            t.number = number;
            t.id = IKEV1_KEY_IKE;
            t.attributes.push_back({ EIKE1_A_ENCR, s.encr, false });
            if (s.encr == EIKE1_ENCR_AES) {
                t.attributes.push_back({ EIKE1_A_KEY_LENGTH, s.keyBits, false });
            }

            t.attributes.push_back({ EIKE1_A_HASH, s.hash, false });
            t.attributes.push_back({ EIKE1_A_AUTH, EIKE1_AUTH_PSK, false });
            t.attributes.push_back({ EIKE1_A_GROUP, s.group, false });
            t.attributes.push_back({ EIKE1_A_LIFE_TYPE, EIKE1_LIFE_SECONDS, false });
            t.attributes.push_back({ EIKE1_A_LIFE_DURATION, life, true });
            return t;
        }

        /* Reads a Phase 1 transform into a suite. */
        bool transformSuite(const SIkev1Transform& t, SIkev1Suite& out) {
            if (t.id != IKEV1_KEY_IKE) {
                return false;
            }

            out = SIkev1Suite();
            out.encr = uint16_t(t.attr(EIKE1_A_ENCR));
            out.hash = uint16_t(t.attr(EIKE1_A_HASH));
            out.auth = uint16_t(t.attr(EIKE1_A_AUTH));
            out.group = uint16_t(t.attr(EIKE1_A_GROUP));
            out.keyBits = uint16_t(t.attr(EIKE1_A_KEY_LENGTH));
            if (out.encr == EIKE1_ENCR_3DES) {
                if (out.keyBits != 0 && out.keyBits != 192) {
                    return false;
                }

                out.keyBits = 192;
            }

            out.lifeSeconds = 28800;
            for (size_t i = 0; i < t.attributes.size(); ++i) {
                const SIkev1Attribute& a = t.attributes[i];
                if (a.type == EIKE1_A_LIFE_TYPE && a.value == EIKE1_LIFE_SECONDS && i + 1 < t.attributes.size() &&
                    t.attributes[i + 1].type == EIKE1_A_LIFE_DURATION) {
                    uint64_t v = t.attributes[i + 1].value;
                    out.lifeSeconds = v > 0xffffffffull ? 0xffffffffu : uint32_t(v);
                }
            }

            // --> Only the groups CIkeDh implements; unknown attribute types are refused
            // (RFC 2409: a responder must not accept attributes it does not understand).
            for (const SIkev1Attribute& a : t.attributes) {
                switch (a.type) {
                case EIKE1_A_ENCR:
                case EIKE1_A_HASH:
                case EIKE1_A_AUTH:
                case EIKE1_A_GROUP:
                case EIKE1_A_LIFE_TYPE:
                case EIKE1_A_LIFE_DURATION:
                case EIKE1_A_KEY_LENGTH:
                    break;
                default:
                    return false;
                }
            }

            return Ikev1KeySize(out.encr, out.keyBits) != 0 && Ikev1HashSize(out.hash) != 0 && IkeDhSupported(out.group);
        }

        /* Compares two suites. */
        bool sameSuite(const SIkev1Suite& a, const SIkev1Suite& b) {
            return a.encr == b.encr && a.keyBits == b.keyBits && a.hash == b.hash && a.group == b.group;
        }

        /* IPsec SA lifetime seconds of a Quick Mode transform (0 when absent). */
        uint32_t transformLife(const SIkev1Transform& t) {
            for (size_t i = 0; i + 1 < t.attributes.size(); ++i) {
                const SIkev1Attribute& a = t.attributes[i];
                if (a.type == EIKE1_IA_LIFE_TYPE && a.value == EIKE1_LIFE_SECONDS && t.attributes[i + 1].type == EIKE1_IA_LIFE_DURATION) {
                    uint64_t v = t.attributes[i + 1].value;
                    return v > 0xffffffffull ? 0xffffffffu : uint32_t(v);
                }
            }

            return 0;
        }

        /* True for UDP-encapsulated encapsulation modes. */
        bool isUdpEncap(uint64_t mode) {
            return mode == EIKE1_ENCAP_UDP_TRANSPORT || mode == EIKE1_ENCAP_UDP_TRANSPORT_DRAFT || mode == EIKE1_ENCAP_UDP_TUNNEL ||
                   mode == EIKE1_ENCAP_UDP_TUNNEL_DRAFT;
        }

        /* True for transport encapsulation modes. */
        bool isTransport(uint64_t mode) {
            return mode == EIKE1_ENCAP_TRANSPORT || mode == EIKE1_ENCAP_UDP_TRANSPORT || mode == EIKE1_ENCAP_UDP_TRANSPORT_DRAFT;
        }

        // ------------------------------------------------------------------------------------
        // State

        enum SaState {
            ST_I_MM1 = 0,       // --> Initiator: MM1 sent.
            ST_I_MM3,           // --> Initiator: MM3 sent.
            ST_I_MM5,           // --> Initiator: MM5 sent.
            ST_R_MM2,           // --> Responder: MM2 sent.
            ST_R_MM4,           // --> Responder: MM4 sent.
            ST_ESTABLISHED,
            ST_DEAD,
        };

        const char* stateName(int s) {
            switch (s) {
            case ST_I_MM1: return "MM1_SENT";
            case ST_I_MM3: return "MM3_SENT";
            case ST_I_MM5: return "MM5_SENT";
            case ST_R_MM2: return "MM2_SENT";
            case ST_R_MM4: return "MM4_SENT";
            case ST_ESTABLISHED: return "ESTABLISHED";
            default: return "DEAD";
            }
        }

        /**
         * One Quick Mode exchange.
         */
        struct Quick {
            uint32_t msgId = 0;
            std::vector<uint8_t> iv;
            std::vector<uint8_t> ni;
            std::vector<uint8_t> nr;
            CIkeDh dh;
            uint16_t pfsGroup = 0;
            std::vector<uint8_t> gxy;
            SIkev1Proposal chosen;          // --> Chosen proposal (one transform).
            uint16_t encr = 0;
            uint16_t keyBits = 0;
            uint16_t integ = 0;
            uint32_t inboundSpi = 0;
            uint32_t outboundSpi = 0;
            bool encap = false;
            uint32_t life = 0;
            SIkev1Id idci;
            SIkev1Id idcr;
            bool hasIds = false;
            net::SIpAddress oaI;
            net::SIpAddress oaR;
            std::vector<uint8_t> lastReceived;
            std::vector<uint8_t> lastSent;
            int64_t nextRetransmit = 0;
            uint32_t tries = 0;
            bool done = false;
            int64_t created = 0;
        };

        /**
         * One ISAKMP SA.
         */
        struct Isakmp {
            uint64_t ckyI = 0;
            uint64_t ckyR = 0;
            bool initiator = false;
            int state = ST_DEAD;
            SEndpoint local;
            SEndpoint remote;
            bool natT = false;              // --> Messages go over the NAT-T port.
            EIkev1NatT natVersion = EIKE1_NATT_NONE;
            bool peerDpd = false;
            bool natLocal = false;          // --> We are behind a NAT (or pretend to be).
            bool natRemote = false;         // --> The peer is behind a NAT.
            SIkev1Suite suite;
            SIkev1Transform chosen;
            std::vector<uint8_t> saiB;
            CIkeDh dh;
            std::vector<uint8_t> gxi;
            std::vector<uint8_t> gxr;
            std::vector<uint8_t> gxy;
            std::vector<uint8_t> ni;
            std::vector<uint8_t> nr;
            SIkev1Keys keys;
            CIkev1Cipher cipher;
            std::vector<uint8_t> iv;        // --> Running Phase 1 IV.
            std::vector<uint8_t> phase1Iv;  // --> Last CBC block of Phase 1.
            SIkev1Id peerId;
            std::string identity;
            std::vector<uint8_t> lastRequest;   // --> Raw last request (duplicate detection).
            std::vector<uint8_t> lastReply;
            std::vector<uint8_t> pending;       // --> Our unanswered request (initiator).
            int64_t nextRetransmit = 0;
            uint32_t tries = 0;
            int64_t created = 0;
            int64_t established = 0;
            int64_t lastHeard = 0;
            int64_t expires = 0;
            std::map<uint32_t, Quick> quicks;
            std::set<uint32_t> infoIds;        // --> Informational message IDs seen (replays).
            uint32_t dpdSeq = 0;
            uint32_t dpdAcked = 0;
            uint32_t dpdOutstanding = 0;        // --> Sequence awaiting an ACK (0: none).
            int64_t dpdNext = 0;
            uint32_t dpdMisses = 0;
            uint16_t lastNotify = 0;
            SIkev1Proposal localProposal;       // --> Initiator: Phase 1 proposal sent.
        };

        using IsakmpPtr = std::shared_ptr<Isakmp>;

        /**
         * One live IPsec SA pair.
         */
        struct IpsecRecord {
            SIkev1IpsecSa sa;
            std::string peer;               // --> Remote address text (owner lookup).
            int64_t expires = 0;
        };

    }

    // ----------------------------------------------------------------------------------------
    // Shared engine

    namespace l2tp {

        /**
         * IKEv1 engine used by both roles.
         */
        struct Ikev1Engine {
            bool initiatorRole = false;
            SIkev1Config config;
            FIkev1Send send;
            FIkev1Log log;
            std::function<void(const SIkev1IpsecSa&)> up;
            std::function<void(const SIkev1IpsecSa&)> down;
            std::function<void(int32_t, const std::string&)> failed;
            std::map<uint64_t, IsakmpPtr> sas;          // --> By our cookie.
            std::map<std::string, uint64_t> halfOpen;   // --> "ckyI remote" -> our cookie (responder MM1).
            std::map<uint32_t, IpsecRecord> ipsec;       // --> By inbound SPI.
            std::set<uint32_t> reservedSpis;
            int64_t now = 0;

            // -- Initiator only.
            SEndpoint server;
            uint16_t serverNatPort = 4500;
            uint16_t localNatPort = 4500;
            uint64_t mine = 0;              // --> Our cookie of the initiated SA.
            bool failedOnce = false;
            uint16_t lastNotify = 0;
            std::vector<std::function<void()>> events;  // --> Callbacks run after the engine is consistent.

            /* Runs the queued callbacks (the owner may re-enter the engine from them). */
            void flush() {
                while (!events.empty()) {
                    std::vector<std::function<void()>> batch;
                    batch.swap(events);
                    for (auto& fn : batch) {
                        fn();
                    }
                }
            }

            /* Current time. */
            int64_t clock() {
                int64_t t = CEventLoop::nowMs();
                return t > now ? t : now;
            }

            /* Logs a message. */
            void logf(EIkeLogLevel level, const std::string& message) {
                if (log) {
                    log(level, "ikev1: " + message);
                }
            }

            /* Prefix for SA log lines. */
            static std::string tag(const Isakmp& s) {
                return s.remote.toString() + " ";
            }

            /* Reports a failure once (initiator). */
            void fail(int32_t error, const std::string& reason) {
                logf(EIKE_LOG_WARNING, reason);
                if (initiatorRole && !failedOnce) {
                    failedOnce = true;
                    if (failed) {
                        auto cb = failed;
                        events.push_back([cb, error, reason]() { cb(error, reason); });
                    }
                }
            }

            /* Sends raw bytes for an SA. */
            void transmit(Isakmp& s, const std::vector<uint8_t>& data) {
                if (send) {
                    send(BytesOf(data), s.local, s.remote, s.natT);
                }
            }

            // -------------------------------------------------------------------------------
            // Message construction

            /* Builds an unencrypted message. */
            std::vector<uint8_t> plainMessage(const Isakmp& s, uint8_t exchange, uint32_t msgId, const std::vector<SIkev1Payload>& payloads) {
                std::vector<uint8_t> chain;
                uint8_t first = 0;
                EncodeIkev1Payloads(payloads, chain, first);
                SIkeHeader h;
                h.spiI = s.ckyI;
                h.spiR = s.ckyR;
                h.nextPayload = first;
                h.version = IKEV1_VERSION;
                h.exchange = exchange;
                h.flags = 0;
                h.messageId = msgId;
                h.length = uint32_t(IKE_HEADER_SIZE + chain.size());
                std::vector<uint8_t> out;
                h.encode(out);
                out.insert(out.end(), chain.begin(), chain.end());
                return out;
            }

            /* Encrypts a payload chain into a message; `iv` advances. */
            int32_t sealMessage(const Isakmp& s, uint8_t exchange, uint32_t msgId, uint8_t first, const std::vector<uint8_t>& chain,
                                std::vector<uint8_t>& iv, std::vector<uint8_t>& out) {
                size_t block = s.cipher.blockSize();
                std::vector<uint8_t> padded = chain;
                size_t pad = (block - padded.size() % block) % block;
                padded.resize(padded.size() + pad, 0);
                if (padded.empty()) {
                    padded.resize(block, 0);
                }

                std::vector<uint8_t> cipher;
                int32_t r = s.cipher.encrypt(iv, BytesOf(padded), cipher);
                if (r != SBOX_OK) {
                    return r;
                }

                SIkeHeader h;
                h.spiI = s.ckyI;
                h.spiR = s.ckyR;
                h.nextPayload = first;
                h.version = IKEV1_VERSION;
                h.exchange = exchange;
                h.flags = EIKE1_F_ENCRYPTED;
                h.messageId = msgId;
                h.length = uint32_t(IKE_HEADER_SIZE + cipher.size());
                out.clear();
                h.encode(out);
                out.insert(out.end(), cipher.begin(), cipher.end());
                return SBOX_OK;
            }

            /* Decrypts a message body; `iv` is advanced only on success. */
            int32_t openMessage(const Isakmp& s, const SReadOnlyByteSpan& data, std::vector<uint8_t>& iv, std::vector<uint8_t>& plain) {
                if (!s.cipher.isValid()) {
                    return -EINVAL;
                }

                std::vector<uint8_t> work = iv;
                int32_t r = s.cipher.decrypt(work, data.slice(IKE_HEADER_SIZE), plain);
                if (r != SBOX_OK) {
                    return r;
                }

                iv = std::move(work);
                return SBOX_OK;
            }

            /* prf(SKEYID_a, prefix | rest). */
            std::vector<uint8_t> authHash(const Isakmp& s, const std::vector<uint8_t>& prefix, const SReadOnlyByteSpan& rest) {
                std::vector<uint8_t> data = prefix;
                ipsec::Append(data, rest);
                std::vector<uint8_t> out;
                Ikev1Prf(s.suite.hash, BytesOf(s.keys.skeyidA), BytesOf(data), out);
                return out;
            }

            /* Builds HASH | rest for a Phase 2 / informational message (`prefix` precedes rest in the hash). */
            void hashedChain(const Isakmp& s, const std::vector<uint8_t>& prefix, const std::vector<SIkev1Payload>& rest,
                             std::vector<uint8_t>& chain, uint8_t& first) {
                std::vector<uint8_t> restBytes;
                uint8_t restFirst = 0;
                EncodeIkev1Payloads(rest, restBytes, restFirst);
                std::vector<uint8_t> hash = authHash(s, prefix, BytesOf(restBytes));
                chain.clear();
                chain.push_back(restFirst);
                chain.push_back(0);
                PutBe16(chain, uint32_t(hash.size() + 4));
                chain.insert(chain.end(), hash.begin(), hash.end());
                chain.insert(chain.end(), restBytes.begin(), restBytes.end());
                first = EIKE1_PL_HASH;
            }

            /* Parses a decrypted Phase 2 message and checks its leading HASH against prf(SKEYID_a, prefix | rest). */
            int32_t checkHashed(const Isakmp& s, uint8_t first, const std::vector<uint8_t>& plain, const std::vector<uint8_t>& prefix,
                                std::vector<SIkev1Payload>& payloads, bool restOnly = false) {
                size_t end = 0;
                if (ParseIkev1Payloads(first, BytesOf(plain), payloads, &end) != SBOX_OK || payloads.empty() ||
                    payloads[0].type != EIKE1_PL_HASH) {
                    return -EBADMSG;
                }

                size_t restStart = payloads[0].offset + payloads[0].size;
                SReadOnlyByteSpan rest(plain.data() + restStart, end - restStart);
                std::vector<uint8_t> expect = authHash(s, prefix, restOnly ? SReadOnlyByteSpan() : rest);
                if (expect.empty() || !IkeSecureEquals(BytesOf(expect), BytesOf(payloads[0].body))) {
                    return -EKEYREJECTED;
                }

                return SBOX_OK;
            }

            /* Message ID bytes. */
            static std::vector<uint8_t> msgIdBytes(uint32_t msgId) {
                std::vector<uint8_t> v;
                PutBe32(v, msgId);
                return v;
            }

            /* Sends an informational exchange (encrypted when Phase 1 is done). */
            void sendInfo(Isakmp& s, const std::vector<SIkev1Payload>& payloads) {
                uint32_t msgId = 0;
                while (msgId == 0) {
                    IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&msgId), sizeof(msgId)));
                }

                if (s.state != ST_ESTABLISHED || s.phase1Iv.empty()) {
                    std::vector<uint8_t> msg = plainMessage(s, EIKE1_X_INFO, 0, payloads);
                    transmit(s, msg);
                    return;
                }

                std::vector<uint8_t> iv;
                if (Ikev1Phase2Iv(s.suite.hash, s.cipher.blockSize(), BytesOf(s.phase1Iv), msgId, iv) != SBOX_OK) {
                    return;
                }

                std::vector<uint8_t> chain;
                uint8_t first = 0;
                hashedChain(s, msgIdBytes(msgId), payloads, chain, first);
                std::vector<uint8_t> msg;
                if (sealMessage(s, EIKE1_X_INFO, msgId, first, chain, iv, msg) == SBOX_OK) {
                    transmit(s, msg);
                }
            }

            /* Builds a notify payload. */
            static SIkev1Payload notifyPayload(uint16_t type, uint8_t protocol, std::vector<uint8_t> spi, std::vector<uint8_t> data) {
                SIkev1Notify n;
                n.type = type;
                n.protocol = protocol;
                n.spi = std::move(spi);
                n.data = std::move(data);
                std::vector<uint8_t> body;
                EncodeIkev1Notify(n, body);
                return MakeIkev1Payload(EIKE1_PL_NOTIFY, std::move(body));
            }

            /* Sends an unencrypted error notification for an exchange we refuse. */
            void sendError(const SIkeHeader& h, const SIkeDatagram& dg, uint16_t type) {
                Isakmp tmp;
                tmp.ckyI = h.spiI;
                tmp.ckyR = h.spiR;
                tmp.local = dg.local;
                tmp.remote = dg.remote;
                tmp.natT = dg.natT;
                std::vector<SIkev1Payload> p;
                p.push_back(notifyPayload(type, EIKE1_PROTO_ISAKMP, cookieBytes(h.spiI, h.spiR), {}));
                std::vector<uint8_t> msg = plainMessage(tmp, EIKE1_X_INFO, 0, p);
                transmit(tmp, msg);
            }

            /* Vendor ID payloads we send. */
            std::vector<SIkev1Payload> ourVendorIds(const Isakmp& s) {
                std::vector<SIkev1Payload> out;
                switch (s.natVersion) {
                case EIKE1_NATT_RFC3947: out.push_back(MakeIkev1Payload(EIKE1_PL_VENDOR, Ikev1VendorId(EIKE1_VID_RFC3947))); break;
                case EIKE1_NATT_DRAFT_03: out.push_back(MakeIkev1Payload(EIKE1_PL_VENDOR, Ikev1VendorId(EIKE1_VID_NATT_DRAFT_03))); break;
                case EIKE1_NATT_DRAFT_02: out.push_back(MakeIkev1Payload(EIKE1_PL_VENDOR, Ikev1VendorId(EIKE1_VID_NATT_DRAFT_02N))); break;
                default: break;
                }

                out.push_back(MakeIkev1Payload(EIKE1_PL_VENDOR, Ikev1VendorId(EIKE1_VID_DPD)));
                return out;
            }

            /* NAT-D payload type of the dialect. */
            static uint8_t natdType(const Isakmp& s) {
                return s.natVersion == EIKE1_NATT_RFC3947 ? uint8_t(EIKE1_PL_NATD) : uint8_t(EIKE1_PL_NATD_DRAFT);
            }

            /* NAT-OA payload type of the dialect. */
            static uint8_t natoaType(const Isakmp& s) {
                return s.natVersion == EIKE1_NATT_RFC3947 ? uint8_t(EIKE1_PL_NATOA) : uint8_t(EIKE1_PL_NATOA_DRAFT);
            }

            /* NAT-D hash of an endpoint. */
            std::vector<uint8_t> natHash(const Isakmp& s, const SEndpoint& ep) {
                std::vector<uint8_t> out;
                Ikev1NatHash(s.suite.hash, s.ckyI, s.ckyR, addressOf(ep), ep.port(), out);
                return out;
            }

            /* Records the vendor IDs of a message. */
            void readVendorIds(Isakmp& s, const std::vector<SIkev1Payload>& payloads) {
                EIkev1NatT best = EIKE1_NATT_NONE;
                for (const SIkev1Payload& p : payloads) {
                    if (p.type != EIKE1_PL_VENDOR) {
                        continue;
                    }

                    switch (Ikev1ClassifyVendorId(BytesOf(p.body))) {
                    case EIKE1_VID_RFC3947: best = std::max(best, EIKE1_NATT_RFC3947); break;
                    case EIKE1_VID_NATT_DRAFT_03: best = std::max(best, EIKE1_NATT_DRAFT_03); break;
                    case EIKE1_VID_NATT_DRAFT_02:
                    case EIKE1_VID_NATT_DRAFT_02N: best = std::max(best, EIKE1_NATT_DRAFT_02); break;
                    case EIKE1_VID_DPD: s.peerDpd = true; break;
                    default: break;
                    }
                }

                s.natVersion = best;
            }

            // -------------------------------------------------------------------------------
            // SA bookkeeping

            /* Removes an ISAKMP SA. */
            void dropIsakmp(uint64_t key) {
                auto it = sas.find(key);
                if (it == sas.end()) {
                    return;
                }

                IsakmpPtr s = it->second;
                s->state = ST_DEAD;
                s->keys.wipe();
                for (auto h = halfOpen.begin(); h != halfOpen.end();) {
                    h = h->second == key ? halfOpen.erase(h) : std::next(h);
                }

                for (auto& [id, q] : s->quicks) {
                    (void)id;
                    if (!q.done && q.inboundSpi) {
                        reservedSpis.erase(q.inboundSpi);
                    }
                }

                sas.erase(it);
            }

            /* Reports and forgets an IPsec SA. */
            void ipsecDown(uint32_t inboundSpi, const std::string& reason) {
                auto it = ipsec.find(inboundSpi);
                if (it == ipsec.end()) {
                    return;
                }

                SIkev1IpsecSa sa = it->second.sa;
                ipsec.erase(it);
                logf(EIKE_LOG_INFO, "IPsec SA " + ipsec::ToHex(BytesOf(spiBytes(sa.inboundSpi))) + "_i/" +
                                        ipsec::ToHex(BytesOf(spiBytes(sa.outboundSpi))) + "_o of " + sa.remote.toString() + " down (" +
                                        reason + ")");
                if (down) {
                    auto cb = down;
                    events.push_back([cb, sa]() { cb(sa); });
                }
            }

            /* Finds an established ISAKMP SA towards a peer address. */
            IsakmpPtr isakmpFor(const std::string& peer) {
                IsakmpPtr best;
                for (auto& [k, s] : sas) {
                    (void)k;
                    if (s->state == ST_ESTABLISHED && addressOf(s->remote).toString() == peer) {
                        if (!best || s->established > best->established) {
                            best = s;
                        }
                    }
                }

                return best;
            }

            /* Sends DELETE for an IPsec SA (our inbound SPI). */
            void sendIpsecDelete(const IpsecRecord& rec) {
                IsakmpPtr s = isakmpFor(rec.peer);
                if (!s) {
                    return;
                }

                SIkev1Delete del;
                del.protocol = EIKE1_PROTO_ESP;
                del.spiSize = 4;
                del.spis.push_back(spiBytes(rec.sa.inboundSpi));
                std::vector<uint8_t> body;
                EncodeIkev1Delete(del, body);
                sendInfo(*s, { MakeIkev1Payload(EIKE1_PL_DELETE, std::move(body)) });
            }

            /* Sends DELETE for an ISAKMP SA. */
            void sendIsakmpDelete(Isakmp& s) {
                if (s.state != ST_ESTABLISHED) {
                    return;
                }

                SIkev1Delete del;
                del.protocol = EIKE1_PROTO_ISAKMP;
                del.spiSize = 16;
                del.spis.push_back(cookieBytes(s.ckyI, s.ckyR));
                std::vector<uint8_t> body;
                EncodeIkev1Delete(del, body);
                sendInfo(s, { MakeIkev1Payload(EIKE1_PL_DELETE, std::move(body)) });
            }

            /* Drops everything of a peer address (dead peer, INITIAL-CONTACT). */
            void dropPeer(const std::string& peer, uint64_t keep, const std::string& reason) {
                std::vector<uint32_t> spis;
                for (auto& [spi, rec] : ipsec) {
                    if (rec.peer == peer && rec.sa.isakmpId != keep) {
                        spis.push_back(spi);
                    }
                }

                for (uint32_t spi : spis) {
                    ipsecDown(spi, reason);
                }

                std::vector<uint64_t> keys;
                for (auto& [k, s] : sas) {
                    if (k != keep && addressOf(s->remote).toString() == peer) {
                        keys.push_back(k);
                    }
                }

                for (uint64_t k : keys) {
                    dropIsakmp(k);
                }
            }

            /* Allocates an unused inbound SPI. */
            uint32_t allocateSpi() {
                for (int32_t i = 0; i < 64; ++i) {
                    uint32_t spi = 0;
                    IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&spi), sizeof(spi)));
                    if (spi < 0x100 || ipsec.count(spi) || reservedSpis.count(spi)) {
                        continue;
                    }

                    reservedSpis.insert(spi);
                    return spi;
                }

                return 0;
            }

            // -------------------------------------------------------------------------------
            // Dispatch

            /* Handles one datagram. */
            void handle(const SIkeDatagram& dg) {
                now = clock();
                SIkeHeader h;
                if (SIkeHeader::parse(BytesOf(dg.data), h) != SBOX_OK || (h.version >> 4) != 1) {
                    return;
                }

                SReadOnlyByteSpan data(dg.data.data(), h.length);
                if (h.spiI == 0) {
                    return;
                }

                IsakmpPtr s;
                if (initiatorRole) {
                    auto it = sas.find(h.spiI);
                    if (it == sas.end()) {
                        return;
                    }

                    s = it->second;
                    if (s->ckyR != 0 && h.spiR != s->ckyR) {
                        return;
                    }
                }
                else {
                    if (h.spiR == 0) {
                        if (h.exchange != EIKE1_X_MAIN) {
                            if (h.exchange == EIKE1_X_AGGRESSIVE) {
                                logf(EIKE_LOG_WARNING, dg.remote.toString() + " Aggressive Mode is not supported");
                                sendError(h, dg, EIKE1_N_INVALID_EXCHANGE_TYPE);
                            }

                            return;
                        }

                        auto ho = halfOpen.find(std::to_string(h.spiI) + " " + addressOf(dg.remote).toString());
                        if (ho != halfOpen.end()) {
                            auto it = sas.find(ho->second);
                            if (it != sas.end() && it->second->lastRequest.size() == data.size &&
                                std::memcmp(it->second->lastRequest.data(), data.data, data.size) == 0) {
                                transmit(*it->second, it->second->lastReply);
                            }

                            return;
                        }

                        handleMm1(h, dg, data);
                        return;
                    }

                    auto it = sas.find(h.spiR);
                    if (it == sas.end() || it->second->ckyI != h.spiI) {
                        return;
                    }

                    s = it->second;
                }

                if (s->state == ST_DEAD) {
                    return;
                }

                // --> A retransmitted request gets the cached reply (main mode only: phase 2
                // exchanges cache per message ID).
                if (h.exchange == EIKE1_X_MAIN && !s->lastRequest.empty() && s->lastRequest.size() == data.size &&
                    std::memcmp(s->lastRequest.data(), data.data, data.size) == 0) {
                    if (!s->lastReply.empty()) {
                        transmit(*s, s->lastReply);
                    }

                    return;
                }

                switch (h.exchange) {
                case EIKE1_X_MAIN:
                    if (h.messageId != 0) {
                        return;
                    }

                    if (initiatorRole) {
                        handleMainInitiator(*s, h, dg, data);
                    }
                    else {
                        handleMainResponder(*s, h, dg, data);
                    }

                    break;

                case EIKE1_X_QUICK:
                    if (s->state == ST_ESTABLISHED && (h.flags & EIKE1_F_ENCRYPTED) && h.messageId != 0) {
                        handleQuick(*s, h, dg, data);
                    }

                    break;

                case EIKE1_X_INFO:
                    handleInfo(*s, h, dg, data);
                    break;

                default:
                    break;
                }
            }

            /* Accepts a (possibly floated) peer endpoint of an authenticated message. */
            void follow(Isakmp& s, const SIkeDatagram& dg) {
                s.remote = dg.remote;
                if (dg.local.isValid()) {
                    s.local = dg.local;
                }

                s.natT = dg.natT;
                s.lastHeard = now;
            }

            // -------------------------------------------------------------------------------
            // Responder Main Mode

            /* MM1: proposal selection. */
            void handleMm1(const SIkeHeader& h, const SIkeDatagram& dg, const SReadOnlyByteSpan& data) {
                if (h.flags & EIKE1_F_ENCRYPTED || h.messageId != 0) {
                    return;
                }

                if (sas.size() >= config.maxSas) {
                    logf(EIKE_LOG_WARNING, dg.remote.toString() + " too many ISAKMP SAs, MM1 dropped");
                    return;
                }

                std::vector<SIkev1Payload> payloads;
                if (ParseIkev1Payloads(h.nextPayload, data.slice(IKE_HEADER_SIZE), payloads) != SBOX_OK) {
                    return;
                }

                const SIkev1Payload* saP = FindIkev1Payload(payloads, EIKE1_PL_SA);
                if (!saP) {
                    return;
                }

                SIkev1Sa offer;
                if (DecodeIkev1Sa(BytesOf(saP->body), offer) != SBOX_OK) {
                    sendError(h, dg, EIKE1_N_PAYLOAD_MALFORMED);
                    return;
                }

                auto s = std::make_shared<Isakmp>();
                s->ckyI = h.spiI;
                s->ckyR = randomCookie();
                s->initiator = false;
                s->local = dg.local;
                s->remote = dg.remote;
                s->natT = dg.natT;
                s->created = now;
                s->lastHeard = now;
                s->saiB = saP->body;
                readVendorIds(*s, payloads);

                // --> Our preference order wins over the initiator's (like the IKEv2 responder).
                const std::vector<SIkev1Suite> ours = config.suites.empty() ? DefaultIkev1Suites() : config.suites;
                bool found = false;
                const SIkev1Proposal* chosenProp = nullptr;
                std::vector<std::string> offered;
                for (const SIkev1Suite& want : ours) {
                    for (const SIkev1Proposal& p : offer.proposals) {
                        if (p.protocol != EIKE1_PROTO_ISAKMP) {
                            continue;
                        }

                        for (const SIkev1Transform& t : p.transforms) {
                            SIkev1Suite got;
                            if (!transformSuite(t, got) || got.auth != EIKE1_AUTH_PSK || !sameSuite(got, want)) {
                                continue;
                            }

                            s->suite = got;
                            s->chosen = t;
                            chosenProp = &p;
                            found = true;
                            break;
                        }

                        if (found) {
                            break;
                        }
                    }

                    if (found) {
                        break;
                    }
                }

                if (!found) {
                    for (const SIkev1Proposal& p : offer.proposals) {
                        for (const SIkev1Transform& t : p.transforms) {
                            SIkev1Suite got;
                            got.encr = uint16_t(t.attr(EIKE1_A_ENCR));
                            got.keyBits = uint16_t(t.attr(EIKE1_A_KEY_LENGTH));
                            got.hash = uint16_t(t.attr(EIKE1_A_HASH));
                            got.group = uint16_t(t.attr(EIKE1_A_GROUP));
                            offered.push_back(got.toString() + "/auth" + std::to_string(t.attr(EIKE1_A_AUTH)));
                        }
                    }

                    std::string list;
                    for (const std::string& o : offered) {
                        list += (list.empty() ? "" : ", ") + o;
                    }

                    logf(EIKE_LOG_WARNING, dg.remote.toString() + " no acceptable Main Mode proposal (offered: " + list + ")");
                    sendError(h, dg, EIKE1_N_NO_PROPOSAL_CHOSEN);
                    return;
                }

                SIkev1Sa reply;
                SIkev1Proposal prop;
                prop.number = chosenProp->number;
                prop.protocol = EIKE1_PROTO_ISAKMP;
                prop.transforms.push_back(s->chosen);
                reply.proposals.push_back(prop);
                std::vector<uint8_t> body;
                EncodeIkev1Sa(reply, body);

                std::vector<SIkev1Payload> out;
                out.push_back(MakeIkev1Payload(EIKE1_PL_SA, std::move(body)));
                for (SIkev1Payload& v : ourVendorIds(*s)) {
                    out.push_back(std::move(v));
                }

                s->state = ST_R_MM2;
                s->lastRequest.assign(data.data, data.data + data.size);
                s->lastReply = plainMessage(*s, EIKE1_X_MAIN, 0, out);
                sas[s->ckyR] = s;
                halfOpen[std::to_string(h.spiI) + " " + addressOf(dg.remote).toString()] = s->ckyR;
                logf(EIKE_LOG_DEBUG, tag(*s) + "MM1: chose " + s->suite.toString());
                transmit(*s, s->lastReply);
            }

            /* MM3 and MM5 on the responder. */
            void handleMainResponder(Isakmp& s, const SIkeHeader& h, const SIkeDatagram& dg, const SReadOnlyByteSpan& data) {
                if (s.state == ST_R_MM2) {
                    handleMm3(s, h, dg, data);
                }
                else if (s.state == ST_R_MM4) {
                    handleMm5(s, h, dg, data);
                }
            }

            /* MM3: key exchange, nonce and NAT detection. */
            void handleMm3(Isakmp& s, const SIkeHeader& h, const SIkeDatagram& dg, const SReadOnlyByteSpan& data) {
                if (h.flags & EIKE1_F_ENCRYPTED) {
                    return;
                }

                std::vector<SIkev1Payload> payloads;
                if (ParseIkev1Payloads(h.nextPayload, data.slice(IKE_HEADER_SIZE), payloads) != SBOX_OK) {
                    return;
                }

                const SIkev1Payload* ke = FindIkev1Payload(payloads, EIKE1_PL_KE);
                const SIkev1Payload* nonce = FindIkev1Payload(payloads, EIKE1_PL_NONCE);
                if (!ke || !nonce || nonce->body.size() < 8 || nonce->body.size() > 256 ||
                    ke->body.size() != CIkeDh::publicSize(s.suite.group)) {
                    logf(EIKE_LOG_WARNING, tag(s) + "MM3 malformed (KE/nonce)");
                    return;
                }

                if (s.dh.generate(s.suite.group) != SBOX_OK || s.dh.agree(BytesOf(ke->body), s.gxy) != SBOX_OK) {
                    logf(EIKE_LOG_WARNING, tag(s) + "MM3 bad KE value");
                    return;
                }

                s.gxi = ke->body;
                s.gxr = s.dh.publicValue();
                s.ni = nonce->body;
                s.nr = randomBytes(32);

                std::vector<SIkev1Payload> out;
                out.push_back(MakeIkev1Payload(EIKE1_PL_KE, s.gxr));
                out.push_back(MakeIkev1Payload(EIKE1_PL_NONCE, s.nr));

                if (s.natVersion != EIKE1_NATT_NONE) {
                    std::vector<std::vector<uint8_t>> natd;
                    for (const SIkev1Payload& p : payloads) {
                        if (p.type == EIKE1_PL_NATD || p.type == EIKE1_PL_NATD_DRAFT) {
                            natd.push_back(p.body);
                        }
                    }

                    if (natd.size() >= 2) {
                        std::vector<uint8_t> ours = natHash(s, dg.local);
                        std::vector<uint8_t> theirs = natHash(s, dg.remote);
                        s.natLocal = natd[0] != ours;
                        s.natRemote = true;
                        for (size_t i = 1; i < natd.size(); ++i) {
                            if (natd[i] == theirs) {
                                s.natRemote = false;
                            }
                        }
                    }

                    std::vector<uint8_t> aboutUs = natHash(s, dg.local);
                    if (config.forceEncap) {
                        // --> A hash that cannot match tells the client we sit behind a NAT, so it
                        // floats to UDP 4500 and proposes UDP-encapsulated transport.
                        aboutUs = randomBytes(aboutUs.size());
                        s.natLocal = true;
                    }

                    out.push_back(MakeIkev1Payload(natdType(s), natHash(s, dg.remote)));
                    out.push_back(MakeIkev1Payload(natdType(s), aboutUs));
                }

                s.state = ST_R_MM4;
                s.lastRequest.assign(data.data, data.data + data.size);
                s.lastReply = plainMessage(s, EIKE1_X_MAIN, 0, out);
                s.lastHeard = now;
                logf(EIKE_LOG_DEBUG, tag(s) + "MM3: KE ok" + (s.natRemote ? ", peer behind NAT" : "") + (s.natLocal ? ", local NAT" : ""));
                transmit(s, s.lastReply);
            }

            /* Candidate PSKs for a peer, in trial order. */
            std::vector<const SIkePsk*> pskCandidates(const Isakmp& s) {
                std::vector<const SIkePsk*> byAddress;
                std::vector<const SIkePsk*> byName;
                std::vector<const SIkePsk*> any;
                std::string addr = addressOf(s.remote).toString();
                for (const SIkePsk& p : config.psks) {
                    if (p.id.empty()) {
                        any.push_back(&p);
                        continue;
                    }

                    net::SIpAddress a;
                    if (net::SIpAddress::parse(p.id, a) == SBOX_OK) {
                        if (a.toString() == addr) {
                            byAddress.push_back(&p);
                        }

                        continue;
                    }

                    byName.push_back(&p);
                }

                std::vector<const SIkePsk*> out = byAddress;
                out.insert(out.end(), byName.begin(), byName.end());
                out.insert(out.end(), any.begin(), any.end());
                if (out.size() > 32) {
                    out.resize(32);
                }

                return out;
            }

            /* MM5: identity and authentication (trial decryption over the candidate PSKs). */
            void handleMm5(Isakmp& s, const SIkeHeader& h, const SIkeDatagram& dg, const SReadOnlyByteSpan& data) {
                if (!(h.flags & EIKE1_F_ENCRYPTED)) {
                    return;
                }

                for (const SIkePsk* psk : pskCandidates(s)) {
                    SIkev1Keys keys;
                    std::vector<uint8_t> skeyid;
                    if (Ikev1SkeyidPsk(s.suite.hash, BytesOf(psk->secret), BytesOf(s.ni), BytesOf(s.nr), skeyid) != SBOX_OK ||
                        Ikev1DeriveKeys(s.suite, BytesOf(skeyid), BytesOf(s.gxy), s.ckyI, s.ckyR, BytesOf(s.gxi), BytesOf(s.gxr), keys) !=
                            SBOX_OK) {
                        IkeWipe(skeyid);
                        return;
                    }

                    IkeWipe(skeyid);
                    CIkev1Cipher cipher;
                    if (cipher.init(s.suite.encr, BytesOf(keys.encKey)) != SBOX_OK) {
                        return;
                    }

                    std::vector<uint8_t> iv = keys.iv;
                    std::vector<uint8_t> plain;
                    if (cipher.decrypt(iv, data.slice(IKE_HEADER_SIZE), plain) != SBOX_OK) {
                        keys.wipe();
                        return;
                    }

                    std::vector<SIkev1Payload> payloads;
                    if (ParseIkev1Payloads(h.nextPayload, BytesOf(plain), payloads) != SBOX_OK) {
                        keys.wipe();
                        continue;
                    }

                    const SIkev1Payload* idP = FindIkev1Payload(payloads, EIKE1_PL_ID);
                    const SIkev1Payload* hashP = FindIkev1Payload(payloads, EIKE1_PL_HASH);
                    SIkev1Id id;
                    if (!idP || !hashP || DecodeIkev1Id(BytesOf(idP->body), id) != SBOX_OK) {
                        keys.wipe();
                        continue;
                    }

                    // --> A PSK bound to a name only applies to that name.
                    net::SIpAddress pskAddr;
                    if (!psk->id.empty() && net::SIpAddress::parse(psk->id, pskAddr) != SBOX_OK) {
                        std::string want = psk->id[0] == '@' ? psk->id.substr(1) : psk->id;
                        if (id.toString() != want && id.toString().substr(0, id.toString().find('[')) != want) {
                            keys.wipe();
                            continue;
                        }
                    }

                    std::vector<uint8_t> expect;
                    Ikev1Phase1Hash(s.suite.hash, BytesOf(keys.skeyid), BytesOf(s.gxi), BytesOf(s.gxr), s.ckyI, s.ckyR, BytesOf(s.saiB),
                                    BytesOf(idP->body), expect);
                    if (expect.empty() || !IkeSecureEquals(BytesOf(expect), BytesOf(hashP->body))) {
                        keys.wipe();
                        continue;
                    }

                    // --> Authenticated.
                    s.keys = std::move(keys);
                    s.cipher = cipher;
                    s.iv = iv;
                    s.peerId = id;
                    s.identity = id.toString();
                    follow(s, dg);

                    bool initialContact = false;
                    for (const SIkev1Payload& p : payloads) {
                        SIkev1Notify n;
                        if (p.type == EIKE1_PL_NOTIFY && DecodeIkev1Notify(BytesOf(p.body), n) == SBOX_OK &&
                            n.type == EIKE1_N_INITIAL_CONTACT) {
                            initialContact = true;
                        }
                    }

                    SIkev1Id ours = config.identity.empty() ? SIkev1Id::fromAddress(addressOf(s.local)) : SIkev1Id::fromString(config.identity);
                    if (config.identity.empty()) {
                        ours.protocol = id.protocol;
                        ours.port = id.protocol ? s.local.port() : 0;
                        if (ours.port == 0 && id.port) {
                            ours.port = id.port;
                        }
                    }

                    std::vector<uint8_t> idBody = ours.body();
                    std::vector<uint8_t> hashR;
                    Ikev1Phase1Hash(s.suite.hash, BytesOf(s.keys.skeyid), BytesOf(s.gxr), BytesOf(s.gxi), s.ckyR, s.ckyI, BytesOf(s.saiB),
                                    BytesOf(idBody), hashR);

                    std::vector<SIkev1Payload> out;
                    out.push_back(MakeIkev1Payload(EIKE1_PL_ID, idBody));
                    out.push_back(MakeIkev1Payload(EIKE1_PL_HASH, hashR));
                    std::vector<uint8_t> chain;
                    uint8_t first = 0;
                    EncodeIkev1Payloads(out, chain, first);
                    std::vector<uint8_t> msg;
                    if (sealMessage(s, EIKE1_X_MAIN, 0, first, chain, s.iv, msg) != SBOX_OK) {
                        return;
                    }

                    s.phase1Iv = s.iv;
                    s.state = ST_ESTABLISHED;
                    s.established = now;
                    s.lastRequest.assign(data.data, data.data + data.size);
                    s.lastReply = msg;
                    uint32_t life = s.suite.lifeSeconds;
                    if (config.phase1LifeSeconds && (life == 0 || life > config.phase1LifeSeconds)) {
                        life = config.phase1LifeSeconds;
                    }

                    s.expires = life ? now + int64_t(life) * 1000 : 0;
                    s.dpdNext = now + int64_t(config.dpdSeconds) * 1000;
                    for (auto ho = halfOpen.begin(); ho != halfOpen.end();) {
                        ho = ho->second == s.ckyR ? halfOpen.erase(ho) : std::next(ho);
                    }

                    logf(EIKE_LOG_INFO, tag(s) + "Main Mode established, id '" + s.identity + "', " + s.suite.toString() +
                                            (s.natT ? ", NAT-T" : "") + (s.peerDpd ? ", DPD" : ""));
                    transmit(s, msg);
                    if (initialContact) {
                        dropPeer(addressOf(s.remote).toString(), s.ckyR, "INITIAL-CONTACT");
                    }

                    return;
                }

                logf(EIKE_LOG_WARNING, tag(s) + "Main Mode authentication failed (pre-shared key mismatch)");
                dropIsakmp(s.ckyR);
            }

            // -------------------------------------------------------------------------------
            // Initiator Main Mode

            /* Starts Main Mode. */
            void startInitiator(const net::SIpAddress& localAddress, uint16_t localPort, uint16_t natPort) {
                now = clock();
                auto s = std::make_shared<Isakmp>();
                s->initiator = true;
                s->ckyI = randomCookie();
                s->local = endpointOf(localAddress, localPort);
                s->remote = server;
                s->created = now;
                s->lastHeard = now;
                localNatPort = natPort;

                const std::vector<SIkev1Suite> suites = config.suites.empty() ? DefaultIkev1Suites() : config.suites;
                SIkev1Proposal prop;
                prop.number = 1;
                prop.protocol = EIKE1_PROTO_ISAKMP;
                uint8_t number = 1;
                for (const SIkev1Suite& su : suites) {
                    prop.transforms.push_back(suiteTransform(su, number++, config.phase1LifeSeconds));
                    if (number == 0) {
                        break;
                    }
                }

                s->localProposal = prop;
                SIkev1Sa sa;
                sa.proposals.push_back(prop);
                std::vector<uint8_t> body;
                EncodeIkev1Sa(sa, body);
                s->saiB = body;

                std::vector<SIkev1Payload> out;
                out.push_back(MakeIkev1Payload(EIKE1_PL_SA, std::move(body)));
                out.push_back(MakeIkev1Payload(EIKE1_PL_VENDOR, Ikev1VendorId(EIKE1_VID_RFC3947)));
                out.push_back(MakeIkev1Payload(EIKE1_PL_VENDOR, Ikev1VendorId(EIKE1_VID_NATT_DRAFT_02N)));
                out.push_back(MakeIkev1Payload(EIKE1_PL_VENDOR, Ikev1VendorId(EIKE1_VID_DPD)));
                s->state = ST_I_MM1;
                mine = s->ckyI;
                sas[s->ckyI] = s;
                request(*s, plainMessage(*s, EIKE1_X_MAIN, 0, out));
            }

            /* Sends a request and arms its retransmission. */
            void request(Isakmp& s, std::vector<uint8_t> msg) {
                s.pending = std::move(msg);
                s.tries = 0;
                s.nextRetransmit = now + config.retransmitMs;
                transmit(s, s.pending);
            }

            /* Main Mode replies on the initiator. */
            void handleMainInitiator(Isakmp& s, const SIkeHeader& h, const SIkeDatagram& dg, const SReadOnlyByteSpan& data) {
                if (s.state == ST_I_MM1 && !(h.flags & EIKE1_F_ENCRYPTED)) {
                    std::vector<SIkev1Payload> payloads;
                    if (ParseIkev1Payloads(h.nextPayload, data.slice(IKE_HEADER_SIZE), payloads) != SBOX_OK) {
                        return;
                    }

                    const SIkev1Payload* saP = FindIkev1Payload(payloads, EIKE1_PL_SA);
                    SIkev1Sa reply;
                    if (!saP || DecodeIkev1Sa(BytesOf(saP->body), reply) != SBOX_OK || reply.proposals.size() != 1 ||
                        reply.proposals[0].transforms.size() != 1) {
                        return;
                    }

                    SIkev1Suite got;
                    if (!transformSuite(reply.proposals[0].transforms[0], got)) {
                        fail(-ENOTSUP, "responder chose an unsupported Main Mode transform");
                        return;
                    }

                    bool ok = false;
                    for (const SIkev1Transform& t : s.localProposal.transforms) {
                        SIkev1Suite mineSuite;
                        if (transformSuite(t, mineSuite) && sameSuite(mineSuite, got)) {
                            ok = true;
                        }
                    }

                    if (!ok) {
                        fail(-EPROTO, "responder chose a transform we did not propose");
                        return;
                    }

                    s.ckyR = h.spiR;
                    s.suite = got;
                    if (dg.local.isValid() && !dg.natT) {
                        // --> The address the kernel actually used towards the responder.
                        s.local = dg.local;
                    }

                    readVendorIds(s, payloads);
                    s.lastHeard = now;
                    if (s.dh.generate(s.suite.group) != SBOX_OK) {
                        fail(-EIO, "DH generation failed");
                        return;
                    }

                    s.gxi = s.dh.publicValue();
                    s.ni = randomBytes(32);
                    std::vector<SIkev1Payload> out;
                    out.push_back(MakeIkev1Payload(EIKE1_PL_KE, s.gxi));
                    out.push_back(MakeIkev1Payload(EIKE1_PL_NONCE, s.ni));
                    if (s.natVersion != EIKE1_NATT_NONE) {
                        out.push_back(MakeIkev1Payload(natdType(s), natHash(s, s.remote)));
                        out.push_back(MakeIkev1Payload(natdType(s), natHash(s, s.local)));
                    }

                    s.state = ST_I_MM3;
                    request(s, plainMessage(s, EIKE1_X_MAIN, 0, out));
                    return;
                }

                if (s.state == ST_I_MM3 && !(h.flags & EIKE1_F_ENCRYPTED)) {
                    std::vector<SIkev1Payload> payloads;
                    if (ParseIkev1Payloads(h.nextPayload, data.slice(IKE_HEADER_SIZE), payloads) != SBOX_OK) {
                        return;
                    }

                    const SIkev1Payload* ke = FindIkev1Payload(payloads, EIKE1_PL_KE);
                    const SIkev1Payload* nonce = FindIkev1Payload(payloads, EIKE1_PL_NONCE);
                    if (!ke || !nonce || nonce->body.size() < 8 || nonce->body.size() > 256 ||
                        ke->body.size() != CIkeDh::publicSize(s.suite.group)) {
                        return;
                    }

                    if (s.dh.agree(BytesOf(ke->body), s.gxy) != SBOX_OK) {
                        fail(-EPROTO, "bad responder KE");
                        return;
                    }

                    s.gxr = ke->body;
                    s.nr = nonce->body;
                    if (s.natVersion != EIKE1_NATT_NONE) {
                        std::vector<std::vector<uint8_t>> natd;
                        for (const SIkev1Payload& p : payloads) {
                            if (p.type == EIKE1_PL_NATD || p.type == EIKE1_PL_NATD_DRAFT) {
                                natd.push_back(p.body);
                            }
                        }

                        if (natd.size() >= 2) {
                            s.natLocal = natd[0] != natHash(s, s.local);
                            s.natRemote = true;
                            std::vector<uint8_t> theirs = natHash(s, s.remote);
                            for (size_t i = 1; i < natd.size(); ++i) {
                                if (natd[i] == theirs) {
                                    s.natRemote = false;
                                }
                            }
                        }

                        if (s.natLocal || s.natRemote) {
                            // --> RFC 3947 4: float to the NAT-T port from message 5 on.
                            s.natT = true;
                            s.remote.port(serverNatPort);
                            s.local.port(localNatPort);
                        }
                    }

                    std::string secret = config.psks.empty() ? std::string() : config.psks[0].secret;
                    std::vector<uint8_t> skeyid;
                    if (Ikev1SkeyidPsk(s.suite.hash, BytesOf(secret), BytesOf(s.ni), BytesOf(s.nr), skeyid) != SBOX_OK ||
                        Ikev1DeriveKeys(s.suite, BytesOf(skeyid), BytesOf(s.gxy), s.ckyI, s.ckyR, BytesOf(s.gxi), BytesOf(s.gxr), s.keys) !=
                            SBOX_OK ||
                        s.cipher.init(s.suite.encr, BytesOf(s.keys.encKey)) != SBOX_OK) {
                        IkeWipe(skeyid);
                        fail(-EIO, "key derivation failed");
                        return;
                    }

                    IkeWipe(skeyid);
                    s.iv = s.keys.iv;
                    SIkev1Id id = config.identity.empty() ? SIkev1Id::fromAddress(addressOf(s.local), 17, 500) : SIkev1Id::fromString(config.identity);
                    std::vector<uint8_t> idBody = id.body();
                    std::vector<uint8_t> hashI;
                    Ikev1Phase1Hash(s.suite.hash, BytesOf(s.keys.skeyid), BytesOf(s.gxi), BytesOf(s.gxr), s.ckyI, s.ckyR, BytesOf(s.saiB),
                                    BytesOf(idBody), hashI);
                    std::vector<SIkev1Payload> out;
                    out.push_back(MakeIkev1Payload(EIKE1_PL_ID, idBody));
                    out.push_back(MakeIkev1Payload(EIKE1_PL_HASH, hashI));
                    out.push_back(notifyPayload(EIKE1_N_INITIAL_CONTACT, EIKE1_PROTO_ISAKMP, cookieBytes(s.ckyI, s.ckyR), {}));
                    std::vector<uint8_t> chain;
                    uint8_t first = 0;
                    EncodeIkev1Payloads(out, chain, first);
                    std::vector<uint8_t> msg;
                    if (sealMessage(s, EIKE1_X_MAIN, 0, first, chain, s.iv, msg) != SBOX_OK) {
                        fail(-EIO, "encryption failed");
                        return;
                    }

                    s.state = ST_I_MM5;
                    s.lastHeard = now;
                    request(s, msg);
                    return;
                }

                if (s.state == ST_I_MM5 && (h.flags & EIKE1_F_ENCRYPTED)) {
                    std::vector<uint8_t> iv = s.iv;
                    std::vector<uint8_t> plain;
                    if (openMessage(s, data, iv, plain) != SBOX_OK) {
                        return;
                    }

                    std::vector<SIkev1Payload> payloads;
                    if (ParseIkev1Payloads(h.nextPayload, BytesOf(plain), payloads) != SBOX_OK) {
                        fail(-EACCES, "MM6 does not decrypt (pre-shared key mismatch?)");
                        return;
                    }

                    const SIkev1Payload* idP = FindIkev1Payload(payloads, EIKE1_PL_ID);
                    const SIkev1Payload* hashP = FindIkev1Payload(payloads, EIKE1_PL_HASH);
                    if (!idP || !hashP) {
                        return;
                    }

                    std::vector<uint8_t> expect;
                    Ikev1Phase1Hash(s.suite.hash, BytesOf(s.keys.skeyid), BytesOf(s.gxr), BytesOf(s.gxi), s.ckyR, s.ckyI, BytesOf(s.saiB),
                                    BytesOf(idP->body), expect);
                    if (expect.empty() || !IkeSecureEquals(BytesOf(expect), BytesOf(hashP->body))) {
                        fail(-EACCES, "responder HASH_R mismatch");
                        return;
                    }

                    DecodeIkev1Id(BytesOf(idP->body), s.peerId);
                    s.identity = s.peerId.toString();
                    s.iv = iv;
                    s.phase1Iv = iv;
                    s.state = ST_ESTABLISHED;
                    s.established = now;
                    s.pending.clear();
                    s.lastHeard = now;
                    s.dpdNext = now + int64_t(config.dpdSeconds) * 1000;
                    logf(EIKE_LOG_INFO, "Main Mode established with " + s.remote.toString() + ", " + s.suite.toString() +
                                            (s.natT ? ", NAT-T" : ""));
                    startQuick(s);
                }
            }

            // -------------------------------------------------------------------------------
            // Quick Mode

            /* Initiator: sends QM1. */
            void startQuick(Isakmp& s) {
                uint32_t msgId = 0;
                while (msgId == 0) {
                    IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&msgId), sizeof(msgId)));
                }

                Quick& q = s.quicks[msgId];
                q.msgId = msgId;
                q.created = now;
                if (Ikev1Phase2Iv(s.suite.hash, s.cipher.blockSize(), BytesOf(s.phase1Iv), msgId, q.iv) != SBOX_OK) {
                    fail(-EIO, "IV derivation failed");
                    return;
                }

                q.inboundSpi = allocateSpi();
                q.ni = randomBytes(32);
                q.encap = s.natT;
                uint16_t mode = EIKE1_ENCAP_TRANSPORT;
                if (s.natT) {
                    mode = s.natVersion == EIKE1_NATT_RFC3947 ? uint16_t(EIKE1_ENCAP_UDP_TRANSPORT) : uint16_t(EIKE1_ENCAP_UDP_TRANSPORT_DRAFT);
                }

                const std::vector<SIkev1EspSuite> suites = config.esp.empty() ? DefaultIkev1EspSuites() : config.esp;
                SIkev1Proposal prop;
                prop.number = 1;
                prop.protocol = EIKE1_PROTO_ESP;
                prop.spi = spiBytes(q.inboundSpi);
                uint8_t number = 1;
                for (const SIkev1EspSuite& e : suites) {
                    SIkev1Transform t;
                    t.number = number++;
                    t.id = e.espId;
                    t.attributes.push_back({ EIKE1_IA_LIFE_TYPE, EIKE1_LIFE_SECONDS, false });
                    t.attributes.push_back({ EIKE1_IA_LIFE_DURATION, config.phase2LifeSeconds, true });
                    t.attributes.push_back({ EIKE1_IA_ENCAP, mode, false });
                    if (e.authAlg != EIKE1_AA_NONE) {
                        t.attributes.push_back({ EIKE1_IA_AUTH, e.authAlg, false });
                    }

                    if (e.keyBits && e.espId != EIKE1_ESP_3DES) {
                        t.attributes.push_back({ EIKE1_IA_KEY_LENGTH, e.keyBits, false });
                    }

                    if (config.pfs) {
                        t.attributes.push_back({ EIKE1_IA_GROUP, s.suite.group, false });
                    }

                    prop.transforms.push_back(std::move(t));
                }

                SIkev1Sa sa;
                sa.proposals.push_back(prop);
                std::vector<uint8_t> saBody;
                EncodeIkev1Sa(sa, saBody);

                std::vector<SIkev1Payload> rest;
                rest.push_back(MakeIkev1Payload(EIKE1_PL_SA, saBody));
                rest.push_back(MakeIkev1Payload(EIKE1_PL_NONCE, q.ni));
                if (config.pfs) {
                    q.pfsGroup = s.suite.group;
                    q.dh.generate(q.pfsGroup);
                    rest.push_back(MakeIkev1Payload(EIKE1_PL_KE, q.dh.publicValue()));
                }

                net::SIpAddress localAddr = addressOf(s.local);
                net::SIpAddress serverAddr = addressOf(s.remote);
                q.idci = SIkev1Id::fromAddress(localAddr, 17, config.l2tpPort);
                q.idcr = SIkev1Id::fromAddress(serverAddr, 17, config.l2tpPort);
                q.hasIds = true;
                rest.push_back(MakeIkev1Payload(EIKE1_PL_ID, q.idci.body()));
                rest.push_back(MakeIkev1Payload(EIKE1_PL_ID, q.idcr.body()));
                if (s.natT) {
                    std::vector<uint8_t> oa;
                    EncodeIkev1NatOa(localAddr, oa);
                    rest.push_back(MakeIkev1Payload(natoaType(s), oa));
                    if (s.natVersion == EIKE1_NATT_RFC3947) {
                        std::vector<uint8_t> oar;
                        EncodeIkev1NatOa(serverAddr, oar);
                        rest.push_back(MakeIkev1Payload(natoaType(s), oar));
                    }
                }

                std::vector<uint8_t> chain;
                uint8_t first = 0;
                hashedChain(s, msgIdBytes(msgId), rest, chain, first);
                std::vector<uint8_t> msg;
                if (sealMessage(s, EIKE1_X_QUICK, msgId, first, chain, q.iv, msg) != SBOX_OK) {
                    fail(-EIO, "QM1 encryption failed");
                    return;
                }

                q.lastSent = msg;
                q.tries = 0;
                q.nextRetransmit = now + config.retransmitMs;
                transmit(s, msg);
            }

            /* Quick Mode messages. */
            void handleQuick(Isakmp& s, const SIkeHeader& h, const SIkeDatagram& dg, const SReadOnlyByteSpan& data) {
                auto it = s.quicks.find(h.messageId);
                if (it != s.quicks.end()) {
                    Quick& q = it->second;
                    if (q.lastReceived.size() == data.size && std::memcmp(q.lastReceived.data(), data.data, data.size) == 0) {
                        if (!s.initiator && !q.lastSent.empty() && !q.done) {
                            transmit(s, q.lastSent);
                        }

                        return;
                    }

                    if (q.done) {
                        return;
                    }

                    if (s.initiator) {
                        handleQm2(s, q, h, dg, data);
                    }
                    else {
                        handleQm3(s, q, h, dg, data);
                    }

                    return;
                }

                if (s.initiator) {
                    return;
                }

                handleQm1(s, h, dg, data);
            }

            /* Responder: QM1. */
            void handleQm1(Isakmp& s, const SIkeHeader& h, const SIkeDatagram& dg, const SReadOnlyByteSpan& data) {
                size_t pendingQuicks = 0;
                for (auto& [id, q] : s.quicks) {
                    (void)id;
                    pendingQuicks += q.done ? 0 : 1;
                }

                if (pendingQuicks >= 16) {
                    return;
                }

                Quick q;
                q.msgId = h.messageId;
                q.created = now;
                if (Ikev1Phase2Iv(s.suite.hash, s.cipher.blockSize(), BytesOf(s.phase1Iv), h.messageId, q.iv) != SBOX_OK) {
                    return;
                }

                std::vector<uint8_t> plain;
                if (openMessage(s, data, q.iv, plain) != SBOX_OK) {
                    return;
                }

                std::vector<SIkev1Payload> payloads;
                if (checkHashed(s, h.nextPayload, plain, msgIdBytes(h.messageId), payloads) != SBOX_OK) {
                    logf(EIKE_LOG_WARNING, tag(s) + "QM1 HASH(1) mismatch");
                    return;
                }

                follow(s, dg);
                q.lastReceived.assign(data.data, data.data + data.size);

                const SIkev1Payload* saP = nullptr;
                const SIkev1Payload* nonceP = nullptr;
                const SIkev1Payload* keP = nullptr;
                std::vector<const SIkev1Payload*> ids;
                std::vector<const SIkev1Payload*> oas;
                for (size_t i = 1; i < payloads.size(); ++i) {
                    const SIkev1Payload& p = payloads[i];
                    switch (p.type) {
                    case EIKE1_PL_SA: saP = saP ? saP : &p; break;
                    case EIKE1_PL_NONCE: nonceP = nonceP ? nonceP : &p; break;
                    case EIKE1_PL_KE: keP = keP ? keP : &p; break;
                    case EIKE1_PL_ID: ids.push_back(&p); break;
                    case EIKE1_PL_NATOA:
                    case EIKE1_PL_NATOA_DRAFT: oas.push_back(&p); break;
                    default: break;
                    }
                }

                SIkev1Sa offer;
                if (!saP || !nonceP || nonceP->body.size() < 8 || nonceP->body.size() > 256 || (ids.size() != 0 && ids.size() != 2) ||
                    DecodeIkev1Sa(BytesOf(saP->body), offer) != SBOX_OK) {
                    logf(EIKE_LOG_WARNING, tag(s) + "QM1 malformed");
                    return;
                }

                q.ni = nonceP->body;
                if (ids.size() == 2) {
                    if (DecodeIkev1Id(BytesOf(ids[0]->body), q.idci) != SBOX_OK || DecodeIkev1Id(BytesOf(ids[1]->body), q.idcr) != SBOX_OK) {
                        return;
                    }

                    q.hasIds = true;
                }

                if (q.hasIds && config.requireL2tp) {
                    bool ok = (q.idcr.type == EIKE1_ID_IPV4_ADDR || q.idcr.type == EIKE1_ID_IPV6_ADDR) &&
                              (q.idci.type == EIKE1_ID_IPV4_ADDR || q.idci.type == EIKE1_ID_IPV6_ADDR) &&
                              (q.idcr.protocol == 17 || q.idcr.protocol == 0) && (q.idci.protocol == q.idcr.protocol) &&
                              (q.idcr.port == config.l2tpPort || q.idcr.port == 0);
                    if (ok && !s.natLocal && q.idcr.address() != addressOf(s.local)) {
                        ok = false;
                    }

                    if (ok && !s.natRemote && !s.natT && q.idci.address() != addressOf(s.remote)) {
                        ok = false;
                    }

                    if (!ok) {
                        logf(EIKE_LOG_WARNING, tag(s) + "Quick Mode IDs " + q.idci.toString() + " <-> " + q.idcr.toString() +
                                                   " are not L2TP (UDP " + std::to_string(config.l2tpPort) + ") transport selectors");
                        sendInfo(s, { notifyPayload(EIKE1_N_INVALID_ID_INFORMATION, EIKE1_PROTO_ISAKMP, cookieBytes(s.ckyI, s.ckyR), {}) });
                        return;
                    }
                }

                // --> Proposal selection: our ESP preference order across every offered transform.
                const std::vector<SIkev1EspSuite> ours = config.esp.empty() ? DefaultIkev1EspSuites() : config.esp;
                const SIkev1Proposal* chosenProp = nullptr;
                const SIkev1Transform* chosenT = nullptr;
                for (const SIkev1EspSuite& want : ours) {
                    for (const SIkev1Proposal& p : offer.proposals) {
                        if (p.protocol != EIKE1_PROTO_ESP || p.spi.size() != 4) {
                            continue;
                        }

                        // --> Proposals sharing a number are ANDed (AH+ESP bundles): not supported.
                        size_t sameNumber = 0;
                        for (const SIkev1Proposal& o : offer.proposals) {
                            sameNumber += o.number == p.number ? 1 : 0;
                        }

                        if (sameNumber != 1) {
                            continue;
                        }

                        for (const SIkev1Transform& t : p.transforms) {
                            uint16_t keyLen = uint16_t(t.attr(EIKE1_IA_KEY_LENGTH));
                            uint16_t authAlg = uint16_t(t.attr(EIKE1_IA_AUTH));
                            uint64_t mode = t.attr(EIKE1_IA_ENCAP, EIKE1_ENCAP_TUNNEL);
                            uint16_t encr = 0;
                            uint16_t keyBits = 0;
                            uint16_t integ = 0;
                            if (t.id != want.espId || authAlg != want.authAlg || !isTransport(mode) ||
                                !Ikev1EspTransform(t.id, keyLen, authAlg, encr, keyBits, integ)) {
                                continue;
                            }

                            if (t.id != EIKE1_ESP_3DES && keyBits != (want.keyBits ? want.keyBits : 128)) {
                                continue;
                            }

                            uint16_t group = uint16_t(t.attr(EIKE1_IA_GROUP));
                            if (group && (!IkeDhSupported(group) || !keP || keP->body.size() != CIkeDh::publicSize(group))) {
                                continue;
                            }

                            bool knownAttrs = true;
                            for (const SIkev1Attribute& a : t.attributes) {
                                if (a.type < EIKE1_IA_LIFE_TYPE || a.type > EIKE1_IA_KEY_LENGTH) {
                                    knownAttrs = false;
                                }
                            }

                            if (!knownAttrs) {
                                continue;
                            }

                            chosenProp = &p;
                            chosenT = &t;
                            q.encr = encr;
                            q.keyBits = keyBits;
                            q.integ = integ;
                            q.pfsGroup = group;
                            q.encap = isUdpEncap(mode) || s.natT;
                            break;
                        }

                        if (chosenT) {
                            break;
                        }
                    }

                    if (chosenT) {
                        break;
                    }
                }

                if (!chosenT) {
                    std::string list;
                    for (const SIkev1Proposal& p : offer.proposals) {
                        for (const SIkev1Transform& t : p.transforms) {
                            list += (list.empty() ? "" : ", ") + std::to_string(t.id) + "/auth" + std::to_string(t.attr(EIKE1_IA_AUTH)) + "/key" +
                                    std::to_string(t.attr(EIKE1_IA_KEY_LENGTH)) + "/mode" + std::to_string(t.attr(EIKE1_IA_ENCAP));
                        }
                    }

                    logf(EIKE_LOG_WARNING, tag(s) + "no acceptable Quick Mode proposal (offered: " + list + ")");
                    sendInfo(s, { notifyPayload(EIKE1_N_NO_PROPOSAL_CHOSEN, EIKE1_PROTO_ISAKMP, cookieBytes(s.ckyI, s.ckyR), {}) });
                    return;
                }

                if (q.pfsGroup) {
                    if (q.dh.generate(q.pfsGroup) != SBOX_OK || q.dh.agree(BytesOf(keP->body), q.gxy) != SBOX_OK) {
                        return;
                    }
                }

                q.outboundSpi = GetBe32(chosenProp->spi.data());
                q.inboundSpi = allocateSpi();
                if (!q.inboundSpi) {
                    return;
                }

                q.life = transformLife(*chosenT);
                bool capped = false;
                if (config.phase2LifeSeconds && (q.life == 0 || q.life > config.phase2LifeSeconds)) {
                    capped = q.life != 0;
                    q.life = config.phase2LifeSeconds;
                }

                // --> NAT-OA: the peer's original address (its own view), for checksums and logs.
                if (!oas.empty()) {
                    DecodeIkev1NatOa(BytesOf(oas[0]->body), q.oaI);
                    if (oas.size() >= 2) {
                        DecodeIkev1NatOa(BytesOf(oas[1]->body), q.oaR);
                    }
                }

                if (!q.oaI.isValid() && q.hasIds) {
                    q.oaI = q.idci.address();
                }

                q.nr = randomBytes(32);
                q.chosen.number = chosenProp->number;
                q.chosen.protocol = EIKE1_PROTO_ESP;
                q.chosen.spi = spiBytes(q.inboundSpi);
                q.chosen.transforms.push_back(*chosenT);

                SIkev1Sa reply;
                reply.proposals.push_back(q.chosen);
                std::vector<uint8_t> saBody;
                EncodeIkev1Sa(reply, saBody);

                std::vector<SIkev1Payload> rest;
                rest.push_back(MakeIkev1Payload(EIKE1_PL_SA, saBody));
                rest.push_back(MakeIkev1Payload(EIKE1_PL_NONCE, q.nr));
                if (q.pfsGroup) {
                    rest.push_back(MakeIkev1Payload(EIKE1_PL_KE, q.dh.publicValue()));
                }

                if (q.hasIds) {
                    rest.push_back(MakeIkev1Payload(EIKE1_PL_ID, q.idci.body()));
                    rest.push_back(MakeIkev1Payload(EIKE1_PL_ID, q.idcr.body()));
                }

                if (q.encap && s.natVersion != EIKE1_NATT_NONE) {
                    std::vector<uint8_t> oa;
                    if (s.natVersion == EIKE1_NATT_RFC3947) {
                        EncodeIkev1NatOa(addressOf(s.remote), oa);
                        rest.push_back(MakeIkev1Payload(natoaType(s), oa));
                        oa.clear();
                    }

                    EncodeIkev1NatOa(addressOf(s.local), oa);
                    rest.push_back(MakeIkev1Payload(natoaType(s), oa));
                }

                if (capped) {
                    std::vector<uint8_t> attrs;
                    PutBe16(attrs, 0x8000u | EIKE1_IA_LIFE_TYPE);
                    PutBe16(attrs, EIKE1_LIFE_SECONDS);
                    PutBe16(attrs, EIKE1_IA_LIFE_DURATION);
                    PutBe16(attrs, 4);
                    PutBe32(attrs, q.life);
                    rest.push_back(notifyPayload(EIKE1_N_RESPONDER_LIFETIME, EIKE1_PROTO_ESP, chosenProp->spi, attrs));
                }

                std::vector<uint8_t> prefix = msgIdBytes(q.msgId);
                ipsec::Append(prefix, BytesOf(q.ni));
                std::vector<uint8_t> chain;
                uint8_t first = 0;
                hashedChain(s, prefix, rest, chain, first);
                std::vector<uint8_t> msg;
                if (sealMessage(s, EIKE1_X_QUICK, q.msgId, first, chain, q.iv, msg) != SBOX_OK) {
                    return;
                }

                q.lastSent = msg;
                q.tries = 0;
                q.nextRetransmit = now + config.retransmitMs;
                uint32_t msgId = q.msgId;
                s.quicks[msgId] = std::move(q);
                transmit(s, msg);
            }

            /* Computes KEYMAT of both directions and reports the SA. */
            void completeQuick(Isakmp& s, Quick& q) {
                size_t encLen = IkeEncrKeyMaterial(q.encr, q.keyBits);
                size_t integLen = IkeIntegKeySize(q.integ);
                std::vector<uint8_t> inKey;
                std::vector<uint8_t> outKey;
                if (Ikev1QuickKeymat(s.suite.hash, BytesOf(s.keys.skeyidD), BytesOf(q.gxy), EIKE1_PROTO_ESP, BytesOf(spiBytes(q.inboundSpi)),
                                     BytesOf(q.ni), BytesOf(q.nr), encLen + integLen, inKey) != SBOX_OK ||
                    Ikev1QuickKeymat(s.suite.hash, BytesOf(s.keys.skeyidD), BytesOf(q.gxy), EIKE1_PROTO_ESP, BytesOf(spiBytes(q.outboundSpi)),
                                     BytesOf(q.ni), BytesOf(q.nr), encLen + integLen, outKey) != SBOX_OK) {
                    return;
                }

                SIkev1IpsecSa sa;
                sa.isakmpId = s.ckyR;
                sa.identity = s.identity;
                sa.local = addressOf(s.local);
                sa.remote = addressOf(s.remote);
                sa.localIkePort = s.local.port();
                sa.remoteIkePort = s.remote.port();
                sa.encap = q.encap;
                sa.inboundSpi = q.inboundSpi;
                sa.outboundSpi = q.outboundSpi;
                sa.encr = q.encr;
                sa.keyBits = q.keyBits;
                sa.integ = q.integ;
                sa.inEncKey.assign(inKey.begin(), inKey.begin() + long(encLen));
                sa.inIntegKey.assign(inKey.begin() + long(encLen), inKey.end());
                sa.outEncKey.assign(outKey.begin(), outKey.begin() + long(encLen));
                sa.outIntegKey.assign(outKey.begin() + long(encLen), outKey.end());
                IkeWipe(inKey);
                IkeWipe(outKey);
                sa.lifeSeconds = q.life;
                if (s.initiator) {
                    sa.localOriginal = q.idci.address();
                    sa.remoteOriginal = q.idcr.address();
                    sa.protocol = q.idci.protocol;
                    sa.localPort = q.idci.port;
                    sa.remotePort = q.idcr.port;
                }
                else {
                    sa.remoteOriginal = q.oaI.isValid() ? q.oaI : sa.remote;
                    sa.localOriginal = q.hasIds ? q.idcr.address() : sa.local;
                    sa.protocol = q.hasIds ? q.idcr.protocol : 0;
                    sa.localPort = q.hasIds ? q.idcr.port : 0;
                    sa.remotePort = q.hasIds ? q.idci.port : 0;
                }

                sa.proposal = espName(q.encr, q.keyBits, q.integ, q.encap);
                q.done = true;
                q.lastSent.clear();
                IkeWipe(q.gxy);
                reservedSpis.erase(q.inboundSpi);

                IpsecRecord rec;
                rec.sa = sa;
                rec.peer = sa.remote.toString();
                rec.expires = q.life ? now + int64_t(q.life) * 1000 + 30000 : 0;
                ipsec[sa.inboundSpi] = rec;
                logf(EIKE_LOG_INFO, tag(s) + "Quick Mode established: " + sa.proposal + ", spi " +
                                        ipsec::ToHex(BytesOf(spiBytes(sa.inboundSpi))) + "_i " + ipsec::ToHex(BytesOf(spiBytes(sa.outboundSpi))) +
                                        "_o" + (q.hasIds ? ", " + q.idci.toString() + " <-> " + q.idcr.toString() : std::string()));
                if (up) {
                    auto cb = up;
                    events.push_back([cb, sa]() { cb(sa); });
                }
            }

            /* Responder: QM3. */
            void handleQm3(Isakmp& s, Quick& q, const SIkeHeader& h, const SIkeDatagram& dg, const SReadOnlyByteSpan& data) {
                std::vector<uint8_t> iv = q.iv;
                std::vector<uint8_t> plain;
                if (openMessage(s, data, iv, plain) != SBOX_OK) {
                    return;
                }

                std::vector<uint8_t> prefix;
                prefix.push_back(0);
                ipsec::Append(prefix, BytesOf(msgIdBytes(q.msgId)));
                ipsec::Append(prefix, BytesOf(q.ni));
                ipsec::Append(prefix, BytesOf(q.nr));
                std::vector<SIkev1Payload> payloads;
                if (checkHashed(s, h.nextPayload, plain, prefix, payloads, true) != SBOX_OK) {
                    logf(EIKE_LOG_WARNING, tag(s) + "QM3 HASH(3) mismatch");
                    return;
                }

                q.iv = iv;
                follow(s, dg);
                completeQuick(s, q);
            }

            /* Initiator: QM2. */
            void handleQm2(Isakmp& s, Quick& q, const SIkeHeader& h, const SIkeDatagram& dg, const SReadOnlyByteSpan& data) {
                std::vector<uint8_t> iv = q.iv;
                std::vector<uint8_t> plain;
                if (openMessage(s, data, iv, plain) != SBOX_OK) {
                    return;
                }

                std::vector<uint8_t> prefix = msgIdBytes(q.msgId);
                ipsec::Append(prefix, BytesOf(q.ni));
                std::vector<SIkev1Payload> payloads;
                if (checkHashed(s, h.nextPayload, plain, prefix, payloads) != SBOX_OK) {
                    return;
                }

                q.iv = iv;
                q.lastReceived.assign(data.data, data.data + data.size);
                follow(s, dg);

                const SIkev1Payload* saP = FindIkev1Payload(payloads, EIKE1_PL_SA);
                const SIkev1Payload* nonceP = FindIkev1Payload(payloads, EIKE1_PL_NONCE);
                const SIkev1Payload* keP = FindIkev1Payload(payloads, EIKE1_PL_KE);
                SIkev1Sa reply;
                if (!saP || !nonceP || DecodeIkev1Sa(BytesOf(saP->body), reply) != SBOX_OK || reply.proposals.size() != 1 ||
                    reply.proposals[0].transforms.size() != 1 || reply.proposals[0].spi.size() != 4) {
                    fail(-EPROTO, "malformed QM2");
                    return;
                }

                const SIkev1Transform& t = reply.proposals[0].transforms[0];
                if (!Ikev1EspTransform(t.id, uint16_t(t.attr(EIKE1_IA_KEY_LENGTH)), uint16_t(t.attr(EIKE1_IA_AUTH)), q.encr, q.keyBits,
                                       q.integ)) {
                    fail(-ENOTSUP, "responder chose an unsupported ESP transform");
                    return;
                }

                q.outboundSpi = GetBe32(reply.proposals[0].spi.data());
                q.nr = nonceP->body;
                q.life = transformLife(t);
                if (q.life == 0) {
                    q.life = config.phase2LifeSeconds;
                }

                if (config.pfs) {
                    if (!keP || q.dh.agree(BytesOf(keP->body), q.gxy) != SBOX_OK) {
                        fail(-EPROTO, "QM2 without a valid KE");
                        return;
                    }
                }

                std::vector<uint8_t> h3prefix;
                h3prefix.push_back(0);
                ipsec::Append(h3prefix, BytesOf(msgIdBytes(q.msgId)));
                ipsec::Append(h3prefix, BytesOf(q.ni));
                ipsec::Append(h3prefix, BytesOf(q.nr));
                std::vector<uint8_t> hash = authHash(s, h3prefix, SReadOnlyByteSpan());
                std::vector<uint8_t> chain;
                chain.push_back(0);
                chain.push_back(0);
                PutBe16(chain, uint32_t(hash.size() + 4));
                chain.insert(chain.end(), hash.begin(), hash.end());
                std::vector<uint8_t> msg;
                if (sealMessage(s, EIKE1_X_QUICK, q.msgId, EIKE1_PL_HASH, chain, q.iv, msg) != SBOX_OK) {
                    return;
                }

                transmit(s, msg);
                completeQuick(s, q);
            }

            // -------------------------------------------------------------------------------
            // Informational

            /* Informational exchange. */
            void handleInfo(Isakmp& s, const SIkeHeader& h, const SIkeDatagram& dg, const SReadOnlyByteSpan& data) {
                std::vector<SIkev1Payload> payloads;
                if (!(h.flags & EIKE1_F_ENCRYPTED)) {
                    // --> Unauthenticated: only believed before Phase 1 completes (error notifies).
                    if (s.state == ST_ESTABLISHED) {
                        return;
                    }

                    if (ParseIkev1Payloads(h.nextPayload, data.slice(IKE_HEADER_SIZE), payloads) != SBOX_OK) {
                        return;
                    }

                    for (const SIkev1Payload& p : payloads) {
                        SIkev1Notify n;
                        if (p.type == EIKE1_PL_NOTIFY && DecodeIkev1Notify(BytesOf(p.body), n) == SBOX_OK) {
                            s.lastNotify = n.type;
                            lastNotify = n.type;
                            logf(EIKE_LOG_WARNING, tag(s) + "peer reports " + Ikev1NotifyName(n.type));
                            if (initiatorRole && n.type < 16384) {
                                fail(-ECONNREFUSED, "responder refused: " + Ikev1NotifyName(n.type));
                                dropIsakmp(s.initiator ? s.ckyI : s.ckyR);
                                return;
                            }
                        }
                    }

                    return;
                }

                if (s.state != ST_ESTABLISHED || h.messageId == 0) {
                    return;
                }

                if (s.infoIds.count(h.messageId)) {
                    return;
                }

                std::vector<uint8_t> iv;
                if (Ikev1Phase2Iv(s.suite.hash, s.cipher.blockSize(), BytesOf(s.phase1Iv), h.messageId, iv) != SBOX_OK) {
                    return;
                }

                std::vector<uint8_t> plain;
                if (openMessage(s, data, iv, plain) != SBOX_OK) {
                    return;
                }

                if (checkHashed(s, h.nextPayload, plain, msgIdBytes(h.messageId), payloads) != SBOX_OK) {
                    return;
                }

                s.infoIds.insert(h.messageId);
                if (s.infoIds.size() > 256) {
                    s.infoIds.erase(s.infoIds.begin());
                }

                follow(s, dg);
                uint64_t key = s.initiator ? s.ckyI : s.ckyR;
                for (size_t i = 1; i < payloads.size(); ++i) {
                    const SIkev1Payload& p = payloads[i];
                    if (p.type == EIKE1_PL_NOTIFY) {
                        SIkev1Notify n;
                        if (DecodeIkev1Notify(BytesOf(p.body), n) != SBOX_OK) {
                            continue;
                        }

                        s.lastNotify = n.type;
                        lastNotify = n.type;
                        if (n.type == EIKE1_N_R_U_THERE && n.data.size() == 4) {
                            sendInfo(s, { notifyPayload(EIKE1_N_R_U_THERE_ACK, EIKE1_PROTO_ISAKMP, cookieBytes(s.ckyI, s.ckyR), n.data) });
                        }
                        else if (n.type == EIKE1_N_R_U_THERE_ACK && n.data.size() == 4) {
                            uint32_t seq = GetBe32(n.data.data());
                            if (seq > s.dpdAcked && seq <= s.dpdSeq) {
                                s.dpdAcked = seq;
                            }

                            s.dpdOutstanding = 0;
                            s.dpdMisses = 0;
                        }
                        else if (n.type == EIKE1_N_INITIAL_CONTACT) {
                            dropPeer(addressOf(s.remote).toString(), key, "INITIAL-CONTACT");
                        }
                        else {
                            logf(EIKE_LOG_INFO, tag(s) + "peer notifies " + Ikev1NotifyName(n.type));
                            if (initiatorRole && n.type < 16384) {
                                fail(-ECONNREFUSED, "responder refused: " + Ikev1NotifyName(n.type));
                            }
                        }
                    }
                    else if (p.type == EIKE1_PL_DELETE) {
                        SIkev1Delete del;
                        if (DecodeIkev1Delete(BytesOf(p.body), del) != SBOX_OK) {
                            continue;
                        }

                        if (del.protocol == EIKE1_PROTO_ESP && del.spiSize == 4) {
                            std::string peer = addressOf(s.remote).toString();
                            for (const std::vector<uint8_t>& spi : del.spis) {
                                uint32_t out = GetBe32(spi.data());
                                uint32_t found = 0;
                                for (auto& [in, rec] : ipsec) {
                                    if (rec.peer == peer && rec.sa.outboundSpi == out) {
                                        found = in;
                                    }
                                }

                                if (found) {
                                    ipsecDown(found, "deleted by peer");
                                }
                            }
                        }
                        else if (del.protocol == EIKE1_PROTO_ISAKMP && del.spiSize == 16) {
                            for (const std::vector<uint8_t>& spi : del.spis) {
                                if (spi == cookieBytes(s.ckyI, s.ckyR)) {
                                    logf(EIKE_LOG_INFO, tag(s) + "ISAKMP SA deleted by peer");
                                    dropIsakmp(key);
                                    return;
                                }
                            }
                        }
                    }
                }
            }

            // -------------------------------------------------------------------------------
            // Timers

            /* Periodic work. */
            void tick(int64_t nowMs) {
                now = nowMs > now ? nowMs : now;
                std::vector<uint64_t> drop;
                std::vector<std::string> deadPeers;
                for (auto& [key, sp] : sas) {
                    Isakmp& s = *sp;
                    if (s.state != ST_ESTABLISHED) {
                        if (now - s.created > int64_t(config.halfOpenSeconds) * 1000) {
                            if (s.initiator) {
                                fail(-ETIMEDOUT, "Main Mode timed out");
                            }

                            drop.push_back(key);
                            continue;
                        }

                        // --> The initiator retransmits its last request.
                        if (s.initiator && !s.pending.empty() && now >= s.nextRetransmit) {
                            if (s.tries >= config.retransmitTries) {
                                fail(-ETIMEDOUT, "no answer from " + s.remote.toString());
                                drop.push_back(key);
                                continue;
                            }

                            ++s.tries;
                            s.nextRetransmit = now + (int64_t(config.retransmitMs) << std::min<uint32_t>(s.tries, 6));
                            transmit(s, s.pending);
                        }

                        continue;
                    }

                    if (s.expires && now >= s.expires) {
                        logf(EIKE_LOG_INFO, tag(s) + "ISAKMP SA lifetime expired");
                        sendIsakmpDelete(s);
                        drop.push_back(key);
                        continue;
                    }

                    // --> Quick Mode retransmissions (initiator QM1, responder QM2 until QM3).
                    for (auto it = s.quicks.begin(); it != s.quicks.end();) {
                        Quick& q = it->second;
                        if (q.done) {
                            it = now - q.created > 60000 ? s.quicks.erase(it) : std::next(it);
                            continue;
                        }

                        if (now - q.created > int64_t(config.halfOpenSeconds) * 1000) {
                            reservedSpis.erase(q.inboundSpi);
                            if (s.initiator) {
                                fail(-ETIMEDOUT, "Quick Mode timed out");
                            }

                            it = s.quicks.erase(it);
                            continue;
                        }

                        if (!q.lastSent.empty() && now >= q.nextRetransmit && q.tries < config.retransmitTries) {
                            ++q.tries;
                            q.nextRetransmit = now + (int64_t(config.retransmitMs) << std::min<uint32_t>(q.tries, 6));
                            transmit(s, q.lastSent);
                        }

                        ++it;
                    }

                    // --> Dead peer detection (RFC 3706), only towards peers that announced it.
                    if (s.peerDpd && config.dpdSeconds) {
                        if (s.dpdOutstanding) {
                            if (now >= s.dpdNext) {
                                if (++s.dpdMisses >= config.dpdTries) {
                                    logf(EIKE_LOG_WARNING, tag(s) + "dead peer (no R-U-THERE-ACK)");
                                    drop.push_back(key);
                                    deadPeers.push_back(addressOf(s.remote).toString());
                                    if (s.initiator) {
                                        fail(-ETIMEDOUT, "dead peer");
                                    }

                                    continue;
                                }

                                sendDpd(s);
                            }
                        }
                        else if (now - s.lastHeard >= int64_t(config.dpdSeconds) * 1000 && now >= s.dpdNext) {
                            sendDpd(s);
                        }
                    }
                }

                for (uint64_t k : drop) {
                    dropIsakmp(k);
                }

                for (const std::string& peer : deadPeers) {
                    std::vector<uint32_t> spis;
                    for (auto& [spi, rec] : ipsec) {
                        if (rec.peer == peer) {
                            spis.push_back(spi);
                        }
                    }

                    for (uint32_t spi : spis) {
                        ipsecDown(spi, "dead peer");
                    }
                }

                std::vector<uint32_t> expired;
                for (auto& [spi, rec] : ipsec) {
                    if (rec.expires && now >= rec.expires) {
                        expired.push_back(spi);
                    }
                }

                for (uint32_t spi : expired) {
                    auto it = ipsec.find(spi);
                    if (it != ipsec.end()) {
                        sendIpsecDelete(it->second);
                    }

                    ipsecDown(spi, "lifetime expired");
                }
            }

            /* Sends one R-U-THERE. */
            uint32_t sendDpd(Isakmp& s) {
                if (s.state != ST_ESTABLISHED) {
                    return 0;
                }

                if (s.dpdSeq == 0) {
                    IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&s.dpdSeq), sizeof(s.dpdSeq)));
                    s.dpdSeq &= 0x7fffffffu;
                }

                ++s.dpdSeq;
                if (s.dpdSeq == 0) {
                    s.dpdSeq = 1;
                }

                s.dpdOutstanding = s.dpdSeq;
                s.dpdNext = now + std::max<int64_t>(int64_t(config.retransmitMs) * 2, 1000);
                std::vector<uint8_t> seq;
                PutBe32(seq, s.dpdSeq);
                sendInfo(s, { notifyPayload(EIKE1_N_R_U_THERE, EIKE1_PROTO_ISAKMP, cookieBytes(s.ckyI, s.ckyR), seq) });
                return s.dpdSeq;
            }

            /* Deletes one IPsec SA. */
            bool deleteIpsec(uint32_t spi) {
                auto it = ipsec.find(spi);
                if (it == ipsec.end()) {
                    return false;
                }

                sendIpsecDelete(it->second);
                ipsecDown(spi, "deleted locally");
                return true;
            }

            /* Deletes everything. */
            void shutdownAll() {
                std::vector<uint32_t> spis;
                for (auto& [spi, rec] : ipsec) {
                    (void)rec;
                    spis.push_back(spi);
                }

                for (uint32_t spi : spis) {
                    deleteIpsec(spi);
                }

                std::vector<uint64_t> keys;
                for (auto& [k, s] : sas) {
                    sendIsakmpDelete(*s);
                    keys.push_back(k);
                }

                for (uint64_t k : keys) {
                    dropIsakmp(k);
                }
            }

            /* Session snapshot. */
            std::vector<SIkev1SessionInfo> snapshot() const {
                std::vector<SIkev1SessionInfo> out;
                for (const auto& [k, s] : sas) {
                    (void)k;
                    SIkev1SessionInfo i;
                    i.cookieI = s->ckyI;
                    i.cookieR = s->ckyR;
                    i.state = stateName(s->state);
                    i.identity = s->identity;
                    i.remote = s->remote.toString();
                    i.suite = s->suite.toString();
                    i.nat = s->natT;
                    std::string peer = addressOf(s->remote).toString();
                    for (const auto& [spi, rec] : ipsec) {
                        (void)spi;
                        i.ipsecSas += rec.sa.isakmpId == s->ckyR ? 1 : 0;
                    }

                    out.push_back(i);
                }

                return out;
            }
        };

    }

    // ----------------------------------------------------------------------------------------
    // Defaults

    /* Default Phase 1 suites. */
    std::vector<SIkev1Suite> DefaultIkev1Suites() {
        std::vector<SIkev1Suite> out;
        const uint16_t groups[] = { EIKE_DH_MODP2048, EIKE_DH_ECP256, EIKE_DH_ECP384, EIKE_DH_MODP1024 };
        const uint16_t hashes[] = { EIKE1_HASH_SHA256, EIKE1_HASH_SHA384, EIKE1_HASH_SHA512, EIKE1_HASH_SHA1 };
        struct Cipher { uint16_t encr; uint16_t bits; };
        const Cipher ciphers[] = { { EIKE1_ENCR_AES, 256 }, { EIKE1_ENCR_AES, 128 }, { EIKE1_ENCR_AES, 192 }, { EIKE1_ENCR_3DES, 192 } };
        for (uint16_t g : groups) {
            for (const Cipher& c : ciphers) {
                for (uint16_t h : hashes) {
                    SIkev1Suite s;
                    s.encr = c.encr;
                    s.keyBits = c.bits;
                    s.hash = h;
                    s.group = g;
                    out.push_back(s);
                }
            }
        }

        return out;
    }

    /* Default ESP suites. */
    std::vector<SIkev1EspSuite> DefaultIkev1EspSuites() {
        std::vector<SIkev1EspSuite> out;
        const uint16_t auths[] = { EIKE1_AA_HMAC_SHA256, EIKE1_AA_HMAC_SHA1, EIKE1_AA_HMAC_SHA384, EIKE1_AA_HMAC_SHA512 };
        out.push_back({ EIKE1_ESP_AES_GCM_16, 256, EIKE1_AA_NONE });
        out.push_back({ EIKE1_ESP_AES_GCM_16, 128, EIKE1_AA_NONE });
        for (uint16_t bits : { uint16_t(256), uint16_t(128), uint16_t(192) }) {
            for (uint16_t a : auths) {
                out.push_back({ EIKE1_ESP_AES, bits, a });
            }
        }

        for (uint16_t a : auths) {
            out.push_back({ EIKE1_ESP_3DES, 0, a });
        }

        return out;
    }

    // ----------------------------------------------------------------------------------------
    // Responder

    struct CIkev1Responder::SState : l2tp::Ikev1Engine {};

    CIkev1Responder::CIkev1Responder(SIkev1Config config) : _state(std::make_shared<SState>()) {
        _state->config = std::move(config);
        _state->initiatorRole = false;
    }

    CIkev1Responder::~CIkev1Responder() = default;

    /* Send function. */
    void CIkev1Responder::sender(FIkev1Send send) {
        _state->send = std::move(send);
    }

    /* Log sink. */
    void CIkev1Responder::logger(FIkev1Log log) {
        _state->log = std::move(log);
    }

    /* SA up handler. */
    void CIkev1Responder::onSaUp(std::function<void(const SIkev1IpsecSa&)> handler) {
        _state->up = std::move(handler);
    }

    /* SA down handler. */
    void CIkev1Responder::onSaDown(std::function<void(const SIkev1IpsecSa&)> handler) {
        _state->down = std::move(handler);
    }

    /* Datagram. */
    void CIkev1Responder::handle(const SIkeDatagram& datagram) {
        // --> Keep the engine alive while callbacks run (they may destroy the owner).
        std::shared_ptr<SState> keep = _state;
        keep->handle(datagram);
        keep->flush();
    }

    /* Timers. */
    void CIkev1Responder::tick(int64_t nowMs) {
        std::shared_ptr<SState> keep = _state;
        keep->tick(nowMs);
        keep->flush();
    }

    /* Deletes an IPsec SA. */
    bool CIkev1Responder::deleteIpsecSa(uint32_t inboundSpi) {
        std::shared_ptr<SState> keep = _state;
        keep->now = keep->clock();
        bool r = keep->deleteIpsec(inboundSpi);
        keep->flush();
        return r;
    }

    /* Deletes everything. */
    void CIkev1Responder::shutdown() {
        std::shared_ptr<SState> keep = _state;
        keep->now = keep->clock();
        keep->shutdownAll();
        keep->flush();
    }

    /* Snapshot. */
    std::vector<SIkev1SessionInfo> CIkev1Responder::sessions() const {
        return _state->snapshot();
    }

    // ----------------------------------------------------------------------------------------
    // Initiator

    struct CIkev1Initiator::SState : l2tp::Ikev1Engine {};

    CIkev1Initiator::CIkev1Initiator(SIkev1Config config, SEndpoint server, uint16_t serverNatPort) : _state(std::make_shared<SState>()) {
        _state->config = std::move(config);
        _state->initiatorRole = true;
        _state->server = server;
        _state->serverNatPort = serverNatPort;
    }

    CIkev1Initiator::~CIkev1Initiator() = default;

    /* Send function. */
    void CIkev1Initiator::sender(FIkev1Send send) {
        _state->send = std::move(send);
    }

    /* Log sink. */
    void CIkev1Initiator::logger(FIkev1Log log) {
        _state->log = std::move(log);
    }

    /* SA up handler. */
    void CIkev1Initiator::onSaUp(std::function<void(const SIkev1IpsecSa&)> handler) {
        _state->up = std::move(handler);
    }

    /* SA down handler. */
    void CIkev1Initiator::onSaDown(std::function<void(const SIkev1IpsecSa&)> handler) {
        _state->down = std::move(handler);
    }

    /* Failure handler. */
    void CIkev1Initiator::onFailed(std::function<void(int32_t, const std::string&)> handler) {
        _state->failed = std::move(handler);
    }

    /* Starts Main Mode. */
    void CIkev1Initiator::start(const net::SIpAddress& localAddress, uint16_t localPort, uint16_t localNatPort) {
        std::shared_ptr<SState> keep = _state;
        keep->startInitiator(localAddress, localPort, localNatPort);
        keep->flush();
    }

    /* Datagram. */
    void CIkev1Initiator::handle(const SIkeDatagram& datagram) {
        std::shared_ptr<SState> keep = _state;
        keep->handle(datagram);
        keep->flush();
    }

    /* Timers. */
    void CIkev1Initiator::tick(int64_t nowMs) {
        std::shared_ptr<SState> keep = _state;
        keep->tick(nowMs);
        keep->flush();
    }

    /* Deletes everything. */
    void CIkev1Initiator::shutdown() {
        std::shared_ptr<SState> keep = _state;
        keep->now = keep->clock();
        keep->shutdownAll();
        keep->flush();
    }

    /* Phase 1 state. */
    bool CIkev1Initiator::phase1Done() const noexcept {
        auto it = _state->sas.find(_state->mine);
        return it != _state->sas.end() && it->second->state == ST_ESTABLISHED;
    }

    /* Quick Mode state. */
    bool CIkev1Initiator::established() const noexcept {
        return !_state->ipsec.empty();
    }

    /* NAT-T state. */
    bool CIkev1Initiator::natT() const noexcept {
        auto it = _state->sas.find(_state->mine);
        return it != _state->sas.end() && it->second->natT;
    }

    /* Phase 1 suite. */
    SIkev1Suite CIkev1Initiator::suite() const {
        auto it = _state->sas.find(_state->mine);
        return it != _state->sas.end() ? it->second->suite : SIkev1Suite();
    }

    /* Last notify. */
    uint16_t CIkev1Initiator::lastNotify() const noexcept {
        return _state->lastNotify;
    }

    /* DPD request. */
    uint32_t CIkev1Initiator::sendDpd() {
        auto it = _state->sas.find(_state->mine);
        if (it == _state->sas.end()) {
            return 0;
        }

        _state->now = _state->clock();
        return _state->sendDpd(*it->second);
    }

    /* DPD acknowledgements. */
    uint32_t CIkev1Initiator::dpdAcked() const noexcept {
        auto it = _state->sas.find(_state->mine);
        return it != _state->sas.end() ? it->second->dpdAcked : 0;
    }

}
}
