#include <sbox/vpn/ipsec/initiator.hpp>
#include <sbox/vpn/ipsec/eap.hpp>
#include <sbox/vpn/ipsec/ikesocket.hpp>
#include <sbox/vpn/ipsec/proposal.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/net/netns.hpp>
#include "crypto.hpp"
#include "ikesa.hpp"
#include <cerrno>
#include <cstring>
#include <deque>
#include <netinet/in.h>
#include <sys/socket.h>

namespace sbox {
namespace vpn {

    using namespace ipsec;

    namespace {

        /* Builds a payload. */
        SIkePayload payload(uint8_t type, std::vector<uint8_t> body) {
            SIkePayload pl;
            pl.type = type;
            pl.body = std::move(body);
            return pl;
        }

        /* Collects notifies. */
        std::vector<SIkeNotify> notifiesOf(const std::vector<SIkePayload>& payloads) {
            std::vector<SIkeNotify> out;
            for (const SIkePayload& pl : payloads) {
                SIkeNotify n;
                if (pl.type == EIKE_PL_NOTIFY && DecodeIkeNotify(BytesOf(pl.body), n) == SBOX_OK) {
                    out.push_back(std::move(n));
                }
            }

            return out;
        }

        /* Returns the first error notify (type < 16384), or 0. */
        uint16_t errorOf(const std::vector<SIkePayload>& payloads) {
            for (const SIkeNotify& n : notifiesOf(payloads)) {
                if (n.type < 16384) {
                    return n.type;
                }
            }

            return 0;
        }

        /* Finds a notify. */
        const SIkeNotify* findNotify(const std::vector<SIkeNotify>& list, uint16_t type) {
            for (const SIkeNotify& n : list) {
                if (n.type == type) {
                    return &n;
                }
            }

            return nullptr;
        }

        /* Discovers the source address the kernel uses towards `remote`. */
        net::SIpAddress localAddressFor(const std::string& netnsPath, const SEndpoint& remote) {
            net::SIpAddress out;
            CFd fd;
            {
                net::CNetnsScope scope(netnsPath);
                if (scope.error() != SBOX_OK) {
                    return out;
                }

                fd.reset(::socket(remote.family(), SOCK_DGRAM | SOCK_CLOEXEC, 0));
            }

            if (!fd.isValid() || ::connect(fd.get(), reinterpret_cast<const sockaddr*>(&remote.storage), remote.length) < 0) {
                return out;
            }

            SEndpoint local;
            local.length = sizeof(local.storage);
            if (::getsockname(fd.get(), reinterpret_cast<sockaddr*>(&local.storage), &local.length) < 0) {
                return out;
            }

            return AddressOf(local);
        }

    }

    struct CIkeInitiator::SState {
        SIkeInitiatorConfig config;
        CIkeSocket socket;
        bool opened = false;
        IIpsecDataPathPtr dataPath;
        CEventLoop* loop = nullptr;
        std::shared_ptr<IkeSa> sa;
        std::deque<SIkeDatagram> mailbox;
        bool established = false;
        bool deletedByPeer = false;
        SEndpoint serverEp;
        SEndpoint serverNatEp;
        SEndpoint localEp;
        SEndpoint localNatEp;
        bool useNatT = false;
        std::vector<uint8_t> initRequest;
        std::vector<uint8_t> initResponse;
        std::vector<uint8_t> idiBody;
        std::vector<uint8_t> idrBody;
        std::vector<uint16_t> peerHashes;
        net::SIpAddress vip;
        std::vector<SIkeCfgAttribute> cpReply;
        SIpsecChildSa child;
        bool hasChild = false;
        std::string ikeText;
        std::string espText;
        uint16_t lastNotify = 0;
        uint32_t answered = 0;
        uint32_t fragments = 0;

        /* Opens the sockets (ephemeral ports). */
        int32_t open() {
            if (opened) {
                return SBOX_OK;
            }

            SIkeSocketOptions so;
            so.port = 0;
            so.natPort = 0;
            so.netnsPath = config.netnsPath;
            SEndpoint probe;
            if (SEndpoint::fromIp(config.server, config.serverPort, probe) != SBOX_OK) {
                return -EINVAL;
            }

            so.ipv4 = probe.family() == AF_INET;
            so.ipv6 = probe.family() == AF_INET6;
            int32_t r = socket.open(so);
            if (r != SBOX_OK) {
                return r;
            }

            loop = CEventLoop::current();
            std::weak_ptr<SState> weak = selfRef;
            socket.start([weak](SIkeDatagram& dg) {
                if (auto st = weak.lock()) {
                    st->onDatagram(dg);
                }
            });

            if (dataPath) {
                dataPath->attachSocket(&socket);
            }

            opened = true;
            return SBOX_OK;
        }

        std::weak_ptr<SState> selfRef;

        /* Handles a received datagram (responses are queued, requests answered). */
        void onDatagram(SIkeDatagram& dg) {
            SIkeHeader h;
            if (SIkeHeader::parse(BytesOf(dg.data), h) != SBOX_OK) {
                return;
            }

            dg.data.resize(h.length);
            if (h.isResponse()) {
                mailbox.push_back(std::move(dg));
                return;
            }

            std::shared_ptr<IkeSa> s = sa;
            if (!s || h.spiI != s->spiI || h.spiR != s->spiR) {
                return;
            }

            if (s->hasLast && h.messageId == s->lastMid) {
                for (const auto& d : s->lastResponse) {
                    socket.send(BytesOf(d), dg.local, dg.remote, dg.natT);
                }

                return;
            }

            if (h.messageId != s->expectMid) {
                return;
            }

            std::vector<SIkePayload> payloads;
            if (s->decrypt(h, BytesOf(dg.data), payloads) != SBOX_OK) {
                return;
            }

            std::vector<SIkePayload> resp;
            if (h.exchange == EIKE_X_INFORMATIONAL) {
                for (const SIkePayload& pl : payloads) {
                    SIkeDelete del;
                    if (pl.type != EIKE_PL_DELETE || DecodeIkeDelete(BytesOf(pl.body), del) != SBOX_OK) {
                        continue;
                    }

                    if (del.protocol == EIKE_PROTO_IKE) {
                        deletedByPeer = true;
                        established = false;
                    }
                    else if (del.protocol == EIKE_PROTO_ESP && hasChild) {
                        for (uint32_t spi : del.spis) {
                            if (spi == child.outboundSpi) {
                                SIkeDelete ours;
                                ours.protocol = EIKE_PROTO_ESP;
                                ours.spis.push_back(child.inboundSpi);
                                std::vector<uint8_t> body;
                                EncodeIkeDelete(ours, body);
                                resp.push_back(payload(EIKE_PL_DELETE, std::move(body)));
                            }
                        }
                    }
                }
            }
            else {
                resp.push_back(MakeIkeNotify(EIKE_N_NO_ADDITIONAL_SAS));
            }

            std::vector<std::vector<uint8_t>> datagrams;
            if (s->encrypt(h.exchange, true, h.messageId, resp, datagrams) != SBOX_OK) {
                return;
            }

            for (const auto& d : datagrams) {
                socket.send(BytesOf(d), dg.local, dg.remote, dg.natT);
            }

            s->lastResponse = std::move(datagrams);
            s->lastMid = h.messageId;
            s->hasLast = true;
            s->expectMid = h.messageId + 1;
            ++answered;

            if (deletedByPeer && hasChild && dataPath && loop) {
                hasChild = false;
                loop->spawn([](IIpsecDataPathPtr path, SIpsecChildSa c) -> TTask<void> {
                    co_await path->removeChild(c, true);
                }(dataPath, child));
            }
        }

        /* Sends a protected request and waits for its response. */
        TTask<int32_t> transact(std::shared_ptr<IkeSa> s, uint8_t exchange, std::vector<SIkePayload> payloads,
                                std::vector<SIkePayload>& out) {
            uint32_t mid = s->nextMid;
            std::vector<std::vector<uint8_t>> datagrams;
            int32_t r = s->encrypt(exchange, false, mid, payloads, datagrams);
            if (r != SBOX_OK) {
                co_return r;
            }

            auto sendAll = [&]() {
                for (int32_t copy = 0; copy < (config.duplicateRequests ? 2 : 1); ++copy) {
                    for (const auto& d : datagrams) {
                        socket.send(BytesOf(d), s->local, s->remote, s->natT);
                    }
                }
            };

            sendAll();
            int64_t now = CEventLoop::nowMs();
            int64_t deadline = now + config.timeoutMs;
            int64_t interval = config.retransmitMs;
            int64_t next = now + interval;

            while (true) {
                while (!mailbox.empty()) {
                    SIkeDatagram dg = std::move(mailbox.front());
                    mailbox.pop_front();
                    SIkeHeader h;
                    if (SIkeHeader::parse(BytesOf(dg.data), h) != SBOX_OK || h.spiI != s->spiI || h.spiR != s->spiR
                        || h.messageId != mid || h.exchange != exchange) {
                        continue;
                    }

                    if (h.nextPayload == EIKE_PL_SKF) {
                        ++fragments;
                    }

                    r = s->decrypt(h, BytesOf(dg.data), out);
                    if (r != SBOX_OK) {
                        continue;
                    }

                    s->nextMid = mid + 1;
                    co_return SBOX_OK;
                }

                now = CEventLoop::nowMs();
                if (now >= deadline) {
                    co_return -ETIMEDOUT;
                }

                if (now >= next) {
                    sendAll();
                    interval *= 2;
                    next = now + interval;
                }

                co_await loop->sleepFor(5);
            }
        }

        /* Our IKE_SA_INIT exchange (with COOKIE and INVALID_KE_PAYLOAD retries). */
        TTask<int32_t> saInit() {
            auto s = std::make_shared<IkeSa>();
            s->initiator = true;
            do {
                IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&s->spiI), sizeof(s->spiI)));
            } while (s->spiI == 0);

            s->ni.assign(32, 0);
            IkeRandom(BytesOf(s->ni));

            uint16_t group = config.ikeProposals[0].first(EIKE_TT_DH).id;
            std::vector<uint8_t> cookie;

            for (int32_t attempt = 0; attempt < 4; ++attempt) {
                CIkeDh dh;
                if (dh.generate(group) != SBOX_OK) {
                    co_return -ENOTSUP;
                }

                std::vector<SIkePayload> payloads;
                if (!cookie.empty()) {
                    payloads.push_back(MakeIkeNotify(EIKE_N_COOKIE, BytesOf(cookie)));
                }

                std::vector<SIkeProposal> offer = config.ikeProposals;
                for (size_t i = 0; i < offer.size(); ++i) {
                    offer[i].number = uint8_t(i + 1);
                    offer[i].spi.clear();
                }

                std::vector<uint8_t> body;
                EncodeIkeSa(offer, body);
                payloads.push_back(payload(EIKE_PL_SA, std::move(body)));
                body.clear();
                EncodeIkeKe(group, BytesOf(dh.publicValue()), body);
                payloads.push_back(payload(EIKE_PL_KE, std::move(body)));
                payloads.push_back(payload(EIKE_PL_NONCE, s->ni));

                std::vector<uint8_t> src = NatHash(s->spiI, 0, localEp);
                if (config.forceNatT) {
                    IkeRandom(BytesOf(src));
                }

                payloads.push_back(MakeIkeNotify(EIKE_N_NAT_DETECTION_SOURCE_IP, BytesOf(src)));
                std::vector<uint8_t> dst = NatHash(s->spiI, 0, serverEp);
                payloads.push_back(MakeIkeNotify(EIKE_N_NAT_DETECTION_DESTINATION_IP, BytesOf(dst)));
                if (config.fragmentation) {
                    payloads.push_back(MakeIkeNotify(EIKE_N_IKEV2_FRAGMENTATION_SUPPORTED));
                }

                if (config.rfc7427) {
                    std::vector<uint8_t> hashes = OurHashAlgorithms();
                    payloads.push_back(MakeIkeNotify(EIKE_N_SIGNATURE_HASH_ALGORITHMS, BytesOf(hashes)));
                }

                SIkeHeader h;
                h.spiI = s->spiI;
                h.exchange = EIKE_X_SA_INIT;
                h.flags = EIKE_F_INITIATOR;
                std::vector<uint8_t> request = EncodePlainMessage(h, payloads);

                // --> Wait for the IKE_SA_INIT response (plain), retransmitting.
                socket.send(BytesOf(request), localEp, serverEp, false);
                if (config.duplicateRequests) {
                    socket.send(BytesOf(request), localEp, serverEp, false);
                }

                int64_t now = CEventLoop::nowMs();
                int64_t deadline = now + config.timeoutMs;
                int64_t interval = config.retransmitMs;
                int64_t next = now + interval;
                SIkeDatagram reply;
                bool got = false;
                while (!got) {
                    while (!mailbox.empty() && !got) {
                        SIkeDatagram dg = std::move(mailbox.front());
                        mailbox.pop_front();
                        SIkeHeader rh;
                        if (SIkeHeader::parse(BytesOf(dg.data), rh) == SBOX_OK && rh.spiI == s->spiI
                            && rh.exchange == EIKE_X_SA_INIT && rh.messageId == 0) {
                            reply = std::move(dg);
                            got = true;
                        }
                    }

                    if (got) {
                        break;
                    }

                    now = CEventLoop::nowMs();
                    if (now >= deadline) {
                        co_return -ETIMEDOUT;
                    }

                    if (now >= next) {
                        socket.send(BytesOf(request), localEp, serverEp, false);
                        interval *= 2;
                        next = now + interval;
                    }

                    co_await loop->sleepFor(5);
                }

                SIkeHeader rh;
                SIkeHeader::parse(BytesOf(reply.data), rh);
                std::vector<SIkePayload> rp;
                if (ParseIkePayloads(rh.nextPayload, BytesOf(reply.data).slice(IKE_HEADER_SIZE), rp) != SBOX_OK) {
                    co_return -EBADMSG;
                }

                std::vector<SIkeNotify> notifies = notifiesOf(rp);
                if (const SIkeNotify* c = findNotify(notifies, EIKE_N_COOKIE)) {
                    cookie = c->data;
                    continue;
                }

                if (const SIkeNotify* ke = findNotify(notifies, EIKE_N_INVALID_KE_PAYLOAD)) {
                    if (ke->data.size() != 2) {
                        co_return -EBADMSG;
                    }

                    group = GetBe16(ke->data.data());
                    continue;
                }

                if (uint16_t err = errorOf(rp)) {
                    lastNotify = err;
                    co_return -EPROTO;
                }

                const SIkePayload* saPl = FindIkePayload(rp, EIKE_PL_SA);
                const SIkePayload* kePl = FindIkePayload(rp, EIKE_PL_KE);
                const SIkePayload* noncePl = FindIkePayload(rp, EIKE_PL_NONCE);
                std::vector<SIkeProposal> chosen;
                uint16_t keGroup = 0;
                std::vector<uint8_t> keData;
                if (!saPl || !kePl || !noncePl || DecodeIkeSa(BytesOf(saPl->body), chosen) != SBOX_OK || chosen.size() != 1
                    || DecodeIkeKe(BytesOf(kePl->body), keGroup, keData) != SBOX_OK || keGroup != group || rh.spiR == 0) {
                    co_return -EBADMSG;
                }

                s->spiR = rh.spiR;
                s->suite = Suite::from(chosen[0]);
                if (s->suite.dh != group) {
                    co_return -EBADMSG;
                }

                s->nr = noncePl->body;
                std::vector<uint8_t> gir;
                if (dh.agree(BytesOf(keData), gir) != SBOX_OK) {
                    co_return -EBADMSG;
                }

                std::vector<uint8_t> skeyseed;
                int32_t r = ComputeSkeyseed(s->suite.prf, BytesOf(s->ni), BytesOf(s->nr), BytesOf(gir), skeyseed);
                IkeWipe(gir);
                if (r == SBOX_OK) {
                    r = s->installKeys(BytesOf(skeyseed));
                }

                IkeWipe(skeyseed);
                if (r != SBOX_OK) {
                    co_return r;
                }

                bool sawNatD = false;
                bool srcMatch = false;
                bool dstMatch = false;
                std::vector<uint8_t> serverHash = NatHash(s->spiI, s->spiR, serverEp);
                std::vector<uint8_t> ourHash = NatHash(s->spiI, s->spiR, localEp);
                for (const SIkeNotify& n : notifies) {
                    if (n.type == EIKE_N_NAT_DETECTION_SOURCE_IP) {
                        sawNatD = true;
                        srcMatch = srcMatch || n.data == serverHash;
                    }
                    else if (n.type == EIKE_N_NAT_DETECTION_DESTINATION_IP) {
                        sawNatD = true;
                        dstMatch = dstMatch || n.data == ourHash;
                    }
                }

                s->natRemote = sawNatD && !srcMatch;
                s->natLocal = (sawNatD && !dstMatch) || config.forceNatT;
                useNatT = s->natRemote || s->natLocal;
                s->fragmentation = config.fragmentation && findNotify(notifies, EIKE_N_IKEV2_FRAGMENTATION_SUPPORTED);
                s->fragmentSize = IkeMessageLimit(config.fragmentSize);
                if (const SIkeNotify* hashes = findNotify(notifies, EIKE_N_SIGNATURE_HASH_ALGORITHMS)) {
                    peerHashes = ParseHashAlgorithms(BytesOf(hashes->data));
                }

                s->local = useNatT ? localNatEp : localEp;
                s->remote = useNatT ? serverNatEp : serverEp;
                s->natT = useNatT;
                s->nextMid = 1;
                s->expectMid = 0;
                initRequest = std::move(request);
                initResponse = reply.data;
                ikeText = FormatIkeProposal(chosen[0]);
                sa = s;
                co_return SBOX_OK;
            }

            co_return -EPROTO;
        }

        /* Verifies the responder's AUTH (PSK, MSK or signature). */
        int32_t verifyServer(const std::vector<SIkePayload>& rp, const std::vector<uint8_t>* sharedKey) {
            const SIkePayload* idrPl = FindIkePayload(rp, EIKE_PL_IDR);
            const SIkePayload* authPl = FindIkePayload(rp, EIKE_PL_AUTH);
            if (idrPl) {
                idrBody = idrPl->body;
            }

            uint8_t method = 0;
            std::vector<uint8_t> data;
            if (idrBody.empty() || !authPl || DecodeIkeAuth(BytesOf(authPl->body), method, data) != SBOX_OK) {
                return -EBADMSG;
            }

            if (!config.remoteId.empty()) {
                SIkeId want;
                SIkeId got;
                if (SIkeId::fromString(config.remoteId, want) != SBOX_OK || DecodeIkeId(BytesOf(idrBody), got) != SBOX_OK
                    || !(want == got)) {
                    return -EACCES;
                }
            }

            std::vector<uint8_t> octets = AuthOctets(BytesOf(initResponse), BytesOf(sa->ni), sa->suite.prf, BytesOf(sa->keys.pr),
                                                     BytesOf(idrBody));
            if (sharedKey) {
                std::vector<uint8_t> expected;
                if (method != EIKE_AUTH_PSK || SharedKeyAuth(sa->suite.prf, BytesOf(*sharedKey), BytesOf(octets), expected) != SBOX_OK
                    || !IkeSecureEquals(BytesOf(expected), BytesOf(data))) {
                    return -EACCES;
                }

                return SBOX_OK;
            }

            std::vector<CIkeCertificate> certs;
            for (const SIkePayload& pl : rp) {
                uint8_t encoding = 0;
                std::vector<uint8_t> der;
                CIkeCertificate c;
                if (pl.type == EIKE_PL_CERT && DecodeIkeCert(BytesOf(pl.body), encoding, der) == SBOX_OK
                    && CIkeCertificate::fromDer(BytesOf(der), c) == SBOX_OK) {
                    certs.push_back(std::move(c));
                }
            }

            if (certs.empty()) {
                return -EACCES;
            }

            std::vector<CIkeCertificate> intermediates(certs.begin() + 1, certs.end());
            if (VerifyIkeCertificate(certs[0], intermediates, config.caCertificates) != SBOX_OK) {
                return -EACCES;
            }

            SIkeId idr;
            if (DecodeIkeId(BytesOf(idrBody), idr) != SBOX_OK || !IdMatchesCertificate(idr, certs[0])) {
                return -EACCES;
            }

            return VerifyAuth(certs[0], method, BytesOf(data), BytesOf(octets)) == SBOX_OK ? SBOX_OK : -EACCES;
        }

        /* Proposals with our inbound SPI. */
        std::vector<SIkeProposal> espOffer(uint32_t spi, bool withPfs) const {
            std::vector<SIkeProposal> offer = config.espProposals;
            for (size_t i = 0; i < offer.size(); ++i) {
                offer[i].number = uint8_t(i + 1);
                offer[i].spi.clear();
                PutBe32(offer[i].spi, spi);

                // --> DH transforms only when we actually do PFS with this group.
                std::vector<SIkeTransform> kept;
                for (const SIkeTransform& t : offer[i].transforms) {
                    if (t.type != EIKE_TT_DH) {
                        kept.push_back(t);
                    }
                }

                if (withPfs) {
                    SIkeTransform t;
                    t.type = EIKE_TT_DH;
                    t.id = config.pfsGroup;
                    kept.push_back(t);
                }

                offer[i].transforms = std::move(kept);
            }

            return offer;
        }

        /* Allocates our inbound SPI. */
        TTask<int32_t> inboundSpi(uint32_t reqid, uint32_t& spi) {
            if (dataPath) {
                co_return co_await dataPath->allocateSpi(AddressOf(sa->local), AddressOf(sa->remote), reqid, spi);
            }

            do {
                IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&spi), sizeof(spi)));
            } while (spi < 0x100);

            co_return SBOX_OK;
        }

        /* Builds and installs a CHILD SA from a response (SA, TSi, TSr). */
        TTask<int32_t> adoptChild(const std::vector<SIkePayload>& rp, uint32_t inbound, uint32_t reqid, const SReadOnlyByteSpan& gir,
                                  const SReadOnlyByteSpan& ni, const SReadOnlyByteSpan& nr, SIpsecChildSa& out) {
            const SIkePayload* saPl = FindIkePayload(rp, EIKE_PL_SA);
            const SIkePayload* tsiPl = FindIkePayload(rp, EIKE_PL_TSI);
            const SIkePayload* tsrPl = FindIkePayload(rp, EIKE_PL_TSR);
            std::vector<SIkeProposal> chosen;
            std::vector<SIkeTrafficSelector> tsi;
            std::vector<SIkeTrafficSelector> tsr;
            if (!saPl || !tsiPl || !tsrPl || DecodeIkeSa(BytesOf(saPl->body), chosen) != SBOX_OK || chosen.size() != 1
                || chosen[0].spi.size() != 4 || DecodeIkeTs(BytesOf(tsiPl->body), tsi) != SBOX_OK
                || DecodeIkeTs(BytesOf(tsrPl->body), tsr) != SBOX_OK) {
                co_return -EBADMSG;
            }

            Suite suite = Suite::from(chosen[0]);
            ChildKeys keys;
            int32_t r = DeriveChildKeys(sa->suite.prf, BytesOf(sa->keys.d), gir, ni, nr, suite, keys);
            if (r != SBOX_OK) {
                co_return r;
            }

            SIpsecChildSa c;
            c.reqid = reqid;
            c.mode = EXMODE_TUNNEL;
            c.local = AddressOf(sa->local);
            c.remote = AddressOf(sa->remote);
            c.encap = sa->natLocal || sa->natRemote;
            c.localPort = sa->local.port();
            c.remotePort = sa->remote.port();
            c.inboundSpi = inbound;
            c.outboundSpi = GetBe32(chosen[0].spi.data());
            c.encr = suite.encr;
            c.keyBits = suite.keyBits;
            c.integ = suite.integ;
            c.esn = suite.esn == EIKE_ESN_YES;
            c.outEncKey = keys.encIr;
            c.outIntegKey = keys.integIr;
            c.inEncKey = keys.encRi;
            c.inIntegKey = keys.integRi;
            c.localTs = tsi;
            c.remoteTs = tsr;
            keys.wipe();

            if (dataPath) {
                r = co_await dataPath->installChild(c);
                if (r != SBOX_OK) {
                    co_return r;
                }
            }

            espText = FormatIkeProposal(chosen[0]);
            out = std::move(c);
            co_return SBOX_OK;
        }
    };

    CIkeInitiator::CIkeInitiator(SIkeInitiatorConfig config) : _state(std::make_shared<SState>()) {
        _state->config = std::move(config);
        _state->selfRef = _state;
        if (_state->config.ikeProposals.empty()) {
            _state->config.ikeProposals = DefaultIkeProposals();
        }

        if (_state->config.espProposals.empty()) {
            _state->config.espProposals = DefaultEspProposals();
        }
    }

    CIkeInitiator::~CIkeInitiator() {
        _state->socket.close();
    }

    /* Opens and attaches. */
    int32_t CIkeInitiator::attach(IIpsecDataPathPtr dataPath) {
        _state->dataPath = std::move(dataPath);
        return _state->open();
    }

    /* Connects. */
    TTask<int32_t> CIkeInitiator::connect(IIpsecDataPathPtr dataPath) {
        SState& st = *_state;
        if (dataPath) {
            st.dataPath = dataPath;
        }

        int32_t r = st.open();
        if (r != SBOX_OK) {
            co_return r;
        }

        const SIkeInitiatorConfig& c = st.config;
        if (SEndpoint::fromIp(c.server, c.serverPort, st.serverEp) != SBOX_OK
            || SEndpoint::fromIp(c.server, c.serverNatPort, st.serverNatEp) != SBOX_OK) {
            co_return -EINVAL;
        }

        net::SIpAddress local = localAddressFor(c.netnsPath, st.serverEp);
        if (!local.isValid()) {
            co_return -ENETUNREACH;
        }

        st.localEp = EndpointOf(local, st.socket.port());
        st.localNatEp = EndpointOf(local, st.socket.natPort());

        r = co_await st.saInit();
        if (r != SBOX_OK) {
            co_return r;
        }

        std::shared_ptr<IkeSa> s = st.sa;

        // -- IKE_AUTH request.
        SIkeId idi;
        if (!c.identity.empty()) {
            if (SIkeId::fromString(c.identity, idi) != SBOX_OK) {
                co_return -EINVAL;
            }
        }
        else if (c.auth == EIKE_IAUTH_CERT && c.certificate.isValid()) {
            idi.type = EIKE_ID_DER_ASN1_DN;
            idi.data = c.certificate.subjectDer();
        }
        else {
            idi.type = local.isV6() ? EIKE_ID_IPV6_ADDR : EIKE_ID_IPV4_ADDR;
            idi.data.assign(local.bytes, local.bytes + local.length());
        }

        st.idiBody = idi.body();

        uint32_t reqid = 0x5c000000u | (s->spiI & 0x00ffffffu);
        uint32_t inbound = 0;
        r = co_await st.inboundSpi(reqid, inbound);
        if (r != SBOX_OK) {
            co_return r;
        }

        std::vector<SIkePayload> req;
        req.push_back(payload(EIKE_PL_IDI, st.idiBody));
        if (c.auth == EIKE_IAUTH_CERT) {
            std::vector<uint8_t> body;
            EncodeIkeCert(EIKE_CERT_X509_SIGNATURE, BytesOf(c.certificate.der()), body);
            req.push_back(payload(EIKE_PL_CERT, std::move(body)));
            for (const auto& extra : c.certificate.chain()) {
                body.clear();
                EncodeIkeCert(EIKE_CERT_X509_SIGNATURE, BytesOf(extra), body);
                req.push_back(payload(EIKE_PL_CERT, std::move(body)));
            }
        }

        if (!c.caCertificates.empty()) {
            std::vector<uint8_t> hashes;
            for (const CIkeCertificate& ca : c.caCertificates) {
                Append(hashes, BytesOf(ca.keyHash()));
            }

            std::vector<uint8_t> body;
            EncodeIkeCert(EIKE_CERT_X509_SIGNATURE, BytesOf(hashes), body);
            req.push_back(payload(EIKE_PL_CERTREQ, std::move(body)));
        }

        if (!c.remoteId.empty()) {
            SIkeId idr;
            if (SIkeId::fromString(c.remoteId, idr) == SBOX_OK) {
                req.push_back(payload(EIKE_PL_IDR, idr.body()));
            }
        }

        std::vector<uint8_t> octets = AuthOctets(BytesOf(st.initRequest), BytesOf(s->nr), s->suite.prf, BytesOf(s->keys.pi),
                                                 BytesOf(st.idiBody));
        if (c.auth == EIKE_IAUTH_PSK) {
            std::vector<uint8_t> mac;
            SharedKeyAuth(s->suite.prf, BytesOf(c.psk), BytesOf(octets), mac);
            std::vector<uint8_t> body;
            EncodeIkeAuth(EIKE_AUTH_PSK, BytesOf(mac), body);
            req.push_back(payload(EIKE_PL_AUTH, std::move(body)));
        }
        else if (c.auth == EIKE_IAUTH_CERT) {
            uint8_t method = 0;
            std::vector<uint8_t> sig;
            r = SignAuth(c.certificate, BytesOf(octets), st.peerHashes, method, sig);
            if (r != SBOX_OK) {
                co_return r;
            }

            std::vector<uint8_t> body;
            EncodeIkeAuth(method, BytesOf(sig), body);
            req.push_back(payload(EIKE_PL_AUTH, std::move(body)));
        }

        if (c.requestAddress) {
            SIkeConfig cp;
            cp.cfgType = EIKE_CFG_REQUEST;
            for (uint16_t t : { uint16_t(EIKE_CA_INTERNAL_IP4_ADDRESS), uint16_t(EIKE_CA_INTERNAL_IP4_NETMASK),
                                uint16_t(EIKE_CA_INTERNAL_IP4_DNS), uint16_t(EIKE_CA_INTERNAL_IP4_SUBNET),
                                uint16_t(EIKE_CA_INTERNAL_DNS_DOMAIN) }) {
                SIkeCfgAttribute a;
                a.type = t;
                cp.attributes.push_back(a);
            }

            std::vector<uint8_t> body;
            EncodeIkeConfig(cp, body);
            req.push_back(payload(EIKE_PL_CP, std::move(body)));
        }

        std::vector<uint8_t> body;
        EncodeIkeSa(st.espOffer(inbound, false), body);
        req.push_back(payload(EIKE_PL_SA, std::move(body)));

        std::vector<SIkeTrafficSelector> tsi = c.tsi.empty() ? std::vector<SIkeTrafficSelector>{ SIkeTrafficSelector::any(false) } : c.tsi;
        std::vector<SIkeTrafficSelector> tsr = c.tsr.empty() ? std::vector<SIkeTrafficSelector>{ SIkeTrafficSelector::any(false) } : c.tsr;
        body.clear();
        EncodeIkeTs(tsi, body);
        req.push_back(payload(EIKE_PL_TSI, std::move(body)));
        body.clear();
        EncodeIkeTs(tsr, body);
        req.push_back(payload(EIKE_PL_TSR, std::move(body)));
        req.push_back(MakeIkeNotify(EIKE_N_INITIAL_CONTACT));
        if (c.mobike) {
            req.push_back(MakeIkeNotify(EIKE_N_MOBIKE_SUPPORTED));
        }

        std::vector<SIkePayload> rp;
        r = co_await st.transact(s, EIKE_X_AUTH, req, rp);
        if (r != SBOX_OK) {
            co_return r;
        }

        if (uint16_t err = errorOf(rp)) {
            st.lastNotify = err;
            co_return err == EIKE_N_AUTHENTICATION_FAILED ? -EACCES : -EPROTO;
        }

        if (c.auth == EIKE_IAUTH_EAP) {
            r = st.verifyServer(rp, nullptr);
            if (r != SBOX_OK) {
                co_return r;
            }

            CEapMsChapV2Peer peer(c.user, c.user, c.password);
            std::vector<uint8_t> msk;
            for (int32_t round = 0; round < 8; ++round) {
                const SIkePayload* eapPl = FindIkePayload(rp, EIKE_PL_EAP);
                if (!eapPl) {
                    co_return -EBADMSG;
                }

                std::vector<uint8_t> answer;
                EEapStatus status = peer.process(BytesOf(eapPl->body), answer);
                if (status == EEAPS_SUCCESS) {
                    msk = peer.msk();
                    break;
                }

                if (answer.empty()) {
                    co_return -EACCES;
                }

                std::vector<SIkePayload> next;
                next.push_back(payload(EIKE_PL_EAP, std::move(answer)));
                rp.clear();
                r = co_await st.transact(s, EIKE_X_AUTH, next, rp);
                if (r != SBOX_OK) {
                    co_return r;
                }

                if (uint16_t err = errorOf(rp)) {
                    st.lastNotify = err;
                    co_return -EACCES;
                }

                if (status == EEAPS_FAILURE) {
                    co_return -EACCES;
                }
            }

            if (msk.empty()) {
                co_return -EACCES;
            }

            std::vector<uint8_t> mac;
            SharedKeyAuth(s->suite.prf, BytesOf(msk), BytesOf(octets), mac);
            std::vector<uint8_t> authBody;
            EncodeIkeAuth(EIKE_AUTH_PSK, BytesOf(mac), authBody);
            std::vector<SIkePayload> last;
            last.push_back(payload(EIKE_PL_AUTH, std::move(authBody)));
            rp.clear();
            r = co_await st.transact(s, EIKE_X_AUTH, last, rp);
            if (r != SBOX_OK) {
                IkeWipe(msk);
                co_return r;
            }

            if (uint16_t err = errorOf(rp); err == EIKE_N_AUTHENTICATION_FAILED) {
                st.lastNotify = err;
                IkeWipe(msk);
                co_return -EACCES;
            }

            r = st.verifyServer(rp, &msk);
            IkeWipe(msk);
            if (r != SBOX_OK) {
                co_return r;
            }
        }
        else {
            std::vector<uint8_t> secret(c.psk.begin(), c.psk.end());
            r = st.verifyServer(rp, c.auth == EIKE_IAUTH_PSK ? &secret : nullptr);
            IkeWipe(secret);
            if (r != SBOX_OK) {
                co_return r;
            }
        }

        st.established = true;

        if (const SIkePayload* cpPl = FindIkePayload(rp, EIKE_PL_CP)) {
            SIkeConfig reply;
            if (DecodeIkeConfig(BytesOf(cpPl->body), reply) == SBOX_OK) {
                st.cpReply = reply.attributes;
                for (const SIkeCfgAttribute& a : reply.attributes) {
                    if (a.type == EIKE_CA_INTERNAL_IP4_ADDRESS && a.value.size() == 4) {
                        net::SIpAddress::fromBytes(a.value.data(), 4, st.vip);
                    }
                }
            }
        }

        if (uint16_t err = errorOf(rp)) {
            // --> Authenticated, but the CHILD SA was refused (TS_UNACCEPTABLE, ...).
            st.lastNotify = err;
            co_return -EPROTO;
        }

        std::vector<uint8_t> none;
        r = co_await st.adoptChild(rp, inbound, reqid, BytesOf(none), BytesOf(s->ni), BytesOf(s->nr), st.child);
        if (r != SBOX_OK) {
            co_return r;
        }

        st.hasChild = true;
        co_return SBOX_OK;
    }

    /* Rekeys the CHILD SA. */
    TTask<int32_t> CIkeInitiator::rekeyChild() {
        SState& st = *_state;
        if (!st.established || !st.hasChild) {
            co_return -ENOTCONN;
        }

        std::shared_ptr<IkeSa> s = st.sa;
        SIpsecChildSa old = st.child;
        uint32_t inbound = 0;
        int32_t r = co_await st.inboundSpi(old.reqid, inbound);
        if (r != SBOX_OK) {
            co_return r;
        }

        bool pfs = st.config.pfsGroup != 0;
        CIkeDh dh;
        if (pfs && dh.generate(st.config.pfsGroup) != SBOX_OK) {
            co_return -ENOTSUP;
        }

        std::vector<uint8_t> ni(32);
        IkeRandom(BytesOf(ni));

        std::vector<SIkePayload> req;
        SIkeNotify rekey;
        rekey.protocol = EIKE_PROTO_ESP;
        PutBe32(rekey.spi, old.inboundSpi);
        rekey.type = EIKE_N_REKEY_SA;
        SIkePayload n;
        n.type = EIKE_PL_NOTIFY;
        EncodeIkeNotify(rekey, n.body);
        req.push_back(std::move(n));

        std::vector<uint8_t> body;
        EncodeIkeSa(st.espOffer(inbound, pfs), body);
        req.push_back(payload(EIKE_PL_SA, std::move(body)));
        req.push_back(payload(EIKE_PL_NONCE, ni));
        if (pfs) {
            body.clear();
            EncodeIkeKe(st.config.pfsGroup, BytesOf(dh.publicValue()), body);
            req.push_back(payload(EIKE_PL_KE, std::move(body)));
        }

        body.clear();
        EncodeIkeTs(old.localTs, body);
        req.push_back(payload(EIKE_PL_TSI, std::move(body)));
        body.clear();
        EncodeIkeTs(old.remoteTs, body);
        req.push_back(payload(EIKE_PL_TSR, std::move(body)));

        std::vector<SIkePayload> rp;
        r = co_await st.transact(s, EIKE_X_CREATE_CHILD_SA, req, rp);
        if (r != SBOX_OK) {
            co_return r;
        }

        if (uint16_t err = errorOf(rp)) {
            st.lastNotify = err;
            co_return -EPROTO;
        }

        const SIkePayload* noncePl = FindIkePayload(rp, EIKE_PL_NONCE);
        if (!noncePl) {
            co_return -EBADMSG;
        }

        std::vector<uint8_t> gir;
        if (pfs) {
            const SIkePayload* kePl = FindIkePayload(rp, EIKE_PL_KE);
            uint16_t group = 0;
            std::vector<uint8_t> data;
            if (!kePl || DecodeIkeKe(BytesOf(kePl->body), group, data) != SBOX_OK || group != st.config.pfsGroup
                || dh.agree(BytesOf(data), gir) != SBOX_OK) {
                co_return -EBADMSG;
            }
        }

        SIpsecChildSa fresh;
        r = co_await st.adoptChild(rp, inbound, old.reqid, BytesOf(gir), BytesOf(ni), BytesOf(noncePl->body), fresh);
        IkeWipe(gir);
        if (r != SBOX_OK) {
            co_return r;
        }

        st.child = fresh;

        // --> Delete the old CHILD SA (RFC 7296 2.8).
        SIkeDelete del;
        del.protocol = EIKE_PROTO_ESP;
        del.spis.push_back(old.inboundSpi);
        body.clear();
        EncodeIkeDelete(del, body);
        std::vector<SIkePayload> delReq;
        delReq.push_back(payload(EIKE_PL_DELETE, std::move(body)));
        rp.clear();
        r = co_await st.transact(s, EIKE_X_INFORMATIONAL, delReq, rp);
        if (st.dataPath) {
            co_await st.dataPath->removeChild(old, false);
        }

        co_return r;
    }

    /* Rekeys the IKE SA. */
    TTask<int32_t> CIkeInitiator::rekeyIke() {
        SState& st = *_state;
        if (!st.established) {
            co_return -ENOTCONN;
        }

        std::shared_ptr<IkeSa> s = st.sa;
        auto n = std::make_shared<IkeSa>();
        n->initiator = true;
        do {
            IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&n->spiI), sizeof(n->spiI)));
        } while (n->spiI == 0);

        n->ni.assign(32, 0);
        IkeRandom(BytesOf(n->ni));

        uint16_t group = s->suite.dh;
        CIkeDh dh;
        if (dh.generate(group) != SBOX_OK) {
            co_return -ENOTSUP;
        }

        std::vector<SIkeProposal> offer = st.config.ikeProposals;
        for (size_t i = 0; i < offer.size(); ++i) {
            offer[i].number = uint8_t(i + 1);
            offer[i].spi.clear();
            PutBe64(offer[i].spi, n->spiI);
        }

        std::vector<SIkePayload> req;
        std::vector<uint8_t> body;
        EncodeIkeSa(offer, body);
        req.push_back(payload(EIKE_PL_SA, std::move(body)));
        req.push_back(payload(EIKE_PL_NONCE, n->ni));
        body.clear();
        EncodeIkeKe(group, BytesOf(dh.publicValue()), body);
        req.push_back(payload(EIKE_PL_KE, std::move(body)));

        std::vector<SIkePayload> rp;
        int32_t r = co_await st.transact(s, EIKE_X_CREATE_CHILD_SA, req, rp);
        if (r != SBOX_OK) {
            co_return r;
        }

        if (uint16_t err = errorOf(rp)) {
            st.lastNotify = err;
            co_return -EPROTO;
        }

        const SIkePayload* saPl = FindIkePayload(rp, EIKE_PL_SA);
        const SIkePayload* noncePl = FindIkePayload(rp, EIKE_PL_NONCE);
        const SIkePayload* kePl = FindIkePayload(rp, EIKE_PL_KE);
        std::vector<SIkeProposal> chosen;
        uint16_t keGroup = 0;
        std::vector<uint8_t> keData;
        if (!saPl || !noncePl || !kePl || DecodeIkeSa(BytesOf(saPl->body), chosen) != SBOX_OK || chosen.size() != 1
            || chosen[0].spi.size() != 8 || DecodeIkeKe(BytesOf(kePl->body), keGroup, keData) != SBOX_OK || keGroup != group) {
            co_return -EBADMSG;
        }

        n->spiR = GetBe64(chosen[0].spi.data());
        n->suite = Suite::from(chosen[0]);
        n->nr = noncePl->body;

        std::vector<uint8_t> gir;
        std::vector<uint8_t> skeyseed;
        if (dh.agree(BytesOf(keData), gir) != SBOX_OK) {
            co_return -EBADMSG;
        }

        r = ComputeRekeySkeyseed(s->suite.prf, BytesOf(s->keys.d), BytesOf(gir), BytesOf(n->ni), BytesOf(n->nr), skeyseed);
        IkeWipe(gir);
        if (r == SBOX_OK) {
            r = n->installKeys(BytesOf(skeyseed));
        }

        IkeWipe(skeyseed);
        if (r != SBOX_OK) {
            co_return r;
        }

        n->local = s->local;
        n->remote = s->remote;
        n->natT = s->natT;
        n->natLocal = s->natLocal;
        n->natRemote = s->natRemote;
        n->fragmentation = s->fragmentation;
        n->fragmentSize = s->fragmentSize;

        SIkeDelete del;
        del.protocol = EIKE_PROTO_IKE;
        body.clear();
        EncodeIkeDelete(del, body);
        std::vector<SIkePayload> delReq;
        delReq.push_back(payload(EIKE_PL_DELETE, std::move(body)));
        rp.clear();
        r = co_await st.transact(s, EIKE_X_INFORMATIONAL, delReq, rp);

        st.sa = n;
        st.ikeText = FormatIkeProposal(chosen[0]);
        co_return r;
    }

    /* Liveness check. */
    TTask<int32_t> CIkeInitiator::dpd() {
        SState& st = *_state;
        if (!st.established) {
            co_return -ENOTCONN;
        }

        std::vector<SIkePayload> rp;
        co_return co_await st.transact(st.sa, EIKE_X_INFORMATIONAL, {}, rp);
    }

    /* Deletes the CHILD SA. */
    TTask<int32_t> CIkeInitiator::deleteChild() {
        SState& st = *_state;
        if (!st.established || !st.hasChild) {
            co_return -ENOTCONN;
        }

        SIkeDelete del;
        del.protocol = EIKE_PROTO_ESP;
        del.spis.push_back(st.child.inboundSpi);
        std::vector<uint8_t> body;
        EncodeIkeDelete(del, body);
        std::vector<SIkePayload> req;
        req.push_back(payload(EIKE_PL_DELETE, std::move(body)));
        std::vector<SIkePayload> rp;
        int32_t r = co_await st.transact(st.sa, EIKE_X_INFORMATIONAL, req, rp);
        if (r != SBOX_OK) {
            co_return r;
        }

        bool confirmed = false;
        for (const SIkePayload& pl : rp) {
            SIkeDelete d;
            if (pl.type == EIKE_PL_DELETE && DecodeIkeDelete(BytesOf(pl.body), d) == SBOX_OK) {
                for (uint32_t spi : d.spis) {
                    confirmed = confirmed || spi == st.child.outboundSpi;
                }
            }
        }

        if (st.dataPath) {
            co_await st.dataPath->removeChild(st.child, true);
        }

        st.hasChild = false;
        co_return confirmed ? SBOX_OK : -EPROTO;
    }

    /* Deletes the IKE SA. */
    TTask<int32_t> CIkeInitiator::close() {
        SState& st = *_state;
        int32_t r = SBOX_OK;
        if (st.established && st.sa) {
            SIkeDelete del;
            del.protocol = EIKE_PROTO_IKE;
            std::vector<uint8_t> body;
            EncodeIkeDelete(del, body);
            std::vector<SIkePayload> req;
            req.push_back(payload(EIKE_PL_DELETE, std::move(body)));
            std::vector<SIkePayload> rp;
            r = co_await st.transact(st.sa, EIKE_X_INFORMATIONAL, req, rp);
        }

        if (st.hasChild && st.dataPath) {
            co_await st.dataPath->removeChild(st.child, true);
        }

        st.hasChild = false;
        st.established = false;
        co_return r;
    }

    /* Accessors. */
    bool CIkeInitiator::established() const noexcept {
        return _state->established;
    }

    net::SIpAddress CIkeInitiator::virtualIp() const {
        return _state->vip;
    }

    std::vector<SIkeCfgAttribute> CIkeInitiator::configReply() const {
        return _state->cpReply;
    }

    SIpsecChildSa CIkeInitiator::child() const {
        return _state->child;
    }

    std::pair<uint64_t, uint64_t> CIkeInitiator::spis() const {
        return _state->sa ? std::make_pair(_state->sa->spiI, _state->sa->spiR) : std::make_pair(uint64_t(0), uint64_t(0));
    }

    std::string CIkeInitiator::ikeProposal() const {
        return _state->ikeText;
    }

    std::string CIkeInitiator::espProposal() const {
        return _state->espText;
    }

    uint16_t CIkeInitiator::lastNotify() const noexcept {
        return _state->lastNotify;
    }

    bool CIkeInitiator::natT() const noexcept {
        return _state->useNatT;
    }

    uint32_t CIkeInitiator::answeredRequests() const noexcept {
        return _state->answered;
    }

    bool CIkeInitiator::deletedByPeer() const noexcept {
        return _state->deletedByPeer;
    }

    uint32_t CIkeInitiator::fragmentsReceived() const noexcept {
        return _state->fragments;
    }

}
}
