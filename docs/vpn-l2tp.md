# vpn 모듈: L2TP/IPsec 서버

vpn 모듈(`sbox::vpn`)의 L2TP/IPsec 작업 흐름입니다. 목표는 Windows 10/11, macOS/iOS(L2TP over IPSec),
Android(L2TP/IPSec PSK)의 **내장 클라이언트**가 드라이버나 앱 설치 없이 IPsec 사전 공유 키(PSK)와 PPP
사용자 인증(기본 MS-CHAPv2)으로 접속해 컨테이너가 붙은 가상 네트워크에 들어오게 하는 것입니다. IKEv2 응답자
([vpn-ipsec.md](vpn-ipsec.md))와 같은 UDP 500/4500을 공유할 수 있습니다.

헤더는 `modules/vpn/include/sbox/vpn/l2tp/`, 소스는 `modules/vpn/src/l2tp/`, 테스트는
`modules/vpn/tests/l2tp/`, 명령줄 도구는 `cli/sbox-l2tp`입니다. pppd, xl2tpd, strongSwan, 커널 PPP/L2TP
드라이버 없이 전부 사용자 공간에서 동작하며, 암호 연산은 모두 libcertpp를 씁니다.

## 구성

| 헤더 | 내용 |
|---|---|
| `ikev1.hpp` | ISAKMP 헤더 외 페이로드 번호, 페이로드 체인(`ParseIkev1Payloads`), SA/제안/변환/속성 코덱, ID, Notify, Delete, NAT-OA, 벤더 ID(`Ikev1VendorId`, `Ikev1ClassifyVendorId`) |
| `ikev1crypto.hpp` | Phase 1 해시와 HMAC PRF, `Ikev1SkeyidPsk`, `Ikev1DeriveKeys`(SKEYID_d/a/e, 키 확장, 초기 IV), `Ikev1Phase1Hash`(HASH_I/R), `Ikev1Phase2Iv`, `Ikev1QuickKeymat`, `Ikev1NatHash`, `CIkev1Cipher`(IV 체인 CBC), `Ikev1EspTransform` |
| `ikev1peer.hpp` | `CIkev1Responder`, `CIkev1Initiator`, `SIkev1Config`, `SIkev1IpsecSa`, 기본 제안(`DefaultIkev1Suites`, `DefaultIkev1EspSuites`), 제안 문자열 파서 |
| `transport.hpp` | `IL2tpTransport`: L2TP 데이터그램이 오가는 경로(커널 XFRM transport 모드, 사용자 공간 ESP transport 모드, 평문 UDP), `CreateL2tpTransport`, `L2tpUdpChecksum` |
| `l2tp.hpp` | L2TPv2 헤더/AVP(숨김 AVP 포함) 코덱, `CL2tpTunnel`(LNS/LAC 제어 연결과 세션) |
| `ppp.hpp` | `CPppSession`: LCP, MS-CHAPv2/CHAP-MD5/PAP(인증자와 피어), IPCP(RFC 1877 DNS/NBNS), 에코, 종료 |
| `server.hpp` | `CL2tpServer`, `SL2tpServerConfig`, `ParseL2tpServerConfig` |
| `client.hpp` | `CL2tpClient`: IKEv1 개시자 + 사용자 공간 ESP + LAC + PPP 피어 + TUN (테스트, 호스트 접속용) |
| `profiles.hpp` | Windows PowerShell(`Add-VpnConnection -TunnelType L2tp -L2tpPsk`), Apple `.mobileconfig`(VPNType L2TP), Android 안내 |

IKEv1·L2TP·PPP는 모두 **동기 상태 기계**입니다. 소유자가 받은 패킷을 `handle()`/`input()`으로 넣고
주기적으로 `tick(nowMs)`를 부르며, 송신 함수와 이벤트 콜백을 연결합니다. 소켓·TUN·타이머를 가진
`CL2tpServer`/`CL2tpClient`가 이벤트 루프 코루틴(`TTask`)으로 이를 묶습니다. 콜백 안에서 소유자가 객체를
지워도 안전하도록 각 객체의 상태는 `shared_ptr`로 두고, IKEv1 엔진은 콜백을 큐에 모았다가 상태가 일관된
뒤에 실행합니다.

## IKEv1 (RFC 2409/2408, 2407, 3947/3948, 3706)

### Main Mode (PSK)

- MM1: 상대 제안 중 우리 선호 순서(`ike.suites`, 기본 `DefaultIkev1Suites`)로 하나를 고릅니다. 인증 방식은
  PSK(1)만, 알 수 없는 속성이 있는 변환은 거절합니다. 공통 제안이 없으면 평문 `NO-PROPOSAL-CHOSEN`.
  Aggressive Mode는 `INVALID-EXCHANGE-TYPE`.
- 벤더 ID: 상대가 보낸 NAT-T 방언 중 가장 새 것(RFC 3947 > draft-03 > draft-02/02\n)을 골라 그 VID와 DPD
  VID로 답합니다. MS NT5 ISAKMPOAKLEY, FRAGMENTATION 등 나머지는 인식만 합니다.
- MM3/MM4: KE(그룹 2/14/19/20), Nonce(8~256바이트), NAT-D(RFC 3947은 페이로드 20, draft는 130). 첫 NAT-D는
  받는 쪽, 나머지는 보내는 쪽 주소의 해시입니다. `forceEncap`이면 우리 쪽 해시를 일부러 틀리게 보내 클라이언트가
  4500으로 옮기게 합니다.
- MM5/MM6(암호화): Main Mode PSK에서는 ID가 PSK로 만든 키로 암호화되어 오므로, **후보 PSK를 차례로 대입해 복호화**
  하고 HASH_I가 맞는 것을 고릅니다. 순서는 상대 주소와 같은 `id`, 이름(FQDN/사용자) `id`, `id`가 빈 기본 키입니다.
  이름이 붙은 PSK는 그 ID에만 쓰입니다. 성공하면 우리 ID(IPv4 주소, 상대 ID의 프로토콜/포트를 따름)와 HASH_R로
  답합니다. MM5의 `INITIAL-CONTACT`는 같은 주소의 이전 ISAKMP/IPsec SA를 지웁니다.
- 키: `SKEYID = prf(PSK, Ni_b | Nr_b)`, `SKEYID_d/a/e`, 암호 키는 SKEYID_e가 짧으면 부록 B 방식(K1 = prf(e, 0),
  Kn = prf(e, Kn-1))으로 늘립니다. PRF는 협상한 해시의 HMAC(MD5/SHA-1/SHA2-256/384/512), Phase 1 암호는
  3DES-CBC, AES-128/192/256-CBC. IV는 `hash(g^xi | g^xr)`부터 CBC 블록으로 이어지고, Phase 2와 정보 교환은
  `hash(Phase 1 마지막 블록 | M-ID)`로 시작합니다.

### Quick Mode (ESP transport, UDP 1701)

- `HASH(1) = prf(SKEYID_a, M-ID | 나머지)`, `HASH(2) = prf(SKEYID_a, M-ID | Ni_b | 나머지)`,
  `HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)`.
- ESP 변환: AES-CBC(128/192/256)·3DES + HMAC-SHA1/SHA2-256/384/512, AES-GCM-16(IKEv1 ESP id 20). HMAC-MD5,
  DES, AH는 지원하지 않습니다(내장 클라이언트는 모두 SHA-1 이상을 함께 제안).
- 캡슐화 모드는 transport(2), UDP-encapsulated transport(RFC 3947의 4, draft의 61444)만 받습니다(tunnel 모드 거부).
  NAT-T로 옮겨 왔으면 모드 값과 관계없이 UDP 캡슐화합니다.
- `requireL2tp`(기본): 클라이언트 ID(IDcr)가 우리 주소의 UDP(17 또는 0)/1701(또는 0)이어야 하고, NAT이 없을 때는
  IDci가 상대 주소여야 합니다. 맞지 않으면 `INVALID-ID-INFORMATION`. ID가 없으면 두 호스트 사이 전체입니다.
- NAT-OA: 상대의 원래(사설) 주소를 기록해(없으면 IDci 주소) 사용자 공간 경로가 UDP 체크섬을 상대가 볼 주소로
  계산합니다. 응답에도 NAT-OAi(관측한 상대 주소), NAT-OAr(우리 주소)를 넣습니다(draft는 하나).
- PFS(변환의 GROUP 속성 + KE) 지원. 제안 수명이 `phase2Lifetime`보다 길면 줄이고 `RESPONDER-LIFETIME`을 알립니다.
- `KEYMAT = prf(SKEYID_d, [g^xy |] protocol | SPI | Ni_b | Nr_b)`를 K1|K2|...로 늘리고, 받는 쪽 SPI로 방향별 키를
  만듭니다(암호 키 다음 무결성 키).
- QM3를 받으면 SA 쌍(`SIkev1IpsecSa`)을 `onSaUp`으로 알립니다. QM2는 QM3가 올 때까지 재전송합니다.

### 정보 교환, 재전송, 수명

- `HASH(1) = prf(SKEYID_a, M-ID | N/D)`. DELETE(ESP는 상대 SPI = 우리 송신 SPI, ISAKMP는 쿠키 16바이트),
  DPD `R-U-THERE` → `R-U-THERE-ACK`(같은 순번), `INITIAL-CONTACT`. 암호화되지 않은 정보 교환은 Phase 1이 끝나기
  전의 오류 통지로만 믿습니다.
- 응답자는 같은 요청(바이트 단위 동일)이 다시 오면 캐시한 응답을 다시 보냅니다(Main Mode는 SA별, Quick Mode는
  M-ID별). 개시자는 지수 백오프로 재전송합니다(`retransmitMs`, `retransmitTries`). 끝나지 않은 교환은
  `halfOpenSeconds` 뒤에 지웁니다.
- DPD: 상대가 DPD VID를 보냈고 `dpdSeconds`가 0이 아니면, 조용한 상대에게 R-U-THERE를 보내고 `dpdTries`번 응답이
  없으면 그 상대의 SA를 모두 내립니다.
- 수명: ISAKMP SA는 협상한 수명(최대 `phase1Lifetime`) 뒤 DELETE, IPsec SA는 수명 + 30초 뒤 DELETE하고
  `onSaDown`. 응답자는 재키잉을 먼저 시작하지 않습니다(클라이언트가 새 Main/Quick Mode로 재키잉).

### IKEv2 응답자와 포트 공유

`CL2tpServer::start(&ikev2Server)`는 `CIkeServer::ikev1Handler()`로 IKEv1 메시지를 받고 `socket()`으로 답합니다.
NAT-T 소켓의 ESP-in-UDP는 SPI별 처리기(`CIkeSocket::espSpiHandler`, 아래 "ipsec/ 변경")로 나눠 받으므로 IKEv2의
사용자 공간 데이터 경로와 함께 쓸 수 있습니다. 데이터 경로 종류는 IKEv2 서버를 따릅니다(커널 경로면 4500 소켓이
이미 `UDP_ENCAP` 상태라 사용자 공간으로 ESP가 오지 않음). 단독으로 돌릴 때는 자체 `CIkeSocket`을 열고
IKEv2 메시지는 버립니다.

## 데이터 경로 (`IL2tpTransport`)

| 종류 | 설명 |
|---|---|
| `kernel` | XFRM transport 모드 SA(NAT-T면 `UDP_ENCAP_ESPINUDP`)와 정책(우리 L2TP 포트 ↔ 상대, UDP)을 설치하고 UDP 1701 소켓으로 평문 L2TP를 주고받습니다. SA가 있는 상대만 채널이 됩니다. reqid 범위 `0x5c000000~`를 시작할 때 정리합니다. |
| `user` | raw `IPPROTO_ESP` 소켓과 NAT-T 소켓(SPI별 처리기)에서 ESP를 받아 `CEspSa`로 복호화·재전송 검사 후, 다음 헤더가 UDP(17)이고 포트가 협상한 셀렉터에 맞을 때만 L2TP 페이로드를 넘깁니다. 보낼 때는 UDP 헤더(체크섬은 NAT-OA 기준 의사 헤더)를 만들어 ESP transport로 감싸 raw 소켓 또는 4500 소켓으로 보냅니다. 인증된 ESP-in-UDP의 출발지가 바뀌면 따라갑니다. |
| `none`(`plain`) | IPsec 없이 UDP 1701. 테스트, 또는 IPsec을 다른 곳에서 끝내는 경우용. 반드시 명시해야 합니다. |

`auto`는 `CXfrm::probe()`로 커널 ESP SA 설치가 가능한지 보고 `kernel`, 아니면 `user`를 고릅니다. 이 개발
머신은 esp4가 없어 `user`가 쓰이고 테스트도 그 경로를 검증합니다.

**채널**: SA 쌍(같은 외부 주소와 NAT-T 포트의 SA들, 재키잉해도 유지)마다 채널 번호가 붙고, L2TP 터널은 SCCRQ가
들어온 채널에 묶입니다. 다른 채널에서 온 같은 터널 ID 패킷은 버리므로 한 클라이언트가 다른 클라이언트의 터널에
끼어들 수 없습니다. 채널의 마지막 SA가 사라지면 그 채널의 터널을 닫습니다.

## L2TPv2 (RFC 2661)

- 헤더: 버전 2만(L2TPv3/L2F는 `-EPROTONOSUPPORT`), 제어 메시지는 T/L/S 필수·O 금지, 데이터 메시지는 L/S/O 선택.
- AVP: M/H 비트, 벤더 AVP, 숨김 AVP(RFC 2661 4.3, MD5(type | secret | RV) 체인)를 풀고 만듭니다. Message Type이
  첫 AVP여야 하고, 모르는 필수 AVP는 세션 메시지면 CDN, 아니면 StopCCN(오류 8)입니다.
- LNS: SCCRQ → SCCRP(Protocol Version 1.0, Framing/Bearer Capabilities, Host Name, Assigned Tunnel ID, RWS) →
  SCCCN, ICRQ → ICRP → ICCN, CDN, StopCCN, HELLO. OCRQ는 CDN으로 거절, WEN/SLI는 확인만 합니다.
  같은 채널·포트·Assigned Tunnel ID의 SCCRQ 재전송은 기존 터널로 갑니다.
- LAC(`CL2tpClient`/테스트): SCCRQ, SCCCN, ICRQ, ICCN.
- 신뢰 전송: Ns/Nr, 상대 수신 창(RWS) 안에서만 송신, 재전송 1초부터 두 배(최대 `retransmitCapMs`),
  `retransmitTries`번 실패하면 터널 종료, 순서가 앞선 메시지는 창 안에서 보관했다가 차례로 처리, 중복은 ZLB로
  다시 확인, 보낼 메시지가 없으면 즉시 ZLB. StopCCN 뒤에는 `closeLingerMs` 동안 재전송을 확인해 줍니다.
- 터널 인증: `tunnelSecret`이 있으면 Challenge/Challenge Response(MD5(type | secret | challenge))를 요구하고
  숨김 AVP를 풉니다. **Windows/Apple/Android 내장 클라이언트는 터널 인증을 쓰지 않으므로 비워 둡니다.**
- HELLO: 제어 메시지가 `hello`초 동안 없으면 보냅니다(응답이 없으면 터널 종료).
- Windows는 터널마다 호출 하나를 엽니다. PPP가 끝나 터널에 세션이 없으면 StopCCN으로 터널도 닫습니다.

## PPP (RFC 1661, 1334, 1994, 2759, 1332, 1877)

- 프레임: FF 03 + 2바이트 프로토콜로 보내고, 받을 때는 FF 03 생략과 1바이트 프로토콜(PFC)을 모두 받습니다.
- LCP: 우리 요청은 MRU(`mru`, 기본 1400), 인증 프로토콜, 매직 넘버. 상대의 MRU/ACCM/매직/PFC/ACFC는 받고, Callback(13),
  MRRU(17), Endpoint Discriminator(19), Quality 등은 Configure-Reject(Windows가 보내는 것들). 매직 넘버가 같으면 루프백으로
  보고 Nak. Echo-Request에 답하고, 링크가 `echo`초 동안 조용하면 Echo-Request를 보내 4번 응답이 없으면 끊습니다.
  Identification/Time-Remaining/Discard는 무시, 모르는 코드는 Code-Reject. Ack를 잃어 다시 온 같은 요청에는 재협상 없이
  Ack만 다시 보냅니다. 링크가 올라간 뒤의 LCP 재협상은 링크를 끝냅니다.
- 인증(서버가 인증자, 설정 순서대로 제안하고 상대가 Nak으로 다른 방식을 원하면 허용된 것 중에서 바꿈):
  - **MS-CHAPv2**(기본): 16바이트 챌린지, 응답의 NT-Response를 `mschapv2.hpp`(RFC 2759)로 검증, 성공 메시지
    `S=<AuthenticatorResponse> M=Access granted`, 실패 `E=691 R=0 C=<새 챌린지> V=3`. 사용자 이름의 `DOMAIN\`은
    떼고 대소문자를 무시합니다. 평문 비밀번호 또는 NT 해시(`ntHash`)로 검증합니다.
  - **CHAP-MD5**: MD5(id | secret | challenge). 평문 비밀번호가 필요합니다.
  - **PAP**: 평문 비교, 또는 NT 해시 계정이면 받은 비밀번호의 NT 해시와 비교.
  - 서버는 응답이 없으면 챌린지를 다시 보내고, 성공 메시지를 잃어 같은 응답이 다시 오면 성공을 다시 보냅니다.
    클라이언트는 MS-CHAPv2 상호 인증(서버의 `S=` 값)을 검증합니다.
- IPCP: 서버는 자기 주소(풀의 첫 호스트)를 요청하고, 클라이언트의 IP-Address(0.0.0.0)에는 인증 후 풀에서 받은 주소로
  Nak, DNS(129/131)·NBNS(130/132)는 설정이 있으면 Nak으로 알려 주고 없으면 Reject, IP 압축은 Reject.
- **CCP(MPPE)와 IPv6CP는 LCP Protocol-Reject**합니다. L2TP/IPsec에서 Windows의 "암호화 필요"는 IPsec을 뜻하며
  MPPE를 요구하지 않습니다(MPPE는 PPTP용). IPsec이 이미 터널 전체를 보호하므로 이중 암호화를 하지 않습니다.
- IP: IPCP가 열린 뒤 받은 IPv4 패킷은 출발지가 할당한 주소일 때만 TUN에 씁니다(위조 방지). IPv6 데이터는 버립니다.

## 주소와 네트워크 연결

- 풀(`pool`, 예 `10.60.0.0/24`)의 첫 호스트(`.1`)가 서버의 PPP 주소이자 TUN 장치(`interface`, 기본 `l2tp0`) 주소
  `10.60.0.1/24`입니다. 커널이 풀 전체를 TUN으로 라우팅하고, 서버는 TUN에서 읽은 패킷을 목적지 주소로 세션을 찾아
  PPP로 보냅니다(TUN 하나가 모든 세션을 담당).
- 같은 사용자는 가능하면 이전 주소를 다시 받고(`ipsec::AddressPool` 재사용), 계정의 `address`는 고정 주소입니다.
  같은 주소의 이전 세션이 남아 있으면 새 세션이 올라올 때 정리합니다.
- 컨테이너 네트워크 연결은 IKEv2와 같습니다([vpn-ipsec.md](vpn-ipsec.md) "컨테이너 네트워크 연결"):
  1. 서버를 브릿지가 있는 netns(호스트 또는 `netns`)에서 돌리고 `forwarding`(기본 true)으로 ip_forward를 켭니다.
  2. 컨테이너의 응답은 기본 게이트웨이(브릿지 주소)로 돌아와 풀 경로를 따라 `l2tp0`으로 들어갑니다.
  3. 풀을 브릿지 서브넷 안의 빈 구간(예: 브릿지 172.18.0.0/16, 풀 172.18.200.0/24)으로 잡고 `bridge`를 주면 브릿지에
     proxy ARP가 켜져 컨테이너가 클라이언트를 같은 L2 이웃처럼 봅니다. IPAM이 그 구간을 쓰지 않게 막아야 합니다.
  4. 클라이언트는 기본적으로 모든 트래픽을 VPN으로 보냅니다(Windows "원격 네트워크의 기본 게이트웨이 사용").
     분할 터널은 클라이언트 쪽 설정입니다(`profile --routes`).
  5. 격리된(internal) 네트워크라면 nftables `sbox` 테이블에 `l2tp0` 허용 규칙이 따로 필요합니다.

## 설정 (JSON)

`sbox-l2tp run -c config.json`과 `ParseL2tpServerConfig`가 읽습니다. 모르는 키는 오류입니다.

```json
{
  "listen": "203.0.113.5", "ikePort": 500, "natPort": 4500, "l2tpPort": 1701, "ipv6": false,
  "netns": "/var/run/netns/vpn",
  "dataPath": "auto",
  "psk": "a long random pre-shared key",
  "ike": ["aes256-aes128-3des-sha256-sha1-modp2048-modp1024-ecp256"],
  "esp": ["aes256-aes128-3des-sha256-sha1", "aes256gcm16"],
  "forceEncap": false, "dpd": 30, "phase1Lifetime": 28800, "phase2Lifetime": 3600,
  "hostName": "sbox-l2tp", "tunnelSecret": "", "hello": 60,
  "users": [ { "name": "alice", "password": "s3cret" },
             { "name": "bob", "ntHash": "8846f7eaee8fb117ad06bdd830b7586c", "address": "10.60.0.50" } ],
  "auth": ["mschapv2"],
  "mru": 1400, "echo": 30,
  "pool": "10.60.0.0/24", "dns": ["10.60.0.1"], "nbns": [],
  "interface": "l2tp0", "mtu": 1400, "routes": [], "bridge": "br-0123456789ab", "forwarding": true,
  "idleTimeout": 0, "maxSessions": 1024, "maxTunnels": 1024
}
```

| 키 | 의미 |
|---|---|
| `psk` | 문자열 하나(모든 상대) 또는 `[{ "id": "203.0.113.9" 또는 "@phone.example", "secret": ... }]`. Main Mode에서는 클라이언트 ID를 PSK로 암호화된 메시지에서만 알 수 있어, 서버가 후보 키를 차례로 시험합니다(최대 32개). |
| `ike` / `esp` | strongSwan 형식 제안 문자열. 생략하면 기본값(Phase 1: AES-256/128/192·3DES × SHA2-256/384/512·SHA-1 × MODP-2048, ECP-256, ECP-384, MODP-1024 / ESP: AES-GCM-16, AES-CBC·3DES × SHA2-256/SHA-1/SHA2-384/512) |
| `dataPath` | `auto`, `kernel`, `user`, `none`(IPsec 없음, PSK 불필요) |
| `forceEncap` | 가짜 NAT-D로 클라이언트가 항상 UDP 4500(ESP-in-UDP)을 쓰게 함 |
| `users` | PPP 계정. `ntHash`(`sbox-l2tp nthash`)는 MS-CHAPv2와 PAP에 쓸 수 있고, CHAP-MD5는 평문 `password`가 필요 |
| `auth` | 허용하는 PPP 인증, 선호 순서(`mschapv2`, `chap`, `pap`) |
| `pool` | 클라이언트 IPv4 풀(/30 이상). `dns`/`nbns`는 IPCP로 알림 |
| `tunnelSecret` | L2TP 터널 인증 비밀(내장 클라이언트용으로는 비움) |
| `idleTimeout` | IP 트래픽이 없는 세션을 끊는 시간(초, 0은 끄기) |

## 명령줄 도구 (`sbox-l2tp`)

```sh
sbox-l2tp check -c /etc/sbox/l2tp.json
sbox-l2tp run -c /etc/sbox/l2tp.json [-v]      # Ctrl-C/SIGTERM: PPP 종료, CDN/StopCCN, IKE DELETE 후 종료. SIGUSR1: SA/세션 목록
sbox-l2tp profile --server vpn.example.com -c /etc/sbox/l2tp.json --format windows [--nat] [--routes 10.88.0.0/16]
sbox-l2tp profile --server vpn.example.com --psk 'KEY' --user alice --format apple > l2tp.mobileconfig
sbox-l2tp profile --server vpn.example.com --psk 'KEY' --format android
sbox-l2tp nthash 's3cret'
```

방화벽에서 UDP 500, 4500을 엽니다(NAT 없이 ESP를 직접 쓰는 클라이언트를 위해 IP 프로토콜 50도). UDP 1701은 열
필요가 없습니다(항상 ESP 안에 있음).

## 운영체제별 접속 방법

공통: 서버 주소, 사전 공유 키(PSK), 사용자 이름/비밀번호가 필요합니다. 인증서는 필요 없습니다.

### Windows 10/11

관리자 PowerShell(`sbox-l2tp profile --format windows`가 만드는 것과 같음):

```powershell
Add-VpnConnection -Name 'Office' -ServerAddress 'vpn.example.com' -TunnelType L2tp `
    -L2tpPsk 'KEY' -AuthenticationMethod MSChapv2 -EncryptionLevel Required -RememberCredential -Force
rasdial 'Office' alice s3cret
```

- GUI: 설정 > 네트워크 및 인터넷 > VPN > VPN 추가: VPN 공급자 "Windows(기본 제공)", VPN 유형 "미리 공유한 키를 사용한
  L2TP/IPsec", 미리 공유한 키, 로그인 정보 유형 "사용자 이름 및 암호". 어댑터 속성 > 보안 탭에서 "다음 프로토콜 허용 >
  Microsoft CHAP 버전 2"를 확인합니다.
- `-EncryptionLevel Required`는 IPsec 보호를 요구한다는 뜻이며 MPPE는 협상되지 않습니다(서버가 CCP를 거절).
- **서버가 NAT 뒤에 있으면**(오류 809) `HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent`에
  `AssumeUDPEncapsulationContextOnSendRule = 2`(DWORD)를 넣고 재부팅해야 합니다(`profile --nat`이 명령을 넣어 줌).
  클라이언트만 NAT 뒤에 있는 경우는 기본 설정으로 됩니다.
- 분할 터널: `Set-VpnConnection -SplitTunneling $true` + `Add-VpnConnectionRoute`(`profile --routes`).
- Windows 기본 제안은 Phase 1에 AES-256/128·3DES + SHA-1(/SHA-256) + MODP-2048/1024, ESP에 AES-CBC/3DES + SHA-1입니다.
  기본 서버 설정이 모두 받아들입니다.

### macOS

- 시스템 설정 > VPN > VPN 구성 추가 > **L2TP over IPSec**: 서버 주소, 계정 이름, 사용자 인증 "암호", 시스템 인증
  "공유 비밀"(PSK). 또는 `profile --format apple`로 만든 `.mobileconfig`를 설치합니다(시스템 설정 > 개인정보 보호 및
  보안 > 프로파일).
- "모든 트래픽을 VPN 연결을 통해 전송" 옵션이 전체 터널입니다.

### iOS / iPadOS

- 설정 > 일반 > VPN 및 기기 관리 > VPN > VPN 구성 추가 > 유형 **L2TP**: 서버, 계정, 암호, 비밀(PSK), "모든 트래픽 보내기".
- 또는 `.mobileconfig`를 메일/AirDrop/웹으로 전달해 설치합니다(VPNType `L2TP`, IPSec `SharedSecret`).

### Android

- 설정 > 네트워크 및 인터넷 > VPN > + : 유형 **L2TP/IPSec PSK**, 서버 주소, L2TP 보안 비밀(비움), IPSec 식별자(비움),
  IPSec 사전 공유 키, 사용자 이름/비밀번호. 고급 옵션의 "전달 경로"로 분할 터널을 지정할 수 있습니다.
- **Android 12부터는 새 L2TP/IPSec 프로파일을 만들 수 없습니다**(업그레이드 전에 만든 것만 유지). 새 기기는 IKEv2
  (`sbox-ike`, [vpn-ipsec.md](vpn-ipsec.md))를 쓰십시오. Android의 L2TP 클라이언트는 MODP-1024/2048과 AES/3DES +
  SHA-1/SHA-256을 제안하며 기본 설정으로 접속됩니다.

## 커널 인터페이스

- 소켓: UDP 500/4500(`CIkeSocket`, `IP_PKTINFO`), 사용자 경로의 `SOCK_RAW`/`IPPROTO_ESP`(IPv4는 IP 헤더 포함으로 받음,
  `IP_PKTINFO`로 출발지 지정), 커널/평문 경로의 UDP 1701 소켓.
- `/dev/net/tun`(`net::CreateTunTap`), rtnetlink(주소·MTU·링크 up·경로, `ipsec::ConfigureInterface` 재사용).
- `NETLINK_XFRM`(`CXfrm`): 커널 경로의 transport 모드 SA(`XFRMA_ENCAP` 포함)와 정책, 소유 reqid 범위 정리.
- sysctl: `net.ipv4.ip_forward`, `net.ipv4.conf.<bridge>.proxy_arp`.

## ipsec/ 변경 (재사용을 위한 추가)

- `CIkeSocket::espSpiHandler(spi, handler)`: NAT-T 소켓의 ESP-in-UDP를 SPI별 처리기로 먼저 넘깁니다(없으면 기존
  `espHandler`). IKEv2 사용자 공간 경로와 L2TP 사용자 공간 경로가 4500 소켓을 함께 쓰기 위한 것이며 기존 동작은
  바뀌지 않습니다.
- 그 밖에는 `src/ipsec/`의 비공개 도우미(`crypto.hpp`의 해시/HMAC/바이트 함수, `pool.hpp`의 `AddressPool`,
  `datapaths.hpp`의 `ConfigureInterface`)를 수정 없이 포함해 씁니다.

## 테스트 (`ctest -L vpn`, `tests/l2tp/`)

| 테스트 | 내용 |
|---|---|
| `l2tp/ikev1crypto` | SKEYID(PSK), SKEYID_d/a/e, 키 확장(AES-256/SHA-1, 3DES), 초기 IV, HASH_I/R, Phase 2 IV, KEYMAT(PFS 유무), NAT-D를 Python `hashlib`/`hmac`으로 독립 계산한 값과 비교(SHA-1/SHA-256/MD5 × AES/3DES), AES-CBC/3DES-CBC를 `cryptography` 결과와 비교, IV 체인, 벤더 ID(MD5), ESP 변환 매핑 |
| `l2tp/ikev1` | 메모리 안 개시자↔응답자: 기본 제안, Windows식 조합 5가지(MODP-1024/2048, ECP-256/384, 3DES/AES, SHA1~512, AES-GCM), NAT 흉내(포트 이동, UDP-encapsulated transport, NAT-OA), `forceEncap`, PFS, 잘못된 PSK, 주소/FQDN/기본 PSK 선택, NO-PROPOSAL-CHOSEN, L2TP가 아닌 셀렉터 거부, 메시지 유실과 재전송, DPD 응답, DELETE, 서버 DPD로 죽은 상대 정리, INITIAL-CONTACT, Aggressive Mode 거부; 실제 소켓(루프백)에서 IKEv2 응답자와 포트를 공유하며 협상 |
| `l2tp/l2tp` | 헤더(제어/데이터/오프셋/L2TPv3 거부), 숨김 AVP(Python으로 만든 벡터 해독, 왕복), LNS↔LAC 터널·세션·데이터·CDN·StopCCN, 터널 인증(성공/불일치/비밀 없음), 유실·중복·순서 바뀜, HELLO와 응답 없는 상대, 모르는 필수 AVP |
| `l2tp/ppp` | MS-CHAPv2(상호 인증, 주소, DNS 2개, IP 양방향, 위조 출발지 차단, 종료), 도메인 접두사·대소문자·NT 해시·고정 주소, CHAP-MD5, PAP, 인증 방식 Nak 협상, 잘못된 비밀번호(3방식)·모르는 사용자, 프레임 유실, LCP 에코로 죽은 상대 감지, Windows식 LCP 옵션 거절과 CCP/IPv6CP Protocol-Reject, 에코 응답 |
| `l2tp/fuzz` | IKEv1 디코더 3만 회, 기록한 정상 교환을 변형해 응답자의 모든 상태에 주입(300회), L2TP 헤더/AVP 2만 회와 터널 300회, PPP 양쪽 400회 — 충돌 없이 진행. UDP 체크섬 |
| `l2tp/e2e` (root) | 세 netns(클라이언트, 서버, 서버 뒤 LAN)와 veth: 클라이언트가 IKEv1 + 사용자 공간 ESP transport + L2TP + PPP로 접속해 주소를 받고, 양쪽 TUN을 거쳐 서버 터널 주소와 LAN 호스트까지 UDP 왕복(raw ESP); NAT-T 강제(3DES/SHA1/MODP-1024)와 관리자 끊기; 잘못된 PSK/비밀번호; IKEv2 응답자와 UDP 500/4500 공유; IPsec 없는 L2TP(CHAP-MD5)와 서버 중지 |
| `l2tp/config` | 설정 파싱(정상/오류 11가지), 제안 문자열, Windows/Apple/Android 프로파일 내용, `sbox-l2tp check/profile/nthash` 실행 |
| `l2tp/interop` | xl2tpd + pppd(+ /dev/ppp)가 있으면 LAC로 접속해 봄, strongSwan은 탐지만. 이 머신에는 없어 건너뜀 |

## 제한 사항

- **실제 Windows/macOS/iOS/Android 클라이언트로는 이 환경에서 시험하지 못했습니다.** 프로토콜은 RFC와 각 클라이언트의
  알려진 동작(제안, VID, ID 형식, LCP 옵션, IPCP 요청)에 맞췄고, 상호 운용 도구(xl2tpd/pppd/strongSwan)도 이 머신에
  없어 interop 테스트는 건너뜁니다.
- **커널 XFRM transport 경로는 실행 검증되지 않았습니다**(esp4 없음). netlink 형식은 IKEv2 작업 흐름의 검증된 `CXfrm`을
  쓰지만, 같은 NAT 뒤의 두 클라이언트가 둘 다 내부 출발 포트 1701을 쓰면 커널 정책으로는 구분할 수 없습니다(사용자 공간
  경로는 SA 단위로 구분하므로 문제없음).
- IKEv1: RSA 서명 인증(인증서)은 지원하지 않습니다. IKEv1 RSA 서명은 DigestInfo 없는 PKCS#1 서명인데 libcertpp가 이를
  제공하지 않습니다. 그래서 IKE 단편화(인증서용, Cisco/Microsoft 방식)도 구현하지 않았습니다(PSK 메시지는 작음).
  Aggressive Mode, XAUTH/Mode Config, Phase 1 DES, ESP HMAC-MD5/DES/AH, Commit 비트 처리, IKEv1 over IPv6 클라이언트 주소
  셀렉터 이외의 tunnel 모드는 지원하지 않습니다.
- 응답자는 ISAKMP/IPsec 재키잉을 먼저 시작하지 않습니다(내장 클라이언트가 스스로 재키잉). kilobyte 수명은 기록만 하고
  적용하지 않습니다.
- PPP: IPv6CP(IPv6 주소)는 Protocol-Reject로 지원하지 않습니다(IPv4만). MPPE/CCP, 멀티링크, 콜백, EAP 인증 없음.
  MS-CHAPv2 실패 뒤 재시도(R=1)와 비밀번호 변경은 지원하지 않습니다.
- L2TP: LNS의 incoming call만(OCRQ 거절). 데이터 메시지의 순서 번호(Sequencing Required)는 보내기만 맞추고 재정렬하지
  않습니다. L2TPv3 없음.
- 주소 풀은 메모리에만 있습니다(재시작하면 처음부터 할당, net 모듈 `CIpam`과 공유하지 않음). IKEv2 응답자와 같은 프로세스에서
  돌릴 때는 서로 다른 풀과 인터페이스를 써야 합니다.
- 사용자 공간 경로는 한 스레드에서 처리하며 패킷마다 복사합니다(수백 Mbit/s 수준). 32비트 시퀀스(ESN 없음).
