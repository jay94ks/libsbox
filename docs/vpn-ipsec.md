# vpn 모듈: IPsec(XFRM)와 IKEv2 응답자

vpn 모듈(`sbox::vpn`, CMake 타깃 `sbox::vpn`)의 IPsec 작업 흐름입니다. 목표는 **드라이버나 앱을 설치하지
않고** 운영체제에 내장된 VPN 클라이언트(Windows 10/11, macOS/iOS, Android 11+)가 libsbox 서버에 붙어,
VPN 클라이언트가 컨테이너 가상 네트워크에 들어오게 하는 것입니다. 헤더는
`modules/vpn/include/sbox/vpn/ipsec/`, 소스는 `modules/vpn/src/ipsec/`, 테스트는
`modules/vpn/tests/ipsec/`, 명령줄 도구는 `cli/sbox-ike`입니다. 모든 암호 연산은 libcertpp를 씁니다.

## 구성

| 헤더 | 내용 |
|---|---|
| `ikecrypto.hpp` | IANA 변환 식별자(`EIkeEncr`, `EIkePrf`, `EIkeInteg`, `EIkeDhGroup`, `EIkeEsn`), `IkePrf`/`IkePrfPlus`, `CIkeDh`(MODP 1024/2048, ECP 256/384, Curve25519), `CIpsecCipher`(SK 페이로드와 ESP가 함께 쓰는 AES-CBC/3DES+HMAC 또는 AES-GCM/ChaCha20-Poly1305) |
| `ikemessage.hpp` | IKE 헤더(`SIkeHeader`), 페이로드 체인, SA/KE/ID/CERT/AUTH/Notify/Delete/TS/CP/SKF 인코더·디코더, `SIkeTrafficSelector` 연산(교집합, 범위→접두사) |
| `proposal.hpp` | strongSwan 형식 제안 문자열(`aes256-sha256-modp2048`), 기본 제안, 응답자 측 선택(`SelectIkeProposal`) |
| `mschapv2.hpp` | RFC 2759 MS-CHAPv2와 RFC 3079 키 유도, EAP-MSCHAPv2 MSK |
| `eap.hpp` | EAP 패킷(`SEapPacket`), `CEapMsChapV2Server`, `CEapMsChapV2Peer` |
| `certs.hpp` | `CIkeCertificate`(PEM/DER 로드, 체인 검증, PKCS#12 내보내기), `GenerateVpnCa`, `IssueVpnCertificate` |
| `profiles.hpp` | Windows PowerShell 스크립트, Apple `.mobileconfig`, Android 설정 안내 생성 |
| `xfrm.hpp` | `CXfrm`(NETLINK_XFRM: SA/정책/SPI 할당/소유자 범위 정리/xfrm 인터페이스/지원 탐지), `CXfrmMonitor`(acquire/expire 알림) |
| `esp.hpp` | 사용자 공간 ESP 한 방향(`CEspSa`: 패딩, 128패킷 재전송 방지 창) |
| `datapath.hpp` | `IIpsecDataPath`(커널 XFRM 또는 사용자 공간 ESP), `SIpsecChildSa`, `CreateIpsecDataPath` |
| `ikesocket.hpp` | `CIkeSocket`: UDP 500/4500(IPv4/IPv6), non-ESP marker, `IP_PKTINFO`, ESP-in-UDP 분기, `UDP_ENCAP` |
| `server.hpp` | `CIkeServer`(IKEv2 응답자), `SIkeServerConfig`, `ParseIkeServerConfig` |
| `initiator.hpp` | `CIkeInitiator`: 테스트와 호스트-게이트웨이 클라이언트용 최소 IKEv2 개시자 |

모든 대기 동작은 호출 스레드의 `CEventLoop`에서 도는 `TTask` 코루틴이고 결과는 `SBOX_OK` 또는 음수
errno입니다. 서버·소켓·데이터 경로는 내부 상태를 `shared_ptr`로 두어, 이벤트 루프에 남은 수신 작업이
객체보다 오래 살아도 안전합니다.

### L2TP/IPsec(IKEv1) 작업과 나누는 부분

IKEv1은 아직 없고 후속 작업이 붙입니다. 그대로 재사용할 수 있게 다음을 프로토콜 중립으로 두었습니다.

- `CIkeSocket`: UDP 500/4500, NAT-T marker, 로컬 주소 복원, ESP-in-UDP 전달(ISAKMP 헤더도 같은 28바이트).
- `ikecrypto.hpp`: DH 그룹(IKEv1 Oakley 그룹 2/14 포함), HMAC PRF, `CIpsecCipher`(IKEv1 Phase 2 ESP 키도 같은 형태).
- `CXfrm`/`IIpsecDataPath`/`SIpsecChildSa`: Quick Mode가 만든 SA를 설치하는 경로. L2TP/IPsec은 transport
  모드이므로 커널 경로의 transport 지원(`EXMODE_TRANSPORT`)을 씁니다(사용자 공간 경로는 tunnel 전용).
- `SIkeHeader::parse`, `ParseIkePayloads`(ISAKMP 페이로드 일반 헤더와 같은 형식), `SIkeId`, `CIkeCertificate`,
  `MsChapNtPasswordHash` 등 MS-CHAPv2 함수(PPP 인증에 그대로 사용).

## 데이터 경로

`CreateIpsecDataPath(options, out)`가 `EIDP_AUTO`이면 `CXfrm::probe()`로 커널을 확인합니다.

- **커널(XFRM)**: ESP SA를 설치할 수 있으면 사용합니다. 응답자 SPI는 `XFRM_MSG_ALLOCSPI`로 받고
  (larval SA를 `XFRM_MSG_UPDSA`로 완성), CHILD SA마다 in/out SA와 out/in/fwd 정책을 만듭니다. 정책은
  reqid 단위로 한 번 설치되고 재키잉 동안 유지됩니다. 커널에 xfrm 인터페이스가 있으면 `if_id`를 쓰는
  `xfrm` 링크(기본 `ipsec0`)를 만들고 풀 게이트웨이 주소를 붙여, 클라이언트 트래픽이 라우팅 가능한
  인터페이스에 나타납니다. 없으면 정책 기반(인터페이스 없음)으로 동작합니다. NAT-T는 `XFRMA_ENCAP`
  (`UDP_ENCAP_ESPINUDP`)과 4500 소켓의 `UDP_ENCAP` 옵션으로 커널이 처리합니다. 알고리즘 이름:
  `cbc(aes)`, `cbc(des3_ede)`, `rfc4106(gcm(aes))`(키+4바이트 salt), `rfc7539esp(chacha20,poly1305)`,
  `hmac(sha1|sha256|sha384|sha512)`(96/128/192/256비트 절단).
- **사용자 공간 ESP**: 커널에 esp4가 없거나(`-EPROTONOSUPPORT`) `EIDP_USER`를 고르면 사용합니다. TUN
  장치(기본 `ipsec0`)에 풀 게이트웨이 주소를 붙이고, TUN에서 읽은 평문 패킷을 트래픽 셀렉터로 CHILD SA에
  대응시켜 `CEspSa`로 암호화한 뒤 NAT-T면 IKE 4500 소켓으로(ESP-in-UDP), 아니면 raw `IPPROTO_ESP`
  소켓으로 보냅니다. 받는 쪽은 SPI로 SA를 찾아 복호화·재전송 검사·패딩 검사 후 내부 패킷의 주소가 협상한
  셀렉터 안에 있을 때만 TUN에 씁니다. NAT 매핑이 바뀌면 인증된 ESP-in-UDP의 출발지로 따라갑니다.
  tunnel 모드, 32비트 시퀀스 번호(ESN 없음)만 지원합니다.

두 경로 모두 가상 IP 없이 붙는 사이트 간 상대(CP 없음)의 원격 셀렉터에 대해, 인터페이스 주소나 `routes`가
이미 덮지 않는 접두사를 데이터 경로 인터페이스로 라우팅합니다(기본 경로 /0과 상대 외부 주소를 포함하는
접두사는 제외).

`SIpsecDataPathOptions`: `kind`, `netnsPath`, `interfaceName`, `ifId`, `mtu`(1400), `addresses`, `routes`,
`reqidBase`(기본 `0x5b000000`, 이 소유자의 reqid 범위), `flushStale`(시작 시 이전 실행이 남긴 같은 범위의
SA/정책 제거). 다른 프로그램(strongSwan 등)의 XFRM 항목은 건드리지 않습니다: `CXfrm::flushOwned()`는
mark, `if_id`, reqid 범위 중 지정한 기준에 맞는 항목만 지웁니다.

## IKEv2 응답자 (`CIkeServer`)

### 교환

- **IKE_SA_INIT**: 제안 선택(아래), KE 그룹 불일치 시 `INVALID_KE_PAYLOAD`, 반쯤 열린 SA가
  `cookieThreshold` 이상이면 상태 없는 `COOKIE`(HMAC-SHA-256(비밀, Ni | IPi | SPIi)), NAT 탐지(RFC 7296
  2.23)와 `forceEncap`(가짜 해시로 클라이언트가 4500을 쓰게 함), `IKEV2_FRAGMENTATION_SUPPORTED`,
  `SIGNATURE_HASH_ALGORITHMS`, 클라이언트 인증서 CA가 있으면 `CERTREQ`(CA SPKI의 SHA-1). 같은 요청의
  재전송에는 캐시한 응답을 다시 보냅니다.
- **IKE_AUTH**: 세 가지 인증.
  - (a) **서버 인증서 + EAP-MSCHAPv2**: AUTH가 없는 첫 IKE_AUTH에 IDr, CERT(+체인), 서명 AUTH,
    EAP-Request(기본 EAP-Identity, Windows는 IDi로 자기 IP를 보내므로)로 답합니다. MS-CHAPv2 Success 뒤
    EAP-Success를 보내고, 클라이언트가 MSK로 만든 AUTH를 검증한 뒤 MSK로 만든 AUTH와 CHILD SA로 답합니다.
    사용자 이름의 `DOMAIN\` 접두사는 무시하고 대소문자를 구분하지 않습니다. 비밀번호 대신 NT 해시를
    저장할 수 있습니다(`sbox-ike nthash`).
  - (b) **PSK 양쪽**: IDi 문자열과 같은 `id`의 PSK, 없으면 `id`가 빈 PSK.
  - (c) **인증서 양쪽**: CERT 페이로드의 인증서를 `caCertificates`까지 검증(서명, 유효 기간, CA 플래그,
    중간 인증서)하고, `strictCertificateId`면 IDi가 인증서에 묶여 있어야 합니다(DN=주체, FQDN/RFC822/IP는
    SAN). 서명 방식: RSA(1, PKCS#1 v1.5 SHA-1), ECDSA(9/10/11, r‖s), RFC 7427 디지털 서명(14: RSA
    PKCS#1 SHA-1/256/384/512, RSASSA-PSS 검증, ECDSA). 우리 서명은 상대가 `SIGNATURE_HASH_ALGORITHMS`를
    보냈으면 RFC 7427(SHA-256 우선), 아니면 키에 맞는 고전 방식입니다(Windows는 RSA SHA-1).
- **CHILD SA**: ESP 제안 선택(데이터 경로가 돌릴 수 있는 것만), 트래픽 셀렉터 좁히기(아래), SPI 할당,
  KEYMAT 유도(RFC 7296 2.17), 데이터 경로 설치. 실패해도 IKE SA는 유지하고 `TS_UNACCEPTABLE`,
  `NO_PROPOSAL_CHOSEN`, `INTERNAL_ADDRESS_FAILURE`, `TEMPORARY_FAILURE`를 알립니다.
- **CREATE_CHILD_SA**: CHILD SA 재키잉(`REKEY_SA`, KE가 있으면 PFS, 같은 reqid 유지, 이전 SA는 상대의
  DELETE 또는 60초 뒤 제거), 추가 CHILD SA, IKE SA 재키잉(RFC 7296 2.18: SKEYSEED = prf(SK_d(old),
  g^ir | Ni | Nr), 자식 SA와 가상 주소 이전).
- **INFORMATIONAL**: 빈 요청(DPD)에 응답, IKE/ESP DELETE 처리(ESP는 우리 쪽 SPI를 담은 DELETE로 답함),
  MOBIKE `UPDATE_SA_ADDRESSES`(주소·NAT 상태 갱신, 데이터 경로 `updateChild`), `COOKIE2` 반사.
- **우리가 시작하는 요청**: `dpdSeconds` 동안 조용하면 빈 INFORMATIONAL을 보내고, `retransmitBaseMs`부터
  두 배씩 늘려 `retransmitTries`번 실패하면 SA를 지웁니다. `ikeLifetimeSeconds` 동안 재키잉이 없으면
  DELETE를 보냅니다. 우리가 NAT 뒤에 있으면 20초마다 NAT keepalive를 보냅니다. `stop()`과 `disconnect()`는
  DELETE를 보냅니다.
- **메시지 ID와 재전송**: 창 크기 1. 처리한 마지막 요청의 응답(단편 전부)을 캐시하고, 같은 ID가 다시 오면
  (단편 요청은 1번 단편일 때만) 캐시를 다시 보냅니다. 기대하지 않은 ID는 버립니다.
- **단편화(RFC 7383)**: 양쪽이 지원을 알리면 IP 데이터그램이 `fragmentSize`(기본 1280바이트, IPv6+UDP+marker 52바이트를 뺀
  크기가 IKE 메시지 한도)를 넘는 메시지를 SKF로 나눕니다.
  받는 쪽은 단편마다 개별 인증·복호화하고 순서와 무관하게 모으며, 더 큰 Total Fragments가 오면 다시
  시작합니다(최대 128개). Windows와 iOS는 인증서가 든 IKE_AUTH에서 이것이 필요합니다.
- **INITIAL_CONTACT**: 같은 신원의 이전 IKE SA를 지우고 주소를 돌려받아, 다시 붙은 클라이언트가 같은 가상
  IP를 받습니다.
- **알 수 없는 critical 페이로드**: `UNSUPPORTED_CRITICAL_PAYLOAD`.

모든 작업(수신 메시지, 1초 틱, `stop`, `disconnect`)은 한 큐에서 차례로 처리되므로 데이터 경로 설치처럼
기다리는 단계가 있어도 SA 상태가 경쟁하지 않습니다.

### 알고리즘

기본 IKE 제안(우리 선호 순):

1. `aes256gcm16-aes128gcm16-chacha20poly1305` / `prfsha512-prfsha384-prfsha256-prfsha1` /
   `curve25519-ecp384-ecp256-modp2048-modp1024`
2. `aes256-aes192-aes128-3des` / `sha512-sha384-sha256-sha1` / 같은 PRF와 DH

기본 ESP 제안: `aes256gcm16-aes128gcm16-chacha20poly1305-aes256gcm12-aes128gcm12`,
`aes256-aes192-aes128-3des` + `sha512-sha384-sha256-sha1`, PFS 그룹은 위와 같고 `noesn`.

선택 규칙: 우리 암호화 알고리즘 순서가 모든 제안에 걸쳐 우선하고(상대가 3DES를 먼저 적어도 AES를
고름), 나머지 변환은 맞은 제안 안에서 우리 순서를 따릅니다. 상대가 KE를 보낸 그룹을 받아들일 수 있으면
그 그룹을 먼저 골라 `INVALID_KE_PAYLOAD` 왕복을 피합니다.

**Windows 기본값**: 사용자 지정 IPsec 정책이 없는 Windows는 IKE에 3DES/AES-CBC + SHA-1/SHA-2 +
**MODP-1024(그룹 2)**만, ESP에 AES-CBC/3DES + SHA-1을 제안합니다. 그룹 2(1024비트)와 3DES는 오늘 기준으로
약하지만 기본 설정의 Windows가 붙게 하려고 기본 제안의 맨 끝에 남겨 두었습니다. 설정 파일의 `ike`/`esp`로
빼고, Windows에는 `Set-VpnConnectionIPsecConfiguration`(아래)을 적용하는 것을 권장합니다.

## 설정 (JSON)

`sbox-ike run -c config.json`과 `ParseIkeServerConfig`가 읽습니다. 상대 경로는 설정 파일 위치 기준입니다.

```json
{
  "listen": "0.0.0.0", "port": 500, "natPort": 4500, "ipv6": false,
  "netns": "/var/run/netns/vpn",
  "serverId": "vpn.example.com",
  "certificate": "server.pem", "key": "server.key",
  "ca": ["clients-ca.pem"],
  "users": [ { "name": "alice", "password": "s3cret" },
             { "name": "bob", "ntHash": "8846f7eaee8fb117ad06bdd830b7586c", "address": "10.10.0.50" } ],
  "psk": [ { "id": "@phone.example", "secret": "a long pre-shared key" }, { "secret": "default psk" } ],
  "pool": "10.10.0.0/24",
  "dns": ["10.10.0.1"], "nbns": [], "dnsDomain": "corp.example",
  "routes": ["10.88.0.0/16"],
  "remoteSubnets": [],
  "ike": ["aes256gcm16-prfsha256-ecp256", "aes256-sha256-modp2048"],
  "esp": ["aes256gcm16", "aes256-sha256"],
  "dataPath": "auto", "interface": "ipsec0", "mtu": 1400,
  "bridge": "br-0123456789ab", "forwarding": true,
  "dpd": 30, "ikeLifetime": 86400, "halfOpenTimeout": 60, "cookieThreshold": 64,
  "retransmitTries": 5, "retransmitBase": 2000, "maxSessions": 1024,
  "fragmentSize": 1280, "forceEncap": false, "mobike": true, "eapIdentity": true,
  "strictCertificateId": true
}
```

| 키 | 의미 |
|---|---|
| `certificate`/`key` | 서버 인증서와 키(PEM 파일 또는 PEM 문자열). EAP 사용자가 있으면 필수 |
| `ca` | 클라이언트 인증서를 검증할 CA 묶음(인증서 인증을 켬) |
| `users` | EAP-MSCHAPv2 계정. `address`는 고정 가상 IP |
| `psk` | 문자열 하나(모든 상대) 또는 `{id, secret}` 목록 |
| `pool` | 가상 IPv4 풀. 첫 호스트(`.1`)가 게이트웨이(인터페이스 주소), 나머지를 클라이언트에 나눔 |
| `routes` | 분할 터널 접두사: TSr로 좁히고 `INTERNAL_IP4_SUBNET`으로도 알림. 비우면 0.0.0.0/0 |
| `remoteSubnets` | CP 없이 붙는 사이트 간 상대의 TSi 허용 범위(비우면 전체) |
| `dataPath` | `auto`, `kernel`, `user` |
| `bridge` | 이 브릿지에 proxy ARP를 켬(아래) |
| `forceEncap` | 가짜 NAT로 항상 UDP 4500 사용(방화벽이 ESP를 막는 경우) |

## 컨테이너 네트워크 연결

VPN 클라이언트를 net 모듈의 가상 네트워크(브릿지)에 넣는 방법입니다.

1. 응답자를 브릿지가 있는 netns(호스트 또는 `netns`)에서 돌립니다. 데이터 경로 인터페이스(`ipsec0`)에
   풀 게이트웨이 주소가 붙어 풀 접두사가 그 인터페이스로 라우팅되고, `forwarding`이 ip_forward를 켭니다.
2. 클라이언트에 `routes`로 컨테이너 서브넷(예: 172.18.0.0/16)을 알리면 클라이언트는 그 범위를 터널로
   보내고, 서버는 ip_forward로 브릿지에 전달합니다. 컨테이너의 답은 기본 게이트웨이(브릿지 주소)로 돌아와
   풀 경로로 `ipsec0`에 들어가 암호화됩니다.
3. 풀을 브릿지 서브넷 **안의** 사용하지 않는 구간(예: 브릿지 172.18.0.0/16, 풀 172.18.200.0/24)으로 잡고
   `bridge`를 지정하면 브릿지에 proxy ARP가 켜져, 컨테이너가 같은 L2 서브넷의 이웃처럼 클라이언트 주소로
   직접 보낼 수 있습니다(풀 경로가 브릿지 서브넷보다 구체적이므로 호스트가 ARP에 대신 답함). IPAM이 그
   구간을 컨테이너에 주지 않도록 `--ip-range`/`rangeStart`로 막아야 합니다.
4. nftables `sbox` 테이블의 네트워크 격리 규칙은 `ipsec0`을 모르므로, 격리된(internal) 네트워크라면 별도
   허용 규칙이 필요합니다.

## 인증서와 명령줄 도구 (`sbox-ike`)

```sh
sbox-ike mkcert --name vpn.example.com --ip 203.0.113.5 --out /etc/sbox/ike --user alice --routes 10.88.0.0/16
sbox-ike mkcert --name vpn.example.com --out /etc/sbox/ike --client laptop --p12-password pw   # 클라이언트 인증서도
sbox-ike check -c /etc/sbox/ike/config.json
sbox-ike run -c /etc/sbox/ike/config.json [-v]      # Ctrl-C/SIGTERM: DELETE 보내고 정리 후 종료
sbox-ike profile --ca ca.pem --server vpn.example.com --auth eap --user alice --format apple > vpn.mobileconfig
sbox-ike nthash 's3cret'
```

`mkcert`는 `ca.pem/ca.key`(10년, cA, keyCertSign|cRLSign), `server.pem/server.key`(기본 825일 — Apple이
더 긴 서버 인증서를 거부, EKU serverAuth + IKE Intermediate `1.3.6.1.5.5.8.2.2`, SAN에 이름과 주소, RSA면
digitalSignature|keyEncipherment), 선택적으로 `<client>.pem/.p12`(clientAuth), `windows-setup.ps1`,
`vpn.mobileconfig`, `android.txt`를 만들고 설정 조각과 Windows 명령을 출력합니다. 기본 키는 RSA 2048
(모든 클라이언트 호환), `--ecdsa`로 P-256. PKCS#12는 PBES2/AES-256 + HMAC-SHA-256이며 반복 횟수 2048로
만듭니다(오래된 Apple 기기 호환을 위해 낮춤).

## 운영체제별 접속 방법

공통: 클라이언트가 접속할 이름(또는 주소)이 서버 인증서의 SAN에 있어야 합니다. 응답자의 IDr은 기본으로
`serverId`(없으면 인증서의 첫 DNS SAN)이지만, 클라이언트가 IKE_AUTH에 IDr을 넣어 오면(macOS/iOS의 원격 ID,
Android, strongSwan) 그것이 `serverId`이거나 인증서 SAN/DN에 묶여 있을 때 그 값으로 답합니다. 그래서
`mkcert --name vpn.example.com --ip 203.0.113.5`로 만든 인증서 하나로 이름과 주소 어느 쪽으로 접속해도 됩니다. 서버의 UDP 500/4500을 열어야 합니다(ESP를 직접 쓰면 IP 프로토콜 50도).

### Windows 10/11 (내장 IKEv2, EAP-MSCHAPv2 또는 머신 인증서)

관리자 PowerShell에서 `mkcert`가 만든 `windows-setup.ps1`을 실행하거나 직접:

```powershell
Import-Certificate -FilePath ca.pem -CertStoreLocation Cert:\LocalMachine\Root
Add-VpnConnection -Name 'Office' -ServerAddress 'vpn.example.com' -TunnelType Ikev2 `
    -AuthenticationMethod Eap -EncryptionLevel Required -RememberCredential
Set-VpnConnectionIPsecConfiguration -ConnectionName 'Office' -AuthenticationTransformConstants GCMAES256 `
    -CipherTransformConstants GCMAES256 -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 `
    -DHGroup Group14 -PfsGroup None -Force
rasdial 'Office' alice s3cret
```

- 머신 인증서: `.p12`를 `Cert:\LocalMachine\My`에 `Import-PfxCertificate`로 넣고
  `-AuthenticationMethod MachineCertificate`. 서버에 `ca`를 설정합니다(Windows는 IDi로 인증서 주체 DN을
  보냄).
- CA는 반드시 **로컬 컴퓨터**의 신뢰할 수 있는 루트에 있어야 합니다(사용자 저장소 불가).
- 분할 터널: `Set-VpnConnection -Name 'Office' -SplitTunneling $true`와 `Add-VpnConnectionRoute`.
  Windows는 TSr 축소와 `INTERNAL_IP4_SUBNET`을 경로로 쓰지 않습니다.
- Windows의 IKEv2 클라이언트는 PSK를 지원하지 않습니다(L2TP/IPsec 작업 흐름에서 다룸).
- 서버가 NAT 뒤에 있으면 Windows에 `HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent\
  AssumeUDPEncapsulationContextOnSendRule = 2`(DWORD)를 넣고 재부팅해야 합니다.
- `Set-VpnConnectionIPsecConfiguration`을 적용하지 않으면 MODP-1024/SHA-1로 협상됩니다(위 "알고리즘").

### macOS / iOS (EAP-MSCHAPv2, 인증서, PSK)

- `vpn.mobileconfig`를 설치합니다(macOS: 시스템 설정 > 개인정보 보호 및 보안 > 프로파일, iOS: 설정 >
  다운로드된 프로파일). CA(`com.apple.security.root`), 필요하면 클라이언트 PKCS#12, IKEv2 VPN 페이로드
  (AES-256-GCM, SHA2-256, DH 19, PFS, MOBIKE, DPD Medium)를 담습니다. `profile --format apple`로
  사용자·PSK별 프로파일을 만들 수 있습니다.
- 수동 설정(설정 > VPN > IKEv2): 서버 = 접속 이름, 원격 ID = `serverId`, 로컬 ID = 사용자 이름(EAP) 또는
  `@phone.example`(PSK, 서버 `psk[].id`와 같게), 사용자 인증 = 사용자 이름(EAP) / 없음+공유 암호(PSK) /
  인증서. 수동 설정에서는 CA 인증서를 먼저 설치하고 "완전히 신뢰"로 켜야 합니다.
- iOS/macOS는 원격 ID와 서버 인증서 SAN이 모두 맞아야 합니다.

### Android 11+ (내장 IKEv2: MSCHAPv2, PSK, RSA)

설정 > 네트워크 및 인터넷 > VPN > 추가:

- **IKEv2/IPSec MSCHAPv2**: 서버 주소, IPSec 식별자(사용자 이름), IPSec CA 인증서(먼저 "CA 인증서"로
  `ca.pem` 설치), 사용자 이름/비밀번호.
- **IKEv2/IPSec PSK**: 서버 주소, IPSec 식별자(서버 `psk[].id`와 같게, 예 `@phone.example`), 사전 공유 키.
- **IKEv2/IPSec RSA**: 클라이언트 `.p12`를 "VPN 및 앱 사용자 인증서"로 설치, CA 인증서, 식별자.
- 서버 인증서 SAN이 서버 주소와 맞아야 합니다. 오래된 Android는 strongSwan VPN Client 앱이 같은 설정을
  받습니다. `profile --format android`가 안내문을 만듭니다.

## 커널 인터페이스

- `NETLINK_XFRM`: `XFRM_MSG_NEWSA/UPDSA/DELSA/GETSA`(덤프 포함), `ALLOCSPI`, `NEWPOLICY/UPDPOLICY/
  DELPOLICY/GETPOLICY`, 속성 `XFRMA_ALG_AEAD/CRYPT/AUTH_TRUNC`, `XFRMA_ENCAP`, `XFRMA_REPLAY_ESN_VAL`,
  `XFRMA_MARK`, `XFRMA_IF_ID`, `XFRMA_TMPL`, `XFRMA_SRCADDR`. 멀티캐스트 `XFRMNLGRP_ACQUIRE/EXPIRE/MAPPING`
  (선택적으로 `SA/POLICY`)을 `CXfrmMonitor`가 이벤트 루프에서 읽습니다.
- rtnetlink: `xfrm` 링크(`IFLA_XFRM_IF_ID`, `IFLA_XFRM_LINK`), 주소·경로(net 모듈 `CRtnl`).
- 소켓: UDP 500/4500(`IP_PKTINFO`/`IPV6_RECVPKTINFO`, `sendmsg`의 출발지 지정), 커널 경로에서
  `setsockopt(IPPROTO_UDP, UDP_ENCAP, UDP_ENCAP_ESPINUDP)`와 IKE 소켓별 우회 정책(`IP_XFRM_POLICY`/
  `IPV6_XFRM_POLICY`, `XFRM_POLICY_ALLOW` in/out — 협상한 정책이 IKE 자신을 감싸지 않도록), 사용자 경로에서
  `SOCK_RAW`/`IPPROTO_ESP`와 `/dev/net/tun`(`CreateTunTap`).
- sysctl: `net.ipv4.ip_forward`, `net.ipv4.conf.<bridge>.proxy_arp`.

이 개발 머신의 커널(6.18)은 `CONFIG_XFRM_USER=y`지만 `CONFIG_INET_ESP`, `CONFIG_XFRM_INTERFACE`,
`CONFIG_CRYPTO_GCM`이 없어 ESP SA 설치가 `-EPROTONOSUPPORT`(AEAD는 `-ENOSYS`)로 실패합니다. 그래서 `auto`는
사용자 공간 ESP를 고르고, 커널 SA/인터페이스 테스트는 건너뜁니다(정책, acquire, 정책 만료 알림은 실제로
검증).

## 테스트 (`ctest -L vpn`)

| 테스트 | 내용 |
|---|---|
| `ipsec/crypto` | prf+(4개 PRF), X25519·MODP-2048 공유 비밀, AES-CBC+HMAC/AES-GCM/ChaCha20-Poly1305 봉인 — 기댓값은 Python `hmac`/`cryptography`(OpenSSL)로 독립 계산. MODP 1024/2048 소수는 OpenSSL과 안전 소수 판정으로 확인. RFC 2759 9.2와 RFC 3079 3.5.3 MS-CHAPv2 벡터, EAP-MSCHAPv2 양방향 |
| `ipsec/message` | 페이로드 왕복, TS 연산, 제안 파싱/선택(Windows 제안), 무작위 변형 2만+ 회 디코더 퍼징, 암호화 페이로드 변조 거부와 단편 역순·중복 재조립, 동작 중인 응답자에 변형 패킷 1500개를 보낸 뒤 정상 접속 |
| `ipsec/ike` | 루프백에서 응답자와 테스트 개시자: PSK, 잘못된 PSK, EAP-MSCHAPv2(RFC 7427 유무, 고정 주소, 잘못된 비밀번호, 신뢰하지 않는 서버 인증서), 인증서 양쪽(DN/FQDN/RFC822 신원, 불일치·미신뢰 거부), 단편화 양방향, CHILD(PFS)/IKE 재키잉 후 DPD·DELETE, 서버 DPD(응답·무응답), 서버 측 끊기, COOKIE, INVALID_KE, 강제 NAT-T, Windows 기본 제안, 공통 제안 없음, INITIAL_CONTACT |
| `ipsec/esp` | ESP 왕복, 재전송 방지 창, 수작업으로 만든 RFC 4303/4106 패킷, 패딩 검사 |
| `ipsec/certs` | RSA CA/서버 인증서(EKU, KU, SAN), PEM/키 왕복, 체인 검증, 서명 방식 1/9/14, 신원 바인딩, PKCS#12, OpenSSL 교차 검증(설치 시), 클라이언트 프로파일 |
| `ipsec/xfrm` (root) | 지원 탐지, 정책 추가/조회/삭제/소유자 범위 정리, SA(커널 ESP 있을 때), xfrm 인터페이스(있을 때), 정책 만료·acquire 알림, 커널 데이터 경로의 SPI 할당(larval SA)·설치 거부·정리, 커널 모드 IKE 소켓(우회 정책 + UDP_ENCAP에서도 IKE 수신) |
| `ipsec/datapath` (root) | 두 netns와 veth: 사용자 공간 ESP로 IKE + 실제 UDP 트래픽 왕복(raw ESP, UDP 4500, 가상 IP 없는 사이트 간), 재키잉 후 트래픽; 커널 XFRM 경로(커널 ESP 있을 때) |
| `ipsec/interop` | strongSwan(swanctl+charon)이 있으면 개시자로 붙여 봄, 없으면 건너뜀 |

## 제한 사항

- **커널 ESP 데이터 경로는 이 머신에서 실행 검증되지 않았습니다**(esp4/xfrm 인터페이스 없음). 정책·알림·
  netlink 형식은 검증했고, SA 설치 코드는 커널 UAPI대로 작성했습니다.
- strongSwan 상호 운용 테스트는 이 머신에 strongSwan이 없어 실행되지 않았습니다. 실제 Windows/Apple/
  Android 클라이언트로의 접속도 이 환경에서는 시험하지 못했습니다(프로토콜은 RFC와 각 클라이언트의 알려진
  동작에 맞춰 구현).
- 사용자 공간 ESP: tunnel 모드만, ESN 없음(32비트 시퀀스, 소진 시 `-EOVERFLOW`로 재키잉 필요), 패킷마다
  CHILD SA 목록을 선형 탐색, 한 스레드에서 처리(수 Gbit/s가 필요하면 커널 경로). TFC 패딩과 dummy 패킷은
  받기만 합니다.
- 응답자는 재키잉을 먼저 시작하지 않습니다(모든 내장 클라이언트가 스스로 재키잉). 재키잉이 없으면
  `ikeLifetime` 뒤 DELETE합니다. CHILD SA 커널 수명은 무한이며 IKE가 관리합니다.
- 가상 주소는 IPv4만(`INTERNAL_IP6_*` 무시). IKE 자체와 외부 주소는 IPv6 가능.
- EAP 방식은 MSCHAPv2뿐입니다(EAP-TLS, EAP-RADIUS 위임 없음). 인증서 폐기(CRL/OCSP) 확인 없음.
- RFC 5998 EAP-only 인증, Multiple Authentication(RFC 4739), Redirect, IKEv2 서명 인증의 Ed25519, ECDSA
  P-521 서명 생성은 지원하지 않습니다(P-521 검증만).
- MOBIKE는 상대가 시작하는 `UPDATE_SA_ADDRESSES`만 처리하고 응답자 주소 목록 알림(ADDITIONAL_*_ADDRESS)과
  경로 점검은 하지 않습니다.
- 사용자 공간 경로의 kernel ACQUIRE(트래픽 기반 SA 요청)와 커널 경로의 EXPIRE 알림은 서버가 아직 구독하지
  않습니다(`CXfrmMonitor`는 제공).
- 가상 주소 풀은 메모리에만 있습니다(net 모듈 `CIpam`과 공유하지 않음): 재시작하면 할당이 처음부터 시작.
- PKCS#12는 PBES2/AES-256만 만듭니다. 오래된 macOS/iOS 키체인은 3DES/RC2 PKCS#12만 읽을 수 있습니다.
