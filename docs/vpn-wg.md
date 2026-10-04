# vpn 모듈: WireGuard와 오버레이 네트워크

vpn 모듈(`sbox::vpn`, `modules/vpn`) 중 WireGuard 부분입니다. 헤더는
`modules/vpn/include/sbox/vpn/wg/`, 소스는 `modules/vpn/src/wg/`, 테스트는 `modules/vpn/tests/wg/`에
있습니다. 같은 모듈의 IPsec/L2TP 부분과 독립적이며 `vpn.hpp`에는 아무것도 추가하지 않았습니다.
암호 연산은 모두 libcertpp(X25519, ChaCha20-Poly1305, XChaCha20-Poly1305, BLAKE2s, keyed BLAKE2s,
HMAC/HKDF-BLAKE2s, CSPRNG)를 씁니다. 직접 구현한 것은 TAI64N 시간 표현, base64/hex 표기, 재전송 창 같은
프로토콜 자료 구조뿐입니다.

명령줄 도구 `cli/sbox-wg`가 이 위에 있습니다.

## 구성

| 헤더 | 내용 |
|---|---|
| `key.hpp` | `SWgKey`(32바이트 키, base64/hex), `GenerateWgPrivateKey`, `GenerateWgPresharedKey`, `DeriveWgPublicKey`, `WgSharedSecret` |
| `allowedips.hpp` | `CWgAllowedIps`(IPv4/IPv6 최장 접두사 일치 트라이), `CWgReplayWindow`(8192비트 재전송 창) |
| `engine.hpp` | `CWgEngine`(I/O 없는 사용자 공간 프로토콜 엔진), `IWgOutput`, `SWgTimers`, `SWgPeerConfig`, `SWgPeerStatus`, `SWgDeviceConfig`, `SWgDeviceStatus`, `CWgBufferPool`, 상수(`WG_OVERHEAD` 80 등) |
| `config.hpp` | `SWgConfig`, `ParseWgConfig`/`WriteWgConfig`(wg-quick/`wg setconf` INI), `ResolveWgConfigEndpoints`, `GenerateWgClientConfig`(공식 앱용 클라이언트 설정) |
| `kernel.hpp` | `wireguard` generic netlink 상수, `BuildWgSetDevice`/`BuildWgGetDevice`/`ParseWgGetDevice`, `CWgKernelClient` |
| `uapi.hpp` | 크로스 플랫폼 UAPI(`/var/run/wireguard/<if>.sock`) 형식/파서와 클라이언트(`WgUapiGet`/`WgUapiSet`) |
| `device.hpp` | `CWgDevice`(커널/사용자 공간 자동 선택), `SWgDeviceOptions`, `EWgMode` |
| `overlay.hpp` | `CWgOverlayDriver`(`INetworkDriver` "wg-overlay"), `SWgOverlayConfig`, `SWgOverlayHost`, `MakeWgOverlayNetwork` |

비공개 `src/wg/noise.hpp`는 Noise 핸드셰이크 단계를 명시적 입력(고정 임시 키, 타임스탬프)을 받는 순수
함수로 제공해 알려진 답 테스트가 각 단계를 검증할 수 있게 합니다.

## 프로토콜 구현 (`CWgEngine`)

WireGuard 백서의 Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s를 그대로 구현합니다.

- **메시지**: 핸드셰이크 시작(148바이트), 응답(92), 쿠키 응답(64), 전송 데이터(16바이트 헤더 + 암호문 +
  16바이트 태그). 필드는 리틀 엔디언이며 정렬되지 않은 버퍼에서도 읽습니다.
- **해시/KDF**: `HASH`=BLAKE2s-256, `MAC`=keyed BLAKE2s-128, `KDF_n`=HKDF(HMAC-BLAKE2s, 빈 info).
  초기 체이닝 키와 해시(`HASH(CONSTRUCTION)`, `HASH(Ci || IDENTIFIER)`)는 한 번만 계산합니다.
- **정적-정적 DH**는 피어마다 미리 계산하고, MAC1 키 `HASH("mac1----" || 공개키)`와 쿠키 키
  `HASH("cookie--" || 공개키)`도 피어/장치마다 미리 계산합니다.
- **TAI64N**: `2^62 + 10 + 초`(빅 엔디언) + 나노초, 나노초는 커널처럼 2^24 단위로 내림해 시계 지문을
  줄입니다. 응답자는 피어마다 가장 큰 타임스탬프보다 큰 것만 받고(재전송 방지), 같은 피어의 시작
  메시지는 20ms(초당 50회)보다 자주 처리하지 않습니다.
- **세션**: 피어마다 current/previous/next 세 키 쌍. 시작자는 응답을 받으면 바로 current로, 응답자는
  next에 두었다가 그 키로 첫 데이터(또는 keepalive)를 받으면 current로 올립니다. 시작자는 세션을 확인시키기
  위해 대기 중인 패킷을, 없으면 keepalive를 즉시 보냅니다.
- **전송**: 평문은 16바이트 배수로(MTU를 넘지 않게) 채운 뒤 제자리에서 암호화합니다. nonce는
  `0^32 || le64(counter)`. 수신은 복호 후 재전송 창을 검사하고(복호에 실패한 패킷은 창을 바꾸지 않음),
  IP 헤더 길이로 패딩을 자르고, 내부 원본 주소가 그 피어의 allowed IP인지 확인합니다(cryptokey routing).
- **재전송 창**: RFC 6479 비트맵 8192비트(사용 가능 8128). 순서가 바뀐 패킷을 받아들이고 창 밖이나 중복은
  버립니다.
- **로밍**: 인증에 성공한 핸드셰이크/데이터 메시지의 출발지로 피어 엔드포인트를 갱신합니다. 인증되지
  않은 패킷은 엔드포인트를 바꾸지 못합니다.
- **cryptokey routing**: `CWgAllowedIps`는 패밀리별 이진 트라이(노드 벡터 + 자유 목록)로 조회 시 할당이
  없습니다. 접두사는 소유 피어가 하나이며 다시 넣으면 옮겨집니다(`wg set` 의미).

### 타이머 (`SWgTimers`, 기본값은 백서 값)

| 이름 | 값 | 동작 |
|---|---|---|
| REKEY_AFTER_MESSAGES / TIME | 2^60 / 120s | 시작자가 보낼 때 세션이 이보다 오래되면 새 핸드셰이크 |
| REJECT_AFTER_MESSAGES / TIME | 2^64-2^13-1 / 180s | 이 세션으로 송수신하지 않음 |
| REKEY_TIMEOUT (+0~333ms 지터) | 5s | 응답이 없으면 재시도, 피어당 핸드셰이크 시작은 이 간격보다 자주 하지 않음 |
| REKEY_ATTEMPT_TIME | 90s | 재시도를 포기하고 대기 패킷을 버림 |
| KEEPALIVE_TIMEOUT | 10s | 데이터를 받고 보낼 것이 없으면 keepalive |
| KEEPALIVE + REKEY_TIMEOUT | 15s | 데이터를 보냈는데 아무것도 못 받으면 새 핸드셰이크 |
| REJECT_AFTER_TIME - KEEPALIVE - REKEY_TIMEOUT | 165s | 받는 쪽 세션이 만료 직전이면 시작자가 새 핸드셰이크 |
| REJECT_AFTER_TIME × 3 | 540s | 키 자료 삭제 |
| persistent keepalive | 피어 설정 | 마지막 인증 패킷 이후 N초마다 keepalive (설정 즉시 한 번) |

커널 `timers.c`의 이벤트 이름(`data_sent`, `any_authenticated_packet_received` 등)과 같은 의미로 구현했고,
엔진은 시계를 주입받으므로(`SWgEngineOptions::clock`) 테스트가 시간을 직접 진행시킵니다.
`nextDeadline()`은 가장 이른 타이머(더 이를 수는 있어도 늦지는 않음)를 돌려주고 장치는 이를 timerfd로
기다립니다.

### 부하 상황의 쿠키

- 모든 핸드셰이크 메시지는 MAC1을 먼저 검사합니다(틀리면 응답 없이 버림).
- 초당 핸드셰이크 메시지가 `underLoadThreshold`(기본 256)를 넘으면 1초 동안 "부하 상태"입니다
  (`forceUnderLoad()`로 강제 가능). 이때 MAC2가 없거나 틀린 메시지에는 쿠키 응답만 보냅니다.
- 쿠키 = `MAC(Rm, 출발지 IP || 포트)`, 비밀 `Rm`은 120초마다 바뀝니다. 쿠키 응답은
  `XChaCha20-Poly1305(HASH("cookie--"||응답자 공개키), 무작위 24바이트 nonce, 쿠키, aad=받은 MAC1)`입니다.
- 시작자는 마지막으로 보낸 MAC1로 쿠키 응답을 열고, 쿠키가 115초 안이면 다음 메시지의 MAC2에 씁니다
  (재시도 타이머가 다시 보냄).
- 부하 상태에서 MAC2가 맞는 메시지도 출발지(IPv4 주소, IPv6 /64)별 토큰 버킷(초당 20, 버스트 5)을
  통과해야 합니다.

### 메모리와 일괄 처리

- 데이터 경로는 패킷마다 할당하지 않습니다. 장치는 recvmmsg/TUN 읽기용 버퍼를 루프 시작 시 한 번
  잡고, 엔진은 핸드셰이크를 기다리는 패킷(피어당 최대 128개, 오래된 것부터 버림)을 `CWgBufferPool`의 고정
  크기 버퍼에 복사합니다.
- 수신은 깨어날 때마다 `recvmmsg`로 최대 `batch`(기본 32)개씩 최대 8번 읽고, TUN은 `batch`개를 읽어 모두
  암호화한 뒤 `sendmmsg`로 한 번에 보냅니다(`IWgOutput::sendDatagram`의 `stable` 표시로 같은 버퍼에 남는
  데이터만 모아 보냄). 핸드셰이크와 대기 패킷은 즉시 보냅니다.

## 장치 (`CWgDevice`)

```cpp
CWgDevice dev;
SWgDeviceOptions o;
o.name = "wg0";
o.netnsPath = "/var/run/netns/x";      // 비우면 현재 netns
o.mode = EWGM_AUTO;                    // 커널 모듈이 있으면 커널, 없으면 사용자 공간
o.addresses = { 10.9.0.1/24 };
o.routeAllowedIps = true;              // 피어 allowed IP(/0 제외)를 인터페이스로 라우팅
co_await dev.create(o);
co_await dev.setConfig(cfg);           // wg setconf
co_await dev.setPeer(peer);            // wg set ... peer
co_await dev.removePeer(key);
co_await dev.status(st);               // wg show
co_await dev.close();
```

- **선택**: `EWGM_AUTO`는 `wireguard` genl 패밀리를 찾고, 없으면 `wireguard` 링크를 만들어 모듈 자동
  로드를 시도한 뒤 다시 찾습니다. 둘 다 실패하면 사용자 공간입니다. `EWGM_KERNEL`은 모듈이 없으면
  `-ENOTSUP`. `CWgDevice::kernelAvailable(netns)`로 미리 확인할 수 있습니다.
- **커널 경로**: rtnetlink `RTM_NEWLINK`(`IFLA_INFO_KIND="wireguard"`)로 링크를 만들고 `WG_CMD_SET_DEVICE`
  /`WG_CMD_GET_DEVICE`로 설정/조회합니다. 장치 속성(개인 키, 포트, fwmark, `REPLACE_PEERS`), 피어 속성
  (공개 키, PSK, `REMOVE_ME`/`REPLACE_ALLOWEDIPS`/`UPDATE_ONLY` 플래그, sockaddr 엔드포인트,
  persistent keepalive, allowed IP 목록), 조회 결과(마지막 핸드셰이크 timespec, rx/tx 바이트)를 다룹니다.
  큰 설정은 `wg`처럼 여러 메시지로 나누며(장치 속성은 첫 메시지에만, allowed IP가 넘치는 피어는 다음
  메시지에서 `UPDATE_ONLY`로 이어감), 여러 부분으로 온 GET 응답의 같은 피어는 합칩니다. 커널 인터페이스는
  객체가 사라져도 남고 `close()`가 지웁니다.
- **사용자 공간 경로**: `/dev/net/tun`(`IFF_TUN|IFF_NO_PI`)을 지정한 netns 안에 만들고, UDP 소켓(IPv4,
  가능하면 같은 포트의 IPv6 `V6ONLY`)도 `CNetnsScope`로 그 netns에서 엽니다. 수신 루프 2개(v4/v6), TUN
  루프, timerfd 루프가 생성한 스레드의 `CEventLoop`에서 돕니다. 포트를 바꾸면 소켓을 새로 열고 이전 수신
  루프는 세대 번호로 끝냅니다. fwmark는 `SO_MARK`로 적용합니다. TUN이 밖에서 삭제되면 장치가 닫힙니다.
- **UAPI**: `uapi=true`이면 `<uapiDir>/<이름>.sock`(0600)에서 wireguard-go와 같은 텍스트 프로토콜
  (`get=1`, `set=1`, 키는 hex, 응답 끝 `errno=N`)을 제공합니다. 그래서 공식 `wg show/set`과
  `sbox-wg show`가 다른 프로세스의 사용자 공간 장치를 읽고 바꿀 수 있습니다.
- MTU 기본값은 1420(이더넷 1500 - `WG_OVERHEAD` 80: IPv6 40 + UDP 8 + 헤더 16 + 태그 16)입니다.

## 설정 파일과 클라이언트 설정

- `ParseWgConfig`는 `wg setconf` 키(`PrivateKey`, `ListenPort`, `FwMark`, 피어의 `PublicKey`,
  `PresharedKey`, `AllowedIPs`, `Endpoint`, `PersistentKeepalive`)와 wg-quick/공식 앱 키(`Address`, `DNS`,
  `MTU`, `Table`, `PreUp`/`PostUp`/`PreDown`/`PostDown`, `SaveConfig`)를 읽습니다. 키는 대소문자 구분 없음,
  `#` 주석, 쉼표 목록, 목록 키 반복 허용. 오류는 `line N: 이유`로 알려 줍니다. IPv6 엔드포인트는
  `[addr]:port`, 이름 엔드포인트는 `endpointHost`에 두었다가 `ResolveWgConfigEndpoints`로 풉니다.
- `WriteWgConfig(cfg, quick)`는 같은 형식으로 쓰며 `quick=false`면 `wg setconf`가 받는 키만 씁니다.
  쓰고 다시 읽으면 같은 텍스트가 됩니다.
- `GenerateWgClientConfig`: 서버 공개 키, 서버 엔드포인트, 클라이언트 주소를 받아 클라이언트 키(와 PSK)를
  만들고, 공식 Windows/macOS/iOS/Android 앱이 가져오는 설정 텍스트(주석·빈 줄을 최소화해 QR 코드에 담기
  좋음, 예: `qrencode -t ansiutf8 < client.conf`)와 서버에 추가할 `[Peer]`(클라이언트 주소의 /32,/128)를
  돌려줍니다. 기본 AllowedIPs는 `0.0.0.0/0, ::/0`, keepalive 25초입니다. 이 OS들의 공식 앱은 별도 드라이버
  설치 없이 이 설정으로 접속합니다.

## 오버레이 네트워크 드라이버 (`wg-overlay`)

여러 호스트에 걸친 컨테이너 네트워크입니다. 각 호스트는 네트워크 대역의 한 부분(호스트 서브넷)을
맡고, 다른 호스트를 WireGuard 피어로 둡니다.

```
 호스트 1 (10.210.1.0/24)                         호스트 2 (10.210.2.0/24)
 c1 10.210.1.2 ─veth─ wgb-<id> 10.210.1.1          wgb-<id> 10.210.2.1 ─veth─ c2 10.210.2.2
                         │ 라우팅                          │
                    wgo-<id> ═══ WireGuard(UDP 51820) ═══ wgo-<id>
                     route 10.210.2.0/24 dev wgo-<id> src 10.210.1.1
```

- **등록**: `mgr.registerDriver(std::make_shared<CWgOverlayDriver>())`.
- **네트워크 생성**: `MakeWgOverlayNetwork(name, overlay, config, request)`가 `SNetworkCreate`를 채웁니다:
  서브넷 = 전체 오버레이 대역, IPAM 범위 = 호스트 서브넷의 첫 주소+1 ~ 브로드캐스트-1, 게이트웨이 = 호스트
  서브넷 첫 호스트 주소(브릿지), 옵션 `sbox.wg.overlay`(JSON)와 `com.docker.network.driver.mtu`.
  설정은 `sbox.wg.overlay.file`로 파일에서 읽을 수도 있습니다.
- **createNetwork**: 설정 검증(호스트 서브넷이 오버레이 안, 게이트웨이가 호스트 서브넷 안, 피어 서브넷이
  오버레이 안이고 서로/호스트 서브넷과 겹치지 않음) → 개인 키가 든 설정을 `<stateDir>/wg-overlay/<id>.json`
  (0600)에 저장하고 네트워크 옵션에는 개인 키를 뺀 JSON만 남김 → 브릿지 `wgb-<id 8자>`(게이트웨이 주소,
  호스트 서브넷 길이) → `ip_forward=1` → WireGuard 장치 `wgo-<id 8자>`(호스트 netns, `mode`에 따라 커널/
  사용자 공간, 사용자 공간이면 UAPI 소켓 제공) → 피어 서브넷마다 `route <subnet> dev wgo src <gateway>`
  (호스트 자신이 보내는 패킷도 상대가 되돌려 보낼 수 있는 주소로 나가게) → NAT(아래). 실패하면 만든 것을
  되돌립니다.
- **엔드포인트**: 브릿지 드라이버처럼 veth 쌍을 브릿지에 붙입니다. 주소는 호스트 서브넷 안이어야 하고
  (`-EADDRNOTAVAIL`) 접두사 길이를 호스트 서브넷 길이로 바꿔 저장합니다(컨테이너의 on-link 범위).
  join 때 주소, MTU, `오버레이 대역 via 게이트웨이`, (internal이 아니면) 기본 경로를 설정합니다. 그래서
  다른 호스트로 가는 트래픽은 L3로 라우팅되어 WireGuard로 암호화되고, 브로드캐스트/ARP는 호스트 밖으로
  나가지 않습니다. `joinInfo`는 Docker 방식 join을 위해 오버레이 경로를 static route로 줍니다.
- **MTU**: 기본 1420(언더레이 1500 - 80). 브릿지, veth, 컨테이너 인터페이스에 같은 값을 씁니다.
- **NAT**(`nat`, 기본 true, internal 네트워크 제외): 드라이버 전용 nftables 테이블 `inet sboxwg_<id 8자>`에
  `postrouting`(nat, priority 100) 체인 하나와 규칙
  `meta nfproto ipv4 ip saddr <호스트 서브넷> ip daddr != <오버레이> oifname != <브릿지> masquerade`를
  둡니다. 오버레이 안의 트래픽은 원래 주소를 유지합니다. net 모듈의 `sbox` 테이블과 독립적입니다.
- **실행 중 호스트 추가/제거**: `addHost(mgr, network, host)` / `removeHost(mgr, network, key)`는 상태
  파일을 잠금(`<id>.lock`) 아래에서 고치고, 장치가 이 프로세스에 있으면 직접, 커널 장치면 genl로, 다른
  프로세스의 사용자 공간 장치면 UAPI 소켓으로 피어를 바꾼 뒤 경로를 추가/삭제합니다. 같은 공개 키로
  addHost하면 갱신(서브넷이 바뀌면 이전 경로 삭제)입니다. `config()`, `status()`로 읽습니다.
- **restore(mgr)**: 데몬 재시작이나 재부팅 뒤 장치가 없는 오버레이 네트워크의 WireGuard 장치를 상태
  파일로 다시 만듭니다(다른 프로세스가 돌리는 사용자 공간 장치는 UAPI로 다시 설정하고 건너뜀).
- **deleteNetwork**: 장치(이 프로세스의 것은 close, 아니면 이름으로 링크 삭제), 브릿지, NAT 테이블, 상태
  파일을 지웁니다.

### 설정 형식 (JSON)

```json
{
  "privateKey": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
  "listenPort": 51820,
  "hostSubnet": "10.210.1.0/24",
  "interface": "wgo-custom",          // 선택, 기본 wgo-<id 8자>
  "bridge": "wgb-custom",             // 선택, 기본 wgb-<id 8자>
  "mode": "auto",                     // auto | kernel | userspace
  "mtu": 1420,                        // 선택, 기본 1500-80
  "nat": true,
  "peers": [
    { "name": "host-2", "publicKey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
      "presharedKey": "...", "endpoint": "192.0.2.2:51820", "subnet": "10.210.2.0/24",
      "persistentKeepalive": 25 }
  ]
}
```

(주석은 설명용이며 실제 JSON에는 쓰지 않습니다.) 같은 형식이 상태 파일 `<stateDir>/wg-overlay/<network id>.json`
에도 쓰입니다(개인 키 포함, 0600).

### 사용 예

```cpp
net::CNetworkManager mgr(opts);
auto drv = std::make_shared<vpn::CWgOverlayDriver>();
mgr.registerDriver(drv);

vpn::SWgOverlayConfig c;
c.privateKey = key;
c.hostSubnet = 10.210.1.0/24;
c.peers.push_back({ "host-2", key2pub, {}, "192.0.2.2:51820", 10.210.2.0/24, 25 });
net::SNetworkCreate req;
vpn::MakeWgOverlayNetwork("ov", 10.210.0.0/16, c, req);
co_await mgr.createNetwork(req, net);
co_await mgr.connect("ov", "/var/run/netns/<container>", ep, out);
co_await drv->addHost(mgr, "ov", host3);     // 실행 중 호스트 추가
```

## `sbox-wg`

| 명령 | 동작 |
|---|---|
| `genkey` / `genpsk` | 새 개인 키 / PSK를 base64로 출력 |
| `pubkey` | 표준 입력의 개인 키에서 공개 키 |
| `up <설정> [--name IF] [--netns PATH] [--mode auto\|kernel\|userspace] [--uapi-dir DIR]` | wg-quick 파일로 인터페이스를 만들고(Address, MTU, allowed IP 경로(/0 제외), `Table = off`면 경로 없음) 설정합니다. 커널이면 설정 후 종료, 사용자 공간이면 wireguard-go처럼 전경에서 돌며 SIGINT/SIGTERM(signalfd)에 인터페이스를 지우고 끝납니다. 이름 기본값은 파일 이름에서 `.conf`를 뺀 것 |
| `show [IF] [--netns] [--uapi-dir]` | `wg show` 형식. 이름이 없으면 커널 `wireguard` 링크와 UAPI 소켓을 모두 |
| `showconf IF` | 장치 설정을 `wg showconf` 형식으로 |
| `client-config --endpoint HOST[:PORT] --address CIDR (--server-config FILE \| --server-key KEY) [--dns] [--allowed-ips] [--keepalive N] [--mtu N] [--no-psk] [--append-to FILE]` | 공식 앱용 클라이언트 설정을 출력하고, 서버 측 `[Peer]`는 표준 오류로 출력하거나 서버 파일에 덧붙임. `--server-config`이면 포트를 생략할 수 있음 |

## 테스트

`ctest --test-dir build -L vpn`의 `vpn_wg_*` 8개 실행 파일:

- `noise`: 독립 구현(Python의 hashlib BLAKE2s, `cryptography`의 X25519/ChaCha20-Poly1305, 별도 HChaCha20)으로
  만든 고정 입력의 알려진 답과 시작/응답 메시지, 전송 키, 첫 데이터 메시지, 쿠키 응답, MAC2를 바이트
  단위로 비교. RFC 7748 X25519 벡터와 base64, 저차 점 거부, TAI64N.
- `engine`: 메모리 안 두 엔진과 가상 시계로 핸드셰이크, 양방향 데이터와 패딩, PSK 유무, 재전송/위조 거부,
  창 안 순서 뒤바뀜, allowed IP 위반, REKEY_AFTER_TIME 재협상과 만료 후 새 핸드셰이크, 재시도 횟수와
  포기, 부하 상태 쿠키 왕복(MAC2로 완료), 속도 기반 부하 감지, 로밍, 수동/지속 keepalive, 피어 관리,
  개인 키 변경.
- `allowedips`: IPv4/IPv6 최장 일치, 소유 이동, 소유자별 삭제, 선형 탐색과의 무작위 비교, 재전송 창.
- `config`: 파싱, 쓰기-다시 읽기 왕복, 오류 줄 번호, 클라이언트 설정.
- `kernel`: SET_DEVICE 인코딩(속성·중첩 플래그·sockaddr·allowed IP), 큰 설정 분할, GET 요청과 다중 응답
  병합 디코딩, UAPI 텍스트 왕복.
- `device`: 임시 netns 두 개를 veth로 잇고 각 netns의 TUN에서 사용자 공간 장치를 돌려, `CNetns::run`
  자식(한쪽 netns)에서 다른 쪽으로 512KiB TCP 에코, 상태/통계, 세션 재사용, 포트 변경 후 로밍, 종료 시
  인터페이스 삭제. wg-quick 설정 적용과 경로(/0 제외), UAPI get/set. 커널 경로는 모듈이 없으면
  MESSAGE로 건너뛰고 `EWGM_KERNEL` 거부와 `EWGM_AUTO` 대체만 확인. `wg`/`wireguard-go`가 있으면
  상호 운용 테스트(없으면 건너뜀).
- `overlay`: 두 "호스트" netns(언더레이 veth)와 각 호스트의 CNetworkManager·드라이버, 컨테이너 netns를
  붙여 컨테이너 간 TCP(양방향), 호스트→원격 컨테이너, 실행 중 addHost/removeHost, 겹치는 서브넷 거부,
  정리 후 링크와 상태 파일이 남지 않음, 파일 설정과 잘못된 설정 거부, restore.
- `cli`: `sbox-wg` genkey/pubkey/genpsk/client-config(`--append-to`), netns 안에서 `up`을 띄우고
  `show`/`showconf`로 읽은 뒤 SIGTERM으로 깨끗하게 끝나는지.

모든 커널 기능 테스트는 루트, netns, `/dev/net/tun`을 먼저 확인하고 없으면 MESSAGE를 남기고 건너뜁니다.
netns는 `mkdtemp` 디렉터리에 만들고 지웁니다.

## 제한 사항

- **제어 평면 없음**: 오버레이 피어 자동 발견(호스트 목록 배포, 키 교환)은 없습니다. 정적 설정과
  `addHost`/`removeHost` API로 관리합니다.
- **오버레이는 IPv4 서브넷만** 라우팅합니다(WireGuard 터널과 언더레이는 IPv6도 지원). 이 환경 커널이
  `ipv6.disable=1`이라 IPv6 종단 간 테스트는 하지 않았습니다.
- 오버레이 WireGuard 장치는 호스트 netns에만 둡니다(전용 netns 옵션 없음). 사용자 공간 장치는 네트워크를
  만든(또는 `restore()`한) 프로세스의 이벤트 루프에서 돌므로, 그 프로세스(플러그인 데몬 등)가 살아 있어야
  합니다. 일회성 CLI 프로세스로 만든 사용자 공간 오버레이는 그 프로세스가 끝나면 사라지며 `restore()`로
  다시 띄워야 합니다.
- NAT와 별개로 호스트의 다른 방화벽(FORWARD 정책 DROP 등)은 건드리지 않습니다.
- `sbox-wg up`은 wg-quick의 DNS 설정(resolvconf), 기본 경로(`0.0.0.0/0`)용 정책 라우팅(fwmark + 별도 테이블),
  `PreUp`/`PostUp` 훅 실행을 하지 않습니다. `/0` allowed IP는 경로 없이 cryptokey routing에만 쓰입니다.
- 사용자 공간 장치: 송신 원본 주소 고정(sticky source, 다중 주소 호스트), GSO/GRO, 다중 큐 TUN, 다중
  스레드 암호화는 없습니다. 핸드셰이크는 이벤트 루프 스레드에서 동기 처리하며 과부하는 쿠키/토큰
  버킷으로만 막습니다. ICMP 도달 불가 응답(경로 없는 패킷)은 보내지 않고 버립니다.
- 커널 경로는 이 환경에 모듈이 없어 메시지 인코딩/디코딩 단위 테스트로만 검증했습니다.
- QR 코드 이미지는 만들지 않습니다. 설정 텍스트를 `qrencode` 같은 도구로 바꾸면 됩니다.
- UAPI 소켓 디렉터리는 마운트 네임스페이스 단위라, 서로 다른 netns에 같은 이름의 사용자 공간 장치를 두면
  `uapiDir`을 나눠야 합니다.
