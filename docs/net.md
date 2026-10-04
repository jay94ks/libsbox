# net 모듈

컨테이너 네트워킹 모듈입니다. 네임스페이스 `sbox::net`, 헤더는 `modules/net/include/sbox/net/`,
CMake 타깃은 `sbox::net`(`sbox_add_module(net DEPENDS core)`)입니다. iproute2/iptables/nft 바이너리와
libnl/libmnl 없이 netlink를 직접 다루며, 설계와 상태 형식은 Docker(libnetwork)와 CNI에 맞췄습니다.
명령줄 도구 `cli/sbox-cni`(CNI 플러그인)가 이 모듈 위에 있습니다.

## 구성

| 헤더 | 내용 |
|---|---|
| `address.hpp` | `SIpAddress`, `SIpPrefix`(서브넷 계산), `SMacAddress`, `RandomBytes`/`RandomHex` |
| `netlink.hpp` | `CNlMessage`(메시지/속성 빌더), `SNlAttr`/`CNlAttrs`(파서), `SNlReply`, `CNetlinkSocket`(비동기 요청/ACK, 덤프, 배치, 확장 ACK), `ResolveGenlFamily`(generic netlink) |
| `netns.hpp` | `CNetnsScope`(스레드의 netns 잠시 전환), `CNetns`(영구 netns 생성/삭제, 자식 프로세스 실행) |
| `rtnl.hpp` | `CRtnl`(링크/주소/경로/이웃), `SLinkInfo`, `SAddressInfo`, `SRouteInfo`, `SNeighbourInfo`, `CreateTunTap` |
| `sysctl.hpp` | `/proc/sys` 읽기/쓰기와 ip_forward, route_localnet, bridge-nf-call, disable_ipv6, accept_ra 헬퍼 |
| `nftables.hpp` | `CNftRule`(표현식 빌더), `SFirewallState`, `CFirewall`(nfnetlink 배치로 `sbox` 테이블 교체) |
| `lock.hpp` | `CFileLock`(flock, 이벤트 루프를 막지 않는 대기) |
| `ipam.hpp` | `CIpam`, `SIpamPool`, `SIpamRequest`, `SAddressPool`, `DefaultAddressPools`, `ParseAddressPools` |
| `dhcp.hpp` | `CDhcpClient`(DHCPv4 클라이언트), `SDhcpMessage`, `SDhcpLease` |
| `network.hpp` | `INetworkDriver`, 내장 드라이버 팩토리, `CNetworkManager`, `SNetwork`, `SNetworkEndpoint`, `SPortMapping` |
| `resolv.hpp` | `GenerateHosts`, `GenerateResolvConf`, `ParseResolvConf`, `ContainerResolvConf` |
| `cni.hpp` | `RunCni`(CNI 명령 처리), `SCniRequest`, `CniRequestFromEnvironment` |
| `docker.hpp` | `CDockerPlugin`(Docker 원격 네트워크/IPAM 플러그인 핸들러) |

모든 대기 동작은 호출 스레드의 `CEventLoop`에서 도는 `TTask` 코루틴이며, 결과는 `SBOX_OK` 또는 음수
errno입니다.

## netlink

- `CNetlinkSocket::open(protocol, netnsPath)`는 `NETLINK_ROUTE`/`NETLINK_NETFILTER`/`NETLINK_GENERIC`
  소켓을 지정한 netns 안에서 만듭니다. 소켓은 만들어진 netns에 영구히 묶이므로 이후 작업은 모두 그
  netns에 적용됩니다.
- 요청마다 고유한 시퀀스 번호를 쓰고, 다른 시퀀스(시간 초과된 이전 요청)의 응답과 커널(포트 0) 이외의
  송신자는 버립니다. 한 소켓을 여러 코루틴이 동시에 써도 요청이 차례로 직렬화됩니다.
- `request()`는 ACK까지, `dump()`는 `NLMSG_DONE`까지 다중 응답을 모읍니다(`NLM_F_DUMP_INTR`이면 최대
  4번 재시도). `batch()`는 nfnetlink 배치를 한 데이터그램으로 보내고 ACK를 요청한 메시지마다 응답을
  기다립니다. 배치 헤더에 대한 오류(서브시스템 없음, 커밋 실패)는 배치 전체의 실패로 처리합니다.
- `NETLINK_EXT_ACK`/`NETLINK_CAP_ACK`를 켜서 실패 시 커널의 확장 ACK 문자열(예: "Unknown device
  type")을 `lastError()`로 돌려줍니다.
- 속성 빌더는 4바이트 정렬, 중첩 속성(`NLA_F_NESTED`), big-endian 정수, 주소 속성을 지원하고, 파서는
  잘린 입력에서 깨끗하게 읽힌 부분까지만 돌려줍니다.
- `ResolveGenlFamily(socket, name, out)`은 `CTRL_CMD_GETFAMILY`로 id, 버전, 멀티캐스트 그룹을
  얻습니다(vpn 모듈의 WireGuard용). 등록되지 않은 패밀리는 `-ENOENT`입니다(일부 커널의 `EINVAL`도
  `-ENOENT`로 바꿉니다). `CNlMessage::genl()`이 genlmsghdr가 붙은 메시지를 만듭니다.

## 네트워크 네임스페이스

### 다른 netns에서 일하는 방법

1. **`CNetnsScope`(기본)**: 호출 스레드를 `setns(CLONE_NEWNET)`로 잠깐 전환했다가 소멸자에서 되돌립니다.
   소켓(netlink, packet, TCP listen), `/dev/net/tun`, `/proc/sys/net` 파일은 열 때의 netns에 묶이므로
   "전환 → socket()/open() → 복귀" 후 비동기 작업은 그 디스크립터로 이어 갑니다. 이벤트 루프 스레드에서
   써도 안전한 이유는 범위 안에서 `co_await`하지 않기 때문입니다. **범위를 `co_await` 너머로 유지하면
   안 됩니다**(같은 루프의 다른 코루틴이 잘못된 netns에서 돌게 됨). 복귀에 실패하면 잘못된 네트워크를
   설정하는 대신 프로세스를 중단(abort)합니다.
2. **`CNetns::run(path, fn)`**: 짧게 사는 자식 프로세스를 fork해 `setns` 후 `fn`을 실행하고, 결과를
   파이프로 받아 pidfd로 기다립니다. 블로킹 호출이나 중첩 이벤트 루프처럼 전체가 그 netns 안에 있어야
   하는 일에 씁니다. 스레드가 있는 프로세스에서는 쓰지 않습니다.

### 영구 netns

- `CNetns::create(path)`: 새 netns를 `unshare(CLONE_NEWNET)`로 만들고 `/proc/thread-self/ns/net`을
  `path`(새 일반 파일)에 bind mount한 뒤 원래 netns로 돌아옵니다. iproute2(`/var/run/netns/<이름>`),
  Docker(`/var/run/docker/netns/<id>`)와 같은 형식이라 서로 호환됩니다.
- `CNetns::createNamed(name, out, dir)`: `ip netns add`처럼 디렉터리를 먼저 자기 자신에 bind mount하고
  shared 전파로 바꿔 다른 마운트 네임스페이스에도 보이게 합니다. 기본 디렉터리 상수
  `CNetns::IPROUTE2_DIR`, `CNetns::DOCKER_DIR`.
- `CNetns::remove(path)`: `umount2(MNT_DETACH)` 후 unlink. 없으면 성공입니다.
- `createAnonymous`, `open`, `openCurrent`, `inode`, `isNetns`(nsfs이고 netns 타입인지)도 있습니다.

## rtnetlink (`CRtnl`)

- 링크: `listLinks`, `getLink`(이름), `getLinkByIndex`, `linkIndex`, `createLink`(일반), `createBridge`,
  `createVeth`(피어를 다른 netns에 바로 생성 가능), `createMacvlan`(bridge/private/vepa/passthru),
  `createIpvlan`(l2/l3/l3s), `createVxlan`, `createDummy`, `setUp`, `setMtu`, `setMac`, `setMaster`
  (0이면 해제), `moveToNetnsFd`(이동하며 이름 변경 가능), `moveToNetnsPid`, `rename`, `deleteLink`,
  `setBridgePort`(hairpin, isolated).
- 주소: `addAddress`(IPv4는 브로드캐스트 자동, IPv6는 `IFA_F_NODAD`), `delAddress`, `listAddresses`.
- 경로: `addRoute`/`delRoute`(기본 경로와 접두사 경로, 게이트웨이 없으면 link scope, 테이블, metric,
  prefsrc, MTU), `listRoutes`, `addDefaultRoute`.
- 이웃: `setNeighbour`, `listNeighbours`.
- `CreateTunTap(name, options, fd)`: `/dev/net/tun`의 `TUNSETIFF`로 TUN/TAP을 만듭니다. 장치는 ioctl을
  호출한 스레드의 netns에 생기므로 `options.netnsPath` 안에서 만듭니다. persist, owner/group, multi
  queue, `%d` 이름 패턴을 지원합니다.
- 다른 netns의 작업은 그 netns로 연 `CRtnl`을 씁니다(`open(netnsPath)`).

## sysctl

`ReadSysctl`/`WriteSysctl`은 `net.ipv4.ip_forward`나 `net/ipv4/ip_forward` 형식 이름을 받습니다.
`/proc/sys/net`은 파일을 여는 스레드의 netns 값을 보여 주므로 `netnsPath`가 주어지면 그 netns에서 엽니다.
헬퍼: `SetIpForward`, `SetIpv6Forward`, `SetRouteLocalnet(if)`, `SetBridgeNfCall`(bridge-nf-call-ip(6)tables),
`SetIpv6Disabled(if)`, `SetAcceptRa(if)`.

## nftables 방화벽

`NETLINK_NETFILTER`의 `NFNL_SUBSYS_NFTABLES` 배치 메시지로 직접 규칙을 씁니다. libsbox는 **자기
테이블(`inet sbox`, 이름 변경 가능)만** 다루고 다른 테이블은 건드리지 않습니다.

`CFirewall::apply(state)`는 한 배치에서 `add table; delete table; add table; 체인; 규칙`을 보내므로
원자적이고 멱등입니다. 실패하면 이전 규칙이 그대로 남습니다. `remove()`는 `add table; delete table`
입니다. nfnetlink나 nf_tables가 없으면 `-ENOTSUP`을 돌려줍니다.

생성되는 규칙(nft 문법으로 표현):

```
table inet sbox {
  chain portmap { }                                           # 일반 체인
  chain prerouting  { type nat hook prerouting priority -100; policy accept;
                      fib daddr type local jump portmap }
  chain output      { type nat hook output priority -100; policy accept;
                      fib daddr type local jump portmap }
  chain postrouting { type nat hook postrouting priority 100; policy accept;
                      meta nfproto ipv4 ip saddr <subnet> oifname != <bridge> masquerade    # 네트워크/서브넷마다
                      meta nfproto ipv4 ip saddr 127.0.0.0/8 oifname <bridge> masquerade }  # 루프백 → 포트 매핑
  chain forward     { type filter hook forward priority 0; policy accept;
                      ct state established,related accept
                      iifname <A> oifname != <A> drop; iifname != <A> oifname <A> drop     # internal 네트워크
                      iifname <A> oifname <A> drop                                         # ICC 끔
                      iifname <A> oifname <B> drop }                                       # 네트워크 간 격리
  # portmap 체인의 포트 매핑마다:
  #   meta nfproto ipv4 [ip daddr <hostIp>] iifname != <bridge> meta l4proto tcp th dport <hp>
  #     dnat ip to <containerIp>:<cp>
}
```

- 포트 매핑은 Docker의 `-m addrtype --dst-type LOCAL -j DOCKER`과 같이 로컬 주소로 오는 연결(외부 유입은
  prerouting, 호스트 자신은 output)을 DNAT합니다. `127.0.0.1:<hp>` 연결은 브릿지의 `route_localnet=1`과
  127/8 masquerade 규칙으로 동작합니다(Docker의 userland-proxy=false 방식).
- `CNftRule`은 nft가 단순 규칙을 컴파일하는 방식(레지스터 1, NAT 포트는 레지스터 2)으로 표현식
  (`meta`, `cmp`, `payload`, `bitwise`, `ct`, `fib`, `immediate`, `nat`, `masq`, `counter`)을 만들며,
  vpn 같은 다른 모듈도 `CFirewall::send()`로 직접 배치를 보낼 수 있습니다.
- 정책은 모두 accept이므로 호스트에 다른 방화벽(예: Docker가 `FORWARD` 정책을 DROP으로 바꾼 iptables)이
  있으면 그쪽에서 허용해야 트래픽이 지나갑니다.

## IPAM (`CIpam`)

- 기본 풀은 Docker의 `default-address-pools`와 같습니다: 172.17/16, 172.18/16, 172.19/16,
  172.20.0.0/14·172.24.0.0/14·172.28.0.0/14를 /16으로, 192.168.0.0/16을 /20으로 나눕니다.
  `ParseAddressPools`로 daemon.json 형식(`[{"base":..., "size":...}]`)을 읽어 바꿀 수 있고 IPv6 풀도 넣을
  수 있습니다(기본 IPv6 풀은 없음 → 서브넷을 명시하지 않은 IPv6 요청은 `-ENOSPC`).
- `requestPool`: 명시 서브넷은 같은 주소 공간(space)의 기존 풀과 겹치면 `-EADDRINUSE`, 자동 선택은 기존
  풀과 `avoid`(호스트 경로)에 겹치지 않는 첫 서브넷입니다. 할당 범위는 `range`(Docker `--ip-range`) 또는
  `rangeStart`/`rangeEnd`(CNI)로 좁힐 수 있고, 게이트웨이(지정 또는 첫 호스트 주소)와 aux 주소를 예약합니다.
- `requestAddress`: 지정 주소(점유 시 `-EADDRINUSE`) 또는 마지막 할당 다음부터 순환 탐색합니다. 네트워크
  주소, IPv4 브로드캐스트, 게이트웨이, 예약 주소는 자동 할당에서 빠집니다. 소유자 문자열(엔드포인트 id)을
  함께 저장하며 `releaseOwner`/`findOwner`로 찾습니다.
- **물리 IP 할당**: macvlan/ipvlan 네트워크에 LAN 서브넷·게이트웨이·범위를 주면 같은 IPAM이 그 범위에서
  정적 주소를 나눠 줍니다. DHCP는 아래 `CDhcpClient`를 씁니다.

### 상태 파일

`<stateDir>/ipam/ipam.json`(0600, `CFile::writeAtomic`), 잠금 `<stateDir>/ipam/ipam.lock`(flock). 호출마다
잠금을 잡고 읽기-수정-쓰기를 한 번에 하므로 여러 프로세스가 같은 디렉터리를 써도 안전합니다(테스트에서
4개 프로세스 동시 할당으로 확인).

```json
{ "version": 1,
  "pools": [ { "id": "local/172.17.0.0/16", "space": "local", "subnet": "172.17.0.0/16",
               "rangeStart": "172.17.0.0", "rangeEnd": "172.17.255.255", "gateway": "172.17.0.1",
               "reserved": [], "allocated": { "172.17.0.2": "<endpoint id>" },
               "last": "172.17.0.2", "dynamic": true, "labels": {} } ] }
```

## DHCP 클라이언트 (`CDhcpClient`)

- `AF_PACKET`/`SOCK_DGRAM`(ETH_P_IP) 소켓을 인터페이스에 묶고 IPv4/UDP 헤더를 직접 만듭니다. 주소가 없는
  인터페이스에서도 동작하고 UDP 68번 포트를 점유하지 않아 여러 컨테이너가 동시에 쓸 수 있습니다.
- `acquire`: DISCOVER(브로드캐스트 플래그) → OFFER → REQUEST(selecting, requested-ip/server-id) → ACK,
  재전송 간격 1·2·4초, NAK이면 새 트랜잭션으로 다시 시작합니다. `renew`는 ciaddr를 채운 REQUEST를 서버
  MAC/IP로 유니캐스트, `rebind`는 브로드캐스트, `release`는 RELEASE를 유니캐스트합니다.
- 임대 정보 `SDhcpLease`: 주소/접두사(옵션 1), 라우터(3), DNS(6), 도메인(15), MTU(26), 임대/T1/T2
  (51/58/59, 기본값 lease/2, lease×7/8), 서버 식별자(54)와 서버 MAC. JSON으로 엔드포인트에 저장됩니다.
- 옵션 인코딩은 RFC 2132, 255바이트가 넘는 옵션은 RFC 3396 방식으로 나누고 합칩니다.

## 네트워크와 드라이버

### `CNetworkManager`

`SNetworkManagerOptions{ stateDir, hostNetns, pools, firewall, avoidHostRoutes, firewallTable }`로
만듭니다. `hostNetns`는 "호스트"로 취급할 netns이며 비우면 현재 netns입니다(테스트는 임시 netns를 씀).

| 호출 | 내용 |
|---|---|
| `createNetwork(SNetworkCreate, SNetwork&)` | 서브넷 할당(`ipamDriver`가 `"sbox"`일 때) → 드라이버 생성 → 저장 → 방화벽 갱신 |
| `deleteNetwork(idOrName)` | 엔드포인트가 있으면 `-EBUSY` |
| `getNetwork` / `listNetworks` | id, 고유한 id 접두사, 이름으로 찾기 |
| `createEndpoint(network, SEndpointCreate, out)` | 주소 할당(요청 주소 우선), MAC(브릿지는 Docker처럼 `02:42:<IPv4>`), 호스트 쪽 인터페이스 |
| `join(endpointId, netnsPath, ifName, out)` | 인터페이스를 netns로 옮기고 이름(비우면 다음 빈 `ethN`)·MAC·MTU·주소·up·기본 경로 설정 |
| `joinInfo(endpointId, SJoinInfo&)` | 인터페이스를 직접 옮기는 쪽(Docker)을 위한 SrcName/게이트웨이 |
| `leave` / `deleteEndpoint` | 인터페이스를 호스트로 되돌림 / 삭제와 주소 반환 |
| `setPortMappings(endpointId, ports)` | 포트 매핑 교체(호스트 포트 0은 32768-60999에서 빈 포트) |
| `connect(network, netnsPath, req, out, ifName)` | create + join (box/oci 계층이 쓰는 호출) |
| `disconnect(network, containerId)` | 그 컨테이너의 엔드포인트를 leave + delete (network가 비면 모든 네트워크) |
| `syncFirewall()` | 저장된 상태로 `sbox` 테이블 재생성 |
| `registerDriver(INetworkDriverPtr)` | 드라이버 추가(vpn 모듈의 overlay) |

변경 호출은 모두 `<stateDir>/net.lock`(flock)을 잡고 진행하므로 CLI, CNI 호출, 플러그인 데몬이 같은 상태
디렉터리를 공유할 수 있습니다. 기본 상태 디렉터리 `DefaultNetworkStateDir()`: 루트는 `/var/lib/sbox/net`,
아니면 `$XDG_RUNTIME_DIR/sbox/net`.

nf_tables가 없을 때: 포트 매핑이 없는 네트워크는 NAT/격리 없이 만들어지고, 포트 매핑을 요구하는 호출만
`-ENOTSUP`으로 실패합니다.

### 상태 파일

- `<stateDir>/networks/<id>.json` (Docker inspect와 비슷한 필드):
  `{"Id","Name","Driver","Created","EnableIPv6","Internal","IPAM":{"Driver","Config":[{"Subnet","Gateway","PoolID"}]},"Options","Labels","DriverState"}`
- `<stateDir>/endpoints/<id>.json`:
  `{"Id","NetworkId","ContainerId","Addresses","Gateways","MacAddress","HostInterface","SandboxInterface","SandboxKey","Ports":[{"Proto","HostIp","HostPort","ContainerPort"}],"Aliases","Mtu","Joined","Labels","DriverState"}`
- `<stateDir>/ipam/ipam.json`(위 참조), 잠금 `net.lock`, `ipam/ipam.lock`.

### `INetworkDriver`

Docker 원격 드라이버의 생명 주기를 따릅니다: `createNetwork` → `createEndpoint`(호스트 netns에 인터페이스)
→ `join`(샌드박스로 이동·설정) → `leave` → `deleteEndpoint` → `deleteNetwork`. `usesIpam()`,
`usesFirewall()`, `usesGateway()`로 관리자가 할 일을 정합니다. `joinInfo()`는 기본 구현이
`driverState.peer`(또는 hostIfName)와 게이트웨이를 돌려줍니다. 드라이버 전용 정보는
`SNetwork::driverState`/`SNetworkEndpoint::driverState`(JSON 객체)에 저장합니다.

### 내장 드라이버와 옵션

| 드라이버 | 동작 | 옵션 |
|---|---|---|
| `bridge` | 리눅스 브릿지(기본 이름 `br-<id 12자>`, 이미 있으면 채택), 게이트웨이 주소, ip_forward, route_localnet, veth 쌍(`veth`+7hex), NAT·포트 매핑·격리 | `com.docker.network.bridge.name`, `com.docker.network.driver.mtu`, `com.docker.network.bridge.enable_ip_masquerade`(기본 true), `com.docker.network.bridge.enable_icc`(기본 true, false면 bridge-nf-call 켬), `com.docker.network.bridge.host_binding_ipv4`, `internal` |
| `macvlan` | 부모 인터페이스 위 macvlan(임시 이름 `mv`+7hex로 만들고 join 때 이동) | `parent`(필수), `macvlan_mode`(bridge/private/vepa/passthru), `sbox.dhcp=true`(DHCP로 물리 IP), `sbox.dhcp.timeout`(ms) |
| `ipvlan` | ipvlan(L3/L3S는 장치 기본 경로) | `parent`(필수), `ipvlan_mode`(l2/l3/l3s) |
| `host` | 아무것도 만들지 않음(샌드박스가 호스트 netns를 씀) | |
| `none`(`null`) | 루프백만 up | |

DHCP 모드 macvlan은 엔드포인트를 만들 때 호스트 netns의 임시 인터페이스에서 임대를 받고(주소·게이트웨이·
MTU를 엔드포인트에 기록), 삭제할 때 RELEASE를 보냅니다.

### hosts / resolv.conf

`GenerateHosts(hostname, addresses, extra, aliases, ipv6)`와 `ContainerResolvConf(hostResolvConf,
hostNetwork, ipv6, dns, search, options)`는 내용 문자열만 만들고 파일 쓰기는 oci/box 계층이 합니다.
`ContainerResolvConf`는 Docker처럼 루프백 nameserver(127.0.0.53 등)를 빼고, 남는 것이 없으면
8.8.8.8/8.8.4.4(ipv6이면 Google IPv6 서버 추가)를 씁니다.

### box/oci 계층에서의 사용

```cpp
SNetworkManagerOptions o;
o.stateDir = DefaultNetworkStateDir();
CNetworkManager mgr(o);
SEndpointCreate req;
req.containerId = id;
req.ports = { ... };
SNetworkEndpoint ep;
co_await mgr.connect("mynet", "/var/run/netns/<id>", req, ep);   // 컨테이너 netns 경로
// ... 컨테이너 종료 후
co_await mgr.disconnect("mynet", id);
```

컨테이너 netns는 `CNetns::create`로 만든 경로를 box의 `EBNET_NAMESPACE`나 OCI config.json의 network
namespace 경로로 넘기면 됩니다.

## CNI 플러그인 (`cli/sbox-cni`)

- 명세 1.0.0의 ADD/DEL/CHECK/VERSION을 구현합니다. 설정의 `cniVersion`은 0.3.0, 0.3.1, 0.4.0, 1.0.0을
  받고(1.1의 STATUS/GC는 코드 4로 거부), 1.0.0 미만이면 결과의 `ips`에 `version`을 넣습니다. CHECK는
  0.4.0 이상만.
- 환경: `CNI_COMMAND`, `CNI_CONTAINERID`, `CNI_NETNS`, `CNI_IFNAME`, `CNI_ARGS`(`IP=`, `MAC=` 지원, 나머지
  무시), `CNI_PATH`. 설정 JSON은 stdin.
- 설정 예(`type`은 바이너리 이름):

```json
{ "cniVersion": "1.0.0", "name": "podnet", "type": "sbox-cni",
  "driver": "bridge", "bridge": "cni0", "ipMasq": true, "mtu": 1450,
  "stateDir": "/var/lib/sbox/net",
  "ipam": { "type": "sbox", "ranges": [[{ "subnet": "10.99.0.0/24", "rangeStart": "10.99.0.10", "gateway": "10.99.0.1" }]],
            "routes": [{ "dst": "0.0.0.0/0" }, { "dst": "192.0.2.0/24" }] },
  "capabilities": { "portMappings": true },
  "runtimeConfig": { "portMappings": [{ "hostPort": 8080, "containerPort": 80, "protocol": "tcp" }] } }
```

  macvlan/ipvlan은 `"driver":"macvlan"`, `"master":"eth0"`, `"mode":"bridge"`, ipam은 `subnet`/`rangeStart`/
  `rangeEnd`/`gateway`(물리 IP 정적 할당) 또는 `"ipam":{"type":"dhcp"}`. `ipam.type`은 `sbox`,
  `host-local`(같은 의미), `dhcp`를 받습니다. `stateDir`이 없으면 `ipam.dataDir`, 그것도 없으면
  `DefaultNetworkStateDir()`.
- 네트워크는 첫 ADD에서 만들어지고(동시 ADD 경쟁은 -EEXIST 후 재조회) 계속 남습니다. 엔드포인트는
  `ContainerId`와 라벨 `io.cni.ifname`으로 다시 찾으므로 DEL/CHECK가 상태만으로 동작하고, DEL은 netns가
  사라졌거나 엔드포인트가 없어도 성공합니다. 같은 (컨테이너, 인터페이스)로 같은 netns에 ADD가 다시 오면
  기존 결과를 돌려줍니다.
- 결과: bridge는 `interfaces`가 [브릿지, 호스트 veth, 샌드박스 인터페이스], macvlan/ipvlan은 [샌드박스
  인터페이스]. `ips[].interface`는 샌드박스 인터페이스의 인덱스, `routes`는 게이트웨이별 기본 경로와
  설정의 추가 경로, `dns`는 설정의 `dns`를 그대로 돌려줍니다.
- 오류는 `{"cniVersion","code","msg","details"}`와 종료 코드 1. 코드: 1 버전, 3 알 수 없는 컨테이너,
  4 환경 변수, 5 I/O, 6 디코드, 7 설정, 11 주소 고갈(나중에 재시도), 100 작업 실패(details에 errno
  문자열), 101 CHECK 불일치.
- 라이브러리 진입점: `TTask<int32_t> RunCni(SCniRequest, std::string& output)`. `SCniRequest::hostNetns`는
  내장/테스트용으로 "호스트" netns를 지정합니다.

## Docker 원격 네트워크 + IPAM 플러그인

HTTP 서버 연결은 이 모듈에 없습니다(http 모듈과 함께 조정자가 연결). 서버는 다음만 하면 됩니다.

```cpp
CNetworkManager mgr(opts);
CDockerPlugin plugin(mgr);
// POST <path>, JSON body → 응답
CJson reply = co_await plugin.handle(path, body);   // 예: "/NetworkDriver.CreateNetwork"
// Content-Type: CDockerPlugin::contentType()  ("application/vnd.docker.plugins.v1.2+json")
// 상태 코드: CDockerPlugin::isError(reply) ? 500 : 200
```

소켓은 Docker 규약대로 `/run/docker/plugins/<이름>.sock`(또는 `/etc/docker/plugins/<이름>.spec`)에 둡니다.

| 경로 | 동작 |
|---|---|
| `/Plugin.Activate` | `{"Implements":["NetworkDriver","IpamDriver"]}` |
| `/NetworkDriver.GetCapabilities` | `{"Scope":"local","ConnectivityScope":"local"}` |
| `CreateNetwork` | `NetworkID`를 id/이름으로, 일반 옵션(`com.docker.network.generic`)을 드라이버 옵션으로(`sbox.driver`로 bridge/macvlan/ipvlan/wg-overlay 선택. 없으면 bridge, 단 `sbox.wg.overlay`나 `sbox.wg.overlay.file`이 있으면 wg-overlay), `IPv4Data`/`IPv6Data`의 Pool·Gateway·AuxAddresses를 그대로 사용(`ipamDriver: external`) |
| `DeleteNetwork` | 없는 네트워크도 성공 |
| `CreateEndpoint` | Docker가 준 `Interface.Address/AddressIPv6/MacAddress`로 엔드포인트 생성, Docker가 주지 않은 값만 응답(MAC 등) |
| `EndpointOperInfo` | `{"Value":{hostInterface, macAddress, addresses, ports}}` |
| `Join` | `{"InterfaceName":{"SrcName":<veth 피어 또는 macvlan>,"DstPrefix":"eth"},"Gateway","GatewayIPv6","StaticRoutes","DisableGatewayService":false}` -- 인터페이스 이동은 Docker가 함 |
| `Leave`, `DiscoverNew`, `DiscoverDelete` | `{}` |
| `ProgramExternalConnectivity` | `com.docker.network.portmap`(Proto 6/17/132, Port, HostIP, HostPort)을 포트 매핑으로 |
| `RevokeExternalConnectivity` | 포트 매핑 제거 |
| `/IpamDriver.GetCapabilities` | `{"RequiresMACAddress":false,"RequiresRequestReplay":false}` |
| `GetDefaultAddressSpaces` | `local` / `global` |
| `RequestPool` | Pool/SubPool/V6 → `CIpam::requestPool`, `{"PoolID","Pool","Data":{}}` |
| `ReleasePool`, `ReleaseAddress` | 없는 것도 성공 |
| `RequestAddress` | 지정 주소 또는 다음 빈 주소, `RequestAddressType=com.docker.network.gateway`이고 주소가 없으면 첫 호스트 주소 |

그 밖의 경로는 `{"Err":"unsupported plugin call ..."}`입니다.

## 루트 없는 실행

호스트 netns에 브릿지나 veth를 만들려면 초기 사용자 네임스페이스의 `CAP_NET_ADMIN`이 필요합니다
(`CanManageHostNetwork()`). 루트가 아니면 샌드박스는 자기 사용자 네임스페이스의 netns에서 루프백만 쓰는
것이 기본입니다(`BringUpLoopback(netnsPath)`, `none` 드라이버). slirp4netns/pasta 같은 사용자 공간 TCP/IP
경로는 구현하지 않았습니다(아래 제한 사항).

## 테스트

`ctest --test-dir build -L net`: 9개 실행 파일(33개 케이스). 루트와 netns가 필요한 케이스는 먼저 확인하고
없으면 `MESSAGE`를 남기고 건너뜁니다. 커널 기능을 쓰는 테스트는 모두 `mkdtemp` 디렉터리에 만든 임시 netns
안에서만 동작하며(호스트 역할도 임시 netns) 끝나면 지웁니다.

- address: 주소/접두사 파싱, 산술, 겹침, MAC.
- netlink: 속성 인코딩/중첩/정렬/잘린 입력, generic netlink(nlctrl), 확장 ACK, 동시 요청 직렬화.
- rtnl: 브릿지·veth(피어를 다른 netns에 생성)·주소·경로·이웃, veth 너머 TCP 연결(`CNetns::run` 자식에서
  connect), macvlan 모드, ipvlan(없으면 건너뜀), vxlan, TUN/TAP, netns 간 이동, sysctl, 영구/이름 있는 netns.
- nftables: 배치 구조, 임시 netns에 적용/멱등/실패 시 이전 규칙 유지/삭제, 종단 간 DNAT(외부 → 호스트
  포트, 호스트 루프백 → 127.0.0.1), masquerade, 네트워크 간 격리.
- ipam: 기본 풀, 겹침, 범위, IPv6 풀, 순환 할당, 영속성, 4개 프로세스 동시 할당, 파일 잠금.
- dhcp: 메시지 인코딩/디코딩, veth 너머 테스트용 최소 DHCP 서버로 acquire(NAK 후 재시도)/renew/rebind/
  release, 서버 없음 시간 초과.
- network: 브릿지 네트워크 두 개, 엔드포인트, 포트 매핑, 격리, 영속성, leave/join, 정리, internal/ICC,
  none/host, macvlan 정적 물리 IP와 DHCP 물리 IP, hosts/resolv.conf.
- cni: VERSION/오류 코드, 빌드된 `sbox-cni`를 임시 "호스트" netns에서 실행한 ADD/CHECK/DEL(브릿지,
  0.4.0 결과, CNI_ARGS IP, macvlan), 동시 ADD 4개.
- docker: Activate/Capabilities/IPAM 흐름, 네트워크 드라이버 전체 흐름(Docker처럼 SrcName을 옮겨 설정
  후 포트 매핑 연결 확인).

## 제한 사항

- 사용자 공간 네트워킹(slirp4netns/pasta 방식)은 없습니다. 루트가 아니면 루프백만 제공합니다.
- 같은 브릿지의 컨테이너가 호스트 주소의 공개 포트로 접속하는 hairpin NAT는 지원하지 않습니다(Docker의
  userland proxy가 하는 일). 같은 네트워크 안에서는 컨테이너 주소로 접속해야 합니다.
- 포트 범위(`HostPortEnd`, `8000-8010:80`)는 첫 포트만 씁니다. SCTP 포트 비어 있음 확인은 소켓을 못 만들면
  건너뜁니다.
- IPv6: 규칙·주소·경로 코드는 있으나 이 개발 환경의 커널은 `ipv6.disable=1`이라 IPv6 종단 간 테스트는
  건너뛰었습니다. IPv6 NAT(masquerade)는 IPv4와 같은 방식으로 생성됩니다. 기본 IPv6 풀은 없습니다.
- dummy 드라이버와 ipvlan이 없는 커널(이 환경)에서는 해당 테스트를 건너뛰고 macvlan 부모로 veth를 씁니다.
- DHCP 임대 갱신은 자동으로 돌지 않습니다. 오래 사는 소유자(플러그인 데몬)가 `renewTime`에 `renew()`를
  불러야 하며, CNI 경로는 ADD에서 받고 DEL에서 반환만 합니다. packet 소켓에 BPF 필터를 붙이지 않아
  인터페이스의 모든 IPv4 패킷을 사용자 공간에서 거릅니다. ipvlan은 DHCP 모드를 지원하지 않습니다
  (`-ENOTSUP`, 부모와 MAC 공유).
- macvlan 부모의 VLAN 하위 인터페이스 자동 생성(`parent=eth0.100`)과 부모가 없을 때의 dummy 생성은
  하지 않습니다.
- CNI: 범위 집합마다 첫 범위만 씁니다. 이미 있는 네트워크의 설정이 바뀌어도 반영하지 않습니다(이름으로
  재사용). `isGateway`/`isDefaultGateway`/`hairpinMode`는 무시하며 게이트웨이와 기본 경로는 항상 설정합니다.
  STATUS/GC(1.1)는 없습니다.
- Docker 플러그인: HTTP/UNIX 소켓 서버 연결은 http 모듈 쪽 몫이며 이 모듈은 핸들러만 제공합니다. swarm
  (`AllocateNetwork`/`FreeNetwork`, global scope)은 지원하지 않습니다.
- 방화벽 체인 정책은 accept라 호스트의 다른 방화벽 정책(예: iptables FORWARD DROP)을 우회하지 않습니다.
  ICC 차단은 bridge netfilter(`bridge-nf-call-iptables`)가 있어야 동작합니다.
- 네트워크 간 격리 규칙은 네트워크 쌍마다 하나씩(O(n²)) 생성합니다. 네트워크가 수백 개면 집합(set)으로
  바꾸는 것이 낫습니다.
