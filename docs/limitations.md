# 제한 사항과 미구현 사항

libsbox 전체의 제한 사항을 한곳에 모은 문서입니다. 각 항목의 자세한 설명은 해당 모듈 문서의
"제한 사항" 절에 있습니다. 이 문서는 그 절들과 함께 현재 상태로 유지합니다.

## 1. 개발 환경에서 실행 검증하지 못한 것

코드는 있지만 개발 기계(커널 6.18, cgroup v1 하이브리드, 루트)에 기능이나 상대가 없어 실제로 돌려 보지
못한 경로입니다. 해당 테스트는 조건을 확인한 뒤 MESSAGE를 남기고 건너뜁니다.

| 항목 | 이유 | 대신 검증한 것 | 문서 |
|---|---|---|---|
| cgroup v2 한도 파일(`memory.max`, `cpu.max`, `io.max` 등) | v2 트리에 컨트롤러가 없음 | v1 한도, v2 소속·kill·통계·장치 eBPF | [box.md](box.md) |
| 커널 ESP/XFRM 데이터 경로(IKEv2 터널, L2TP 전송 모드) | esp4, xfrm 인터페이스, GCM 없음 | 사용자 공간 ESP로 실제 트래픽, XFRM 정책·SPI·알림 | [vpn-ipsec.md](vpn-ipsec.md), [vpn-l2tp.md](vpn-l2tp.md) |
| 커널 WireGuard 경로 | wireguard 모듈 없음 | generic netlink 메시지 인코딩/디코딩, 사용자 공간 장치 | [vpn-wg.md](vpn-wg.md) |
| 실제 OS 내장 VPN 클라이언트(Windows/macOS/iOS/Android) | 클라이언트 없음 | 테스트용 개시자/LAC와 종단 간 | [vpn-ipsec.md](vpn-ipsec.md), [vpn-l2tp.md](vpn-l2tp.md) |
| strongSwan, xl2tpd, pppd, `wg`, wireguard-go 상호 운용 | 설치되어 있지 않음 | 독립 계산한 기지 답 벡터 | 각 vpn 문서 |
| 프로젝트 쿼터 한도(ext4/XFS) | `CONFIG_QUOTA` 없음, `mkfs.xfs` 없음 | `-ENOTSUP` 경로 | [vol.md](vol.md) |
| NFS 볼륨 실제 마운트 | NFS 서버 없음(`SBOX_TEST_NFS`로만 실행) | 옵션 해석, 주소 해석 | [vol.md](vol.md) |
| IPv6 종단 간(브릿지, 오버레이, NAT) | 커널이 `ipv6.disable=1` | 규칙·주소 코드 단위 테스트 | [net.md](net.md), [vpn-wg.md](vpn-wg.md) |
| ipvlan, dummy 드라이버 | 커널에 없음 | macvlan(veth 부모) | [net.md](net.md) |
| Docker 엔진 연동 | 기본 실행에서는 끔(`SBOX_TEST_DOCKER=1`로 실행) | 한 번 실제 dockerd/containerd로 확인 | [oci.md](oci.md) |
| 실제 레지스트리 pull, TLS | 기본 실행에서는 끔(`SBOX_TEST_NETWORK=1`로 실행) | 한 번 Docker Hub로 확인 | [image.md](image.md), [tls.md](tls.md) |

## 2. 모듈을 가로지르는 미구현 사항

- **svarch(가상 머신 격리 백엔드)**: 설계만 있고 구현은 보류 중입니다([svarch.md](svarch.md)). 커널 취약점을
  통한 탈출은 지금의 프로세스 격리로는 막지 못합니다.
- **루트 없는 네트워킹**: slirp4netns/pasta 같은 사용자 공간 네트워크 스택이 없어, 루트가 아니면 루프백만
  제공합니다.
- **루트 없는 다중 ID 매핑**: `newuidmap`/`newgidmap`을 쓰지 않아 비특권 호출자는 자기 uid/gid 하나만
  매핑합니다. 루트 없는 이미지 추출도 subuid 범위로 id를 옮기지 않습니다. cgroup v1 위임도 없습니다.
- **systemd cgroup 드라이버**: `--systemd-cgroup`은 경로만 cgroupfs로 바꿉니다.
- **보안 모듈**: AppArmor, SELinux 라벨(`z`/`Z` 재라벨 포함)은 받아들이되 적용하지 않습니다.
- **seccomp 사용자 공간 알림**(`SCMP_ACT_NOTIFY`)과 x86_64·x86·x32·aarch64 이외 아키텍처의 시스템 콜 표가
  없습니다.
- **동기 디스크 I/O**: 레이어 추출, 압축, 볼륨 백업은 동기 연산이라 그동안 이벤트 루프 스레드를 점유합니다.
- **인증서 폐기 확인**: TLS와 IKE 모두 OCSP/CRL을 보지 않습니다.
- **HTTP/2와 압축 응답**: HTTP 클라이언트는 HTTP/1.1만, `Content-Encoding`을 풀지 않습니다.
- **zstd 압축**: 해제만 지원합니다(새 레이어와 백업은 gzip). xz/bzip2는 읽지도 못합니다.
- **IPv4 위주 VPN 주소**: IKEv2·L2TP 가상 주소와 wg-overlay 서브넷은 IPv4만입니다. VPN 주소 풀은 메모리에만
  있고 net 모듈의 IPAM과 공유하지 않습니다.
- **오버레이 제어면**: wg-overlay는 호스트 피어를 정적 설정과 API로만 관리합니다(자동 발견 없음).
- **JSON 정수 범위**: `sbox::CJson`은 INT64_MAX보다 큰 정수를 double로 저장합니다. 그런 값(예:
  `RLIMIT_INFINITY`)은 저장된 `state.json`에 지수 표기로 기록되지만 다시 읽으면 같은 값입니다.

## 3. 모듈별 주요 항목

### core ([core.md](core.md))

- `CEventLoop`는 단일 스레드입니다. 스레드 안전한 것은 `post()`뿐입니다.
- `runBlocking`(이름 해석에 쓰임)은 짧은 스레드를 만들므로 fork할 프로세스에서는 숫자 주소를 써야 합니다.
- 기다리는 중인 코루틴 프레임을 파괴하면 안 됩니다(먼저 `cancelFd`/`close()`). 일반 취소 토큰은 없습니다.

### box ([box.md](box.md))

- OCI `linux.resources` 중 hugepage, `memory.swappiness`, 커널 메모리, rdma, network classid/priorities,
  CPU 실시간, `cpu.idle`, blkio 장치별 weight가 없습니다(`unified` 원시 키로 v2 파일은 쓸 수 있음).
- `personality`, `ioPriority`, `scheduler`, 세션 키링, time 네임스페이스 오프셋, Intel RDT 미지원.
- 루트가 샌드박스를 띄우면 안쪽 uid 0을 호스트 65534로 매핑하므로, 마운트하는 경로와 실행 파일을 그 uid가
  읽을 수 있어야 합니다(설계상 선택).
- 다른 컨테이너 안처럼 `/proc`이 가려진 환경에서는 새 proc 마운트가 거절될 수 있습니다.
- 이벤트 루프가 먼저 없어지면 소멸자가 SIGKILL만 보내므로 좀비가 남을 수 있습니다.

### oci ([oci.md](oci.md))

- checkpoint/restore(CRIU) 없음. `events`는 runc 통계의 부분집합이고 OOM은 폴링으로 감지합니다.
- `linux.netDevices`, idmapped 마운트는 거절합니다. Intel RDT, `execCPUAffinity`, `memoryPolicy` 등은 무시(경고).
- `createContainer`/`startContainer` 훅은 init 안이 아니라 init의 네임스페이스(pid 제외)에 들어간 자식에서
  실행하며, 호출 프로세스가 단일 스레드여야 합니다.
- `exec --user`는 숫자 id만, `exec --cgroup`·`--pidfd-socket`은 무시합니다.
- v1 호스트에서 컨테이너에 `name=systemd` 계층을 넣지 않습니다.

### archive ([archive.md](archive.md))

- sparse·multi-volume tar 미지원, deflate sync flush 없음, 스트림 뒤 쓰레기 바이트는 오류.
- 하드링크 엔트리의 메타데이터를 대상에 다시 적용하지 않고 uname/gname은 무시합니다.
- userxattr whiteout은 커널 6.7 이상에서만 overlayfs가 인식합니다.

### http ([http.md](http.md)), tls ([tls.md](tls.md))

- 쿠키, Digest/NTLM, HTTPS/SOCKS 프록시, Happy Eyeballs 없음. 서버는 Range/조건부 요청을 자동 처리하지 않습니다.
- TLS 세션 재개·0-RTT·사후 클라이언트 인증 없음. 이름 제약은 leaf SAN에만, 인증서 정책 미처리.
  libcertpp가 모르는 키(RSASSA-PSS 전용, Ed448)는 쓸 수 없고, P-256/P-384 ECDH는 상수 시간이 아닙니다.

### image ([image.md](image.md))

- 자격 증명 도우미(`credsStore`/`credHelpers`) 미실행, 서명·attestation 미검증, schema 1 미지원.
- push는 플랫폼 manifest 하나만, 다른 레지스트리로부터의 마운트 없음, 청크 업로드 이어 하기 없음.
- 복사 방식 컨테이너는 commit 불가. 이미지 `Volumes`로 익명 볼륨을 만들지 않고 `Healthcheck`는 해석하지 않습니다.
- 이미지 `Size`는 압축 레이어 크기의 합입니다(Docker는 풀린 크기).

### vol ([vol.md](vol.md))

- 내장 드라이버는 `local`만. 외부 드라이버 위임, `bind-recursive`, `image`/`npipe`/`cluster` 마운트 없음.
- 사라진 컨테이너가 release하지 않으면 재부팅 전까지 사용 중으로 남습니다(`rm -f`/`releaseUser`).
- `size=`는 디렉터리 볼륨에만, 백업은 gzip tar만.

### net ([net.md](net.md))

- hairpin NAT 없음, 포트 범위는 첫 포트만.
- DHCP 임대 자동 갱신 없음(소유자가 `renew()`), packet 소켓 BPF 필터 없음, ipvlan은 DHCP 불가.
- CNI: 범위 집합의 첫 범위만, `isGateway`/`hairpinMode` 무시, STATUS/GC(1.1) 없음.
- Docker 플러그인의 swarm 기능 없음. 네트워크 간 격리 규칙이 O(n²)로 늘어납니다.
- `sbox-image bundle --network`는 컨테이너의 `/etc/resolv.conf`·`/etc/hosts`를 쓰지 않습니다.

### vpn/wg ([vpn-wg.md](vpn-wg.md))

- 사용자 공간 오버레이 장치는 그것을 만든 프로세스가 살아 있어야 합니다(`sboxnet` 데몬은 시작 시 `restore()`).
  `sbox-cni`는 wg-overlay를 등록하지 않습니다.
- `sbox-wg up`은 wg-quick의 DNS 설정, 기본 경로 정책 라우팅, PreUp/PostUp 훅을 하지 않습니다.
- 사용자 공간 경로에 sticky source, GSO/GRO, 다중 큐, 다중 스레드 암호화가 없습니다.

### vpn/ipsec ([vpn-ipsec.md](vpn-ipsec.md))

- 사용자 공간 ESP는 터널 모드만, ESN 없음, 단일 스레드.
- 응답자는 재키잉을 먼저 시작하지 않습니다. EAP는 MSCHAPv2만, EAP-only·다중 인증·Redirect 없음.
- MOBIKE는 상대가 시작한 주소 갱신만, 커널 ACQUIRE/EXPIRE 알림은 아직 구독하지 않습니다.
- PKCS#12는 AES-256만 만들어 오래된 Apple 키체인이 읽지 못합니다.

### vpn/l2tp ([vpn-l2tp.md](vpn-l2tp.md))

- IKEv1 인증서 인증 없음(libcertpp에 DigestInfo 없는 PKCS#1 서명이 없음), 따라서 IKE 단편화도 없음.
  Aggressive Mode/XAUTH 미지원.
- PPP는 IPv4만(IPv6CP 거절), MPPE·EAP 없음, MS-CHAPv2 재시도·비밀번호 변경 없음.
- 같은 NAT 뒤 두 클라이언트가 모두 내부 포트 1701을 쓰면 커널 경로로는 구분하지 못합니다(사용자 공간 경로는 가능).
- Android 12 이상은 새 L2TP/IPsec 프로필을 만들 수 없으므로 IKEv2를 써야 합니다.
