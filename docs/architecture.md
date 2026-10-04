# 아키텍처

libsbox는 리눅스 커널 기능만으로 프로그램을 격리해 실행하는 라이브러리와, 그 위에 만든 OCI 컨테이너
런타임 도구 모음(sbox)입니다. 커널 모듈은 만들거나 고치지 않고, 이미 있는 커널 기능(네임스페이스,
cgroups, seccomp, overlayfs, nftables, XFRM, WireGuard, macvlan 등)을 쓰며, 없으면 사용자 공간 경로로
대체합니다.

## 저장소 구조

```
include/sbox/       필수 모듈(core, box)의 공개 헤더
modules/<m>/        모듈. src/(구현), tests/(doctest), 선택 모듈은 include/sbox/<m>/(공개 헤더)
cli/<tool>/         명령줄 도구(sbox, sboxrun, sboxvol, sboxnet, sbox-cni ...)
docs/               모듈별 설계 문서(현재 상태만). 작업 기록은 docs/logs/
thirdparty/         git submodule: doctest, libcertpp
```

## 모듈

| 모듈 | 네임스페이스 | 헤더 위치 | 의존 | 내용 |
|---|---|---|---|---|
| core | `sbox` | `include/sbox/core/` | - | 공통 타입, `TTask` 코루틴, `CEventLoop`(epoll), `CFd`, 스트림/파이프/소켓, JSON, 파일 유틸 |
| box | `sbox` | `include/sbox/box/` | core | 네임스페이스, 마운트와 pivot_root, cgroups v1/v2, seccomp BPF, capabilities, rlimit, 사용자 네임스페이스 매핑, 실행 엔진, `CSandbox`/`SBoxPolicy` |
| oci | `sbox::oci` | `modules/oci/include/sbox/oci/` | box | OCI 런타임 명세 타입과 JSON, 컨테이너 상태 저장, `CRuntime`(create/start/state/kill/delete/exec/...) |
| archive | `sbox::archive` | `modules/archive/include/sbox/archive/` | core | tar(ustar/pax/GNU), DEFLATE/gzip, zstd 해제 |
| http | `sbox::http` | `modules/http/include/sbox/http/` | core | HTTP/1.1 클라이언트와 서버(유닉스 소켓 포함), URL |
| tls | `sbox::tls` | `modules/tls/include/sbox/tls/` | core, libcertpp | TLS 1.3 클라이언트, X.509 검증 |
| image | `sbox::image` | `modules/image/include/sbox/image/` | archive, http, tls, libcertpp | 내용 주소 저장소(OCI image layout), Registry API v2 pull, 레이어 풀기, overlayfs 스냅샷, docker save/load |
| vol | `sbox::vol` | `modules/vol/include/sbox/vol/` | archive, http | 이름 있는 볼륨, bind/tmpfs/NFS, 프로젝트 쿼터, 백업, Docker 볼륨 플러그인 |
| net | `sbox::net` | `modules/net/include/sbox/net/` | http | rtnetlink, nftables, 브릿지/veth/macvlan/ipvlan, IPAM, CNI 플러그인, Docker 네트워크 플러그인 |
| vpn | `sbox::vpn` | `modules/vpn/include/sbox/vpn/` | net, libcertpp | WireGuard(커널 또는 사용자 공간), IKEv2/IPsec(XFRM), L2TP/IPsec, 호스트 간 가상 네트워크 드라이버 |

모듈 의존은 위에서 아래로만 흐릅니다. 각 모듈은 `modules/<m>/CMakeLists.txt`의
`sbox_add_module(<m> DEPENDS ...)` 한 줄로 선언되고, 루트 CMake가 모듈 디렉터리를 자동으로 찾습니다.

## 실행 모델

- 단일 스레드 이벤트 루프(`CEventLoop`)가 epoll로 디스크립터와 타이머를 기다리고 `TTask` 코루틴을
  재개합니다. 프로세스 종료는 pidfd를 같은 루프에서 기다립니다(SIGCHLD, 블로킹 waitpid 없음).
- 스레드를 만들지 않으므로 `CSandbox::fork`(현재 프로그램의 함수를 샌드박스에서 실행)의 규칙,
  "fork 시점에 다른 스레드가 없을 것"이 기본으로 지켜집니다.
- 공개 API는 C++20 코루틴입니다.

```cpp
SBoxPolicy p;
p.mounts = { { "/usr", "/usr", EBMNT_READ_ONLY }, { "/srv/job", "/work", EBMNT_READ_WRITE } };
p.memoryMax = 256 << 20;
p.pidsMax = 64;
p.wallTimeoutMs = 5000;
p.network = EBNET_NONE;

CSandbox box = co_await CSandbox::spawn(p, { "/usr/bin/python3", "main.py" });
co_await box.stdinPipe().send(BytesOf(input));
box.stdinPipe().close();
SBoxResult r = co_await box.wait();
```

## 위협 모델

샌드박스 안의 코드는 악의적이라고 가정합니다. 막는 것은 호스트 파일 접근, 다른 프로세스 관찰,
네트워크 접근, 자원 고갈(CPU, 메모리, 프로세스 수, 디스크), 위험한 시스템 콜입니다. 커널 취약점을 통한
탈출은 프로세스 격리의 한계라 막지 못하며, 그 수준이 필요하면 마이크로VM이 필요합니다
([svarch.md](svarch.md)).

## 지원 환경

- 리눅스 5.10 이상(`clone3`, pidfd, `openat2`, `close_range`), cgroups v1과 v2.
- 루트가 아니어도 사용자 네임스페이스로 동작합니다. 루트이면 cgroups 한도와 네트워크 연결까지 씁니다.

## Docker 호환

- 런타임: `sbox`/`sboxrun`은 runc와 같은 명령줄과 상태 형식을 가져 dockerd(`runtimes`)와
  containerd(runc shim의 `BinaryName`)가 그대로 씁니다.
- 이미지: OCI image layout과 Docker 이미지 manifest(schema2), Registry API v2, `docker save` 형식.
- 볼륨: Docker 볼륨 플러그인 프로토콜, `local` 드라이버와 같은 옵션(`type`, `device`, `o`).
- 네트워크: CNI 1.0 플러그인과 Docker 네트워크/IPAM 원격 플러그인 프로토콜.
