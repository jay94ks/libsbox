# libsbox

리눅스 커널 기능만으로 프로그램을 격리해 실행하는 C++20 라이브러리와, 그 위에 만든 OCI 컨테이너
런타임 도구 모음(sbox)입니다.

- **샌드박스**: 신뢰할 수 없는 코드(채점기, 플러그인, 사용자 스크립트)를 네임스페이스, cgroups v1/v2,
  seccomp 허용 목록, capability 제거, rlimit, 벽시계 제한 아래에서 실행하고 종료 사유와 사용량을
  돌려줍니다. 루트가 아니어도 사용자 네임스페이스로 동작합니다.
- **OCI 런타임**: runc와 같은 명령줄(`sbox create/start/state/kill/delete`, `config.json`). dockerd와
  containerd에 런타임(`sboxrun`)으로 등록할 수 있습니다.
- **이미지**: Registry API v2에서 OCI/Docker 이미지를 받아 내용 주소 저장소(OCI image layout)에 두고
  overlayfs 스냅샷으로 루트를 구성합니다.
- **볼륨**: 이름 있는 볼륨, bind, tmpfs, NFS, 프로젝트 쿼터, 백업, Docker 볼륨 플러그인(`sboxvol`).
- **네트워크**: 브릿지, IP 관리, 물리 IP 할당(macvlan/ipvlan), CNI와 Docker 네트워크 플러그인.
- **가상 네트워크**: WireGuard, IKEv2/IPsec, L2TP/IPsec으로 컨테이너를 호스트 간 가상 네트워크에 연결.

```cpp
#include <sbox/box/sandbox.hpp>

using namespace sbox;

TTask<SBoxResult> judge(std::string input) {
    SBoxPolicy p = SBoxPolicy::strict();
    p.mounts = SBoxPolicy::systemMounts();      // /usr, /etc ... read-only
    p.mounts.push_back({ "/srv/job", "/work", EBMNT_READ_WRITE });
    p.cwd = "/work";
    p.memoryMax = 256 << 20;
    p.pidsMax = 64;
    p.wallTimeoutMs = 5000;

    CSandbox box = co_await CSandbox::spawn(p, { "/usr/bin/python3", "main.py" });
    co_await box.stdinPipe().send(BytesOf(input));
    box.stdinPipe().close();
    co_return co_await box.wait();
}

int main() {
    CEventLoop loop;
    SBoxResult r = loop.run(judge("1 2\n"));
    return r.exitCode;
}
```

## 빌드

```sh
git submodule update --init
cmake -S . -B build && cmake --build build -j
ctest --test-dir build -j8 --output-on-failure
```

필요한 것: 리눅스 5.10 이상, CMake 3.20 이상, C++20 컴파일러(GCC 11+, Clang 14+).
외부 종속성은 `thirdparty/`의 git submodule([doctest](https://github.com/doctest/doctest),
[libcertpp](https://github.com/jay94ks/libcertpp))뿐입니다.

## 명령줄 도구

| 도구 | 역할 |
|---|---|
| `sbox`, `sboxrun` | runc 호환 OCI 런타임(dockerd/containerd에 런타임으로 등록) |
| `sbox-image` | 이미지 pull/push, 저장소, 번들 생성, overlay 마운트, save/load |
| `sboxvol` | 볼륨 관리와 Docker 볼륨 플러그인 데몬 |
| `sboxnet` | Docker 네트워크/IPAM 플러그인 데몬 |
| `sbox-cni` | CNI 1.0 플러그인 |
| `sbox-wg` | WireGuard(사용자 공간/커널) 터널과 클라이언트 설정 |
| `sbox-ike` | IKEv2/IPsec 서버, 인증서와 OS별 클라이언트 설정 생성 |
| `sbox-l2tp` | L2TP/IPsec 서버와 OS별 클라이언트 설정 생성 |

사용법은 [docs/usage.md](docs/usage.md)를 보십시오.

## 문서

- [아키텍처](docs/architecture.md): 모듈 구성, 실행 모델, 위협 모델
- [빠른 시작](docs/usage.md)
- [코딩 컨벤션](docs/coding-conventions.md)
- 모듈별 문서: `docs/<모듈>.md`, 통합 테스트: [docs/e2e.md](docs/e2e.md)
