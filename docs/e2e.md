# e2e: 모듈 간 종단 간 테스트

`modules/e2e`는 라이브러리 코드가 없는 테스트 전용 모듈입니다. 각 모듈의 단위·통합 테스트가 자기
모듈만 보는 것과 달리, 사용자가 실제로 하듯 여러 모듈과 명령줄 도구를 이어서 씁니다. 이미지를 만들어
받고, 번들로 바꿔 런타임으로 돌리고, 볼륨과 네트워크를 붙이고, 악성 코드를 가둡니다.

- CMake: `sbox_add_module(e2e DEPENDS box oci image vol net archive http tls)`. 라이브러리 타깃
  `sbox::e2e`에는 빈 소스(`src/e2e.cpp`)만 있습니다.
- 테스트: `modules/e2e/tests/*.cpp`(파일마다 doctest 실행 파일 하나, 라벨 `e2e`, 시간 제한 600초)
- 보조 프로그램: `testhelpers/e2ehelper.c` → `build/modules/e2e/helpers/e2ehelper`
- README 예제: CMake가 `README.md`의 첫 ```` ```cpp ```` 블록을 그대로 잘라
  `build/modules/e2e/readme_example.cpp`로 쓰고 `readme_example`로 빌드합니다(경고도 오류로 취급).

## 실행

```sh
cmake -S . -B build -DSBOX_WERROR=ON && cmake --build build -j
ctest --test-dir build -j8 -L e2e --output-on-failure      # e2e만
ctest --test-dir build -j8                                  # 전체
```

필요한 것: 루트, 사용자/네트워크/마운트 네임스페이스, cgroup(v1 hybrid 또는 v2), nf_tables(포트 매핑),
`/dev/net/tun`은 쓰지 않음. overlayfs가 없으면 이미지 시나리오는 복사 스냅샷만 돌립니다. 루트가 아니거나
CLI 도구를 빌드하지 않았으면(`SBOX_BUILD_CLI=OFF`) 각 케이스가 `MESSAGE`를 남기고 건너뜁니다.

## 격리와 정리

- **사적 마운트 네임스페이스**: 각 테스트 실행 파일은 doctest가 시작하기 전(정적 초기화)에
  `unshare(CLONE_NEWNS)` + `MS_REC|MS_PRIVATE`로 자기 마운트 네임스페이스로 옮깁니다. 테스트와 테스트가
  띄운 도구(`sbox-image`의 overlay 루트, 볼륨 마운트, netns 고정 bind, README 테스트의 `/srv` tmpfs)의
  마운트는 호스트 마운트 표에 나타나지 않고, 테스트가 중간에 죽어도 프로세스와 함께 사라집니다.
- **임시 "호스트" netns**: 네트워크 시나리오는 `CNetns::create`로 만든 netns를 호스트 역할로 씁니다
  (`SNetworkManagerOptions::hostNetns`, `sbox-cni`는 그 netns 안에서 실행). 브릿지, veth, nftables `sbox`
  테이블, sysctl이 모두 그 안에만 생기므로 실제 호스트 네트워크는 바뀌지 않습니다. 그 netns의 `lo`는
  `BringUpLoopback`으로 켭니다(실제 호스트처럼 127.0.0.1 포트 매핑을 시험하기 위해).
- **고유한 이름**: 임시 디렉터리는 `/var/tmp/sbox-e2e-XXXXXX`(0755; 샌드박스의 uid 65534가 지나갈 수
  있어야 함), 컨테이너 id와 상태 루트, 이미지 저장소, 볼륨 저장소, 네트워크 상태 디렉터리가 모두 그 안에
  있습니다. 포트는 0(임시 포트)이거나 각자의 netns 안에서만 씁니다.
- **정리**: 컨테이너는 `delete`/`remove`, 컨테이너 루트는 `sbox-image rm`, 볼륨은 `releaseUser`/`remove`,
  네트워크는 `disconnect`/`deleteNetwork`, netns는 `CNetns::remove`로 지웁니다. `TempDir` 소멸자는 그 아래의
  남은 마운트를 분리(`MNT_DETACH`)한 뒤 디렉터리를 지웁니다. cgroup은 런타임과 샌드박스가 지웁니다.
- **도구 실행**: `runTool`은 fork + exec로 도구를 띄우고 표준 입출력을 파일로 돌리며(분리된 컨테이너가
  상속해도 막히지 않음), pidfd를 이벤트 루프에서 기다립니다. 그래서 같은 루프에서 도는 테스트 레지스트리
  (http 서버)가 도구의 요청에 답할 수 있습니다. 네트워크 네임스페이스(`setns`)와 uid 전환(rootless)을
  선택할 수 있습니다.

## 픽스처

- **rootfs**: 호스트의 `sh cat sleep echo ls id hostname true false touch mkdir head rm wc`(없으면 busybox
  애플릿 링크)와 `ldd`가 알려 준 공유 라이브러리, `e2ehelper`, `/etc/passwd`·`/etc/group`.
- **이미지**(`buildImage`): 레이어 1 = rootfs + `/etc/removed`, 레이어 2 = `/etc/.wh.removed`(whiteout),
  `/etc/motd`(`layer-two`), `/data/seed.txt`. 설정은 Env `E2E=1`, Cmd
  `sh -c "echo hello from $(cat /etc/motd)"`, Volumes `/data`. archive 모듈로 무압축 tar를 만들고 diffID를
  계산하며, `docker save` 고전 형식(`manifest.json`, `<id>.json`, `<diffID>/layer.tar`)과 레지스트리 형식
  (gzip 레이어 + Docker schema2 manifest)을 둘 다 만듭니다.
- **e2ehelper**: `serve PORT MSG N`(N개 연결에 MSG를 보내고 끝), `fetch HOST PORT`(재시도하며 연결해 받은
  것을 출력), `connect`, `read`, `write`, `pids`, `forkbomb`, `memhog MiB`, `spin`,
  `syscall ptrace|mount|unshare|setns|bpf|keyctl`. 거부된 호출은 `error <errno 이름>`으로 출력합니다.

## 시나리오

| 실행 파일 | 시나리오 |
|---|---|
| `e2e_image_oci` | (1) docker save 아카이브를 `sbox-image load` → `inspect`의 Id가 설정 다이제스트. overlay와 copy 스냅샷마다: `sbox-image bundle`(overlay는 마운트 확인, whiteout 적용 확인) → `CRuntime`으로 create(created 상태 확인)/start/출력/종료 코드/delete → `sbox run` 전경 실행과 자동 삭제 → `bundle --env ... -- 명령`의 종료 코드 7 → `sbox create --pid-file`/`state`(created, pid 파일)/`start`/`state`(running)/`list -q`/`ps --format json`/`exec`/`kill KILL`/`state`(stopped)/`delete` → (overlay) 컨테이너가 파일을 만들고 지운 루트를 `sbox-image commit`해 새 이미지로 번들을 만들어 변경과 whiteout 확인 → `sbox-image rm`으로 언마운트·삭제, `ps`가 빔. 마지막으로 `sbox-image save` 결과를 새 저장소에 load해 같은 Id. (2) http 모듈로 띄운 테스트 레지스트리(API v2, 읽기 전용)에서 `sbox-image --plain-http ... pull` → 같은 Id, RepoDigest, 두 번째 pull은 다운로드 0 → `sbox run` 출력, `--user nobody --read-only` 번들(65534, 읽기 전용 루트). (3) rootless: uid 65534로 기본 저장소(`$XDG_DATA_HOME`)에 load, 자동 rootless 복사 번들, 기본 상태 루트(`$XDG_RUNTIME_DIR/sbox`)로 `sbox run`(안에서 uid 0, uid_map `0 65534 1`, cgroup 없음 경고) |
| `e2e_vol_oci` | `-v e2edata:/data`, `--mount type=bind,...,readonly`, `--tmpfs /scratch:size=1m`을 `ParseVolumeFlag`/`ParseMountFlag`/`ParseTmpfsFlag` → `PrepareContainerMounts` → config.json `mounts`에 추가. 컨테이너 1: copy-up된 이미지 내용, 볼륨 쓰기, bind 읽기와 쓰기 거부, tmpfs 크기 제한. 볼륨 사용자 등록/해제. 컨테이너 2(`sbox run`, `:ro`): 이전 데이터와 쓰기 거부. `BackupVolumeToFile` → `remove` → `RestoreVolumeFromFile`(새 이름) → 컨테이너 3이 복원 데이터를 읽음. `sboxvol backup` → `sboxvol restore ... -`(표준 입력, 라벨). 익명 볼륨이 `releaseUser(.., true)`로 지워짐 |
| `e2e_net_oci` | 임시 호스트 netns의 `CNetworkManager`로 브릿지 네트워크(10.123.0.0/24) 생성, 컨테이너 netns 3개를 `connect`(첫째는 `0:8080/tcp` 포트 매핑, 임시 호스트 포트). config.json의 network 경로로 들어간 컨테이너 1이 서버, 컨테이너 2가 TCP로 받음, 호스트 netns에서 브릿지 주소와 127.0.0.1의 매핑 포트로 받음, `EBNET_NAMESPACE` CSandbox가 셋째 netns에서 받음. `disconnect`한 netns는 더 이상 닿지 않음. 네트워크와 netns 삭제 |
| `e2e_cni_oci` | 빌드된 `sbox-cni`를 임시 호스트 netns에서 ADD(브릿지, `ipam` 범위, `runtimeConfig.portMappings`) → 결과의 ips/interfaces. 그 netns에 들어간 컨테이너의 `/sys/class/net`이 `eth0 lo`이고 MAC이 CNI 결과와 같음. `sbox run --detach`로 띄운 서버에 컨테이너 주소와 매핑 포트(10.124.0.1:18080)로 접속, `state`가 stopped가 되면 `delete`. CHECK 성공, DEL 뒤 `lo`만 남음, DEL 재실행도 성공 |
| `e2e_readme` | README.md의 C++ 예제를 그대로 컴파일한 프로그램을 실행합니다. 이 테스트의 마운트 네임스페이스에서 `/srv`에 tmpfs를 올리고 `/srv/job`에 임시 디렉터리를 bind한 뒤, 표준 입력의 수를 더해 `/work/result.txt`에 쓰고 그 합으로 끝나는 `main.py`(python3이 없으면 sh 스크립트, 예제의 인터프리터도 `/bin/sh`로 바뀜)를 둡니다. 종료 코드 3과 결과 파일을 확인합니다 |
| `e2e_hostile` | `SBoxPolicy::strict()` + 보조 프로그램 디렉터리. 마운트 밖 호스트 파일(절대 경로, `/etc/shadow`, `/proc/1/root/...`, `/sbx/../../..`) 읽기 → ENOENT/EACCES. 읽기 전용 마운트 쓰기 → EROFS. `/proc`의 pid는 `1 2`뿐. 호스트 127.0.0.1의 리스너 → ECONNREFUSED(자기 루프백), 192.0.2.1 → ENETUNREACH, 리스너는 연결을 받지 않음. 포크 폭탄(`pidsMax` 16) → fork가 EAGAIN, 16개 미만. `memoryMax` 64 MiB에서 512 MiB → `EBEXIT_MEMORY`, `oomKills > 0`. `ptrace`/`mount`/`unshare`/`setns`/`bpf`/`keyctl` → `EBEXIT_SECCOMP`(SIGSYS), errno 프로필에서는 EPERM. CPU 소모 → `EBEXIT_CPU_TIME`(`cpuTimeLimitMs` 1000), 벽시계 → `EBEXIT_WALL_TIMEOUT` |

## 이 테스트로 찾은 문제

| 문제 | 수정 |
|---|---|
| README 예제가 컴파일되지 않음: `sandbox.hpp`만 포함하면 `CEventLoop`가 없음 | `include/sbox/box/sandbox.hpp`가 `core/eventloop.hpp`를 포함(회귀 테스트 `box_header`) |
| `SIGPIPE`를 무시하지 않은 호출자가 샌드박스 표준 입력에 쓰다가 죽음(샌드박스 프로그램이 먼저 끝나거나 stdin을 닫으면). 악성 프로그램이 감독 프로세스를 죽일 수 있음 | `CStream::send`가 파이프에도 SIGPIPE를 일으키지 않고 `-EPIPE`(`modules/core/src/stream.cpp`, 회귀 테스트 `core_stream`) |
| merged-/usr 호스트(`/lib64 -> usr/lib64`)에서 `/usr`만 bind한 정책(README와 architecture.md 예제)은 동적 링크 프로그램을 실행하지 못함(로더 `/lib64/ld-linux-x86-64.so.2` 없음, `execve` ENOENT) | 정책이 호스트 `/usr`를 bind하고 그 경로를 직접 마운트하지 않으면 `/bin`, `/sbin`, `/lib*`를 `/usr` 안에서 읽기 전용으로 bind(`modules/box/src/sandbox.cpp`, 회귀 테스트 `box_sandbox`의 merged-/usr 케이스) |

## 제한 사항과 남은 문제

- **README 예제는 쓰인 그대로는 동작하지 않습니다**(`e2e_readme` 실패). 남은 원인은 문서입니다.
  `p.cwd`를 정하지 않아 `python3 main.py`가 샌드박스 루트(`/main.py`)를 찾고, `/etc`를 마운트하지 않아
  `/usr/bin/python3 -> /etc/alternatives/python3`인 호스트(이 기계)에서는 프로그램이 보이지 않습니다
  (`EBEXIT_SETUP_FAILURE`, `execve` ENOENT. 예제는 `exitCode`만 돌려주므로 0). 다음처럼 고치면 이
  테스트가 통과합니다(이 기계에서 확인).
  ```cpp
  SBoxPolicy p = SBoxPolicy::strict();
  p.mounts = SBoxPolicy::systemMounts();                         // /usr, /bin, /lib*, /etc (읽기 전용)
  p.mounts.push_back({ "/srv/job", "/work", EBMNT_READ_WRITE });
  p.cwd = "/work";
  ```
- `sbox`/`sbox-image bundle` 명령줄에는 `-v`/`--mount`/`--tmpfs`와 네트워크 연결 옵션이 없습니다. 볼륨과
  네트워크는 라이브러리(`PrepareContainerMounts`, `CNetworkManager::connect`) 또는 config.json 편집,
  `sbox-cni`로 붙입니다([usage.md](usage.md)).
- WireGuard 오버레이(`wg-overlay` 드라이버)는 라이브러리로만 만들 수 있습니다. `sboxnet`(Docker 플러그인)과
  `sbox-cni`는 그 드라이버를 등록하지 않으므로 이 테스트에는 오버레이 시나리오가 없습니다(vpn 모듈의
  `vpn_wg_overlay` 테스트가 다룸).
- Docker/containerd에 `sboxrun`을 등록한 시나리오는 oci 모듈의 `oci_docker`(`SBOX_TEST_DOCKER=1`)에 있고
  여기서는 반복하지 않습니다.
- IPv6, macvlan/DHCP, NFS 볼륨, 프로젝트 쿼터는 각 모듈 테스트가 다루며 이 환경(커널 설정) 때문에 e2e에는
  넣지 않았습니다.
