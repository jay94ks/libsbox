# oci 모듈

OCI 런타임입니다. OCI runtime-spec 1.2의 설정(config.json)을 읽고 검증해 box 모듈의 실행 엔진으로
컨테이너를 만들고, runc와 같은 명령줄·상태 형식으로 수명 주기를 다룹니다. 명령줄 도구
`cli/sbox`(바이너리 `sbox`와 `sboxrun`)가 이 모듈 위에 있으며, dockerd와 containerd가 runc 대신
그대로 씁니다.

- 네임스페이스: `sbox::oci`
- 헤더: `modules/oci/include/sbox/oci/`, CMake 타깃: `sbox::oci` (`sbox_add_module(oci DEPENDS box)`)

| 헤더 | 내용 |
|---|---|
| `spec.hpp` | 설정 값 타입(`SSpec`, `SProcessSpec`, `SLinuxSpec`, `SResourcesSpec`, `SSeccompSpec`, `SHooks` ...), `ParseSpec`/`ParseSpecText`/`LoadSpec`, `SpecToJson`, `ParseProcess`/`ProcessToJson`, `ParseResources`/`ResourcesToJson`, `ValidateSpec`, `DefaultSpec`, 이름 표(`RlimitFromName`, `CapabilityName`, `NamespaceFromName`, `NamespaceProcName`) |
| `seccomp.hpp` | `SeccompProfileFromSpec`/`CompileSeccompSpec`(OCI → box seccomp), `SeccompSpecFromDockerProfile`(Docker 프로필 → OCI), `SDockerSeccompContext`, `DockerDefaultCapabilities` |
| `state.hpp` | `EContainerStatus`, `SState`(runc `state` 출력), `SContainerRecord`(state.json), `ReadProcStat`/`ProcessAlive`, `NowRfc3339Nano`, `ValidContainerId` |
| `hooks.hpp` | `SHookContext`, `RunHook`, `RunHooks` |
| `runtime.hpp` | `CRuntime`(create/start/state/kill/remove/exec/processes/pause/resume/update/stats/config/list), `SRuntimeOptions`, `SCreateOptions`, `SExecOptions`, `CContainerProcess`, `ParseSignal` |

## 1. 설정 (`spec.hpp`)

### 1.1 타입과 JSON

`SSpec`은 runtime-spec 1.2의 리눅스 부분 전체를 담습니다(`ociVersion`, `process`, `root`, `hostname`,
`domainname`, `mounts`, `hooks`, `annotations`, `linux`). `linux`는 GNU 모드에서 미리 정의된 매크로라
필드 이름을 `linux_`로 씁니다.

- 선택 필드는 `std::optional`로 있고 없음을 구분하며, `SpecToJson`은 runc(Go의 `omitempty`)처럼 설정되지
  않은 필드를 쓰지 않습니다. 그래서 runc의 기본 설정과 모든 필드를 쓴 문서가 그대로 왕복합니다(테스트).
- 강제하지 않는 섹션(`process.scheduler`, `ioPriority`, `execCPUAffinity`, `linux.intelRdt`, `personality`,
  `timeOffsets`, `netDevices`, `memoryPolicy`, `resources.network`, `resources.rdma`)은 원본 `CJson`으로
  보관해 왕복은 하되 적용하지 않습니다.
- 파서는 형식이 틀린 필드를 경로와 함께 거절합니다(`process.user.uid: expected an unsigned 32-bit integer`).
  모르는 필드는 경고(`process.bogus: unknown field ignored`)이고, `solaris`/`windows`/`vm`/`zos` 섹션은
  무시한다는 경고만 남깁니다.
- `CJson`은 INT64_MAX보다 큰 정수를 double로 저장하므로, 2^64에 가깝게 반올림된 값(`RLIMIT_INFINITY`
  18446744073709551615, 모든 비트가 1인 마스크)은 UINT64_MAX로 읽습니다.

### 1.2 검증 (`ValidateSpec`)

런타임이 거절해야 하는 것을 첫 번째 문제의 설명과 함께 `-EINVAL`로 돌려줍니다.

- `ociVersion`이 없거나 1.x가 아님, `root.path` 없음, (create/run에서) `process` 없음, 빈 `args`,
  절대 경로가 아닌 `cwd`
- 모르는 rlimit, soft > hard, 중복 rlimit, 범위 밖 `oomScoreAdj`
- 모르는 네임스페이스 종류, 중복, 상대 경로, mount 네임스페이스 없음
- 사용자 네임스페이스 없는 ID 매핑, 새 사용자 네임스페이스인데 매핑 없음
- 새 UTS 네임스페이스 없는 `hostname`/`domainname`(들어가기만 하는 UTS도 거절)
- 장치 노드의 종류(`c`,`b`,`u`,`p`)·경로, 장치 cgroup 규칙의 종류(`a`,`c`,`b`)와 접근(`rwm`)
- 전파 모드 이름, seccomp 동작·연산자·인자 번호, 가림/읽기 전용 경로가 절대 경로인지
- sysctl은 runc 규칙대로 네임스페이스로 격리되는 것만: IPC(`kernel.msg*`, `kernel.sem`, `kernel.shm*`,
  `fs.mqueue.*`)는 ipc 네임스페이스, `net.*`는 network 네임스페이스, `kernel.hostname`/`domainname`은
  uts 네임스페이스가 있어야 하고 그 밖은 거절
- 훅 경로가 절대 경로인지, timeout이 양수인지

적용하지 않는 필드(AppArmor, SELinux 라벨, `mountLabel`, `personality`, `intelRdt`, `scheduler`,
`ioPriority`, `timeOffsets` ...), 모르는 capability 이름, 상대 경로 마운트 대상, deprecated
`prestart` 훅은 경고로 돌려줍니다(CLI는 runc처럼 warning 로그로 남김).

### 1.3 기본 설정 (`DefaultSpec`, `sbox spec`)

`runc spec`과 같은 문서를 만듭니다(hostname만 인자로, CLI는 `sbox`). `--rootless` 변형도 runc의
`ToRootless`와 같습니다: network 네임스페이스 제거, user 네임스페이스와 호출자 uid/gid → 0 단일 매핑,
`/sys`는 sysfs 대신 호스트 `/sys`의 읽기 전용 rbind, devpts의 `gid=5` 제거, 장치 cgroup 규칙 제거.
테스트가 runc 1.3.6의 실제 출력(`tests/data/runc-default.json`, `runc-rootless.json`)과 구조 비교합니다.

## 2. seccomp (`seccomp.hpp`)

### 2.1 OCI → box

`SeccompProfileFromSpec`은 `linux.seccomp`를 box의 `SSeccompProfile`로 옮깁니다(runc/libseccomp 의미).

- `SCMP_ACT_KILL` = `KILL_THREAD`, `ERRNO`/`TRACE`에 `errnoRet`이 없으면 EPERM, `defaultErrnoRet`
- 네이티브 ABI는 libseccomp처럼 항상 포함하고, 목록의 ABI 중 box 표가 없는 것(ARM, MIPS, PPC, S390,
  RISC-V)은 그 규칙을 건너뛴다는 경고와 함께 뺍니다.
- 플래그: `SECCOMP_FILTER_FLAG_LOG`, `SPEC_ALLOW`는 그대로, `TSYNC`는 의미 없음(설치 시 단일 스레드),
  `WAIT_KILLABLE_RECV`는 NOTIFY 전용이라 무시, 그 밖은 거절
- `SCMP_ACT_NOTIFY`는 `-ENOTSUP`(listenerPath는 경고)
- 모르는 시스템 콜 이름은 runc처럼 건너뜁니다(`CompileSeccompSpec`의 `unknown`, CLI는 debug 로그).

seccomp는 컨테이너의 init뿐 아니라 `exec`로 들어가는 모든 프로세스에도 같은 프로필이 적용됩니다.

### 2.2 Docker 프로필 (`SeccompSpecFromDockerProfile`)

Docker의 `profiles/seccomp/default.json` 형식을 dockerd가 config.json에 쓰는 OCI 섹션으로 바꿉니다.
`archMap`에서 네이티브 ABI의 항목과 하위 ABI(x86_64 → x86, x32)를 고르고, 규칙마다 `excludes`(ABI,
capability, 최소 커널) → `includes`(ABI, 모든 capability, 최소 커널) 순으로 거릅니다. ABI 비교는 Go
이름(`amd64`, `arm64`)으로 합니다. `SDockerSeccompContext::host(caps)`는 네이티브 ABI와 실행 중인 커널
버전으로 문맥을 만듭니다. 실제 Docker 기본 프로필(`tests/data/docker-default-seccomp.json`)이 변환되고
컴파일되며 판정이 Docker와 같음을 테스트합니다(`mount` EPERM, `clone`의 네임스페이스 플래그 EPERM,
`clone3` ENOSYS, `personality` 값 목록, CAP_SYS_ADMIN이 있으면 `mount` 허용, 4.8 미만 커널의 `ptrace`).

## 3. 상태 저장

### 3.1 디렉터리

상태 루트(기본 `/run/sbox`, rootless는 `$XDG_RUNTIME_DIR/sbox`, 없으면 `/tmp/sbox-<uid>`; CLI의 `--root`)
아래 컨테이너마다 디렉터리가 하나 있습니다.

```
<root>/<id>/            0711
    state.json          0600, CFile::writeAtomic(임시 파일 + fsync + rename)
    exec.fifo           0622, create와 start 사이에만 있음 (start gate)
    .lock               POSIX 레코드 잠금 파일
```

`state.json`(`SContainerRecord`):

```json
{ "id": "...", "bundle": "/abs/bundle", "rootfs": "/abs/bundle/rootfs", "created": "2026-10-04T12:51:27.232160881Z",
  "ownerUid": 0, "initProcessPid": 1234, "initProcessStartTime": 98765, "cgroupPath": "sbox/<id>",
  "rootless": false, "status": "created", "config": { ...config.json 전체... } }
```

`config`를 함께 저장하므로 번들이 지워져도 `exec`, `delete`(poststop 훅), `update`가 동작합니다.

### 3.2 잠금

변경하는 명령(create, start, delete, update)은 `<dir>/.lock`에 `fcntl(F_SETLK)` 쓰기 잠금을 겁니다(이벤트
루프를 막지 않도록 `F_SETLK` + 짧은 sleep 재시도, 30초 제한). flock 대신 POSIX 레코드 잠금을 쓰는 이유:
create가 만든 init은 프로그램을 exec할 때까지 런타임의 모든 디스크립터 사본을 갖고 있는데, flock은 열린
파일 설명(open file description)에 붙어 init이 잠금을 계속 쥐게 됩니다. POSIX 잠금은 프로세스 소유라
자식에게 상속되지 않습니다. 같은 프로세스의 코루틴끼리는 프로세스 안의 잠금 목록으로 배제합니다.
`state`, `kill`, `exec`, `ps`는 잠그지 않습니다(state.json은 원자적으로 바뀜).

### 3.3 상태 판정과 pid 재사용

`initProcessPid`와 함께 `/proc/<pid>/stat`의 22번째 필드(starttime)를 기록합니다. 상태는 매번 계산합니다.

| 조건 | 상태 |
|---|---|
| pid가 아직 없음(create 진행 중) | `creating` |
| `/proc/<pid>/stat`이 없거나, starttime이 다르거나, 좀비(Z/X) | `stopped` (`state`의 pid는 0) |
| 기록상 아직 create 중(훅 실행 중) | `creating` |
| `exec.fifo`가 있음 | `created` |
| cgroup이 얼어 있음(v1 `freezer.state` FROZEN/FREEZING, v2 `cgroup.freeze` 1) | `paused` |
| 그 밖 | `running` |

pid를 재사용한 다른 프로세스는 starttime이 달라 `stopped`로 보입니다. `kill`/`delete`/`exec`는 먼저
`pidfd_open`으로 pidfd(또는 네임스페이스 파일)를 연 다음 starttime을 확인하므로, 확인과 신호 사이에
pid가 재사용되어도 다른 프로세스에 신호를 보내지 않습니다(`OpenVerifiedPidfd`).

## 4. 수명 주기 (`CRuntime`)

### 4.1 create

1. id 검사(`[A-Za-z0-9_+.-]`, `.`/`..` 아님, 1024자 이하), 번들의 config.json을 읽고 검증, rootfs 경로
   (번들 기준 상대 경로 가능)를 realpath로 확정
2. `mkdir <root>/<id>`(이미 있으면 `container with id exists: <id>`), 잠금, `status: creating` 기록
3. cgroup 생성과 자원 적용(5장). 실패하면 root에서는 오류, rootless에서는 경고 후 cgroup 없이 진행
4. config → `SLaunchSpec` 변환(4.6), seccomp 컴파일, 표준 입출력 매핑(기본 0/1/2 상속, `--preserve-fds N`이면
   3..3+N-1), 콘솔 소켓 연결
5. `mkfifo exec.fifo` 후 `O_RDWR`로 열어 `ESG_FD` start gate로 넘김. box가 init을 설정을 끝낸 상태로
   gate에서 기다리게 함
6. init pid와 starttime 기록, `/proc/<pid>/root`(init의 루트, 마운트 포함) 안에서 `openat2(RESOLVE_IN_ROOT)`로
   프로그램을 PATH 검색해 없으면 runc와 같은 `exec: "x": executable file not found in $PATH`로 실패
7. 훅: `prestart` → `createRuntime`(런타임 네임스페이스) → `createContainer`(컨테이너 네임스페이스, 6장)
8. `status: created` 기록, `--pid-file`에 pid를 원자적으로 씀(개행 없음)

어느 단계든 실패하면 init을 죽이고(pidfd), cgroup을 비우고 지운 뒤 상태 디렉터리를 지웁니다.

### 4.2 create가 끝난 뒤의 init (runc의 detach 모델)

runc의 create는 init을 남긴 채 돌아오고 런타임 프로세스는 끝납니다. 같은 구조입니다.

- box가 `clone3(CLONE_NEWPID ...)`로 만든 init은 런타임의 직접 자식입니다. `CProcess::detach()`로 감독을
  포기하고 pidfd를 닫으면 런타임이 끝날 때 init은 가장 가까운 child subreaper(containerd shim)나 pid 1에게
  입양됩니다. 커널이 입양할 때 exit signal을 SIGCHLD로 되돌리므로 shim이 정상적으로 거둡니다.
- init은 런타임의 어떤 프로세스에도 의존하지 않습니다. 이후의 `state`/`kill`/`delete`는 기록된 pid와
  starttime으로 찾고 pidfd로 다룹니다.
- 네임스페이스에 "들어가기"가 섞여 box가 한 번 더 fork해야 하는 경우(새 user 네임스페이스와 기존 netns,
  `exec`의 pid 네임스페이스 들어가기)에는 box의 `orphanPayload`를 씁니다. 바깥 프로세스가 페이로드 pid를
  보고하고 바로 끝나므로 페이로드가 shim에 직접 입양되어, shim이 pid 파일의 pid를 거둘 수 있습니다
  (runc의 exec과 같은 모양). 바깥 프로세스는 create/exec 안에서 거둡니다.
- 전경 실행(`run`, `exec` 전경, 라이브러리의 `keep`)은 `CContainerProcess`로 init을 계속 감독합니다.
  early fork가 있는 create에서는 호출자에게 `PR_SET_CHILD_SUBREAPER`를 켜고 입양된 페이로드를
  `pidfd_open` + `waitid(P_PIDFD)`로 기다립니다.

### 4.3 start

상태가 `created`가 아니면 runc의 메시지(`cannot start an already running container`, `cannot start a
container that has stopped`, ...)로 실패합니다. `startContainer` 훅(컨테이너 네임스페이스) → FIFO를
`O_WRONLY|O_NONBLOCK`으로 열어(읽는 쪽이 없으면 ENXIO = init이 죽음) 1바이트를 쓰고 FIFO를 지움 → init이
바이트를 가져갈 때까지(FIONREAD가 0) 기다림 → `status: running` 기록 → `poststart` 훅(실패는 경고).

### 4.4 kill, delete, pause/resume, update, ps

- `kill [--all] <id> [sig]`: 신호는 번호 또는 이름(`KILL`, `SIGKILL`, `sigterm`, `RTMIN+3`), 기본 SIGTERM.
  `stopped`이면 `container not running`(`-ESRCH`). `--all`은 cgroup의 모든 프로세스(`CCgroup::signalAll`,
  SIGKILL은 v2 `cgroup.kill`), 없으면 init만. 멈춘 컨테이너에 SIGKILL을 보내면 녹여서 죽게 합니다.
  pid 네임스페이스의 init은 핸들러 없는 신호를 무시하므로 `sleep` 같은 init은 SIGTERM에 죽지 않습니다(runc와 같음).
- `delete [--force]`: 없으면 `container does not exist`(containerd가 이 문자열로 판별). `running`/`paused`는
  `--force` 없이 `cannot delete container <id> that is not stopped: <status>`. `created`는 runc처럼 force 없이도
  init을 죽이고 지웁니다. 그다음 cgroup의 남은 프로세스를 죽이고(`killAll`) cgroup을 지우고(`EBUSY`면 2초까지
  재시도), `poststop` 훅(실패는 경고)을 실행하고 상태 디렉터리를 지웁니다.
- `pause`/`resume`: cgroup freezer(`CCgroup::freeze`). cgroup이 없으면 `-ENOTSUP`.
- `update`: `SResourcesSpec`에서 설정된 필드만 바꿔 적용하고 저장된 config에도 병합합니다. 장치 규칙은
  runc처럼 바꾸지 않습니다.
- `processes`(ps): cgroup의 `cgroup.procs`(v2 트리 우선). cgroup이 없으면 init과 같은 pid 네임스페이스의 프로세스.

### 4.5 exec

`created`/`running` 컨테이너에 프로세스를 더합니다(`paused`는 `ignorePaused`가 없으면 거절).

- config의 네임스페이스 종류마다 `/proc/<init>/ns/<file>`을 먼저 연 뒤 init의 starttime을 확인하고
  `/proc/self/fd/<n>` 경로로 box에 넘깁니다(user 네임스페이스는 box가 먼저 들어감). pid 네임스페이스는
  들어간 뒤 fork해야 하므로 box의 early fork가 일어납니다.
- 루트는 바꾸지 않습니다(`ERFS_HOST`): mount 네임스페이스에 들어가면 커널이 루트와 cwd를 그 네임스페이스의
  루트(=pivot_root된 컨테이너 루트)로 바꿉니다.
- 컨테이너 cgroup(v2는 `CLONE_INTO_CGROUP`, v1은 SYNC 단계), 컨테이너의 seccomp 프로필, 프로세스의
  capabilities/rlimit/사용자/no_new_privs/umask를 적용합니다.
- `detach`(또는 keep 없음): `orphanPayload`로 바깥 프로세스가 바로 끝나 프로세스가 shim에 입양됩니다.
  전경(keep): 바깥 프로세스가 reaper로 남아 신호를 전달하고 종료 상태를 그대로 돌려줍니다.
- 프로그램이 없으면 box가 `execve` 오류를 동기적으로 보고합니다(`exec failed: exec: "x": ...`).

### 4.6 config → `SLaunchSpec`

| OCI | box |
|---|---|
| `process.args/env/cwd/user(uid,gid,additionalGids,umask)` | `args`, `env`, `cwd`, `uid`, `gid`, `additionalGids`, `umask` |
| `process.capabilities` | 이름 → 비트 마스크 5종(없으면 모두 0). permitted와 inheritable에 없는 ambient는 runc처럼 경고 후 버림 |
| `process.rlimits`, `oomScoreAdj`, `noNewPrivileges` | `rlimits`, `oomScoreAdj`, `noNewPrivileges` |
| `process.terminal`, `consoleSize` | `terminal`, `terminalRows/Columns`, 콘솔 소켓 fd |
| `linux.namespaces` | 새로(경로 없음) 또는 들어가기(경로), `loopbackUp` = 새 network 네임스페이스 |
| `linux.uidMappings/gidMappings` | 그대로(설정에 사용자 네임스페이스가 없으면 진짜 root로 실행, runc와 같음) |
| `root.path/readonly`, `linux.rootfsPropagation` | `ERFS_DIRECTORY`, `rootReadOnly`, `rootPropagation`(기본 rslave), `--no-pivot` → `noPivot` |
| `mounts` | `ParseMountOptions`; `type: bind` 또는 `bind`/`rbind` 옵션은 bind(상대 source는 번들 기준), `tmpcopyup`은 경고 후 제거, `defaults` 제거 |
| `mounts`의 `cgroup` | 아래 참고 |
| `linux.devices` + 기본 장치 | `DefaultDevices()`(null, zero, full, random, urandom, tty)에 설정의 노드를 덮어씀(`p` FIFO는 경고 후 건너뜀), `/dev` 링크. `/dev`가 bind면 만들지 않음 |
| `maskedPaths`, `readonlyPaths`, `sysctl`, `hostname`, `domainname` | 그대로 |

`/sys/fs/cgroup`(type `cgroup`): v2 전용 호스트에서는 새 cgroup 네임스페이스면 `cgroup2`를 마운트하고, 아니면
컨테이너 cgroup 디렉터리를 bind합니다. v1/hybrid 호스트에서는 runc처럼 tmpfs를 올리고 컨테이너 cgroup의 각 v1
계층 디렉터리를 계층 이름(`memory`, `cpu,cpuacct` ...)으로, v2 디렉터리를 `unified`로 bind합니다. 원래 마운트가
`ro`면 bind도 읽기 전용이고 tmpfs 자체도 마지막에 읽기 전용이 됩니다. 컨테이너 안에서 `/sys/fs/cgroup/pids/pids.max`
는 컨테이너 자신의 제한입니다(테스트).

## 5. cgroup

- 경로: `cgroupsPath`가 `/a/b`면 계층 루트 기준 `a/b`, 상대 경로면 `CCgroup::defaultParent()`(root는 `sbox`) 아래,
  없으면 `<parent>/<id>`. `--systemd-cgroup`이면 `slice:prefix:name`을 cgroupfs 경로로 바꿉니다:
  `system.slice:docker:abc` → `system.slice/docker-abc.scope`, `a-b.slice` → `a.slice/a-b.slice`, 빈 slice는
  `system.slice`(rootless는 `user.slice`), name이 `.slice`로 끝나면 그 slice 자체. systemd에 단위를 만들지는
  않습니다(제한 사항).
- 자원: `linux.resources` → `SCgroupResources`(memory limit/reservation/swap, pids, cpu shares/quota/period/cpus/mems,
  blkio weight/throttle, unified, devices). `pids.limit`이 0 이하면 runc처럼 무제한. 적용할 수 없는 항목(커널
  메모리, swappiness, hugepage, rdma, network, 실시간 CPU, idle, burst, weightDevice, leafWeight, disableOOMKiller)은
  경고입니다. 컨트롤러가 없어 건너뛴 제한은 `cgroup controller unavailable, limit not enforced: <name>` 경고.
- 장치 규칙: 설정의 규칙 뒤에 runc가 항상 허용하는 규칙(`c/b *:* m`, null, zero, full, random, urandom, tty,
  console, ptmx, `/dev/pts/*`, tun)과 설정한 장치 노드의 허용 규칙을 붙입니다(마지막 일치가 이김). rootless는 적용하지 않습니다.

## 6. 훅 (`hooks.hpp`)

- 각 훅은 `path`를 `args`(args[0]이 argv[0], 없으면 path)와 정확히 `env`로 실행하고, 표준 입력에 상태 JSON을
  쓰고, 표준 출력/오류를 64 KiB까지 모읍니다. 런타임의 capability 집합(`/proc/self/status`)을 그대로 넘겨 root
  런타임의 훅은 root 권한을 가집니다. `timeout`(초)이 지나면 SIGKILL하고 `-ETIMEDOUT`.
- 실패 메시지는 runc 형식: `error running hook <path>: exit status 4, stdout: ..., stderr: ...`.
- `prestart`, `createRuntime`, `poststart`, `poststop`은 런타임 네임스페이스에서 실행합니다. libnetwork-setkey
  같은 네트워크 훅은 상태의 pid로 `/proc/<pid>/ns/net`에 들어가 설정합니다.
- `createContainer`, `startContainer`는 실행 파일을 런타임의 mount 네임스페이스에서 `O_PATH`로 연 뒤, init의
  네임스페이스(pid 제외)에 들어간 자식에서 `execveat(fd, "", AT_EMPTY_PATH)`로 실행합니다(box의 함수 페이로드).
- 상태 JSON의 status: create 훅은 `creating`, `startContainer`는 `created`, `poststart`는 `running`,
  `poststop`은 `stopped`. 순서와 각 단계의 상태, 네임스페이스(UTS의 hostname)를 테스트합니다.
- 실패 처리: create 단계 훅이나 `startContainer`가 실패하면 명령이 실패하고(create는 정리까지),
  `poststart`/`poststop`의 실패는 명세대로 경고만 남깁니다.

## 7. 콘솔

- `process.terminal`이면 box가 컨테이너의 새 devpts에서 pty를 만들고 slave를 0/1/2에 둡니다.
- `--console-socket <path>`: 런타임이 그 AF_UNIX 소켓에 연결해 box에 넘기고, box가 pty master를
  `SCM_RIGHTS`로 보냅니다(runc와 같은 프로토콜, containerd/dockerd가 받음). `consoleSize`는 pty에 바로 적용됩니다.
- 콘솔 소켓 없이 terminal이면 detach할 수 없으므로 runc 메시지로 거절합니다(`cannot allocate tty if runc will
  detach without setting console socket`). 전경 `run`/`exec -t`는 master를 받아 프록시합니다(8.3).

## 8. 명령줄 (`cli/sbox`)

같은 소스로 `sbox`와 `sboxrun` 두 바이너리를 만듭니다(`build/bin/`). 이름은 사용법/버전 출력에만 쓰입니다.

### 8.1 전역 플래그 (runc와 같음)

`--root <dir>`, `--log <file>`(추가 모드), `--log-format text|json`, `--debug`, `--systemd-cgroup`,
`--rootless true|false|auto`(auto = euid가 0이 아님), `--criu <path>`(무시), `--help/-h`, `--version/-v`.
플래그는 `--name value`, `--name=value`, `-name value`(Go flag 형식), 짧은 이름을 받고 첫 위치 인자에서 멈춥니다.

### 8.2 명령

| 명령 | 플래그 |
|---|---|
| `create <id>` | `--bundle/-b`, `--console-socket`, `--pid-file`, `--no-pivot`, `--no-new-keyring`, `--preserve-fds N`, `--pidfd-socket`(경고 후 무시) |
| `start <id>`, `state <id>`, `pause <id>`, `resume <id>` | |
| `run <id>` | create 플래그 + `--detach/-d`, `--keep`, `--no-subreaper` |
| `kill [--all/-a] <id> [signal]` | |
| `delete [--force/-f] <id>` | |
| `exec <id> <cmd> [args...]` | `--process/-p <file\|->`, `--detach/-d`, `--pid-file`, `--console-socket`, `--tty/-t`, `--cwd`, `--env/-e`(반복), `--user/-u uid[:gid]`, `--additional-gids/-g`, `--cap/-c`, `--no-new-privs`, `--preserve-fds`, `--ignore-paused`, `--cgroup`/`--apparmor`/`--process-label`(경고 후 무시) |
| `ps [--format table\|json] <id> [ps 옵션...]` | 표는 `ps -ef`(또는 주어진 옵션) 출력에서 헤더의 PID 열로 컨테이너 pid만 남김 |
| `update <id>` | `--resources/-r <file\|->`, `--memory`, `--memory-reservation`, `--memory-swap`(512m, 1g, -1), `--kernel-memory[-tcp]`, `--cpu-share`, `--cpu-quota`, `--cpu-period`, `--cpu-rt-*`, `--cpuset-cpus`, `--cpuset-mems`, `--cpu-idle`, `--pids-limit`, `--blkio-weight`, `--l3-cache-schema`/`--mem-bw-schema`(경고) |
| `list [--format table\|json] [-q]` | 표는 Go tabwriter(최소 12, 여백 3) 배치, OWNER는 `/etc/passwd`의 이름 |
| `events [--stats] [--interval 5s] <id>` | `--stats`: 통계 이벤트 하나. 아니면 간격마다 통계, `oom_kill`이 늘면 `{"type":"oom"}`, 컨테이너가 멈추면 끝 |
| `features` | runc의 features JSON 형식(지원하는 훅, 마운트 옵션, 네임스페이스, capability, seccomp 동작/연산자/ABI/플래그, cgroup v1/v2, apparmor/selinux/intelRdt/idmap 비활성) |
| `spec [--bundle] [--rootless]` | config.json 생성(이미 있으면 실패) |
| `checkpoint`, `restore` | 지원하지 않음(오류) |

출력: `state`는 2칸 들여쓴 JSON(끝 개행 없음, runc와 같음), `list --format json`/`ps --format json`/`events`는 한
줄 JSON. 이벤트의 `data`는 runc 형식의 부분집합(`cpu.usage.total/kernel/user`(ns), `memory.usage.usage/max/failcnt`,
`pids.current`)입니다.

### 8.3 전경 실행

`run`(detach 없음)과 전경 `exec`는 SIGINT/TERM/HUP/QUIT/USR1/USR2/WINCH를 막고 signalfd로 받아 컨테이너
프로세스에 전달합니다(WINCH는 pty 창 크기 복사). terminal이면 표준 입력이 터미널일 때 raw 모드로 바꾸고 pty와
표준 입출력 사이를 코루틴으로 복사하며, 끝나면 터미널 설정과 시그널 마스크를 되돌립니다. 종료 상태는 코드 또는
128 + 시그널입니다. `run`은 끝난 컨테이너를 지웁니다(`--keep`이면 남김).

### 8.4 로그와 오류

오류는 종료 코드 1입니다. 로그 형식은 logrus와 같습니다.

- text: `time="2026-10-04T12:51:37Z" level=error msg="container does not exist"`
- json: `{"level":"error","msg":"container does not exist","time":"2026-10-04T12:51:37Z"}`

`--log`가 없으면 로그는 표준 오류로 갑니다. `--log`가 있으면 그 파일에 쓰고, 오류 메시지는 runc처럼 표준
오류에 평문으로도 한 줄 씁니다. containerd(go-runc)는 json 로그 파일의 마지막 error 줄을 오류로 씁니다.

## 9. Docker / containerd 등록

dockerd는 컨테이너를 containerd의 runc shim(`io.containerd.runc.v2`)으로 실행하고, shim이 런타임 바이너리를
runc와 같은 명령줄로 부릅니다.

```
sboxrun --root /var/run/docker/runtime-runc/moby --log <task>/log.json --log-format json [--systemd-cgroup] \
        create --bundle <bundle> --pid-file <bundle>/init.pid [--console-socket <sock>] <id>
sboxrun ... start <id> | state <id> | kill [--all] <id> <signo> | delete [--force] <id>
sboxrun ... exec --process <file> --detach --pid-file <file> [--console-socket <sock>] <id>
sboxrun ... ps --format json <id> | pause <id> | resume <id> | update --resources - <id> | features
```

dockerd(`/etc/docker/daemon.json`):

```json
{ "runtimes": { "sboxrun": { "path": "/usr/local/bin/sboxrun" } } }
```

```sh
docker run --runtime=sboxrun --rm busybox echo hello
# 기본 런타임으로: "default-runtime": "sboxrun"
```

containerd(`/etc/containerd/config.toml`, containerd 2.x의 CRI 예):

```toml
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.sboxrun]
  runtime_type = "io.containerd.runc.v2"
  [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.sboxrun.options]
    BinaryName = "/usr/local/bin/sboxrun"
```

containerd 1.x는 `[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.sboxrun]`에 같은 값을 씁니다.
`ctr run --runc-binary /usr/local/bin/sboxrun ...`, nerdctl은 `nerdctl run --runtime /usr/local/bin/sboxrun ...`
(runc 호환 바이너리 경로를 받음) 또는 위 설정의 런타임 이름을 씁니다.

이 기계(Docker 29.6.2, containerd 2.x, cgroup v1 hybrid)에서 `docker run --runtime=sboxrun`(종료 코드, 없는 프로그램
오류 127, `-t`, `-d`, `exec`(-t 포함), `top`, `pause/unpause`, `update`, `stats`, `stop`(137), `rm`, `--network host`,
`-u`, `--read-only`, `-m`)과 `ctr run --runc-binary`가 동작함을 확인했습니다. 같은 시나리오가 `oci_docker` 테스트로
있습니다(`SBOX_TEST_DOCKER=1`일 때만 실행).

## 10. 네트워킹

런타임은 runc처럼 네트워크를 만들지 않습니다. 컨테이너를 네트워크에 붙이는 방법:

- config.json의 `linux.namespaces`에 `{"type": "network", "path": "/var/run/netns/<name>"}`을 주면 그
  네트워크 네임스페이스에 들어갑니다(테스트: 영구 netns의 inode와 컨테이너의 `/proc/self/ns/net`이 같음).
  새 사용자 네임스페이스와 함께여도 box가 netns에 먼저 들어간 뒤 사용자 네임스페이스를 만듭니다.
- 네임스페이스는 net 모듈로 미리 만들고 연결합니다: `CNetns::createNamed`(iproute2 형식) 또는 `sbox-cni`
  (CNI 1.0 플러그인, `CNI_NETNS=/var/run/netns/<name>`)로 `ADD`한 뒤 그 경로를 config.json에 넣습니다.
  `CNetworkManager::connect(network, netnsPath, ...)`도 같은 경로를 받습니다([net.md](net.md)).
- Docker는 자체 libnetwork 훅(prestart/createRuntime의 `libnetwork-setkey`)으로 init의 `/proc/<pid>/ns/net`을
  설정하며 그대로 동작합니다(훅이 상태 JSON의 pid를 받음).

## 11. rootless

- 비특권 사용자가 `sbox spec --rootless`의 설정(자기 uid/gid → 0 매핑)으로 실행합니다. box가 `setgroups`를
  `deny`로 쓰고 매핑을 기록합니다. 기본 상태 루트는 `$XDG_RUNTIME_DIR/sbox`.
- 위임된 cgroup이 없으면 cgroup 없이 실행합니다(경고). 그때 `/sys/fs/cgroup`은 빈 tmpfs, pause/update/stats는
  `-ENOTSUP`, `ps`는 pid 네임스페이스로 찾습니다.
- 장치 노드는 mknod 대신 호스트 노드 bind(box). 테스트는 uid 65534로 내려간 자식이 컨테이너를 만들어 안에서
  `id -u` = 0, uid_map이 `0 65534 1`임을 확인합니다.

## 12. 사용하는 커널 인터페이스

box의 것(clone3, setns, pivot_root, seccomp, cgroupfs ...)에 더해: `pidfd_open`, `pidfd_send_signal`,
`waitid(P_PIDFD)`, `mkfifo`와 FIFO의 `O_NONBLOCK` 열기(ENXIO), `FIONREAD`, `fcntl(F_SETLK)` 레코드 잠금,
`openat2(RESOLVE_IN_ROOT)`(`/proc/<pid>/root` 안의 프로그램 확인), `/proc/<pid>/stat`(starttime),
`/proc/<pid>/ns/*`, `execveat(AT_EMPTY_PATH)`(컨테이너 네임스페이스 훅), `prctl(PR_SET_CHILD_SUBREAPER)`,
`signalfd`, `TIOCGWINSZ`/`TIOCSWINSZ`, `SCM_RIGHTS`.

## 13. 제한 사항

- systemd cgroup 드라이버: `--systemd-cgroup`은 경로만 cgroupfs로 바꾸며 systemd 단위(scope/slice)를 만들거나
  속성(`org.systemd.property.*` 주석)을 적용하지 않습니다.
- AppArmor, SELinux(`selinuxLabel`, `mountLabel`), Intel RDT, `personality`, `scheduler`, `ioPriority`,
  `execCPUAffinity`, `timeOffsets`, `memoryPolicy`는 받아들이되 적용하지 않습니다(경고). `linux.netDevices`와
  idmapped 마운트(`uidMappings`/`gidMappings`, `idmap` 옵션)는 create에서 거절합니다.
- seccomp `SCMP_ACT_NOTIFY`(listenerPath)는 지원하지 않고, box 표가 없는 ABI(ARM, MIPS, PPC, S390, RISC-V)의
  규칙은 건너뜁니다.
- `createContainer`/`startContainer` 훅은 init 안이 아니라 런타임이 init의 네임스페이스(pid 제외)에 들어간
  자식에서 실행하며, `createContainer`는 pivot_root 전이 아니라 설정이 모두 끝난 뒤에 실행됩니다. 컨테이너
  네임스페이스의 훅이 스크립트나 동적 링크 실행 파일이면 인터프리터/로더가 컨테이너 루트에 있어야 하고, 그
  훅에서 `/proc/self`는 쓸 수 없습니다(컨테이너 pid 네임스페이스 밖).
- `checkpoint`/`restore`(CRIU) 없음. `events`는 runc 통계의 부분집합이고 OOM은 주기적 폴링으로 알립니다.
- `exec --user`는 숫자 uid[:gid]만 받고(이름 조회 없음), `exec --cgroup`(하위 cgroup), `--pidfd-socket`은 무시합니다.
- v1 호스트에서 컨테이너의 `/sys/fs/cgroup`에 `name=systemd` 계층은 넣지 않습니다(그 안에서 systemd를 init으로
  돌리기 어려움).
- 라이브러리로 `CRuntime::create`/`exec`를 keep 없이 오래 사는 프로세스에서 부르면, detach된 init이 그 프로세스가
  끝날 때까지 자식(종료 후 좀비)으로 남습니다. CLI는 바로 끝나므로 문제가 없습니다. keep으로 early fork가 있는
  create를 하면 호출자에게 `PR_SET_CHILD_SUBREAPER`가 켜집니다.
- init은 프로그램을 exec할 때까지(start 전까지) 런타임 프로세스의 디스크립터 사본을 close-on-exec 상태로 갖고
  있습니다(box의 동작). 그래서 상태 잠금은 상속되지 않는 POSIX 잠금을 씁니다.
- 컨테이너 네임스페이스 훅(`createContainer`/`startContainer`)은 box의 함수 페이로드(fork)를 쓰므로 호출
  프로세스가 단일 스레드여야 합니다(CLI는 항상 그렇고, 멀티스레드 라이브러리 사용자는 `-EBUSY`).
- 같은 프로세스 안의 동시 잠금은 프로세스 내부 목록으로만 배제합니다(스레드 간 공유는 지원하지 않음).
- rootless는 box의 제한대로 단일 uid/gid 매핑만(`newuidmap` 없음), 위임된 v2 cgroup이 있을 때만 cgroup을 씁니다.
- `CJson`은 INT64_MAX보다 큰 정수를 double로 쓰므로, 그런 값(예: RLIMIT_INFINITY)은 저장된 state.json의 config에
  지수 표기로 기록됩니다(다시 읽으면 UINT64_MAX).

## 14. 테스트

`ctest --test-dir build -j8 -L oci`

| 실행 파일 | 내용 |
|---|---|
| `oci_spec` | runc 기본/rootless 설정 왕복과 `DefaultSpec` 일치, 모든 필드 왕복, 큰 부호 없는 값, 필드 경로가 있는 형식 오류, 모르는 필드 경고, 검증 오류 30여 가지와 경고, process/resources 문서, 이름 표 |
| `oci_seccomp` | Docker 기본 프로필 변환·컴파일·판정(capability/커널/ABI 조건, 32비트 ABI), 호스트 문맥, 프로필 오류, OCI 의미(동작, errno 기본값, 플래그, ABI 경고, NOTIFY 거절), 자식에 설치해 거부 확인 |
| `oci_state` | 상태 JSON 순서, 기록 왕복, starttime·좀비 판정, 타임스탬프와 id, 신호 이름, systemd 경로 변환, 전파 이름, 자원 변환과 기본 장치 규칙 |
| `oci_runtime` | 라이브러리 수명 주기(create→created→start→running→kill→stopped→delete, pid 파일, 오류 메시지), 사용자 네임스페이스 없는 진짜 root와 출력, 전경 종료 코드, 없는 프로그램, exec가 같은 pid/mount 네임스페이스와 cgroup에 들어감(전경/detach/실패), pause/resume과 paused 상태의 exec/force delete, 훅 순서·상태·네임스페이스, 실패/시간 초과 훅의 정리, 콘솔 소켓 pty와 창 크기, cgroup 자원(v1)·장치 규칙·컨테이너 안의 `/sys/fs/cgroup`·update·stats, pid 재사용, netns 경로 들어가기, rootless(uid 65534), created 컨테이너 삭제 |
| `oci_cli` | 버전/도움말/모르는 명령, `spec`(--rootless), `features`, CLI 수명 주기(list 표/json/-q, ps 표/json, kill 이름, 오류 메시지), 전경 `run`과 `--keep`, pty 프록시, exec(env/cwd/user/detach/paused), events --stats, update 플래그 |
| `oci_compat` | dockerd/containerd(go-runc) 명령줄 재생: Docker 형태 설정(Docker seccomp, capability, 가림 경로, cgroupfs 경로, sysctl, prestart 훅)으로 create/state/start/exec --process --detach/ps --format json/update --resources -/pause/resume/events --stats/kill/kill --all/delete와 JSON 로그; 콘솔 소켓 create/exec와 delete --force; `--systemd-cgroup`; create 실패의 JSON 로그 |
| `oci_docker` | (`SBOX_TEST_DOCKER=1`) 전용 dockerd에 `sboxrun`을 등록하고 `docker run/exec/pause/update/top/stop/rm` 확인 |

컨테이너 테스트는 root가 필요하고(아니면 MESSAGE 후 건너뜀), rootfs는 호스트의 `sh`, `sleep`, `cat` ... 과 `ldd`가
알려 준 공유 라이브러리를 `/var/tmp` 아래 mkdtemp 디렉터리에 복사해 만듭니다. id, 상태 루트, cgroup 경로가 모두
고유해 병렬로 안전합니다.
