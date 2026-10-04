# box 모듈

libsbox의 격리 엔진입니다. 네임스페이스, 마운트와 루트 전환, cgroups v1/v2, seccomp BPF, capabilities,
rlimit, 사용자 네임스페이스 ID 매핑을 다루고, 그 위에 샌드박스 API(`CSandbox`, `SBoxPolicy`)를
제공합니다. OCI 런타임(oci 모듈)은 이 모듈의 공개 실행 엔진(`SLaunchSpec`, `CProcess`)과
`CCgroup`, `CSeccompFilter` 위에 만들어집니다.

- 네임스페이스: `sbox` (중첩하지 않음)
- 헤더: `include/sbox/box/`, CMake 타깃: `sbox::box` (의존: `sbox::core`)

| 헤더 | 내용 |
|---|---|
| `box/launch.hpp` | 실행 엔진: `SLaunchSpec`(컨테이너 프로세스 하나의 값 명세), `CProcess`(pidfd 핸들), `ParseMountOptions`, `DefaultDevices`, `CapabilityFromName` |
| `box/cgroup.hpp` | `SCgroupSystem`(레이아웃 감지), `SCgroupResources`(OCI `linux.resources` 부분집합), `SCgroupStats`, `CCgroup` |
| `box/seccomp.hpp` | `SSeccompProfile`/`SSeccompRule`(선언형 정책), `CSeccompFilter`(classic BPF 컴파일러), 시스템 콜 이름↔번호 표 |
| `box/policy.hpp` | `SBoxPolicy`(샌드박스 정책과 프리셋), `SBoxResult`, `EBoxExitReason` |
| `box/sandbox.hpp` | `CSandbox`: `spawn`, `fork`, `stdinPipe`/`stdoutPipe`/`stderrPipe`, `wait`, `kill` |

## 1. 실행 엔진 (`launch.hpp`)

### 1.1 명세

`SLaunchSpec`은 프로세스 하나를 clone3에서 execve까지 준비하는 데 필요한 것을 모두 담은 값 타입입니다.

| 묶음 | 필드 |
|---|---|
| 프로세스 | `args`, `env`, `executable`(명시 경로), `cwd`, `function`(exec 대신 실행할 함수), `uid`, `gid`, `additionalGids`, `umask`, `newSession` |
| 네임스페이스 | `namespaces`(종류별로 새로 만들기 = 빈 경로, 들어가기 = `/proc/<pid>/ns/net` 같은 경로), `uidMappings`/`gidMappings`, `denySetgroups`, `hostname`, `domainname` |
| 파일 시스템 | `rootfsMode`(`ERFS_HOST`/`ERFS_TMPFS`/`ERFS_DIRECTORY`), `rootfs`, `stagingDir`, `rootTmpfsOptions`, `rootReadOnly`, `rootPropagation`, `noPivot`, `mounts`, `devices`, `devSymlinks`, `maskedPaths`, `readonlyPaths`, `sysctls`, `loopbackUp` |
| 보안 | `capabilities`(bounding/effective/permitted/inheritable/ambient 비트 마스크, 기본 전부 0), `noNewPrivileges`(기본 true), `seccomp`(`CSeccompFilter`), `rlimits`, `oomScoreAdj`, `parentDeathSignal` |
| 입출력 | `fds`(호출자 fd → 대상 번호; 나머지는 exec 전에 닫힘), `terminal`, `consoleSocketFd`, `terminalRows`/`terminalColumns` |
| 수명 | `gate`(`ESG_NONE`/`ESG_INTERNAL`/`ESG_FD`), `gateFd`, `reaper`, `cgroup`(`CCgroup*`), `setupTimeoutMs` |

`SMountSpec`은 OCI 마운트와 같은 모양(source, destination, type, MS_* flags, 전파 플래그, data,
`recursiveReadOnly`, `optional`)이며 `ParseMountOptions`가 OCI 옵션 문자열(`rbind`, `ro`, `rprivate`,
`rro`, `nosymfollow` ...)을 이 필드들로 바꿉니다. 모르는 옵션은 파일 시스템 data로 넘어갑니다.

### 1.2 프로세스 구조

```
호출자 (CProcess::spawn, 이벤트 루프 위의 코루틴)
 └─ clone3(CLONE_PIDFD | 새 네임스페이스 | CLONE_INTO_CGROUP, exit_signal = 0)
     └─ 자식: setns → unshare → [동기화] → 설정 → [reaper fork] → gate → seccomp → execve
```

- 새 네임스페이스는 가능하면 clone3에 바로 넘깁니다. 자식은 새 pid 네임스페이스의 pid 1입니다.
- 네임스페이스에 "들어가기"가 섞이면 순서가 중요합니다. 사용자 네임스페이스에 들어가거나, 새 사용자
  네임스페이스와 다른 네임스페이스 들어가기가 함께 있으면 clone3는 아무 네임스페이스도 만들지 않고, 자식이
  `setns`(사용자 네임스페이스 먼저)로 들어간 뒤 `unshare`로 나머지를 만듭니다(deferred). 기존 네트워크
  네임스페이스에 들어간 다음에 새 사용자 네임스페이스를 만들어야 그 네트워크 네임스페이스에 들어갈 권한이
  있기 때문입니다.
- pid 네임스페이스는 `unshare`/`setns` 후 자식에게만 적용되므로, 그 경우(early fork) 자식이 한 번 더
  fork하고 바깥 프로세스는 reaper가 됩니다.
- `reaper`(샌드박스 기본값, `function`이면 강제): 설정을 마친 init이 페이로드를 fork하고 남습니다.
  페이로드가 pid 1이 아니게 되어(pid 1은 핸들러 없는 시그널을 무시하므로 `kill -TERM $$`, abort,
  SIGXCPU가 다르게 동작) 일반 프로세스처럼 죽습니다. reaper는 모든 자식을 거두고, 잡을 수 있는 시그널을
  페이로드에 전달하고, 자신의 capabilities를 모두 버린 뒤, 페이로드의 wait 상태를 보고 파이프로 알리고
  끝납니다. reaper가 끝나면 pid 네임스페이스의 나머지는 커널이 죽입니다.
- `orphanPayload`: early fork의 바깥 프로세스가 reaper로 남지 않고 페이로드 pid(`PID` 레코드)를 보고한 뒤
  바로 끝납니다. 페이로드는 가장 가까운 child subreaper(OCI shim, 또는 `PR_SET_CHILD_SUBREAPER`를 켠
  호출자)에게 입양되며, runc의 `exec`/`create`가 프로세스를 남기는 방식과 같습니다(oci 모듈이 씀). 이때
  `payloadPid()`는 호출자의 자식이 아닌 페이로드이고 `pid()`/`wait()`는 이미 끝난 바깥 프로세스입니다.
- 페이로드 fork는 glibc `_Fork`(락과 atfork 처리 없음, 비동기 시그널 안전)를 씁니다. raw clone과 달리
  glibc의 캐시된 tid를 갱신하므로 `function` 페이로드의 `raise`/`abort`가 올바르게 동작합니다.
- 부모는 시그널을 모두 막은 채 clone3를 부르고, 자식은 처음에 모든 시그널 처리기를 기본값으로 되돌린 뒤
  마스크를 풉니다. 자식에서는 할당이나 락 없이 미리 만든 평면 데이터(`LaunchPlan`)만 읽고 시스템 콜만
  부르므로 호출자가 멀티스레드여도 됩니다(`function` 페이로드는 예외: 1.8 참고).

### 1.3 보고 파이프와 동기화

자식 → 부모로 close-on-exec 파이프에 고정 크기 레코드(`kind, error, step, index, value`, PIPE_BUF 이하라
원자적)를 씁니다.

| 레코드 | 의미 |
|---|---|
| `SYNC` | 네임스페이스가 준비됨. 부모는 `/proc/<pid>/setgroups`(비특권이면 `deny`), `uid_map`, `gid_map`을 쓰고 v1 cgroup에 pid를 넣은 뒤 동기화 파이프로 1바이트를 보냄 |
| `ERROR` | 설정 단계 실패: errno와 단계 이름(`mount[3]`, `pivot_root`, `execve` ...) |
| `READY` | 설정 완료, start gate에서 대기 중 |
| `EXEC` | (reaper가 보냄) 페이로드가 exec했거나 함수를 시작함 |
| `PID` | (pid 네임스페이스 밖 reaper가 보냄) 호출자 기준 페이로드 pid |
| `EXIT` | (reaper가 보냄) 페이로드의 wait 상태 |

- reaper가 없으면 파이프가 exec에서 닫히는 것(EOF)이 성공 신호입니다. exec 실패는 `ERROR` 레코드로 옵니다.
- 사용자 네임스페이스를 새로 만들 때 자식은 동기화 전 잠시 dumpable이 되어(비특권 부모가 자식의 `/proc`
  파일을 쓸 수 있도록) 동기화 뒤 원래 값으로 돌아갑니다. 그다음 매핑된 ID(매핑되어 있으면 0)로 바꿔
  capabilities를 유지한 채 설정을 계속합니다. 새 파일 시스템(tmpfs)에 만드는 파일은 매핑된 ID가 소유해야
  하기 때문입니다.
- `CProcess::spawn`은 페이로드가 실행되면(gate가 있으면 `READY`에서) 돌아옵니다. 자식 단계가 실패하면 그
  errno를 돌려주고 `failedStep()`에 단계 이름을 남기며 자식은 이미 거둬진 상태입니다.

### 1.4 start gate (OCI create/start)

- `ESG_INTERNAL`: 엔진이 파이프를 만들고 `CProcess::start()`가 1바이트를 씁니다. 이후 `waitStarted()`가
  exec 결과(성공 또는 `execve` 오류)를 알려 줍니다.
- `ESG_FD`: 프로세스가 `gateFd`에서 1바이트를 읽을 때까지 기다립니다. OCI 런타임은 상태 디렉터리의 FIFO를
  `O_RDWR`로 열어 넘기면 됩니다(양쪽 모두 open에서 막히지 않음). `start` 명령은 FIFO를 `O_WRONLY`로 열어
  1바이트를 쓰면 됩니다. 바이트 없이 EOF면 페이로드는 실행하지 않고 끝납니다.
- gate 대기는 seccomp 설치 전, capabilities와 ID를 바꾼 뒤입니다.

### 1.5 설정 순서 (자식)

1. 시그널 초기화, 내부 fd를 매핑 대상 번호 위로 옮김(`F_DUPFD_CLOEXEC`), `PR_SET_PDEATHSIG`
2. `setns`(사용자 → 나머지), `unshare`, 동기화, 필요하면 early fork, 매핑된 ID로 전환
3. `oom_score_adj`, 루프백 활성화, `sethostname`/`setdomainname`
4. 파일 시스템(새 마운트 네임스페이스일 때): `/` 전파 설정(기본 `MS_SLAVE|MS_REC`) → bind 소스 확보 →
   루트 준비 → 마운트 → 장치 노드 → `/dev` 심볼릭 링크 → `pivot_root(".", ".")` + `umount2(".", MNT_DETACH)`
   (또는 `noPivot`: `MS_MOVE` + `chroot`) → 공유 전파는 pivot 뒤에 적용
5. sysctl(`/proc/sys/...`) → 읽기 전용 경로 → 가림 경로 → 루트 읽기 전용
6. rlimit → `setsid` → pty
7. (`noNewPrivileges`가 false이고 seccomp가 있으면 여기서 seccomp 설치: CAP_SYS_ADMIN이 있을 때)
8. bounding 집합에서 빼기 → `PR_SET_KEEPCAPS` → `setgroups` → `setresgid` → `setresuid` → `capset` →
   ambient → umask → `chdir`
9. fd 매핑: 대상에 `dup2`, 대상이 아닌 낮은 번호 닫기, 나머지 전부 `close_range(CLOSE_RANGE_CLOEXEC)`
10. reaper fork → gate → `PR_SET_NO_NEW_PRIVS` → seccomp(마지막) → `execve`(PATH 검색은 명세의 `PATH`로
    직접; `EACCES`를 우선 보고) 또는 함수 실행

### 1.6 파일 시스템 세부

- 대상 경로 해석: 모든 마운트 대상은 새 루트 안에서 `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`로
  열고, 없으면 구성 요소를 하나씩 걸으며 만듭니다. 이때 심볼릭 링크는 직접 읽어 루트 기준으로 다시 해석하므로
  신뢰할 수 없는 rootfs의 `/etc -> /host-path` 같은 링크(대상이 아직 없어도)도 루트 밖으로 나가지 못합니다.
  마운트는 그렇게 얻은 O_PATH 디스크립터의 `/proc/self/fd/N` 경로에 합니다.
- bind 소스: 자식이 자기 마운트 네임스페이스에서, 새 루트를 만들기 전에 `open_tree(OPEN_TREE_CLONE
  [| AT_RECURSIVE])`로 떼어 낸 트리를 잡고 `move_mount`로 붙입니다(5.2 미만은 O_PATH + `/proc/self/fd` bind).
  그래서 staging 디렉터리를 포함하는 경로(`/tmp`, `/`)를 bind해도 새 루트가 끼어들지 않습니다.
- bind의 ro/nosuid/nodev/noexec는 `MS_REMOUNT|MS_BIND`로 적용하며, 더 특권 있는 네임스페이스가 잠근
  플래그는 `statfs`로 읽어 함께 넘깁니다. `recursiveReadOnly`는 `mount_setattr(AT_RECURSIVE,
  MOUNT_ATTR_RDONLY)`(5.12+)로 하위 마운트까지 읽기 전용으로 만듭니다.
- `ERFS_TMPFS`: `stagingDir`(기본 `/tmp`, 새 마운트 네임스페이스 안에서만 보임)에 tmpfs를 올리고 그 안에
  트리를 짭니다. `ERFS_DIRECTORY`: 주어진 디렉터리를 자기 자신에 rbind해 마운트 지점으로 만듭니다
  (overlay는 호출자가 미리 마운트).
- 장치: `mknod`를 먼저 시도하고, 사용자 네임스페이스라 `EPERM`이면 같은 경로의 호스트 노드(번호가 같을
  때만)를 빈 파일 위에 bind합니다. `devSymlinks`는 `/dev/fd`, `stdin`, `stdout`, `stderr`, `ptmx -> pts/ptmx`를
  만듭니다(이미 있으면 그대로 둠).
- 가림 경로: 디렉터리는 읽기 전용 tmpfs, 파일은 `/dev/null` bind. 없는 경로는 건너뜁니다.

### 1.7 기다리기와 자원 사용량

- `CProcess::wait`는 pidfd를 `CEventLoop::waitFd`로 기다린 뒤 `waitid(P_PIDFD, WEXITED | __WALL)`로 거두며
  rusage를 함께 받습니다. SIGCHLD도 블로킹 waitpid도 쓰지 않습니다. 시간 제한을 줄 수 있고 `tryWait`는
  기다리지 않습니다.
- reaper가 보낸 `EXIT`가 있으면 종료 코드와 시그널은 페이로드의 것을, rusage는 init의 것(거둔 자손 포함)을
  씁니다.
- `SExitStatus`의 `userTimeUs`/`systemTimeUs`/`maxRssBytes`는 rusage입니다. CPU 시간은 거둔 자손의 합이고,
  최대 RSS는 한 프로세스의 최댓값입니다. 프로세스 트리 전체의 정확한 값은 cgroup 통계로 얻습니다(3장).
- 소멸자는 거두지 않은 프로세스를 SIGKILL하고 거둘 수 있으면 거둡니다. `detach()`는 감독을 포기하고 pidfd를
  돌려줍니다(OCI `create` 뒤처럼 프로세스를 계속 돌릴 때).

### 1.8 함수 페이로드와 fork 규칙

`function`은 exec 없이 현재 프로그램의 함수를 격리된 프로세스에서 실행합니다(`CSandbox::fork`의 기반).
fork 시점에 다른 스레드가 malloc/stdio 락을 쥐고 있으면 자식에서 영원히 풀리지 않으므로
`/proc/self/task`가 2개 이상이면 `-EBUSY`로 거절합니다. 함수 실행 전에 내부 fd를 모두 닫고 호출자가 버퍼에
남긴 stdout/stderr 내용을 버립니다(`__fpurge`). 함수 안에서는 호출자의 `CEventLoop`를 쓰면 안 됩니다(그
epoll fd는 닫혀 있음). 필요하면 새 `CEventLoop`를 만듭니다. 반환값이 종료 코드이고, 끝나면 stdio를
flush하고 `_exit`합니다(atexit와 정적 소멸자는 실행하지 않음).

## 2. seccomp (`seccomp.hpp`)

### 2.1 모델

`SSeccompProfile`은 OCI `linux.seccomp`와 일대일로 대응합니다.

- `defaultAction`/`defaultErrno`, `architectures`, `badArchAction`(목록에 없는 ABI), `flags`(`LOG`,
  `SPEC_ALLOW`), `rules`
- `SSeccompRule`: `names`, `action`(`KILL_PROCESS`, `KILL_THREAD`, `TRAP`, `ERRNO`, `TRACE`, `LOG`, `ALLOW`),
  `errnoRet`, `args`
- `SSeccompArg`: `index`, `op`(`NE`, `LT`, `LE`, `EQ`, `GE`, `GT`, `MASKED_EQ`), `value`, `valueTwo`
  (`MASKED_EQ`는 `(arg & value) == valueTwo`)

한 시스템 콜에 대해 인자 조건이 있는 규칙을 주어진 순서로 먼저 보고, 그다음 조건 없는 첫 규칙을 봅니다.
첫 일치가 이깁니다. 한 규칙의 인자 조건은 모두 만족해야 합니다(AND). 어떤 ABI에 없는 이름은 그 ABI에서만
건너뛰며, `compile`의 `unknown` 출력으로 모든 ABI에서 모르는 이름을 알 수 있습니다. Docker 기본 프로필의
의미(여러 ABI, `SCMP_ACT_ERRNO` 기본, 규칙별 errno, `personality` 값 목록, `clone` 플래그의 `MASKED_EQ`)는
모두 이 모델로 표현됩니다. capability/커널 버전에 따른 includes/excludes 해석은 oci 모듈이 합니다.

### 2.2 BPF 생성

libseccomp 없이 classic BPF를 직접 만듭니다.

```
ld arch;  jeq AUDIT_ARCH_A ? ja SEC_A ;  ... ;  ret badArch
SEC_A:    ld nr;  [x86_64: nr >= 0x40000000 이면 x32 구역 또는 badArch]
          블록(최대 64개): jeq nr_i -> 블록 안 ret/트램펄린 ... ; ja 다음 블록
          ret default
          본문: 규칙별 인자 비교 ... ret action ; 실패하면 다음 규칙 ; ... ret default
```

- 조건 점프 오프셋은 8비트이므로 디스패치를 64개 단위 블록으로 나누고 블록 안에 return과 본문으로 가는
  트램펄린(`ja`)을 둡니다. 레이블은 어셈블러가 풀고 4096 명령 제한을 넘으면 `-E2BIG`입니다.
- 64비트 인자는 상/하위 32비트를 따로 비교합니다(지원 ABI는 모두 리틀 엔디언). 32비트 ABI(x86)는 상위
  워드가 항상 0이므로 하위만 비교하고, 상위 비트가 있는 피연산자는 정적으로 결정합니다.
- 같은 `AUDIT_ARCH_X86_64`를 쓰는 x86_64와 x32는 x32 비트로 나눕니다. x32를 목록에 넣지 않으면 x32 호출은
  bad arch입니다.
- `CSeccompFilter::evaluate`는 커널과 같은 방식으로 프로그램을 해석하는 작은 인터프리터로, 테스트와 진단에
  씁니다. `install()`은 `seccomp(SECCOMP_SET_MODE_FILTER)`를 부르는 비동기 시그널 안전 함수입니다.

### 2.3 시스템 콜 표

`modules/box/src/syscalls.inc`는 `modules/box/tools/gen_syscalls.py`가 Linux UAPI 헤더(빌드 호스트의
linux-libc-dev)에서 만든 표를 커밋한 것입니다(x86_64, x86, x32, aarch64; 헤더보다 새로운 공통 번호
462~469는 생성기에 직접 적음). `SyscallNumber(name, arch)`, `SyscallName(nr, arch)`,
`SeccompArchFromName("SCMP_ARCH_X86_64" | "amd64" | "arm64" ...)`.

### 2.4 기본 프로필 `SSeccompProfile::general(violation)`

python, gcc로 만든 프로그램, 셸이 쓰는 호출(파일 I/O, 메모리, 스레드와 futex, 시그널, 타이머, 소켓, IPC,
`execve`, `prctl`, `seccomp`, landlock 등)을 허용하는 허용 목록입니다. 네이티브 ABI만 허용합니다.

- 거부: `ptrace`, `mount`/`umount2`/`pivot_root`/`chroot`과 새 마운트 API, `kexec_*`, `bpf`,
  `perf_event_open`, `userfaultfd`, `keyctl`/`add_key`/`request_key`, `unshare`/`setns`, `io_uring_*`,
  `open_by_handle_at`/`name_to_handle_at`, 모듈 적재, `reboot`, 시계 설정, `swapon`, `acct`, `quotactl`,
  `process_vm_*`, `kcmp`, `pidfd_getfd`, NUMA 정책 변경, `modify_ldt`, `iopl`/`ioperm` 등 목록에 없는 모든 것
- `clone`: 네임스페이스 플래그(`CLONE_NEWNS|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET|NEWCGROUP|NEWTIME`)가 없을 때만
- `clone3`: 항상 `ENOSYS`(플래그가 메모리에 있어 필터가 볼 수 없음; glibc는 `ENOSYS`면 `clone`으로 대체)
- `socket`: `AF_VSOCK`(네트워크 네임스페이스로 격리되지 않음)만 거부
- `personality`: Docker와 같은 안전한 값만
- 위반 처리: `ESVIO_ERRNO`(EPERM), `ESVIO_KILL`(SIGSYS로 프로세스 종료), `ESVIO_LOG`(기록만)

## 3. cgroups (`cgroup.hpp`)

### 3.1 레이아웃

`SCgroupSystem::detect`는 `/proc/self/mountinfo`에서 cgroup2 마운트와 v1 계층(컨트롤러 이름이 슈퍼블록
옵션에 있음, `name=systemd`는 무시)을 찾고 v2 루트의 `cgroup.controllers`를 읽습니다.

| 레이아웃 | 판정 | 사용 방식 |
|---|---|---|
| `ECGL_V2` | cgroup2만 | 모든 것을 v2로 |
| `ECGL_HYBRID` | cgroup2(보통 `/sys/fs/cgroup/unified`) + v1 계층 | v2 트리는 소속(CLONE_INTO_CGROUP), `cgroup.kill`, `cpu.stat`; 제한은 v2에 없는 컨트롤러를 가진 v1 계층으로 |
| `ECGL_V1` | v1만 | 컨트롤러별 계층 |

`CCgroup`은 계층 루트 기준 상대 경로(`sbox/box-123-1-...`) 하나로 모든 계층의 디렉터리를 함께 다룹니다.
`create`는 v2에서 내려가며 원하는 컨트롤러를 각 단계의 `cgroup.subtree_control`에 하나씩 켜고(거절되면 그
컨트롤러만 없음), v1에서는 필요한 계층(v2에 없는 컨트롤러 + freezer + cpuacct)에 디렉터리를 만들고 v1
cpuset이면 부모의 `cpuset.cpus`/`mems`를 복사합니다.

### 3.2 제한 (설정된 것만 씀)

| `SCgroupResources` | v2 | v1 |
|---|---|---|
| `memoryLimit` | `memory.max` | `memory.limit_in_bytes` |
| `memoryReservation` | `memory.low` | `memory.soft_limit_in_bytes` |
| `memorySwap`(OCI: 메모리+스왑 합) | `memory.swap.max` = 합 − 메모리 | `memory.memsw.limit_in_bytes`(순서 문제 시 memsw 먼저) |
| `pidsLimit` | `pids.max` | `pids.max` |
| `cpuQuota`/`cpuPeriod` | `cpu.max` | `cpu.cfs_period_us`, `cpu.cfs_quota_us` |
| `cpuShares`/`cpuWeight` | `cpu.weight`(shares 2..262144 → 1..10000 변환) | `cpu.shares`(weight는 역변환) |
| `cpusetCpus`/`cpusetMems` | `cpuset.cpus`/`cpuset.mems` | 같음 |
| `blkioWeight` | `io.bfq.weight` 또는 `io.weight` | `blkio.weight` 또는 `blkio.bfq.weight` |
| `readBps` 등 throttle | `io.max`(`MAJ:MIN rbps=...`) | `blkio.throttle.*_device` |
| `devices` | `BPF_PROG_TYPE_CGROUP_DEVICE` eBPF 프로그램 부착 | `devices.deny`/`devices.allow` |
| `unified` | 원시 v2 파일 쓰기 | (건너뜀) |

컨트롤러가 없어서 적용하지 못한 항목은 `apply`의 `skipped`에 이름(`memory`, `pids`, `cpu`, `io`,
`cpuset`, `devices`, `memory.swap` ...)으로 돌려줍니다. 커널이 거절한 값은 첫 errno를 반환합니다.

장치 규칙은 "모두 허용" 위에 마지막 일치가 이기는 방식으로 평가합니다(v1 장치 컨트롤러가 흔한 "모두 거부,
그다음 이것들 허용" 목록에서 동작하는 방식). eBPF 프로그램은 규칙을 뒤에서부터 검사해 처음 맞는 규칙의
결과를 돌려주고, 조건 없는 규칙 뒤의 도달 불가 코드는 만들지 않습니다(검증기가 거절함). 다시 적용하면 새
프로그램을 붙인 뒤 이전 것을 뗍니다.

### 3.3 통계

| `SCgroupStats` | v2 | v1 |
|---|---|---|
| `memoryCurrent` | `memory.current` | `memory.usage_in_bytes` |
| `memoryPeak` | `memory.peak`(5.19+, 없으면 current) | `memory.max_usage_in_bytes` |
| `oomEvents` / `oomKills` | `memory.events`의 `oom` / `oom_kill` | `memory.failcnt` / `memory.oom_control`의 `oom_kill` |
| `cpuUsageUs`, `cpuUserUs`, `cpuSystemUs` | `cpu.stat`(모든 v2 cgroup에 있음) | `cpuacct.usage`, `usage_user`, `usage_sys`(ns) |
| `pidsCurrent` | `pids.current` | `pids.current` |

### 3.4 모두 죽이기, 얼리기, 지우기

- `killAll`: v2에 `cgroup.kill`(5.14+)이 있으면 그것, 없으면 얼리기(v2 `cgroup.freeze` 또는 v1 freezer) →
  `cgroup.procs`의 각 pid에 SIGKILL → 녹이기. 그다음 비워질 때까지(v2 `cgroup.events`의 `populated`, v1
  `cgroup.procs`) 이벤트 루프에서 짧게 잠들며 기다립니다. 거두지 않은 호출자의 직계 자식(좀비)은 거둘
  때까지 남을 수 있습니다.
- `freeze(bool)`: 상태가 바뀔 때까지 기다립니다(OCI pause/resume).
- `destroy`: 모든 계층의 디렉터리를 `rmdir`합니다(만들면서 생긴 부모는 남김).

### 3.5 위임과 rootless

`CCgroup::defaultParent`는 root면 `sbox`, 아니면 자신의 v2 cgroup에서 위로 올라가며 자신이 소유하고 쓸 수
있는(`cgroup.procs` 포함) 가장 위 디렉터리(systemd `Delegate=yes` 하위 트리)를 찾아 그 아래 `sbox`를
돌려줍니다. 없으면 `-EACCES`이고, 그때 샌드박스는 cgroup 없이 실행합니다(4.4). v1은 위임을 지원하지 않습니다.

## 4. 샌드박스 (`policy.hpp`, `sandbox.hpp`)

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

### 4.1 격리 기본값 (정책 → `SLaunchSpec`)

- 네임스페이스: user, pid, mount, ipc, uts, cgroup은 항상 새로. 네트워크는 `EBNET_NONE`(새 네임스페이스,
  `lo`만 켬), `EBNET_HOST`(공유), `EBNET_NAMESPACE`(`netnsPath`에 들어감; 새 사용자 네임스페이스보다 먼저
  들어가므로 net 모듈이 만든 네임스페이스를 그대로 씀).
- 파일 시스템: 1 MiB tmpfs 루트, 목록의 호스트 경로만 bind(`nosuid,nodev`, 기본 읽기 전용이며 하위 마운트까지
  읽기 전용, 마운트별 `noexec`, `optional`), `pivot_root`, 루트 읽기 전용, 새 pid 네임스페이스의 `/proc`
  (OCI 기본 가림 경로와 `/proc/sys` 등 읽기 전용 경로), `/tmp`(`tmpSize`, `tmpNoexec`), `/dev` tmpfs에
  null/zero/full/random/urandom/tty, `/dev/pts`(newinstance), `/dev/shm`(`shmSize`), `/dev/fd` 등 링크.
  마운트는 경로 깊이 순으로 정렬해 부모가 먼저 마운트됩니다.
- merged-/usr: 정책이 호스트 `/usr`를 `/usr`에 bind하고, 호스트의 `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`,
  `/libx32`가 `usr/...`를 가리키는 링크이며 정책이 그 경로를 직접 마운트하지 않으면, 그 경로를 `/usr` 안의
  대상 디렉터리에서 읽기 전용으로 bind합니다. `/usr`만 bind해도 로더(`/lib64/ld-linux-x86-64.so.2`)와
  `#!/bin/sh`가 호스트와 같이 해석됩니다. `/etc`를 거치는 링크(`/etc/alternatives/...`)는 `/etc`를 마운트해야
  합니다.
- 보안: capabilities 전부 0(bounding 포함), `no_new_privs`, seccomp 기본 프로필(`seccompViolation`으로 EPERM /
  kill / log 선택, `seccompProfile`로 교체 가능), `RLIMIT_CORE` 0, 부모가 죽으면 SIGKILL.
- reaper 사용: 샌드박스의 pid 1은 엔진의 init이고 프로그램은 pid 2입니다.

### 4.2 ID 매핑

샌드박스 안의 `uid`/`gid`(기본 0) 하나를 호스트 ID 하나에 매핑합니다.

- rootless: 호출자의 uid/gid로 매핑합니다(안의 root = 바깥의 나).
- root: 기본으로 호스트 65534(nobody/nogroup)에 매핑합니다. 호스트 root로 매핑하면 capability가 없어도
  bind된 경로의 root 소유 파일에 소유자 권한이 생기고 `/proc/sys` 쓰기 검사도 통과하기 때문입니다. 그래서
  쓰기 가능한 마운트(`EBMNT_READ_WRITE`)는 매핑된 호스트 uid가 쓸 수 있어야 하고(소유권 또는 모드), 연결할
  UNIX 소켓도 그 uid가 쓸 수 있어야 합니다. 다른 호스트 ID가 필요하면 `hostUid`/`hostGid`로 정합니다.

### 4.3 제한

| 정책 | cgroup 있을 때 | cgroup 없을 때(대체) |
|---|---|---|
| `memoryMax` (+`swapMax`) | `memory.max`/`limit_in_bytes`, 스왑은 기본 0 | `RLIMIT_AS` (`"memory (RLIMIT_AS fallback)"`) |
| `pidsMax` | `pids.max` | `RLIMIT_NPROC`(5.14+ 커널에서 사용자 네임스페이스별 계산) (`"pids (RLIMIT_NPROC fallback)"`) |
| `cpuQuotaUs`/`cpuPeriodUs` | `cpu.max`/cfs | 적용 안 됨(`"cpu"`) |
| `ioLimits` | `io.max`/blkio throttle | 적용 안 됨(`"io"`) |
| `wallTimeoutMs` | 이벤트 루프 타이머; 만료 시 cgroup과 pid 네임스페이스 전체를 죽임 | 같음 |
| `cpuTimeLimitMs` | `RLIMIT_CPU`(초 단위 올림, soft에 SIGXCPU, hard = soft+1에 SIGKILL) | 같음 |
| `fileSizeMax`, `openFilesMax`, `stackMax`, `addressSpaceMax`, `rlimits` | rlimit | 같음 |

적용하지 못한 제한은 `SBoxResult::unenforced`에 이름이 남습니다. `requireCgroupLimits`면 대신
`EBEXIT_SETUP_FAILURE`(`-ENOTSUP`)로 실패합니다. cgroup은 제한이 없어도 만들 수 있으면 만듭니다(통계와
남은 프로세스 정리). `memory.swap`을 적용할 수 없는 것(v1 swapaccount 꺼짐)은 프로그램이 스왑할 수 있다는
뜻일 뿐이라 `unenforced`에 넣지 않습니다.

### 4.4 감독과 결과

`spawn`이 성공하면 감독 태스크(`CEventLoop::spawn`)가 pidfd를 기다립니다(벽시계 제한이 있으면 그 시간까지).
프로그램이 끝나면 cgroup의 남은 프로세스를 모두 죽이고 비워질 때까지 기다린 뒤 통계를 읽고 cgroup을
지우고 결과를 확정해 `wait()` 대기자를 깨웁니다. `CSandbox`를 없애면 실행 중인 프로그램을 죽입니다(감독
태스크가 정리를 마저 함).

`SBoxResult::reason` 판정 순서:

1. 설정 실패 → `EBEXIT_SETUP_FAILURE`(`error`, `failedStep`)
2. 벽시계 제한으로 죽임 → `EBEXIT_WALL_TIMEOUT`
3. 시그널로 끝남: SIGSYS → `EBEXIT_SECCOMP`; SIGXCPU → `EBEXIT_CPU_TIME`; SIGKILL이고 `oomKills > 0` →
   `EBEXIT_MEMORY`; SIGKILL이고 CPU 시간이 `RLIMIT_CPU` 이상 → `EBEXIT_CPU_TIME`; 그 밖(호출자의 `kill()`
   포함) → `EBEXIT_SIGNAL`
4. 정상 종료 → `EBEXIT_NORMAL`(`exitCode`)

자원 수치(`cpuSource`, `memorySource`):

- CPU 시간: cgroup이 있으면 cgroup(v1 `cpuacct`, 아니면 v2 `cpu.stat`)의 사용량으로, 샌드박스의 모든
  프로세스(거두지 않은 것 포함)를 셉니다. 없으면 waitid rusage(거둔 프로세스만)입니다. 커널은
  `RLIMIT_CPU`를 틱 단위로 샘플링한 user+system 시간으로 검사하므로, CPU를 다투는 기계에서는
  `EBEXIT_CPU_TIME`으로 끝난 실행의 `cpuTimeUs`(정확한 실행 시간)가 한도보다 10~20% 작을 수 있습니다.
- 최대 메모리: cgroup 메모리 컨트롤러가 있으면 `memory.peak`/`max_usage_in_bytes`(페이지 캐시와 `/tmp`
  tmpfs 포함, 즉 메모리 제한이 실제로 재는 값)이고, 없으면 rusage `ru_maxrss`(가장 큰 단일 프로세스의 RSS)입니다.
- `wallTimeMs`는 spawn 시작부터 종료 확인까지입니다.

### 4.5 표준 입출력

`stdinMode`/`stdoutMode`/`stderrMode`마다 `EBSTD_PIPE`(기본, `CStream&`로 노출), `EBSTD_INHERIT`(호출자 fd를
복제해 넘김), `EBSTD_NULL`. 파이프를 쓰는 호출자는 SIGPIPE를 무시해야 하고(core 규칙), 출력이 파이프
버퍼보다 클 수 있으면 `wait()`와 동시에 읽어야 합니다.

### 4.6 `CSandbox::fork`

`CSandbox::fork(policy, fn)`은 같은 격리(seccomp 포함) 안에서 `fn`을 실행하고 반환값을 종료 코드로
씁니다. fork 규칙(다른 스레드 없음)을 확인해 어기면 `-EBUSY` 설정 실패입니다. 1.8의 제약이 그대로
적용됩니다.

### 4.7 프리셋

| 프리셋 | 내용 |
|---|---|
| `SBoxPolicy::strict()` | 시스템 디렉터리(/etc 제외) 읽기 전용, 네트워크 없음, 메모리 256 MiB, 프로세스 64, CPU 1개, 벽시계와 CPU 10초, 파일 64 MiB, 열린 파일 256, `/tmp` noexec, seccomp 위반 시 kill |
| `SBoxPolicy::worker(dir, sockets)` | 시스템 디렉터리(/etc 포함) 읽기 전용, `dir`만 쓰기 가능(작업 디렉터리), 나열한 UNIX 소켓만 bind(그 밖의 네트워크 없음), 메모리 1 GiB, 프로세스 512 |
| `SBoxPolicy::permissive()` | 시스템 디렉터리, 호스트 네트워크, 제한 없음, seccomp는 기록만 |

`SBoxPolicy::systemMounts(withEtc)`는 `/usr`, `/bin`, `/sbin`, `/lib*`, (`/etc`) 중 있는 것을 읽기 전용
마운트로 돌려줍니다. merged-usr 호스트의 `/bin -> usr/bin` 같은 링크는 실제 디렉터리를 bind합니다.

## 5. 사용하는 커널 인터페이스

`clone3`(`CLONE_PIDFD`, `CLONE_INTO_CGROUP`, 네임스페이스 플래그), `setns`, `unshare`, `pidfd_send_signal`,
`waitid(P_PIDFD)`, `/proc/<pid>/{uid_map,gid_map,setgroups}`, `openat2(RESOLVE_IN_ROOT)`, `open_tree`,
`move_mount`, `mount_setattr`, `mount`/`umount2`/`pivot_root`, `mknodat`, `close_range`, `prctl`
(`PDEATHSIG`, `KEEPCAPS`, `CAPBSET_DROP`, `CAP_AMBIENT`, `NO_NEW_PRIVS`, `DUMPABLE`), `capset`, `prlimit64`,
`seccomp(SECCOMP_SET_MODE_FILTER)`, `bpf(BPF_PROG_LOAD/ATTACH, BPF_PROG_TYPE_CGROUP_DEVICE)`, `TIOCGPTPEER`,
`SCM_RIGHTS`, `SIOCSIFFLAGS`, cgroupfs v1/v2 파일, `/proc/self/mountinfo`, `/proc/sys/kernel/cap_last_cap`.
요구 커널은 5.10 이상이며 `mount_setattr`(5.12), `cgroup.kill`(5.14), `memory.peak`(5.19)는 없으면 대체
경로를 씁니다.

## 6. 위협 모델과 한계

샌드박스 안의 코드는 악의적이라고 가정합니다. 막는 것: 목록 밖 호스트 파일 접근(마운트 네임스페이스 +
pivot_root + 읽기 전용 bind), 다른 프로세스 관찰(pid 네임스페이스, 새 `/proc`), 네트워크(빈 네트워크
네임스페이스), 권한 상승(capabilities 0, no_new_privs, 비특권 매핑 ID), 위험한 시스템 콜(seccomp 허용 목록,
네임스페이스 생성 차단), 자원 고갈(cgroups, rlimit, 크기 제한 tmpfs, 벽시계 감독).

막지 못하는 것:

- 커널 취약점을 통한 탈출. 프로세스 격리는 커널 전체를 공격 표면으로 공유합니다. 그 수준의 격리가 필요하면
  마이크로VM이 필요합니다([svarch.md](svarch.md)).
- 허용된 시스템 콜 안의 부채널(타이밍, 캐시)과 CPU 취약점.
- cgroup이 없는 rootless 실행에서의 메모리/프로세스 수 제한은 근사치입니다(`RLIMIT_AS`는 매핑 크기를 세고,
  `RLIMIT_NPROC`는 오래된 커널에서 사용자 단위). CPU/IO 제한은 적용되지 않습니다.

## 7. 제한 사항

- seccomp `SCMP_ACT_NOTIFY`(사용자 공간 알림, OCI `listenerPath`)는 지원하지 않습니다. 디스패치는 선형
  (블록 단위)이며 이진 트리 최적화는 하지 않습니다.
- 시스템 콜 표는 x86_64, x86, x32, aarch64만 있습니다(arm, riscv64, s390x, ppc64le 등 없음).
- rootless에서 여러 범위의 ID 매핑(`newuidmap`/`newgidmap` 호출)은 하지 않습니다. 비특권 호출자는 자기
  uid/gid 하나만 매핑할 수 있고, 여러 범위가 필요하면 미리 매핑된 사용자 네임스페이스에 들어가야 합니다.
- cgroup v1 위임(rootless)은 지원하지 않습니다. 이 기계 같은 hybrid 호스트에서는 v2 트리에 컨트롤러가 없어
  v2 제한 파일 경로는 실제 커널로 시험되지 않았습니다(v1 경로와 v2 소속/kill/통계/장치 eBPF는 시험됨).
- OCI `linux.resources` 중 hugepage 제한, `memory.swappiness`, 커널 메모리, `rdma`, `network`(classid,
  priorities), CPU 실시간(`rt_runtime`/`rt_period`), `cpu.idle`, blkio 장치별 weight는 아직 없습니다(`unified`
  원시 키로는 v2 파일을 쓸 수 있음).
- 프로세스 속성 중 AppArmor/SELinux 라벨, `personality`, `ioPriority`, `scheduler`, 새 세션 키링,
  time 네임스페이스 오프셋(`timeOffsets`), Intel RDT는 지원하지 않습니다.
- `stagingDir`(기본 `/tmp`)는 새 마운트 네임스페이스 안에서 tmpfs로 덮이므로 호스트에는 영향이 없지만,
  그 디렉터리가 있어야 합니다.
- `/proc`이 이미 일부 가려진 환경(다른 컨테이너 안)에서 사용자 네임스페이스의 새 proc 마운트는 커널이
  거절할 수 있습니다(`mount_too_revealing`). 그때는 설정 실패(`mount[...]`)로 보고합니다.
- 부모 사망 시그널(`PR_SET_PDEATHSIG`)은 clone3를 부른 스레드가 끝날 때 발동합니다. 멀티스레드 호출자는
  수명이 긴 스레드에서 spawn해야 합니다.
- 이벤트 루프가 먼저 없어지면 감독 태스크가 사라지므로 `CSandbox`/`CProcess` 소멸자는 SIGKILL을 보내고
  기다리지 않고 거둘 수 있을 때만 거둡니다(좀비가 남을 수 있음).

## 8. 테스트

`ctest --test-dir build -j8 -L box`

| 실행 파일 | 내용 |
|---|---|
| `box_seccomp` | 표 조회, 기본 프로필 판정(인터프리터), 7개 연산자 × 15개 경계값의 64비트 비교 전수 검사, 32비트 ABI, 다중 ABI(Docker 형), 규칙 우선순위, 잘못된 프로필과 `-E2BIG`, fork한 자식에 설치해 errno/SIGSYS 확인 |
| `box_cgroup` | 레이아웃 감지, 생성/적용/다시 열기/삭제, 프로세스 트리 추적·얼리기·모두 죽이기, v1 메모리 OOM과 `oom_kill`/peak, pids 제한, 장치 규칙(v1 컨트롤러와 v2 eBPF) |
| `box_launch` | 새 네임스페이스에서 실행·종료 코드·입출력, exec/마운트 실패 보고, pid/uts/net/파일 시스템 격리, capabilities와 no_new_privs, reaper의 시그널 상태 전달, 내부·FIFO start gate, fd 매핑, pty(내부·콘솔 소켓), 실행 중 프로세스의 네임스페이스 들어가기, 함수 페이로드, 기존 rootfs 디렉터리와 악성 심볼릭 링크, no-pivot, sysctl/rlimit/umask, 사용자 네임스페이스 없는 mknod와 oom_score_adj, OCI 마운트 옵션 |
| `box_sandbox` | 문서의 python 예제, `/usr`만 bind한 merged-/usr 정책, 입출력과 종료 코드, 벽시계 제한(자손까지 죽음), 포크 폭탄(pids), 메모리 OOM 사유, seccomp kill/EPERM, kill 프로필에서 python, 네트워크 없음, 호스트 파일·프로세스 안 보임, CapEff 0/NoNewPrivs/Seccomp 2, `/tmp` 크기, CPU 시간 사유, cgroup 통계 출처, stdio 상속//dev/null, 설정 실패 보고, `kill()`, `CSandbox::fork`와 fork 규칙, worker 프리셋과 UNIX 소켓, strict/permissive, rootless(uid 65534로 내려간 자식), 네트워크 네임스페이스 들어가기 |
| `box_header` | `sandbox.hpp`만 포함해 `CEventLoop`로 코루틴을 돌리고 프리셋을 씀(README 예제처럼 헤더 하나로 충분한지) |

테스트용 보조 프로그램(`forkbomb`, `memhog`, `badsyscall`, `cpuburn`)은 `modules/box/testhelpers/`에서
`build/modules/box/helpers/`로 빌드되어 샌드박스에 읽기 전용으로 bind됩니다. 사용자 네임스페이스나 root가
필요한 케이스는 조건을 먼저 확인하고 없으면 `MESSAGE`를 남기고 건너뜁니다.
