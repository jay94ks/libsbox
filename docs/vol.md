# vol 모듈

Docker와 호환되는 이름 있는 볼륨을 제공합니다. 네임스페이스는 `sbox::vol`, 헤더는
`modules/vol/include/sbox/vol/`, CMake 타깃은 `sbox::vol`(의존: `archive`, `http`)입니다.
명령줄 도구 두 개가 이 모듈 위에 있습니다.

- `sboxvol`(`cli/sboxvol/`): 볼륨 관리 명령(`create`, `ls`, `inspect`, `rm`, `prune`, `backup`, `restore`)과
  Docker 볼륨 플러그인 데몬(`serve`).
- `sboxnet`(`cli/sboxnet/`): net 모듈의 `CDockerPlugin`(Docker 원격 네트워크 + IPAM 드라이버)을 HTTP 서버에
  연결한 데몬. vpn 모듈의 WireGuard 오버레이 드라이버(`wg-overlay`)도 등록합니다.

이미지에서 만든 OCI 번들에 볼륨을 붙이는 명령줄은 `sbox-image bundle -v/--mount/--tmpfs`입니다
([image.md](image.md), [usage.md](usage.md)). 이 도구가 `PrepareContainerMounts`를 부르고, `sbox-image rm`이
`releaseUser`로 볼륨을 돌려줍니다.

## 헤더

| 헤더 | 내용 |
|---|---|
| `vol/local.hpp` | `local` 드라이버 옵션: `SLocalOptions`, `ELocalKind`, `ParseLocalOptions`, `ParseMountOptions`, `ParseSize`/`FormatSize`, `MountLocalVolume`, `UnmountLocalVolume`, `IsMountPoint`, `CopyUpIfEmpty`, `OpenInRoot`, `IsDirectoryEmpty` |
| `vol/quota.hpp` | 프로젝트 쿼터: `ProbeProjectQuota`, `GetProjectId`/`SetProjectId`, `SetProjectLimit`, `GetProjectUsage`, `QuotaFsOf`, `BlockDeviceOf` |
| `vol/store.hpp` | `SVolume`, `SVolumeCreate`, `SVolumeStoreOptions`, `CVolumeStore`, `SPruneOptions`/`SPruneReport`, `SVolumeUsage`, `DefaultVolumeRoot`, `IsValidVolumeName`, `NewAnonymousVolumeName`, `ANONYMOUS_LABEL` |
| `vol/backup.hpp` | `BackupVolume`(sink), `BackupVolumeToStream`(IStream), `BackupVolumeToFile`, `RestoreVolume`(source), `RestoreVolumeFromStream`, `RestoreVolumeFromFile`, `SBackupOptions`, `SRestoreOptions` |
| `vol/mount.hpp` | 컨테이너 마운트 요청: `SMountRequest`, `ParseVolumeFlag`(`-v`), `ParseMountFlag`(`--mount`), `ParseTmpfsFlag`(`--tmpfs`), `BuildOciMount`, `ValidateHostPath`, `CleanAbsolutePath`, `PrepareContainerMounts` |
| `vol/plugin.hpp` | `CVolumePlugin`: Docker 볼륨 플러그인 프로토콜 핸들러(`handle`, `attach`) |

결과 코드는 libsbox 규칙대로 `SBOX_OK` 또는 음수 errno입니다. 저장소 호출이 실패하면
`CVolumeStore::lastError()`가 사람이 읽을 이유를 돌려줍니다(플러그인 `Err`와 CLI 오류 메시지에 그대로 씀).

## 저장소 (`CVolumeStore`)

### 디스크 형식

Docker의 `/var/lib/docker/volumes`와 같은 모양입니다.

```
<root>/                     0701
  .lock                     flock: 모든 변경 호출이 잡음(프로세스 간 공유)
  .quota.json               {"NextProjectId": N}  프로젝트 id 할당 기록
  <name>/                   0755
    _data/                  볼륨 내용. tmpfs/nfs/bind/장치 볼륨은 여기에 마운트됨
    volume.json             메타데이터(0600)
    opts.json               Docker local 드라이버의 옵션 파일(옵션 있는 볼륨만)
    state.json              런타임 상태(0600)
  .trash-<name>-<rand>/     지우는 중인 볼륨(먼저 rename 후 삭제)
```

- 기본 루트 `DefaultVolumeRoot()`: 루트는 `/var/lib/sbox/volumes`, 루트가 아니면 `$XDG_DATA_HOME/sbox/volumes`
  (없으면 `~/.local/share/sbox/volumes`).
- `volume.json`은 `docker volume inspect` 한 항목과 같은 필드에 쿼터 정보를 더한 것입니다.
  ```json
  {"CreatedAt":"2026-10-04T12:00:00Z","Driver":"local","Labels":{},"Mountpoint":"/var/lib/sbox/volumes/web/_data",
   "Name":"web","Options":{"size":"10G"},"Scope":"local","ProjectId":65536,"SizeLimit":10737418240}
  ```
  `CreatedAt`은 UTC RFC 3339, `Labels`/`Options`는 키 순서로 정렬됩니다(Go 맵 JSON과 같음).
- `opts.json`: Docker local 드라이버 형식 `{"MountType","MountOpts","MountDevice","Quota":{"Size"}}`.
- `state.json`: `{"Users":[...], "Mounted": bool, "BootId": "..."}`. `Users`는 볼륨을 쓰는 컨테이너 id(또는
  플러그인 Mount ID)이고 이것이 참조 계수입니다. `BootId`(`/proc/sys/kernel/random/boot_id`)가 지금과 다르면
  재부팅 전의 상태이므로 사용자 없음, 마운트 없음으로 봅니다.
- `volume.json`은 생성의 마지막 단계에 씁니다. 메타데이터가 없는 디렉터리(중단된 생성)는 목록에서 빠지고
  같은 이름으로 다시 만들 때 정리됩니다. 삭제는 `.trash-*`로 rename한 뒤 지우므로 중간에 죽어도 반쪽 볼륨이
  이름으로 남지 않습니다. 파일은 모두 `CFile::writeAtomic`(임시 파일, fsync, rename)으로 씁니다.

### 동작

| 호출 | 동작 |
|---|---|
| `create(SVolumeCreate, out)` | 이름이 비면 익명 볼륨(64자 16진수, 라벨 `com.docker.volume.anonymous=""`). 이미 있으면 그대로 돌려줌(Docker와 같음, 드라이버가 다르면 `-EEXIST`). 드라이버는 `local`만(`-ENOTSUP`). 옵션 검증, `size=`면 쿼터 설정 |
| `inspect(name, out)` / `list(out)` | 메타데이터 + 런타임 상태. 목록은 이름순 |
| `remove(name, force)` | 사용자가 있으면 `-EBUSY`("volume is in use - [ids]"). `force`면 언마운트 후 지움 |
| `acquire(name, user, mountpoint)` | 사용자 등록(같은 user는 한 번만 셈). 마운트가 필요한 볼륨이면 첫 사용자일 때 마운트 |
| `release(name, user)` | 사용자 제거. 마지막 사용자면 언마운트(바쁘면 `MNT_DETACH`) |
| `releaseUser(user, removeAnonymous)` | 그 사용자의 모든 볼륨을 놓고, `removeAnonymous`면 남는 익명 볼륨을 지움(`docker run --rm`) |
| `prune(SPruneOptions, report)` | 사용자 없는 볼륨 중 익명 볼륨만(Docker 23+ 기본), `all`이면 이름 있는 것까지. 라벨 필터 `key`, `key=value`, `!key`, `key!=value` |
| `usage(name, out)` | 쿼터가 있으면 쿼터 사용량, 아니면 `_data`를 걸으며 `st_blocks` 합(하드링크 한 번, 다른 마운트로 넘어가지 않음) |
| `copyUp(name, source)` | 비어 있는 볼륨에 이미지 내용 복사(`CopyUpIfEmpty`) |

- 이름 규칙은 Docker local 드라이버와 같습니다: `[a-zA-Z0-9][a-zA-Z0-9_.-]+`(2자 이상), 255바이트 이하.
- 모든 변경 호출은 `<root>/.lock`을 끝까지 잡습니다. 잠금 대기는 `LOCK_NB` 재시도와 `sleepFor`(1→25ms)로
  이벤트 루프를 막지 않습니다. 같은 프로세스 안의 두 호출도 서로 배제됩니다(호출마다 새 open file description).
  CLI, 플러그인 데몬, 런타임이 한 루트를 함께 쓸 수 있습니다.
- `SVolumeStoreOptions::dataUid/dataGid`: 새 `_data`의 소유자. box가 기본으로 안쪽 uid 0을 호스트 65534로
  매핑하므로, 그런 샌드박스가 쓸 볼륨은 65534로 만들어야 쓸 수 있습니다.
- 바인드나 NFS가 마운트된 채로 디렉터리를 지우는 일은 없습니다. 언마운트 후 다시 `IsMountPoint`를 확인하고,
  여전히 마운트 지점이면 `-EBUSY`로 거부합니다(호스트 데이터 보호).

## local 드라이버 (`local.hpp`)

Docker `local` 드라이버의 옵션을 그대로 받습니다(`docker volume create --opt ...`).

| 옵션 | 결과 |
|---|---|
| 없음 | `ELK_DIRECTORY`: `_data` 디렉터리 |
| `size=10G` | 디렉터리 볼륨 + 프로젝트 쿼터(Docker overlay2/xfs의 `--opt size`) |
| `type=tmpfs,device=tmpfs[,o=size=100m,mode=1777,uid=1000,gid=1000]` | `ELK_TMPFS` |
| `type=nfs`/`nfs4,device=:/export,o=addr=host,rw,nfsvers=4` | `ELK_NFS`(커널 NFS 클라이언트) |
| `type=none,device=/host/path,o=bind` (또는 `rbind`) | `ELK_BIND` |
| `type=<fs>,device=/dev/sdb1[,o=...]` | `ELK_DEVICE`(ext4, xfs, 그 밖의 파일시스템) |

- 검증은 Docker의 규칙과 같습니다: 키는 `type`, `device`, `o`, `size`만(`invalid option: "x"`),
  `type`과 `device`는 서로를 요구하고 `o`는 둘 다 요구합니다(`missing required option: "device"`).
  추가로 `size`와 `type`을 함께 쓰거나, `o=bind` 없는 `type=none`, 절대 경로가 아닌 bind 장치, `:`가 없는 NFS
  장치, `remount`는 생성 시점에 거부합니다.
- `o`는 Docker `mount.ParseOptions`와 같은 표로 `MS_*` 플래그(`ro`/`rw`, `nosuid`, `nodev`, `noexec`, `sync`,
  `dirsync`, `noatime`, `nodiratime`, `relatime`, `strictatime`, `bind`, `rbind`, 전파 단어)와 파일시스템 데이터
  문자열로 나눕니다.
- 크기(`ParseSize`)는 go-units `RAMInBytes`와 같습니다: 소수 허용, `k/m/g/t/p`(+`b`/`i`/`ib`), 대소문자 무시,
  모두 2진 단위(`10G` = 10 GiB).
- 마운트(`MountLocalVolume`)는 Docker처럼 첫 사용 때, 언마운트는 마지막 사용자가 놓을 때 합니다.
  - tmpfs, 장치: `mount(device, _data, type, flags, data)`.
  - NFS: 커널 NFS 클라이언트는 숫자 주소만 받으므로 `addr=`가 호스트 이름이면 직접 해석해 숫자로 바꿉니다
    (Docker local 드라이버와 같음, IPv4 우선). `addr=`가 없으면 `host:/export`의 호스트를 해석해 `addr=`를
    붙입니다. 해석은 core `ResolveEndpoints`(getaddrinfo를 짧은 스레드에서)이므로 fork할 프로세스에서 NFS 볼륨을
    마운트하지 마십시오.
  - bind: `MS_BIND`(+`MS_REC`) 뒤에 `ro`/`nosuid`/`nodev`/`noexec` 등을 `MS_REMOUNT|MS_BIND`로 적용합니다.
  - 전파 단어가 있으면 마지막에 따로 적용합니다.
- 언마운트(`UnmountLocalVolume`)는 `umount2(UMOUNT_NOFOLLOW)`, 바쁘면 `MNT_DETACH`. 마운트 지점이 아니면 성공.
- `IsMountPoint`: `statx`의 `STATX_ATTR_MOUNT_ROOT`(5.8+), 없으면 부모와 `st_dev` 비교.

### copy-up

`CopyUpIfEmpty(source, target)`는 Docker처럼 비어 있는 볼륨이 이미지에 내용이 있는 경로에 처음 마운트될 때
이미지 내용을 볼륨으로 복사합니다. archive 모듈의 `CTreeTarSource`(includeRoot, xattr, 정밀 시간) →
`CTarSink` → `CExtractor`(안전한 추출) 파이프라인이므로 소유자, 모드, 시간, xattr, 심볼릭 링크, 하드링크,
장치가 보존되고 링크를 따라가지 않습니다. 원본 디렉터리 자체의 소유자와 모드도 볼륨 루트에 적용합니다.
반환값은 1(복사함), 0(대상이 비어 있지 않거나 원본이 없음), 음수 errno입니다.

이미지 경로는 `OpenInRoot(rootfs, path)`로 엽니다: `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`라서
rootfs 안의 심볼릭 링크가 밖을 가리켜도 rootfs를 `/`로 보고 해석합니다. 그 디스크립터의
`/proc/self/fd/N` 경로를 원본으로 씁니다.

## 프로젝트 쿼터 (`quota.hpp`)

`--opt size=10G`인 디렉터리 볼륨의 크기 제한입니다.

1. 생성 시 `ProbeProjectQuota(root)`로 지원 여부를 확인합니다. 지원하지 않으면 `-ENOTSUP`과 함께
   "quota size requested but no quota support: ... needs project quotas (xfs mounted with pquota, or ext4 with the
   project,quota features mounted with prjquota)" 이유를 남깁니다.
   - XFS: `Q_XGETQSTAT`의 `FS_QUOTA_PDQ_ENFD`(강제 적용 켜짐)를 요구합니다.
   - 그 밖(ext4 등): `Q_GETQUOTA`(PRJQUOTA, id 0)가 성공해야 합니다.
   - `ENOSYS`/`ENOTTY`/`EOPNOTSUPP`/`ESRCH`(쿼터 꺼짐)/`EINVAL`은 `-ENOTSUP`으로 바꿉니다.
2. 프로젝트 id 할당: `.quota.json`의 `NextProjectId`(기본 시작 `projectIdBase` = 65536)와 현재 볼륨들이 쓰는
   가장 큰 id + 1 중 큰 값. 할당 파일을 잃어도 쓰는 id와 겹치지 않습니다.
3. `SetProjectId(_data, id, inherit)`: `FS_IOC_FSGETXATTR` → `fsx_projid`와 `FS_XFLAG_PROJINHERIT` →
   `FS_IOC_FSSETXATTR`. 아래에 만들어지는 모든 파일이 같은 프로젝트 id를 받습니다.
4. `SetProjectLimit`: XFS는 `quotactl(Q_XSETQLIM, PRJQUOTA)`(`fs_disk_quota`, 512바이트 블록, soft = hard),
   그 밖은 `quotactl(Q_SETQUOTA, PRJQUOTA)`(`if_dqblk`, 1 KiB 블록, `QIF_BLIMITS`).
   커널에 `quotactl_fd`(5.14+)가 있으면 경로의 디스크립터로 호출하고, 없으면 `/proc/self/mountinfo`에서 st_dev가
   같은 마운트의 블록 장치를 찾아 `quotactl`을 부릅니다.
5. 사용량(`GetProjectUsage`): `Q_XGETQUOTA`(`d_bcount`×512) 또는 `Q_GETQUOTA`(`dqb_curspace`).
6. 볼륨을 지울 때 한도를 0으로 되돌립니다.

tmpfs 볼륨은 쿼터 대신 `o=size=`를 씁니다.

## 백업과 복원 (`backup.hpp`)

- 백업은 gzip tar(`WriteTreeArchive`, PAX)입니다. 루트 엔트리(`./`)를 포함하고, 소유자(숫자 id), 모드, 초 미만
  시간, xattr(`SCHILY.xattr.*`), 심볼릭 링크, 하드링크, FIFO/장치를 기록합니다. 시스템 `tar -tzf`로 읽힙니다.
- 백업과 복원은 고유한 사용자 id(`sbox-backup-<pid>-<rand>`)로 볼륨을 acquire합니다. 그래서 마운트가 필요한
  볼륨(장치, NFS)은 쓰는 사람이 없어도 그동안 마운트되고, 진행 중에는 `rm`이 거부됩니다.
- 출력: `IByteSink`(동기), `IStream`(코루틴, `CTreeTarSource` → `CCodecSource` → `PumpSourceToStream`), 파일
  (`<path>.tmp-*`에 쓰고 fsync 후 rename. 실패하면 임시 파일을 지움).
- 복원: `ExtractArchive`/`ExtractArchiveAsync`(gzip/zstd/평문 자동 판별)와 archive 모듈의 안전한 추출기를 씁니다.
  볼륨 밖으로 쓰는 엔트리(`..`, 밖을 가리키는 링크를 통한 쓰기)는 불가능합니다. 소유자는 `EOWN_AUTO`(루트면
  복원).
  - 볼륨이 없으면 `SRestoreOptions::create`(기본 참)일 때 `createOptions`(라벨, 드라이버 옵션)로 만듭니다.
  - 내용이 있으면 `-ENOTEMPTY`, `overwrite`면 먼저 내용을 지웁니다(마운트를 넘어가지 않음).
- 일관성: 기본은 최선 노력입니다. 쓰는 중인 파일은 중간 상태로 담길 수 있습니다. `SBackupOptions::freeze`는
  볼륨이 자기 파일시스템(장치 볼륨 등)일 때 `FIFREEZE`로 얼린 채 읽고 `FITHAW`로 풉니다(실패해도 반드시 풂).
  디렉터리 볼륨에 쓰면 저장소 전체 파일시스템을 얼리게 되므로 `-ENOTSUP`, tmpfs처럼 얼릴 수 없는 파일시스템도
  `-ENOTSUP`입니다. 얼린 동안 그 파일시스템에 쓰는 프로세스는 멈춥니다.

## 컨테이너 마운트 명세 (`mount.hpp`)

Docker 명령줄의 마운트 요청을 OCI 런타임 명세의 `mounts[]` 항목(`CJson`)으로 바꿉니다. oci 런타임이나 이미지
번들 코드가 이 객체를 `config.json`에 그대로 넣습니다.

### `-v` (`ParseVolumeFlag`)

`[source:]target[:mode]`. 출처가 `/`로 시작하면 bind(호스트 경로가 없으면 만듦, Docker의 옛 동작), 아니면 볼륨
이름, 출처가 없으면 익명 볼륨입니다. 모드는 쉼표 목록이며 종류마다 한 번만: `ro`/`rw`, `z`/`Z`(기록만 하고
SELinux 레이블은 바꾸지 않음), `nocopy`(볼륨만), 전파 `shared`/`rshared`/`slave`/`rslave`/`private`/`rprivate`
(bind만), 일관성 `consistent`/`cached`/`delegated`(무시). `/foo:rw`(대상 + 모드), 상대 경로 출처, 대상 `/`,
상대 대상은 거부합니다.

### `--mount` (`ParseMountFlag`)

docker CLI처럼 CSV(큰따옴표 인용)로 나눕니다: `"volume-opt=o=addr=10.0.0.1,rw"`. 키는 대소문자를 무시합니다.

| 키 | 의미 |
|---|---|
| `type` | `volume`(기본), `bind`, `tmpfs` |
| `source`/`src`, `target`/`destination`/`dst` | 출처, 대상(필수) |
| `readonly`/`ro` | 값 없음 또는 Go `ParseBool` 값 |
| `bind-propagation`, `bind-nonrecursive` | bind 전용 |
| `volume-driver`, `volume-label`, `volume-opt`, `volume-nocopy`, `volume-subpath` | volume 전용 |
| `tmpfs-size`(RAMInBytes), `tmpfs-mode`(8진수) | tmpfs 전용 |
| `consistency` | 받고 무시 |

다른 종류의 옵션을 섞으면 `cannot mix 'volume-*' options with mount type 'bind'`처럼 거부하고, 모르는 키는
`unexpected key`. bind는 출처가 필수이며 `--mount`는 없는 호스트 경로를 만들지 않습니다
(`bind source path does not exist`).

### `--tmpfs` (`ParseTmpfsFlag`)

`target[:options]`. 옵션은 그대로 쓰되 Docker처럼 기본 `noexec,nosuid,nodev`를 붙이고 `exec`/`suid`/`dev`가
있으면 해당 기본값을 뺍니다.

### OCI 객체 (`BuildOciMount`)

| 종류 | 결과 |
|---|---|
| volume, bind | `{"destination","type":"bind","source":<호스트 경로>,"options":["rbind"|"bind","rw"|"ro",<전파, 기본 rprivate>]}` |
| tmpfs | `{"destination","type":"tmpfs","source":"tmpfs","options":["nosuid","nodev","noexec",("ro"),"size=64m","mode=1770"]}` |

tmpfs 크기는 Docker처럼 나누어떨어지는 가장 큰 단위로 씁니다(`size=10g`).

### `PrepareContainerMounts`

한 컨테이너의 요청 목록을 처리합니다.

1. 대상 중복은 `-EINVAL`(`duplicate mount point`).
2. volume: 없으면 만들고(익명은 무작위 이름 + 라벨, `volume-opt`/`volume-label` 적용), 컨테이너 id로 acquire합니다.
   `volume-subpath`는 볼륨 안에서 `openat2(RESOLVE_IN_ROOT)`로 해석하고 결과 경로가 볼륨 밖이면 `-EXDEV`.
   `nocopy`가 아니고 rootfs가 주어지면 rootfs 안의 대상 경로 내용을 copy-up합니다.
3. bind: `ValidateHostPath`(어휘 정리, 존재 확인 또는 생성). 볼륨 저장소 안은 `<root>/<name>/_data` 아래만
   허용하고 메타데이터 쪽은 `-EACCES`.
4. 실패하면 이 호출이 acquire한 볼륨을 모두 놓고, 이 호출이 만든 익명 볼륨을 지웁니다.

컨테이너를 지울 때는 `releaseUser(containerId, removeAnonymous)`를 부릅니다.

## Docker 볼륨 플러그인 (`CVolumePlugin`)

`handle(path, body)`가 프로토콜 전체이고, `attach(server)`가 http 모듈의 `CHttpServer`에 경로를 등록합니다
(Content-Type `application/vnd.docker.plugins.v1.2+json`).

| 경로 | 요청 | 응답 |
|---|---|---|
| `/Plugin.Activate` | | `{"Implements":["VolumeDriver"]}` |
| `/VolumeDriver.Create` | `{"Name","Opts"}` | `{"Err":""}` (Opts는 local 드라이버 옵션) |
| `/VolumeDriver.Remove` | `{"Name"}` | `{"Err":""}`, 사용 중이면 Err |
| `/VolumeDriver.Mount` | `{"Name","ID"}` | `{"Mountpoint","Err":""}` (ID가 사용자, 없으면 `docker`) |
| `/VolumeDriver.Unmount` | `{"Name","ID"}` | `{"Err":""}` |
| `/VolumeDriver.Path` | `{"Name"}` | `{"Mountpoint","Err":""}` |
| `/VolumeDriver.Get` | `{"Name"}` | `{"Volume":{"Name","Mountpoint","CreatedAt","Status":{"Mounted","RefCount","Options","Labels"}},"Err":""}` |
| `/VolumeDriver.List` | `{}` | `{"Volumes":[{"Name","Mountpoint","CreatedAt"}],"Err":""}` |
| `/VolumeDriver.Capabilities` | `{}` | `{"Capabilities":{"Scope":"local"}}` |

- 오류는 Docker 플러그인 규약대로 HTTP 200과 `{"Err":"<이유>"}`입니다(dockerd는 본문의 Err를 읽음).
  없는 볼륨은 dockerd가 알아보는 문구 `no such volume: <name>`을 씁니다.
- 등록되지 않은 경로는 404와 `{"Err":"unsupported plugin call ..."}`입니다.
- 플러그인으로 만든 볼륨은 `sboxvol` CLI와 같은 저장소에 있으므로 CLI(`ls`, `backup` 등)로도 다룰 수 있습니다.

## 데몬과 dockerd 등록

### sboxvol

```sh
sboxvol [--root DIR] create [-d local] [--opt k=v]... [--label k=v]... [NAME]
sboxvol [--root DIR] ls [-q] [--filter label=k[=v]] [--filter dangling=true]
sboxvol [--root DIR] inspect [--size] NAME...
sboxvol [--root DIR] rm [-f] NAME...
sboxvol [--root DIR] prune [-a] [--filter label=k[=v]]
sboxvol [--root DIR] backup [--level N] [--freeze] [--no-xattrs] NAME FILE|-
sboxvol [--root DIR] restore [--overwrite] [--no-create] [--opt k=v] [--label k=v] NAME FILE|-
sboxvol [--root DIR] serve [--socket PATH]      # 기본 /run/docker/plugins/sboxvol.sock
```

`ls`/`inspect`/`prune` 출력은 docker CLI와 같은 모양입니다. `backup ... -`는 표준 출력, `restore ... -`는 표준
입력을 씁니다.

### sboxnet

```sh
sboxnet [--socket PATH] [--state-dir DIR] [--no-firewall] [--host-netns PATH] [--wg-uapi-dir DIR]
# 기본 소켓 /run/docker/plugins/sboxnet.sock, 상태 /var/lib/sbox/net (net 모듈의 DefaultNetworkStateDir)
# --host-netns: "호스트"로 취급할 네트워크 네임스페이스(기본: 데몬 자신의 것, 테스트용)
# --wg-uapi-dir: 사용자 공간 WireGuard 장치의 UAPI 소켓 디렉터리(기본 /var/run/wireguard)
```

`CNetworkManager`(상태 디렉터리)와 `CDockerPlugin`을 만들어 모든 POST 경로를 `plugin.handle(path, body)`로
넘깁니다. net 모듈의 권고대로 `Err`가 있는 응답은 500, 나머지는 200입니다(dockerd는 두 경우 모두 Err를 읽음).

데몬은 net 모듈의 드라이버(bridge, macvlan, ipvlan, host, none)에 더해 vpn 모듈의 `CWgOverlayDriver`를
등록하고, 요청을 받기 전에 `restore()`를 불러 상태 디렉터리에 있는 오버레이 네트워크 중 장치가 없는 것(재부팅,
또는 사용자 공간 장치를 돌리던 데몬이 끝난 경우)의 WireGuard 장치를 다시 올립니다. 커널 `wireguard` 모듈이
없으면 장치는 사용자 공간 구현이고 이 데몬의 이벤트 루프에서 돌므로, 데몬이 끝나면 터널도 내려가고 다음 시작
때 복구됩니다. 오버레이 네트워크는 일반 옵션으로 만듭니다(`sbox.driver`가 없어도 `sbox.wg.overlay`나
`sbox.wg.overlay.file`이 있으면 `wg-overlay` 드라이버). 주소는 Docker IPAM이 이 호스트 대역(`--ip-range`)에서,
게이트웨이는 이 호스트 대역의 첫 주소(`--gateway`)로 줍니다.

```sh
# /etc/sbox/ov.json: {"privateKey":"<sbox-wg genkey>","hostSubnet":"10.210.1.0/24","listenPort":51820,
#                     "peers":[{"name":"host-b","publicKey":"...","endpoint":"192.0.2.2:51820","subnet":"10.210.2.0/24"}]}
docker network create -d sboxnet --subnet 10.210.0.0/16 --ip-range 10.210.1.0/24 --gateway 10.210.1.1 \
    -o sbox.wg.overlay.file=/etc/sbox/ov.json ov
docker run --rm --network ov alpine ping -c1 10.210.2.2       # 다른 호스트의 컨테이너
```

Docker 없이 같은 상태를 다루는 일회성 명령도 있습니다(같은 드라이버 등록, 같은 잠금).

```sh
sboxnet [--state-dir DIR] [--host-netns PATH] network create [-d DRIVER] [--subnet CIDR [--gateway IP] [--ip-range CIDR]]...
        [--internal] [--ipv6] [-o KEY=VALUE]... [--label KEY=VALUE]... NAME     # 네트워크 ID 출력
sboxnet network ls [-q]
sboxnet network inspect NAME...                                                # SNetwork JSON 배열
sboxnet network rm NAME...                                                     # 엔드포인트가 있으면 실패
```

설정 형식과 실행 중 호스트 추가는 [vpn-wg.md](vpn-wg.md)를 보십시오. 개인 키는 드라이버의 0600 상태 파일로
옮겨지고 네트워크 객체(Docker `network inspect`의 옵션)에는 남지 않습니다.

### 신호와 종료

두 데몬 모두 신호 처리기를 쓰지 않습니다. 시작할 때 `SIGTERM`/`SIGINT`를 `sigprocmask`로 막고(이후 생기는
스레드도 상속) `signalfd`를 이벤트 루프에서 `waitFd`로 기다립니다. 신호가 오면 `CHttpServer::stop()`으로 새
연결을 막고 처리 중인 요청을 마친 뒤 소켓 파일을 지우고 0으로 끝납니다. `SIGPIPE`는 무시합니다.

### dockerd에 등록하기

dockerd는 `/run/docker/plugins/<이름>.sock` 유닉스 소켓(또는 `/etc/docker/plugins/<이름>.spec|json`)으로 플러그인을
찾습니다. 소켓 파일 이름이 드라이버 이름이 되므로 데몬을 기본 소켓으로 띄우기만 하면 됩니다. dockerd는
드라이버를 처음 쓸 때 소켓에 `/Plugin.Activate`를 보내고, 연결이 안 되면 잠시 재시도합니다.

```sh
# 데몬 시작(루트). systemd라면 docker.service보다 먼저(Before=docker.service) 띄웁니다.
sboxvol serve &                       # /run/docker/plugins/sboxvol.sock
sboxnet &                             # /run/docker/plugins/sboxnet.sock

# 볼륨
docker volume create -d sboxvol data
docker volume create -d sboxvol --opt type=tmpfs --opt device=tmpfs --opt o=size=100m,uid=1000 scratch
docker volume create -d sboxvol --opt type=nfs --opt device=:/export --opt o=addr=nas.local,rw,nfsvers=4 shared
docker volume create -d sboxvol --opt size=10G limited      # 저장소가 prjquota 파일시스템일 때
docker run --rm -v data:/data alpine ls /data               # 이미 만든 볼륨
docker run --rm --volume-driver sboxvol -v new:/data alpine true
docker run --rm --mount type=volume,src=x,dst=/x,volume-driver=sboxvol alpine true

# 네트워크 + IPAM
docker network create -d sboxnet --ipam-driver sboxnet --subnet 10.10.0.0/24 sboxlan
docker run --rm --network sboxlan alpine ip addr
```

`docker volume inspect`의 `Mountpoint`는 플러그인이 돌려준 `<root>/<name>/_data`입니다. 같은 볼륨을 sbox 런타임에서
쓸 때는 `PrepareContainerMounts`가 같은 저장소를 쓰도록 `--root`를 맞춥니다.

## 사용하는 커널 인터페이스

`mount(2)`(tmpfs, nfs/nfs4, bind/rbind, `MS_REMOUNT|MS_BIND`, 전파), `umount2(UMOUNT_NOFOLLOW, MNT_DETACH)`,
`statx(STATX_ATTR_MOUNT_ROOT)`, `openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS)`, `ioctl(FS_IOC_FSGETXATTR/
FS_IOC_FSSETXATTR)`, `quotactl_fd(2)`/`quotactl(2)`(`Q_XGETQSTAT`, `Q_XSETQLIM`, `Q_XGETQUOTA`, `Q_GETQUOTA`,
`Q_SETQUOTA`, PRJQUOTA), `ioctl(FIFREEZE/FITHAW)`, `flock(2)`, `getrandom(2)`, `signalfd(2)`,
`/proc/self/mountinfo`, `/proc/sys/kernel/random/boot_id`.

## 테스트

`ctest --test-dir build -L vol`: 7개 실행 파일. 마운트가 필요한 케이스는 포크한 자식에서 `unshare(CLONE_NEWNS)` +
`MS_REC|MS_PRIVATE`로 만든 사적인 마운트 네임스페이스 안에서만 마운트하므로 호스트 마운트 표는 바뀌지 않습니다.
루트, 루프 장치, `mkfs.*`가 없으면 `MESSAGE`를 남기고 건너뜁니다. 경로는 모두 `mkdtemp`라 병렬로 안전합니다.

- `local`: `ParseSize`/`FormatSize` 표, `ParseMountOptions`, local 옵션 검증 표(21개), tmpfs(크기/모드/소유자
  확인)·읽기 전용 bind(`EROFS`, 플래그)·바쁜 마운트의 지연 언마운트·잘못된 타입, 루프 장치 ext4 장치 볼륨
  (다시 마운트해도 데이터 유지), NFS 이름 해석 실패와 `addr` 없음(`SBOX_TEST_NFS=host:/export`가 있으면 실제
  NFS 마운트), copy-up(소유자, 모드, 링크, 하드링크, xattr, 비어 있지 않으면 안 함), `OpenInRoot` 링크 탈출 방지.
- `quota`: 지원 확인(`-ENOTSUP`), `BlockDeviceOf`, 쿼터 없는 파일시스템의 `size=` 거부, ext4 `project` 기능의
  프로젝트 id, ext4(`quota,project` + `prjquota`)와 XFS(`prjquota`)에서 한도 초과 `EDQUOT`, 사용량, id 할당 영속성.
- `store`: 이름 규칙, 생명 주기(멱등 생성, 참조 계수, 두 번째 인스턴스에서 보이는 상태, `-EBUSY`, force, 중단된
  생성 정리), 잘못된 옵션, 익명 볼륨·`releaseUser`·prune(라벨 필터), 재부팅 감지, **두 프로세스 동시 생성**
  (공유/개별/익명 이름 70개, 이후 동시 release와 prune), tmpfs 볼륨의 첫 acquire 마운트/마지막 release 언마운트,
  force 삭제가 bind 출처를 보존, 마운트 실패 시 사용자 미등록, `_data` 소유자.
- `backup`: 소유자/xattr(`user.*`, `trusted.*`)/심볼릭·하드 링크/FIFO/모드 왕복, 시스템 tar 호환, `-ENOTEMPTY`와
  overwrite, 없는 볼륨, 라벨 붙여 생성, 디렉터리 볼륨 freeze `-ENOTSUP`, 파이프를 통한 스트림 백업 → 복원,
  링크 탈출 tar 거부, 루프 ext4 장치 볼륨의 freeze 백업과 사용하지 않는 장치 볼륨의 임시 마운트 백업.
- `mount`: `-v` 표(23개), `--mount` 표(30개, 인용된 volume-opt 포함), `--tmpfs`, `ValidateHostPath`,
  `PrepareContainerMounts`(생성, copy-up, rootfs 안 링크를 따른 copy-up, nocopy, 공유 볼륨, 실패 시 롤백, 중복 대상,
  저장소 메타데이터 bind 거부, volume-subpath와 링크 탈출, `--rm` 정리).
- `plugin`: HTTP 없는 핸들러, 유닉스 소켓 위 전체 흐름(Activate, Capabilities, Create(옵션/오류는 200+Err),
  Get, List, Path, Mount/Unmount 참조 계수, 사용 중 Remove, 없는 볼륨 문구, 404, 동시 Create 8개), 사적 마운트
  네임스페이스에서 tmpfs 볼륨 Mount/Unmount.
- `daemons`: 빌드된 `sboxvol` CLI(create/ls/inspect/backup/restore/표준 입출력/prune/rm), `sboxvol serve`를 임시
  소켓에 띄워 프로토콜 흐름 후 SIGTERM으로 정상 종료와 소켓 제거, `sboxnet`을 임시 소켓/상태 디렉터리에 띄워
  `/Plugin.Activate`, `/NetworkDriver.GetCapabilities`, `/IpamDriver.GetDefaultAddressSpaces` 후 SIGINT 종료.
  (`sboxnet`의 `wg-overlay` 흐름과 재시작 후 복구는 vpn 모듈의 `vpn_wg_plugin`이 시험합니다.)

## 제한 사항

- 볼륨 드라이버는 `local`만 내장입니다. 다른 이름의 드라이버(외부 플러그인으로 위임)는 `-ENOTSUP`입니다.
- 이 개발 환경 커널은 `CONFIG_QUOTA`가 없어 ext4/XFS 프로젝트 쿼터 한도 테스트와 ext4 프로젝트 id 테스트는
  건너뛰었습니다(코드 경로는 그런 커널에서 `-ENOTSUP`으로 끝남을 확인). XFS는 `mkfs.xfs`가 없어 건너뜀.
- NFS 실제 마운트는 서버가 없어 `SBOX_TEST_NFS`가 있을 때만 테스트합니다. NFSv4.0 콜백용 `clientaddr`는
  붙이지 않습니다(커널이 자동 선택). CIFS 장치의 호스트 이름 해석은 하지 않습니다.
- `size=`는 디렉터리 볼륨에만 적용합니다(`type`과 함께 쓰면 거부). 쿼터가 있는 볼륨을 복원하면 파일이 상속된
  프로젝트 id를 받지만, 이미 있던 하위 파일의 id를 다시 매기지는 않습니다.
- 참조 계수(`Users`)는 디스크에 남으므로 컨테이너가 release 없이 사라지면 재부팅 전까지 사용 중으로 남습니다.
  `rm -f`나 `releaseUser`로 정리합니다.
- SELinux `z`/`Z`는 해석만 하고 레이블은 바꾸지 않습니다. `consistency`는 무시합니다. `bind-recursive`(Docker 25+의
  `readonly`/`writable` 재귀 옵션), `volume-driver`의 외부 드라이버, `image`/`npipe`/`cluster` 마운트 종류는 없습니다.
- 백업은 동기 파일시스템 읽기라 큰 볼륨은 그동안 이벤트 루프를 점유합니다. freeze는 볼륨 자체 마운트가 있는
  경우에만 됩니다. 백업 형식은 gzip tar 하나입니다(zstd 압축 없음, 복원은 zstd도 읽음).
- `-v`로 받은 상대 경로 bind 출처는 거부합니다(docker CLI처럼 절대 경로로 바꾸는 일은 호출자의 몫).
- 플러그인 프로토콜의 `Status`는 sbox 고유 필드(`Mounted`, `RefCount`, `Options`, `Labels`, `SizeLimit`)입니다.
