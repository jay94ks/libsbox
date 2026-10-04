# image 모듈

컨테이너 이미지를 받아 저장하고, 레이어를 풀어 컨테이너 루트 파일 시스템을 만들고, OCI 런타임 번들을
만드는 모듈입니다. 네임스페이스는 `sbox::image`, 헤더는 `modules/image/include/sbox/image/`, CMake 타깃은
`sbox::image`(`sbox_add_module(image DEPENDS archive http tls LINK certpp::certpp)`)입니다. 명령줄 도구는
`cli/sbox-image/`의 `sbox-image`입니다.

설계 원칙은 Docker 호환입니다. 이미지 참조 문법과 정규화, manifest/설정/레이어 다이제스트, 이미지 ID(설정
다이제스트), diffID와 chainID, `docker save` 아카이브와 OCI 레이아웃이 Docker/containerd와 같은 값을
만들고 서로 읽힙니다. SHA-256/SHA-512는 libcertpp(`certpp::crypto::SHA256/SHA512`)로 계산합니다.

## 헤더 한눈에 보기

| 헤더 | 내용 |
|---|---|
| `digest.hpp` | `ValidateDigest`, `DigestAlgorithm`, `DigestHex`, `CDigester`(증분 SHA-256/512), `DigestOf`, `DigestFile`, `ChainId`, `ChainIds` |
| `reference.hpp` | `SReference`(엄격 파싱), `ParseNormalizedReference`, `ParseDockerReference`, `WithDefaultTag`, `IsValidTag`, `IsFullHexId`, `RegistryHost`, `IsLoopbackRegistry` |
| `spec.hpp` | 미디어 타입 상수, `SPlatform`/`HostPlatform`/`PlatformScore`, `SDescriptor`, `SManifest`, `SIndex`(`select`), `ClassifyManifest`, `SImageConfig`, `NowRfc3339` |
| `store.hpp` | `CContentStore`(OCI 레이아웃 저장소), `CBlobWriter`(검증 후 원자적 반영, 재개), `CStoreLock`(flock), `CLease`(GC 보호), `SImageRecord`, `SImageInfo`, `DefaultStoreRoot` |
| `registry.hpp` | `CRegistryClient`(`pull`, `push`, `fetchManifest`, `listTags`), `SRegistryOptions`, `SPullResult`, `SPushResult`, `SRegistryAuth`, `LoadDockerCredentials`, `DockerConfigPath` |
| `snapshot.hpp` | `CSnapshotter`(레이어 스냅샷, overlay/복사 컨테이너 루트, mount/umount, commit), `SMountPlan`, `SContainerInfo`, `SSnapshotInfo`, `SCommitOptions`, 진행 이벤트 `SProgress`/`FImageProgress` |
| `runtime.hpp` | `GenerateRuntimeSpec`(이미지 설정 → OCI runtime-spec `config.json`), `CreateBundle`, `ResolveUser`, `DefaultCapabilities`, `DockerDefaultSeccompProfile`, `SeccompProfileToOci` |
| `transfer.hpp` | `SaveDockerArchive`(`docker save`), `SaveOciArchive`, `LoadImageArchive`(`docker load`, OCI 아카이브) |
| `gc.hpp` | `CollectGarbage`(mark and sweep, prune), `RemoveImage`(`docker rmi` 의미) |

결과 코드는 libsbox 규칙대로 `SBOX_OK` 또는 음수 errno입니다. 자주 쓰는 값:

| 값 | 뜻 |
|---|---|
| `-EINVAL` | 잘못된 참조/다이제스트/문서 형식 |
| `-ENOENT` | 없는 이미지, 태그, blob(레지스트리 404 포함) |
| `-EACCES` | 레지스트리 인증 실패(401/403, 토큰 서버 거부) |
| `-EBADMSG` | 다이제스트·크기·diffID 불일치, 손상된 manifest |
| `-EPROTONOSUPPORT` | Docker manifest schema 1 |
| `-ENOEXEC` | index에 요청한 플랫폼이 없음 |
| `-ENOTSUP` | 지원하지 않는 미디어 타입, 복사 컨테이너 commit |
| `-EEXIST` / `-EBUSY` | `rmi` 충돌(여러 저장소에서 참조, 컨테이너가 사용), 모호한 짧은 ID, 이미 있는 컨테이너 |
| `-E2BIG` | overlay 마운트 데이터가 너무 김(대체 경로로도 불가) |

사람이 읽을 이유는 `CRegistryClient::lastError()`, `CSnapshotter::lastError()`, 또는 함수의 `std::string* error`
인자로 돌려줍니다.

## 1. 참조 (`reference.hpp`)

Docker `distribution/reference`의 문법을 그대로 구현했습니다.

```
reference := name [ ":" tag ] [ "@" digest ]
name      := [ domain "/" ] path          (전체 길이 255 이하)
domain    := host [ ":" port ]            (DNS 이름, IPv4, "[IPv6]")
path      := component ( "/" component )*
component := [a-z0-9]+ ( ( "." | "_" | "__" | "-"+ ) [a-z0-9]+ )*
tag       := [A-Za-z0-9_][A-Za-z0-9_.-]{0,127}
digest    := algorithm ":" hex{32,}       (다시 ValidateDigest로 검사)
```

- `SReference::parse`는 엄격 파싱입니다. 정규식과 똑같이 도메인을 먼저 시도하므로 `foo/bar`는 도메인 `foo`,
  경로 `bar`가 됩니다.
- `ParseNormalizedReference`는 `ParseNormalizedNamed`와 같습니다. 첫 성분에 `.`이나 `:`가 있거나
  `localhost`이거나 대문자가 있으면 도메인, 아니면 `docker.io`; `index.docker.io`는 `docker.io`로;
  Docker Hub의 한 성분 경로에는 `library/`를 붙입니다. 경로에 대문자가 있거나 64자리 16진수만 주면
  거부합니다(이미지 ID와 혼동 방지).
- `ParseDockerReference`는 `ParseDockerRef`처럼 태그도 다이제스트도 없으면 `:latest`를 붙이고, 둘 다 있으면
  다이제스트만 남깁니다.
- `familiarName()`/`familiarString()`은 Docker가 보여 주는 짧은 형태(`alpine:latest`, `user/app:1`)입니다.
- `RegistryHost("docker.io") == "registry-1.docker.io"`. `IsLoopbackRegistry`는 `localhost`, `127.0.0.0/8`,
  `[::1]`(Docker가 기본으로 insecure로 취급하는 대상)입니다.

## 2. 저장소 (`store.hpp`)

### 디스크 형식

기본 위치는 root면 `/var/lib/sbox/image`, 아니면 `$XDG_DATA_HOME/sbox/image`(없으면
`~/.local/share/sbox/image`)입니다(`DefaultStoreRoot`, CLI는 `--root`/`SBOX_IMAGE_ROOT`).

```
<root>/oci-layout                {"imageLayoutVersion":"1.0.0"}
<root>/index.json                OCI image index: 이름 있는(또는 dangling) 이미지 목록
<root>/blobs/sha256/<hex>        manifest, index, 설정, 레이어 blob
<root>/ingest/                   쓰는 중인 blob(tmp-*, <alg>-<hex>.partial), load/save 임시 디렉터리
<root>/leases/<rand>.json        진행 중인 pull/load가 붙잡은 blob·스냅샷(flock)
<root>/db.json                   메타데이터: {"version":1,"diffIds":{blob:diffID},"sources":{blob:[repo]}}
<root>/snapshots/<chainID hex>/  풀린 레이어: fs/ 와 meta.json
<root>/snapshots/empty           레이어가 없는 이미지용 빈 lowerdir
<root>/l/<짧은 이름>              legacy overlay 마운트용 짧은 심볼릭 링크 → ../snapshots/<hex>/fs
<root>/containers/<id>/          컨테이너 루트: meta.json, upper/ work/ merged/ (overlay) 또는 rootfs/ (복사)
<root>/lock                      메타데이터 갱신용 flock 파일
```

저장소 디렉터리 자체가 유효한 OCI image layout이므로 skopeo/containerd의 OCI 레이아웃 도구가 그대로 읽습니다.

### index.json

항목 하나가 이름 하나입니다. 대상은 항상 **플랫폼 manifest**(설정과 레이어가 모두 저장소에 있는 문서)입니다.

```json
{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:...","size":1023,
 "annotations":{"io.containerd.image.name":"docker.io/library/alpine:3.20",
                "org.opencontainers.image.ref.name":"3.20"},
 "platform":{"architecture":"amd64","os":"linux"}}
```

- 이름은 정규화한 전체 참조로 `io.containerd.image.name`에 둡니다(Docker 25+/containerd 아카이브와 같음).
  `org.opencontainers.image.ref.name`에는 OCI 레이아웃 관례대로 태그만 둡니다. 다이제스트 이름
  (`name@sha256:...`)은 RepoDigests이며 ref.name이 없습니다.
- 주석이 없는 항목은 이름 없는(dangling, `<none>`) 이미지입니다. 태그를 다른 manifest로 옮겼을 때 원래
  manifest를 가리키는 다른 항목이 없으면 dangling 항목으로 남깁니다(Docker의 `<none>:<none>`과 같음).
- 이미지 ID는 Docker처럼 설정 blob의 다이제스트입니다. `listImages`는 같은 설정을 쓰는 manifest들을 한
  이미지로 묶고 RepoTags/RepoDigests를 모읍니다.
- `resolve(nameOrId)`: 전체 ID(`sha256:...`/64자리) → 참조(정규화, `:latest` 보충) → 고유한 ID 접두사 순.
  접두사가 여러 이미지에 맞으면 `-EEXIST`.

### blob 쓰기와 동시성

- `CBlobWriter`는 `ingest/`에 쓰면서 다이제스트를 계산하고, `commit(digest, size)`에서 검증한 뒤 fsync하고
  `blobs/`로 rename합니다. 같은 blob이 이미 있으면 임시 파일만 지웁니다(내용 주소라 같은 내용).
  검증 실패는 `-EBADMSG`이고 파일을 버립니다.
- 이름 있는 ingest(`sha256-<hex>.partial`)는 프로세스가 끝나도 남아 다음 pull이 `Range`로 이어 받습니다.
  다시 열 때 기존 내용을 다시 해시합니다. 파일에 `flock(LOCK_EX|LOCK_NB)`를 걸어 두 프로세스가 같은
  blob을 동시에 쓰지 않으며, 늦게 온 쪽은 `-EBUSY`를 받고(레지스트리 클라이언트는 blob이 나타날 때까지
  200 ms 간격으로 기다림) 같은 파일을 건드리지 않습니다.
- `index.json`과 `db.json`은 `CStoreLock`(`<root>/lock`의 flock, 객체 안에서 재진입 가능) 아래에서
  읽고-고치고-쓰며, 임시 파일 + rename으로 원자적으로 바꿉니다. 이 구간은 짧아서 블로킹 flock을 씁니다.
- `CLease`는 pull/load/commit 중에 만들어진 blob과 스냅샷이 아직 index.json에 이름이 없을 때 GC가 지우지
  못하게 합니다. 파일을 flock한 채로 두고, GC는 잠긴 lease를 루트로 보고 잠기지 않은(프로세스가 죽은)
  lease 파일은 지웁니다. lease 생성은 저장소 잠금 아래에서 하므로 GC가 잠기기 전의 파일을 볼 수 없습니다.

## 3. 레지스트리 (`registry.hpp`)

`CRegistryClient`는 Docker Registry HTTP API v2 / OCI distribution 클라이언트입니다. http 모듈의
`CHttpClient`(연결 풀, 리다이렉트, 스트리밍 본문) 위에 TLS 훅으로 tls 모듈의 `ConnectTls`를 끼웁니다.
모든 동작은 호출 스레드의 `CEventLoop` 위 코루틴입니다.

### 엔드포인트

- pull은 미러를 먼저, 그다음 레지스트리를 시도합니다. `mirrors`의 `"https://mirror"`는 Docker Hub용
  (`registry-mirrors`와 같음), `"domain=https://mirror"`는 다른 레지스트리용입니다. 미러 URL의 경로는 접두사로
  씁니다. 미러가 manifest를 못 주면(네트워크 오류, 404) 다음으로 넘어가고, 레지스트리 자체의 오류는
  최종입니다. blob은 manifest를 준 엔드포인트에서 받습니다. push는 미러를 쓰지 않습니다.
- 기본은 HTTPS입니다. `insecureRegistries`와 루프백 레지스트리는 검증 없는 HTTPS를 먼저 시도하고 실패하면
  평문 HTTP로 바꿉니다(Docker와 같음). `plainHttpRegistries`는 처음부터 HTTP입니다.
- `/etc/docker/certs.d/<host:port>/`(없으면 `<host>/`)의 `*.crt`는 시스템 신뢰 저장소 위에 더한 CA로,
  `*.cert`+`*.key` 짝은 mTLS 클라이언트 인증서로 씁니다(`certsDir`로 위치 변경).
- 프록시는 `SRegistryOptions::proxy`(http 모듈 `SProxyConfig`)입니다. CLI는 항상
  `SProxyConfig::fromEnvironment()`(HTTPS_PROXY, NO_PROXY)를 씁니다.

### 인증

1. 엔드포인트마다 처음 한 번 `GET /v2/`를 보내 스킴을 정하고 `WWW-Authenticate` 챌린지를 기록합니다. 여러
   코루틴이 동시에 요청해도 핑은 하나만 돌고 나머지는 기다립니다.
2. Bearer 챌린지면 `realm?service=...&scope=repository:<path>:pull[,push]`로 토큰을 받습니다. 자격 증명이
   있으면 Basic으로, identity token이 있으면 OAuth2 `grant_type=refresh_token` POST로 요청합니다. 응답의
   `token`/`access_token`과 `expires_in`(최소 60초, 10초 일찍 만료)을 (realm, service, scope) 키로 캐시합니다.
3. Basic 챌린지면 자격 증명을 바로 보냅니다.
4. 요청이 401을 받으면 응답의 챌린지(예: `error="insufficient_scope"`, `scope=...`)로 갱신하고 그 realm의
   토큰을 버린 뒤 한 번 재시도합니다. 스트림 본문은 재시도 때 다시 만듭니다.
5. 자격 증명: `credentials`(도메인별 명시)가 먼저, 그다음 Docker `config.json`(`$DOCKER_CONFIG/config.json`
   또는 `~/.docker/config.json`)의 `auths`. 키는 `https://index.docker.io/v1/` 같은 URL이든 `host:port`든
   됩니다. `auth`(base64 `user:pass`), `username`/`password`, `identitytoken`, `registrytoken`을 읽습니다.
6. CDN으로의 blob 리다이렉트는 http 클라이언트가 따라가며, 오리진이 바뀌면 `Authorization`을 버립니다.

### pull

1. `ParseDockerReference` 후 `GET /v2/<path>/manifests/<tag|digest>`를 Accept
   `oci index, docker manifest list, oci manifest, docker schema2`로 보냅니다. 본문의 다이제스트를 계산해
   다이제스트로 요청했으면 일치를, 태그로 요청했으면 `Docker-Content-Digest`(sha256일 때)와 일치를
   확인합니다. 문서의 `mediaType`이 Content-Type보다 우선하며, 없으면 구조로 판별합니다.
2. schema 1이면 `-EPROTONOSUPPORT`와 이유를 돌려줍니다.
3. index/manifest list면 `SIndex::select`로 플랫폼을 고릅니다. 기본은 호스트(`HostPlatform`: uname, arm
   변형 포함), `platform` 옵션으로 바꿀 수 있습니다. 정규화(aarch64→arm64, arm→arm/v7, amd64 v1→"")한 뒤
   정확히 맞는 것을 가장 높게, arm v7 호스트의 v6/v5와 amd64 상위 마이크로아키텍처의 하위 변형을 낮게
   점수 매깁니다. `unknown/unknown`(BuildKit attestation)은 건너뜁니다. 고른 manifest를 다이제스트로 받고
   크기를 확인합니다. index blob도 저장합니다(RepoDigests가 가리키는 문서).
4. 설정 blob을 받고 diffID 개수가 레이어 수와 같은지 확인합니다.
5. 레이어를 `maxConcurrentDownloads`(기본 3, Docker와 같음)개의 코루틴으로 동시에 받습니다. 받는 바이트는
   `CBlobWriter`로 바로 디스크에 쓰며 다이제스트를 계산합니다. 네트워크 오류나 5xx/429면 받은 데까지
   남기고 `Range: bytes=<offset>-`로 이어 받습니다(206의 `Content-Range` 시작이 맞지 않거나 서버가 200을
   주면 처음부터). 크기 초과, 다이제스트 불일치는 처음부터 다시 받고, 시도는 `maxAttempts`(기본 5)번,
   대기는 `retryDelayMs × 시도 횟수`입니다. 401/403/404는 재시도하지 않습니다.
6. `unpack`이면(기본) 레이어를 스냅샷으로 풀면서 diffID를 검증합니다(4장).
7. index.json에 `name:tag`(또는 `name@digest`)와, 태그로 받았으면 `name@<받은 문서 다이제스트>`(RepoDigest)를
   기록합니다. 받은 레이어의 출처 저장소를 `db.json`의 `sources`에 남깁니다(push의 mount용).
8. 진행 상황은 `SRegistryOptions::progress`로 알립니다(`EPP_EXISTS`, `EPP_DOWNLOADING`, `EPP_RETRYING`,
   `EPP_VERIFIED`, `EPP_EXTRACTING`, `EPP_EXTRACTED`, `EPP_DONE` ...).

이 모든 과정은 `CLease`로 보호되므로 동시에 도는 `prune`이 받는 중인 내용을 지우지 않습니다.

### push

1. 로컬 이미지를 찾고 대상 참조를 정규화합니다(대상이 없으면 원래 이름으로).
2. 레이어와 설정마다(`maxConcurrentUploads`, 기본 5): `HEAD /v2/<name>/blobs/<digest>`가 200이면 건너뜀.
   같은 레지스트리의 다른 저장소에서 온 blob이면 `POST .../blobs/uploads/?mount=<digest>&from=<repo>`
   (스코프에 `repository:<from>:pull` 추가)로 마운트를 시도하고 201이면 끝. 아니면 업로드 세션을 열고
   `Location`(상대 URL 해석)에
   - 단일 업로드: `PUT <location>&digest=<digest>`, 본문은 파일 스트림(Content-Length).
   - 청크 업로드(`uploadChunkSize > 0`): `PATCH`(Content-Range `start-end`)를 반복하고 매번 새 `Location`을
     따른 뒤 빈 `PUT ...&digest=`.
3. manifest 원본 바이트를 그대로 `PUT /v2/<name>/manifests/<tag|digest>`(Content-Type은 manifest의 미디어 타입)
   하고, 응답의 `Docker-Content-Digest`가 같은지 확인합니다.

`listTags`는 `GET /v2/<name>/tags/list`의 `Link: <...>; rel="next"` 페이지를 따라갑니다.

## 4. 스냅샷과 컨테이너 루트 (`snapshot.hpp`)

### 레이어 스냅샷

- 레이어 하나는 한 번만 `snapshots/<chainID hex>/fs`에 풉니다. chainID는 OCI 규칙
  `ChainID(L0) = DiffID(L0)`, `ChainID(L0..Ln) = sha256(ChainID(L0..Ln-1) + " " + DiffID(Ln))`입니다.
- 압축 형식은 앞 바이트로 판별합니다(gzip, zstd, 무압축). 푸는 동안 tar 바이트의 SHA-256(diffID)을 계산해
  이미지 설정의 `rootfs.diff_ids[i]`와 비교하고, 다르면 지우고 `-EBADMSG`입니다.
- whiteout은 overlay 형식으로 둡니다. root: `EWHT_OVERLAY`(0/0 문자 장치, `trusted.overlay.opaque=y`).
  rootless(실제 root가 아니면 자동, `SSnapshotterOptions::rootless`로 강제): `EWHT_OVERLAY_USERXATTR`(빈 파일 +
  `user.overlay.whiteout`, `user.overlay.opaque`; 커널 6.7+ xwhiteout).
- `snapshots/tmp-<rand>`에 푼 뒤 `meta.json`(chainId, diffId, parent, blob, whiteouts, size, created)을 쓰고
  rename으로 반영합니다. 다른 프로세스가 먼저 만들었으면 우리 것을 버립니다. 지울 때도 먼저
  `rm-<rand>`로 rename합니다. 반쯤 만든 스냅샷이 완성된 것처럼 보이는 일이 없습니다.
- 소유자는 root면 이미지의 uid/gid 그대로(`EOWN_AUTO`), rootless면 실행 사용자입니다.

### overlay 컨테이너 루트

`prepare(id, image, ESNAP_OVERLAY, out)`는 레이어를 풀고 `containers/<id>/{upper,work,merged}`를 만든 뒤
(기본) 마운트합니다. lowerdir 순서는 위 레이어가 먼저입니다.

- 새 마운트 API: `fsopen("overlay")`, 레이어마다 `fsconfig(FSCONFIG_SET_STRING, "lowerdir+", path)`(리눅스
  6.8+), `upperdir`/`workdir`, 옵션(`userxattr` 등), `FSCONFIG_CMD_CREATE`, `fsmount`, `move_mount`.
  경로 길이 제한이 없습니다. 실패하면 fs 컨텍스트의 오류 로그를 `lastError()`에 붙입니다.
- `lowerdir+`가 없는 커널(첫 키가 `EINVAL`)이나 `legacyMount` 옵션이면 `mount(2)`의 데이터 문자열을 씁니다.
  한 페이지를 넘으면 overlay2처럼 `<root>/l/<chainID 앞 12자 이상>` → `../snapshots/<hex>/fs` 짧은 링크를
  만들고 `<root>/l`로 chdir한 상태에서 짧은 이름만으로 마운트한 뒤 원래 작업 디렉터리로 돌아갑니다(링크
  이름이 겹치면 4자씩 늘림). 그래도 넘치면 `-E2BIG`.
- rootless overlay: `userxattr` 옵션이 붙은 `SMountPlan`을 돌려줍니다. 마운트는 사용자 네임스페이스와 마운트
  네임스페이스를 가진 프로세스(리눅스 5.11+)가 `mountPlan()`이나 직접 수행합니다(테스트가 그렇게 함).
  `SMountPlan::toMountData()`는 legacy 데이터 문자열입니다.
- `mount(id[, target])`/`unmount(id)`(`EBUSY`면 `MNT_DETACH`), `remove(id)`(언마운트 후 디렉터리 삭제, 다른
  마운트를 넘어 지우지 않음).
- `overlaySupported()`는 저장소 안에서 작은 overlay를 실제로 마운트해 봅니다. `ESNAP_AUTO`는 이 결과로
  overlay와 복사 중에서 고릅니다.

### 복사 스냅샷

`flatten(image, dir)`과 `prepare(..., ESNAP_COPY)`는 모든 레이어 blob을 차례로 `EWHT_APPLY`로 한 디렉터리에
풉니다(whiteout 대상 삭제, opaque 디렉터리 비우기). 레이어마다 diffID를 검증합니다. overlay를 쓸 수 없는
환경(권한 없는 사용자, overlay 없는 커널)과 번들 내보내기에 씁니다.

### commit (`docker commit`)

overlay 컨테이너의 upper 디렉터리를 `WriteTreeArchive(..., overlayWhiteouts=true)`로 gzip 레이어로 만들고
(0/0 장치·xwhiteout → `.wh.<name>`, opaque → `.wh..wh..opq`, overlay xattr 제외), diffID와 blob 다이제스트를
훅으로 동시에 계산합니다. 부모 설정에 diffID와 history 항목(`created_by`, `author`, `comment`)을 더하고
필요하면 컨테이너 기본값(Cmd, Env, User ...)을 바꾼 새 설정과, 부모와 같은 계열(OCI 또는 Docker schema2)의
manifest를 저장한 뒤 이름을 붙입니다(이름이 없으면 dangling).

### 컨테이너 메타데이터

`containers/<id>/meta.json`: `id`, `imageId`, `imageName`, `manifestDigest`, `mode`, `rootfs`, `chainIds`,
`created`, overlay면 `plan`(`lowerDirs`, `upperDir`, `workDir`, `target`, `options`). 이 파일이 컨테이너의
GC lease 역할을 합니다(이미지가 지워져도 컨테이너가 쓰는 blob과 스냅샷은 남음).

## 5. OCI 런타임 번들 (`runtime.hpp`)

`GenerateRuntimeSpec(config, rootfs, options, out)`은 OCI runtime-spec 1.2 `config.json`을 core `CJson`으로
만듭니다(oci 모듈에 의존하지 않음).

- process: `args` = Entrypoint + Cmd(옵션 `args`가 Cmd를, `entrypoint`가 Entrypoint를 바꾸며 entrypoint를 바꾸면
  Cmd는 버림 — `docker run`과 같음). 명령이 없으면 `-EINVAL`. `env`: 기본 PATH, `HOSTNAME`, 이미지 Env, 옵션
  Env(같은 이름 교체), 없으면 `HOME`(passwd의 홈), 터미널이면 `TERM=xterm`. `cwd`: WorkingDir(없으면 `/`).
  `user`: `ResolveUser`(아래). 능력: Docker 기본 14개(CAP_CHOWN, DAC_OVERRIDE, FSETID, FOWNER, MKNOD,
  NET_RAW, SETGID, SETUID, SETFCAP, SETPCAP, NET_BIND_SERVICE, SYS_CHROOT, KILL, AUDIT_WRITE)에
  `capAdd`/`capDrop`(`ALL` 지원)을 적용해 bounding/effective/permitted에 둡니다. `noNewPrivileges` 기본 false.
- `ResolveUser`: `user`, `uid`, `user:group`, `uid:gid` 등. rootfs의 `/etc/passwd`, `/etc/group`을
  `openat2(RESOLVE_IN_ROOT)`(없으면 루트 안에서 링크를 직접 해석하는 걷기)로 읽으므로 악의적인 심볼릭 링크가
  호스트 파일을 가리킬 수 없습니다. 없는 이름은 `-ENOENT`, 없는 숫자 uid는 gid 0으로 허용(runc와 같음).
  사용자를 구성원으로 나열한 그룹을 `additionalGids`로 넣습니다(Docker의 `docker run alpine id`와 같은 결과).
- mounts: Docker 기본과 같음 — `/proc`, `/dev`(tmpfs, mode=755, size=65536k), `/dev/pts`(newinstance,
  ptmxmode=0666, mode=0620, gid=5), `/sys`(sysfs ro), `/sys/fs/cgroup`(cgroup ro), `/dev/mqueue`,
  `/dev/shm`(mode=1777, size=65536k).
- linux: pid, network, ipc, uts, mount, cgroup 네임스페이스; Docker의 masked paths(`/proc/asound`, `/proc/acpi`,
  `/proc/interrupts`, `/proc/kcore`, `/proc/keys`, `/proc/latency_stats`, `/proc/timer_list`, `/proc/timer_stats`,
  `/proc/sched_debug`, `/proc/scsi`, `/sys/firmware`, `/sys/devices/virtual/powercap`)와 read-only paths
  (`/proc/bus`, `/proc/fs`, `/proc/irq`, `/proc/sys`, `/proc/sysrq-trigger`); 장치 cgroup 규칙(전부 거부 후 null,
  zero, full, random, urandom, tty, pts, ptmx와 `c/b *:* m` 허용).
- seccomp: `DockerDefaultSeccompProfile()`은 moby `profiles/seccomp/default.json` 형식(archMap, 능력·아키텍처별
  includes/excludes, minKernel)의 JSON 문자열입니다. `SeccompProfileToOci`가 dockerd처럼 아키텍처와 능력
  집합에 맞춰 OCI `linux.seccomp`로 바꿉니다(예: CAP_SYS_ADMIN이 없으면 `mount`는 빠지고 `clone`은
  네임스페이스 플래그 마스크 조건으로, `clone3`은 ENOSYS로).
- rootless 옵션(`runc spec --rootless`와 같음): 사용자 네임스페이스와 호출자 → 0 매핑, 네트워크 네임스페이스와
  장치 cgroup 없음, `/sys`는 rbind ro, devpts에 `gid=5` 없음, cgroup 마운트 없음.
- annotations: 이미지 라벨, 그다음 image-spec 변환 규칙의 `org.opencontainers.image.{os,architecture,variant,
  author,created,stopSignal,exposedPorts}`, 볼륨 목록 `org.sbox.image.volumes`(쉼표 구분), 옵션의 주석.
- hostname: 옵션 또는 임의의 12자리 16진수.

`CreateBundle(snapshotter, image, dir, options, mode)`는 `dir/rootfs`에 루트를 만들고(복사 또는 overlay 마운트,
컨테이너 ID는 `containerId`와 주석 `org.sbox.image.container`) rootfs로 사용자를 해석한 `config.json`을
씁니다. `sbox run`이나 oci 런타임이 이 번들을 그대로 씁니다.

## 6. 아카이브 (`transfer.hpp`)

### `docker save` 내보내기

Docker 25+와 같은 모양의 tar를 만듭니다. 옛 `docker load`는 `manifest.json`만 읽고, 새 Docker와 containerd는
OCI 부분도 읽습니다.

```
oci-layout
blobs/sha256/<diffID hex>      무압축 레이어 tar (blob 다이제스트 = diffID)
blobs/sha256/<config hex>      설정 (원래 바이트 그대로 → 이미지 ID 유지)
blobs/sha256/<manifest hex>    무압축 레이어를 가리키는 OCI manifest
index.json                     io.containerd.image.name / org.opencontainers.image.ref.name 주석
manifest.json                  [{"Config":"blobs/sha256/<hex>","RepoTags":["alpine:3.20"],"Layers":["blobs/sha256/<hex>", ...]}]
repositories                   {"alpine":{"3.20":"<맨 위 레이어 diffID hex>"}}
```

- 레이어는 저장소의 압축 blob을 임시 파일로 풀어 diffID를 확인한 뒤 넣습니다. 같은 레이어는 한 번만 넣습니다.
- 태그가 있는 이름은 그 태그만, 태그 없는 저장소 이름은 그 저장소의 모든 태그, 이미지 ID는 태그 없이
  (`RepoTags: null`) 내보냅니다. 같은 이미지는 하나로 합칩니다.

### OCI 아카이브 내보내기

저장소에 있는 그대로의 blob(압축 레이어 포함)과 `index.json`(두 주석), `oci-layout`의 tar입니다.

### 가져오기 (`LoadImageArchive`)

압축(gzip/zstd)된 아카이브도 받습니다. 먼저 `ingest/load-<rand>/`에 안전하게(소유자 무시, 장치·xattr 없이,
경로 탈출 차단) 풀고 나서 판별합니다.

- `manifest.json`이 있으면 Docker 형식. 항목마다 설정을 저장하고, 레이어 파일(무압축 또는 gzip/zstd, 고전
  형식 `<id>/layer.tar`도 됨)의 다이제스트와 diffID를 계산해 설정의 `diff_ids`와 비교합니다. 레이어 blob은 파일
  그대로 저장하고(미디어 타입은 압축에 맞춰 OCI `tar`, `tar+gzip`, `tar+zstd`) diffID를 기록합니다. 같은
  아카이브의 `index.json`에 정확히 이 blob들을 가리키는 manifest가 있으면 그 바이트를 재사용해 manifest
  다이제스트도 유지하고, 없으면 OCI manifest를 새로 만듭니다. `RepoTags`가 없으면 dangling으로 남깁니다.
- `oci-layout` + `index.json`이면 OCI 형식. 모든 blob의 다이제스트를 확인하고 옮깁니다. 중첩 index는 플랫폼을
  골라 따라갑니다. 이름은 `io.containerd.image.name`, 없으면 전체 참조 모양의 `ref.name`, 태그만 있으면
  `SLoadOptions::name`과 합칩니다.
- `repositories`만 있는 1.10 이전 형식은 `-ENOTSUP`, 그 밖은 `-EINVAL`.

## 7. GC와 rmi (`gc.hpp`)

`CollectGarbage`는 저장소 잠금 아래에서 mark and sweep을 합니다.

- 루트: index.json의 모든 항목(manifest, 하위 index의 저장된 manifest, 설정, 레이어, 설정의 diffID에서 계산한
  chainID 스냅샷, RepoDigest가 가리키는 index blob), 컨테이너 메타데이터(이미지 manifest와 `chainIds`), 살아 있는
  lease.
- 표시되지 않은 blob과 스냅샷을 지우고, 1시간 지난 `snapshots/tmp-*`, `rm-*`, 대상이 사라진 `l/` 링크, 잠기지
  않은 오래된 ingest(기본 24시간), 남은 overlay 프로브 디렉터리를 정리하며, `db.json`의 해당 기록도 지웁니다.
- `pruneDangling`(`docker image prune`): 태그 없고 컨테이너가 쓰지 않는 이미지를 먼저 이름 목록에서 뺍니다.
  `pruneUnused`(`prune -a`): 컨테이너가 쓰지 않는 모든 이미지. `dryRun`은 지울 목록만 계산합니다.

`RemoveImage`는 `docker rmi`와 같은 의미입니다.

- 이름(태그/다이제스트)으로 지울 때 그 이미지의 다른 태그가 남으면 이름만 뗍니다(Untagged).
- 마지막 태그(또는 ID)면 그 이미지를 가리키는 모든 항목(RepoDigests, dangling 포함)을 지우고 GC로 blob과
  스냅샷을 회수합니다(Deleted).
- ID로 지우는데 태그가 둘 이상이면 `-EEXIST`("referenced in multiple repositories"), 컨테이너 루트가 쓰는
  이미지는 `-EBUSY`. `force`면 진행하되 컨테이너가 쓰는 blob·스냅샷은 GC가 남깁니다.

## 8. CLI (`sbox-image`)

```
sbox-image [--root DIR] [--json] [--platform OS/ARCH[/VAR]] [--registry-mirror URL] [--insecure-registry HOST]
           [--plain-http HOST] [--certs-dir DIR] [--docker-config FILE] [--snapshotter overlay|copy|auto] [-q] <명령>

pull [--no-unpack] IMAGE                  push [--chunk-size N] IMAGE [TARGET]
images|ls [--digests]                     inspect IMAGE...          tag SOURCE TARGET
rmi [-f] IMAGE...                         save [-o FILE] [--format docker|oci] IMAGE...
load [-i FILE] [--name NAME]              bundle [옵션] IMAGE DIR [-- ARGS...]
mount [--id ID] IMAGE [TARGET]            umount ID      rm ID      ps
commit [--author A] [--message M] ID [IMAGE]                        prune [-a] [--dry-run]
tags REPOSITORY                           snapshots
```

- 프록시는 항상 환경 변수(`HTTPS_PROXY`, `NO_PROXY`)를 따릅니다.
- pull 진행은 Docker처럼 레이어별 한 줄(`Downloading`, `Download complete`, `Pull complete`)을 stderr에 씁니다.
- `--json`은 각 명령의 결과를 JSON으로 출력합니다. `inspect`는 항상 `docker inspect`와 비슷한 JSON입니다.
- `bundle` 옵션: `--user`, `--hostname`, `--entrypoint`, `--env K=V`, `--cap-add`, `--cap-drop`, `--workdir`, `--tty`,
  `--read-only`, `--rootless`(권한 없는 실행자면 자동), `--no-seccomp`, `--no-new-privileges`, `--` 뒤는 Cmd.
- `save`는 터미널로 쓰지 않으며 `load`도 터미널에서 읽지 않습니다(Docker와 같음).

## 9. 사용하는 커널 인터페이스

| 인터페이스 | 용도 |
|---|---|
| `fsopen`, `fsconfig`(`lowerdir+`, 6.8+), `fsmount`, `move_mount` | overlay 마운트(경로 길이 무제한) |
| `mount(2)` overlay, `chdir`/`fchdir`, 심볼릭 링크 | legacy 마운트와 페이지 크기 대체 경로 |
| `umount2`(`MNT_DETACH` 대체) | 언마운트 |
| `trusted.overlay.*` / `user.overlay.*` xattr, `mknod`(0/0) | whiteout과 opaque 디렉터리(archive 모듈 경유) |
| overlayfs `userxattr`(5.11+), xwhiteout(6.7+) | rootless overlay |
| `flock` | 저장소 메타데이터 잠금, ingest·lease 소유 |
| `openat2(RESOLVE_IN_ROOT \| RESOLVE_NO_MAGICLINKS)` | rootfs 안의 `/etc/passwd`, `/etc/group` 읽기 |
| `rename`, `fsync`, `link` | 원자적 blob/스냅샷 반영, load 시 레이어 옮기기 |
| `getrandom` | 임시 이름, 컨테이너 ID, hostname |
| `uname` | 호스트 플랫폼, seccomp `minKernel` |

## 10. 테스트

`ctest --test-dir build -L image`(8개 실행 파일). 픽스처는 모두 테스트 안에서 archive 모듈로 만듭니다.

- `reference`: distribution/reference와 normalize 테스트의 사례(엄격 파싱 40여 개, 정규화 25개, IPv6 도메인,
  태그 길이, 이름 길이 255, 대문자, 64자리 16진수), ParseDockerRef 규칙, 다이제스트 검증과 SHA-256/512 알려진 값,
  chainID 계산, 플랫폼 정규화/점수/선택(attestation 제외), manifest/설정 왕복과 분류.
- `store`: OCI 레이아웃 형식(oci-layout, index.json 주석), 재열기, 해석 순서, 태그 이동 시 dangling,
  모호한 짧은 ID, blob 검증·손상 감지, 이름 있는 ingest의 `-EBUSY`와 재개, lease와 낡은 lease 정리.
- `registry`: 테스트 안의 레지스트리(http 서버: Bearer 챌린지 + 토큰 엔드포인트, `127.0.0.2`의 CDN으로 blob
  307 리다이렉트, Range, 업로드/마운트/태그 목록 페이지네이션)로 pull(HTTPS 시도 후 HTTP 대체, CDN에
  Authorization이 새지 않음, 재 pull은 다운로드 0), 다이제스트 pull, 없는 태그, 플랫폼 선택(arm64, arm/v7,
  없는 플랫폼), schema 1 거부, 중간에 끊긴 다운로드의 Range 재개, 손상 blob 거부, config.json Basic 자격 증명과
  잘못된 자격 증명, 미러 우선과 대체, push(마운트, 단일, 1000바이트 청크, 다시 pull), config.json 형식,
  그리고 pull → 스냅샷 → overlay 마운트(root) → whiteout 확인까지의 종단 간 시험.
- `snapshot`: overlay whiteout 형식의 스냅샷(0/0 장치, trusted opaque), 한 번만 풀기, diffID 불일치 거부, 복사
  스냅샷, overlay 루트에서 변경 → commit → 새 이미지를 펼쳐 확인(새 마운트 API와 legacy 둘 다), 70개 레이어의
  legacy 마운트(짧은 링크 + chdir), 사용자 네임스페이스 안의 rootless overlay(`userxattr`, xwhiteout; fork한
  자식이 pidfd로 기다려짐).
- `transfer`: docker save 내용 검사(manifest.json, 무압축 레이어 = diffID, repositories, 저장소 이름/ID 선택),
  docker load 왕복(이미지 ID와 manifest 다이제스트 유지), gzip 압축 아카이브, 손으로 만든 고전 형식
  (`<id>/layer.tar`, gzip 레이어 섞임) 로드, diffID 불일치와 경로 탈출 거부, OCI 아카이브 왕복, 태그만 있는
  ref.name + 중첩 index 로드, 손상 blob 거부.
- `gc`: rmi 의미(태그 떼기, 마지막 태그 삭제, 공유 레이어 유지, 여러 저장소 충돌, 컨테이너 충돌과 force), GC의
  dry run, 고아 blob, lease 보호와 해제 후 회수, dangling prune과 스냅샷 회수, prune -a.
- `runtime`: 사용자/그룹 해석(이름, 숫자, 그룹 지정, 보조 그룹, 없는 이름, rootfs 밖을 가리키는 링크), 이미지
  설정 → 런타임 명세(args, env 병합, cwd, 능력, 마운트, 주석, 네임스페이스, masked/readonly, 장치, seccomp 변환),
  entrypoint/능력/rootless 재정의, seccomp 아키텍처별 변환(arm64, s390x 인자 순서), 번들 생성(복사, overlay).
- `network`: `SBOX_TEST_NETWORK=1`일 때만 Docker Hub에서 `alpine:latest`와 `busybox`를 실제로 받아 스냅샷과
  펼친 루트를 확인합니다(HTTPS_PROXY와 SSL_CERT_FILE을 따름).

루트 권한이나 overlay가 필요한 사례는 먼저 확인하고 없으면 `MESSAGE`를 남기고 건너뜁니다. 모든 테스트는
`mkdtemp`(/var/tmp) 경로와 포트 0을 써서 병렬로 안전합니다.

## 제한 사항

- 자격 증명 도우미(`credsStore`, `credHelpers`)는 실행하지 않습니다. `auths`에 들어 있는 값만 씁니다.
- insecure/plain HTTP 레지스트리는 `host[:port]` 정확히 일치로만 지정합니다(Docker의 CIDR 형식 없음). 루프백은
  기본으로 insecure입니다.
- Docker manifest schema 1은 지원하지 않습니다(`-EPROTONOSUPPORT`). foreign/non-distributable 레이어의 `urls`는
  쓰지 않고 레지스트리에서 받습니다.
- push는 플랫폼 manifest 하나만 올립니다(manifest list/index를 만들어 올리지 않음). 다른 레지스트리로부터의
  마운트는 하지 않습니다. 청크 업로드가 중간에 실패하면 처음부터 다시 해야 합니다.
- commit과 새 레이어는 gzip만 만듭니다(zstd 압축 없음). xz/bzip2 레이어(아주 오래된 이미지)는 읽지 못합니다.
- 복사 방식 컨테이너는 commit할 수 없습니다(변경 집합이 없음).
- 이미지의 `Volumes`는 주석으로만 기록하고 익명 볼륨을 만들지 않습니다. `Healthcheck`, `OnBuild`, `Shell`은
  해석하지 않습니다(설정 원문에는 남음).
- rootless 추출은 uid/gid를 실행 사용자로 둡니다(subuid 범위로의 id 이동은 하지 않음). rootless overlay
  마운트는 호출자가 사용자·마운트 네임스페이스 안에 있어야 하며, CLI를 권한 없이 실행하면 복사 방식으로
  바뀝니다.
- 이미지 크기(`Size`)는 압축된 레이어 blob 크기의 합입니다(Docker는 풀린 크기를 보여 줌).
- 추출과 압축 해제, 파일 쓰기는 동기 연산이라 이벤트 루프 스레드를 잠시 점유합니다. 다운로드 자체는 여러
  코루틴이 동시에 진행합니다.
- legacy overlay 마운트의 대체 경로는 마운트하는 동안 프로세스의 작업 디렉터리를 바꿉니다(libsbox는 스레드를
  쓰지 않으므로 안전).
- seccomp 기본 프로필은 moby의 기본 프로필을 이 모듈 안에 옮겨 둔 것이며, 이후 moby에서 바뀐 항목은 따로
  반영해야 합니다.
- 서명(cosign, Notary)과 attestation은 검사하지 않습니다(플랫폼 선택에서 건너뛸 뿐).
