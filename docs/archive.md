# archive 모듈

tar 아카이브와 압축 형식(DEFLATE/zlib/gzip, zstd 해제)을 외부 라이브러리 없이 직접 구현한
모듈입니다. 네임스페이스는 `sbox::archive`, 헤더는 `modules/archive/include/sbox/archive/`,
CMake 타깃은 `sbox::archive`(의존: `core`)입니다.

주 사용처:

- **image**: OCI/Docker 레이어 풀기(tar, tar+gzip, tar+zstd), 레이어 tar와 `docker save` 아카이브
  만들기, 컨테이너 upper 디렉터리를 레이어로 커밋하기. blob 다이제스트(sha256)와 diffID는
  파이프라인 훅으로 한 번에 계산합니다(SHA-256 자체는 image 모듈이 libcertpp로 계산).
- **vol**: 볼륨 백업(tar.gz)과 복원.

CRC-32, Adler-32, XXH64는 암호 기능이 아닌 오류 검출용 체크섬이라 이 모듈에 직접 구현했습니다.

## 헤더 한눈에 보기

| 헤더 | 내용 |
|---|---|
| `checksum.hpp` | `CCrc32`(slice-by-8), `CAdler32`, `CXxHash64` |
| `codec.hpp` | `ICodec`(증분 상태 기계), `ECompression`, `CODEC_END`, `DetectCompression`, `CreateDecoder`, `CreateEncoder`, `CPassThrough` |
| `deflate.hpp` | `CInflater`(RFC 1951/1950/1952 해제), `CDeflater`(압축, 레벨 0~9), `EDeflateFormat`, `SGzipHeader` |
| `zstd.hpp` | `CZstdDecoder`(RFC 8878 해제) |
| `stream.hpp` | `IByteSource`/`IByteSink`, fd·메모리·벡터 어댑터, 탭(다이제스트 훅), 코덱 어댑터, `CDecodeStream`/`CEncodeStream`(IStream), `Pump`/`PumpStreamToSink`/`PumpSourceToStream` |
| `tar.hpp` | `STarEntry`, `CTarParser`(증분 파서), `ITarHandler`/`CTarSink`(push), `CTarReader`(pull), `CTarWriter` |
| `extract.hpp` | `CExtractor`(안전한 풀기), `SExtractOptions`, whiteout 정책, `ExtractArchive`/`ExtractArchiveAsync`, `CleanArchivePath` |
| `tree.hpp` | `WriteTree`, `WriteTreeArchive`, `CTreeTarSource`(디렉터리 → tar, overlay whiteout 역변환) |

결과 코드는 libsbox 규칙대로 `SBOX_OK` 또는 음수 errno입니다. 이 모듈에서 자주 쓰는 값:

| 값 | 의미 |
|---|---|
| `CODEC_END` (= 1) | 코덱 스트림이 정상적으로 끝남 |
| `-EBADMSG` | 손상된 데이터(체크섬 불일치, 잘못된 Huffman 코드, 잘못된 tar 헤더/PAX 레코드) |
| `-ENODATA` | 입력이 스트림/엔트리 중간에서 끝남(잘림) |
| `-EFBIG` | 한도 초과(zstd 창 크기, PAX/긴 이름 크기) |
| `-ENOTSUP` | 지원하지 않는 기능(zstd 사전, zlib 사전, sparse tar, zstd 압축) |
| `-EXDEV` | 아카이브 경로가 루트 밖으로 나감(`..`) |
| `-EOVERFLOW` | id 이동 후 uid/gid 범위 초과, strict ustar로 표현 불가한 숫자 |

## 코덱 (`codec.hpp`)

`ICodec::process(in, consumed, out, produced, finish)`는 zlib의 `z_stream`과 같은 동기 증분 상태
기계입니다. 블로킹하지 않고, 입력/출력을 아무 크기로 나눠 넣어도 됩니다. 입력이 끝나면 이후 모든
호출에 `finish = true`를 주고 `CODEC_END`가 나올 때까지 부릅니다. 오류는 `reset()` 전까지
유지됩니다(sticky).

- `CreateDecoder(ECOMP_AUTO)`: 첫 바이트로 gzip(`1f 8b 08`), zstd(`28 b5 2f fd` 또는 skippable
  frame), 그 외는 평문으로 판단합니다. zlib 헤더는 2바이트뿐이라 우연히 일치하기 쉬워(예: 이름이
  `x^`로 시작하는 tar) 자동 판별하지 않습니다.
- `CreateEncoder`: gzip/zlib/raw deflate/none. zstd 압축은 없습니다(`nullptr`).
- `SDecoderOptions`: `zstdMaxWindow`(기본 128 MiB), `gzipMultiMember`(기본 true).

### DEFLATE 해제 (`CInflater`)

- stored/fixed/dynamic 블록 전부. 리터럴/길이는 10비트, 거리는 8비트 루트 테이블 + 서브 테이블로
  한 번의 조회에 심볼, 추가 비트 수, 기준값을 얻습니다.
- 비트 버퍼는 64비트이고, 입력이 8바이트 이상 남아 있으면 분기 없는 8바이트 리필을 씁니다. 입력이
  부족한 구간에서는 심볼 단위로 스냅샷을 잡고, 심볼 하나를 끝까지 디코드할 비트가 없으면 스냅샷으로
  되돌린 뒤 입력을 기다립니다. 따라서 입력을 1바이트씩 넣어도 결과가 같습니다.
- 출력은 256 KiB 창 버퍼에 쓴 뒤 호출자 버퍼로 복사하고, 창이 차면 마지막 32 KiB만 남기고 앞으로
  옮깁니다. 메모리는 디코더당 약 300 KiB로 고정이며 수 GB 레이어도 스트리밍으로 처리합니다.
- 허프만 코드 검증은 zlib 규칙을 따릅니다: 과다 할당(over-subscribed) 코드는 거부, 불완전 코드는
  길이 1짜리 코드 하나뿐일 때만 허용, 코드 길이 코드는 반드시 완전해야 함, EOB(256) 코드 필수.
  거리가 현재 멤버의 출력보다 멀면 거부합니다.
- gzip: FEXTRA/FNAME/FCOMMENT/FHCRC 헤더 필드(각 1 MiB 한도), 멤버마다 CRC-32와 ISIZE 검사,
  이어 붙인 멤버(multi-member)를 하나의 스트림으로 해제(gzip(1)과 같음). 마지막 멤버 뒤에 다른
  바이트가 오면 Go의 `gzip.Reader`처럼 오류(`-EBADMSG`)입니다.
- zlib: 헤더 검사(CM=8, CINFO≤7, FCHECK), Adler-32 검사. 사전(FDICT)은 `-ENOTSUP`.
- raw/zlib 스트림이 끝난 뒤 비트 버퍼가 미리 읽은 바이트는 이번 호출의 입력이면 `consumed`에서
  돌려줍니다.

### DEFLATE 압축 (`CDeflater`)

- 32 KiB 창, 3바이트 곱셈 해시(2^15 버킷)와 해시 체인. 위치는 32비트 전역 위치로 저장해서 창을
  밀 때 해시 테이블을 고칠 필요가 없습니다. 체인의 후보는 실제 바이트 비교로 확인하고 거리가
  단조 증가하지 않으면 멈추므로, 오래된 항목은 압축률에만 영향을 줍니다.
- 레벨별 매개변수는 zlib과 같습니다: 1~3 탐욕(greedy), 4~9 지연(lazy) 매칭,
  good/lazy/nice/chain 값도 zlib 표를 씁니다. 매치 비교는 8바이트 XOR + ctz.
- 블록당 최대 16383 심볼. 블록마다 stored/fixed/dynamic의 비트 수를 계산해서 가장 작은 것을
  고릅니다(압축 불가능한 데이터는 stored로 나가 64 KiB당 몇 바이트만 늘어남).
- 허프만 길이는 두 큐 방식으로 만든 뒤 zlib의 길이 제한(리터럴/거리 15비트, 코드 길이 코드 7비트)
  방법으로 줄입니다. 깊이 제한을 넘는 모든 노드를 overflow로 세므로 결과 코드는 항상 완전합니다.
- 레벨 0은 stored 블록만 씁니다.
- gzip 헤더에 이름과 mtime을 넣을 수 있습니다(`gzipHeader`). 기본 mtime은 0이라 결과가 결정적입니다.
- sync flush(`Z_SYNC_FLUSH`)는 없습니다. 스트림은 `finish`로만 끝냅니다.

### zstd 해제 (`CZstdDecoder`)

- 프레임 헤더(Single_Segment, Window_Descriptor, FCS 1/2/4/8바이트, Dictionary_ID), raw/RLE/
  compressed 블록, Block_Maximum_Size(창과 128 KiB 중 작은 값) 검사.
- 리터럴: raw/RLE/Huffman/treeless, 스트림 1개 또는 4개(점프 테이블). Huffman 트리는 직접 가중치
  (4비트) 또는 FSE 압축 가중치(정확도 ≤ 6, 두 상태 교차 디코드). 최대 11비트 단일 심볼 테이블.
- 시퀀스: LL/OF/ML 테이블의 predefined/RLE/FSE/repeat 모드, FSE 정규화 카운트 디코드와 테이블
  펼치기(RFC 8878 4.1.1), 반복 오프셋 3개(리터럴 길이 0일 때의 이동 포함).
- 출력 창: 창 크기 + 블록 하나 + 여유분 크기의 버퍼에 블록 단위로 씁니다. 버퍼 끝에 닿으면 처음으로
  돌아가고, 직전 구간을 "이전 세그먼트"로 두어 매치가 두 구간에 걸치면 나눠 복사합니다. 창 크기가
  128 MiB면 메모리도 약 128 MiB입니다(`maxWindow`로 상한 지정, 최대 2 GiB). 오프셋은 프레임의 지금까지
  출력과 창 크기를 넘으면 거부합니다.
- 프레임 끝에서 XXH64 content checksum(하위 32비트)과 Frame_Content_Size를 검사합니다.
- 프레임을 이어 붙인 입력과 skippable frame(`0x184D2A5?`)을 처리합니다. `CODEC_END`는 `finish`가
  주어지고 프레임 경계일 때만 나옵니다. 빈 입력도 0 프레임으로 정상 종료입니다.
- 사전(Dictionary_ID ≠ 0)은 `-ENOTSUP`, 예약 비트나 예약 블록 타입은 `-EBADMSG`입니다.
- 압축은 구현하지 않았습니다. Docker/OCI에서 zstd 레이어를 *만들* 필요가 생기면 별도 작업입니다.

## 스트림 배관 (`stream.hpp`)

동기 파이프라인은 `IByteSource`(pull)와 `IByteSink`(push) 두 인터페이스로 만듭니다.

| 클래스 | 역할 |
|---|---|
| `CFdSource` / `CFdSink` | 블로킹 디스크립터(일반 파일)에 read/write. 소유하지 않음 |
| `CMemorySource` / `CVectorSink` | 메모리 |
| `CTapSource` / `CTapSink` | 지나가는 바이트를 `FByteHook`으로 보여 줌(다이제스트) |
| `CCodecSource` | 읽으면 상류를 읽어 코덱을 통과시킴(파일 해제, tar 생산자 압축) |
| `CCodecSink` | 쓰면 코덱을 통과시켜 하류로 씀. `finish()`가 트레일러와 완결성 검사 |
| `CDecodeStream` | `IStream`을 감싸 `recv()`로 해제된 바이트를 줌(원본 바이트 훅 가능) |
| `CEncodeStream` | `IStream`을 감싸 `send()`를 압축해 보냄. 끝에 `co_await finish()` |

`Pump(source, sink)`는 동기 복사, `PumpStreamToSink(IStream, sink)`와
`PumpSourceToStream(source, IStream)`은 core 이벤트 루프의 코루틴입니다.

대표 파이프라인:

```cpp
// 소켓 -> gzip/zstd 해제 -> tar -> 추출 (비동기), blob/diffID 다이제스트 동시 계산
SPipelineHooks hooks;
hooks.compressed = [&](const SReadOnlyByteSpan& s) { blobSha.update(s); };
hooks.uncompressed = [&](const SReadOnlyByteSpan& s) { diffSha.update(s); };
int32_t rc = co_await ExtractArchiveAsync(socket, "/var/lib/x/layer", opts, ECOMP_AUTO, hooks);

// 디렉터리 -> tar -> gzip -> 파일 (동기)
CFdSink out(fd);
int32_t rc = WriteTreeArchive("/data/vol", out, ECOMP_GZIP, 6, STreeOptions(), hooks);

// 디렉터리 -> tar -> gzip -> 소켓 (비동기, pull 방식)
CTreeTarSource tree("/data/vol");
CCodecSource gz(CreateEncoder(ECOMP_GZIP), tree);
int32_t rc = co_await PumpSourceToStream(gz, socket);
```

동기 단계(코덱, 파일시스템 연산)는 이벤트 루프 스레드에서 그대로 돌아갑니다. 일반 파일은 epoll로
기다릴 수 없으므로 디스크 I/O는 블로킹이며, 큰 추출은 `recv` 사이에 루프를 점유합니다.

## tar (`tar.hpp`)

### 읽기

`CTarParser::next(in, consumed, event, data)`가 핵심입니다. 입력을 받아 `ETEV_ENTRY`,
`ETEV_DATA`(입력의 일부를 가리키는 span, 복사 없음), `ETEV_ENTRY_END`, `ETEV_END`,
`ETEV_NEED_INPUT` 이벤트를 하나씩 돌려줍니다. 그 위에:

- `CTarSink`(push): `IByteSink`로 받아 `ITarHandler`(`onEntry`/`onData`/`onEntryEnd`/`onEnd`)에
  전달합니다. `finish()`에서 엔트리 중간에 끝났으면 `-ENODATA`. 종료 표시(0 블록 두 개)가 없어도
  엔트리 경계에서 끝나면 GNU tar처럼 허용합니다.
- `CTarReader`(pull): `next(entry)`(1/0/오류)와 `read(buffer)`. 읽지 않은 데이터는 건너뜁니다.

지원 형식:

- ustar(`prefix` + `name`), v7(매직 없음, 끝이 `/`인 일반 엔트리는 디렉터리), GNU(`ustar  `).
- 숫자: 8진수(앞뒤 공백/NUL 허용), GNU base-256(음수 포함). 체크섬은 unsigned/signed 합 모두 인정.
- PAX `x`(엔트리별)와 `g`(전역) 레코드: `path`, `linkpath`, `size`, `uid`, `gid`, `uname`, `gname`,
  `mtime`/`atime`/`ctime`(소수 초, 음수), `SCHILY.xattr.*`(값은 바이너리 그대로),
  `LIBARCHIVE.xattr.*`(이름 URL 인코딩, 값 base64), `SCHILY.devmajor/devminor`. 빈 값은 키 삭제
  (헤더 값으로 복귀). 해석하지 않은 레코드는 `STarEntry::paxRecords`에 남습니다.
- GNU `L`/`K` 긴 이름/링크, `V`(볼륨 레이블, 무시), `D`(dumpdir: 디렉터리로 보고 데이터는 건너뜀).
- 엔트리 타입: 일반('0', '\0', '7', 모르는 타입), 하드링크, 심볼릭 링크, 문자/블록 장치, 디렉터리,
  FIFO. Go `archive/tar`처럼 일반 파일 외의 타입은 데이터 블록이 없는 것으로 봅니다.
- 한도: PAX 헤더와 긴 이름은 기본 1 MiB(`STarLimits::maxMetaSize`), 넘으면 `-EFBIG`.
- sparse(`S`, `GNU.sparse.*`)와 multi-volume(`M`, `N`)은 `-ENOTSUP`.

### 쓰기

`CTarWriter(sink, format)`: `writeHeader(entry)` 뒤 일반 파일이면 정확히 `entry.size` 바이트를
`writeData()`로 쓰고, 마지막에 `finish()`(0 블록 두 개 + `sink.finish()`). 패딩은 자동입니다.
레코드(10240바이트) 단위 패딩은 하지 않습니다(Go/Docker와 같음).

| 형식 | 표현할 수 없을 때 |
|---|---|
| `ETFMT_PAX`(기본) | ustar 헤더 + 필요한 PAX 레코드(`path`, `linkpath`, `size`, `uid`, `gid`, `uname`, `gname`, 소수 `mtime`, `atime`, `ctime`, `SCHILY.xattr.*`). 긴 경로는 먼저 prefix 분할을 시도. 장치 번호는 base-256 |
| `ETFMT_GNU` | `L`/`K` 엔트리와 base-256. 긴 uname은 잘림. xattr은 PAX 레코드로 씀 |
| `ETFMT_USTAR` | `-ENAMETOOLONG`/`-EOVERFLOW`/`-ENOTSUP` |

PAX 헤더 엔트리 이름은 Go와 같이 `<dir>/PaxHeaders.0/<name>`입니다.

## 안전한 추출 (`extract.hpp`)

`CExtractor`는 `ITarHandler`입니다. `ExtractArchive`(동기)와 `ExtractArchiveAsync`(코루틴)가
해제 → tar → 추출 사슬을 만들어 줍니다.

### 경로 처리 (보안 모델)

1. 엔트리 경로를 `CleanArchivePath`로 어휘적으로 정리합니다: 빈 성분과 `.` 제거, 앞의 `/` 제거
   (절대 경로는 루트 기준), `..` 처리. `..`가 루트를 벗어나면 `-EXDEV`(또는 `skipUnsafe`면 알림 후
   건너뜀). NUL이 들어 있으면 `-EINVAL`. 하드링크 대상도 같은 규칙입니다.
2. 부모 디렉터리는 `openat2(root, parent, O_PATH|O_DIRECTORY, RESOLVE_IN_ROOT |
   RESOLVE_NO_MAGICLINKS)`로 엽니다. 중간 심볼릭 링크는 루트를 `/`로 보고 해석되므로 절대 링크든
   `../../..` 링크든 루트 밖으로 나가지 못합니다(chroot 안에서 푸는 것과 같은 의미).
3. openat2가 없으면(`ENOSYS`, 오래된 seccomp의 `EPERM`) 성분마다 `openat(O_PATH|O_NOFOLLOW)`로
   걷고, 심볼릭 링크는 `readlinkat`으로 직접 읽어 같은 규칙으로 해석합니다(링크 40개 한도,
   `..`는 해석된 디렉터리 스택에서 pop). `noOpenat2` 옵션으로 강제할 수 있고 테스트는 두 경로를 모두
   돌립니다.
4. 마지막 성분은 절대 따라가지 않습니다. 이미 있는 것은 지우고(디렉터리 엔트리가 기존 디렉터리를
   만나는 경우만 유지) `O_CREAT|O_EXCL|O_NOFOLLOW`, `mkdirat`, `symlinkat`, `mknodat`, `linkat`로
   새로 만듭니다. 그래서 앞 엔트리가 심어 둔 심볼릭 링크로 뒤 엔트리의 쓰기를 밖으로 돌릴 수 없습니다
   (symlink-then-file 기법 차단).
5. 하드링크는 대상 부모도 루트 안에서 해석하고 `linkat(..., 0)`(대상의 마지막 링크를 따라가지 않음)
   으로 만듭니다. 대상이 디렉터리면 `-EPERM`, 없으면 `-ENOENT`.
6. 지우기(`removeTreeAt`)는 디스크립터 기준으로 `unlinkat`/`O_NOFOLLOW` 재귀이며 링크를 따라가지
   않습니다.
7. 부모 디렉터리 디스크립터 캐시는 무언가를 지우거나 일반 파일 외의 엔트리를 만들 때마다 버립니다
   (디렉터리가 링크로 바뀐 뒤 옛 디렉터리에 쓰는 일을 막음).

### 메타데이터

- 소유자: `EOWN_AUTO`(euid 0이면 chown, 거부되면 알림만), `EOWN_PRESERVE`(실패는 오류),
  `EOWN_IGNORE`. `uidShift`/`gidShift`를 더하며(rootless, userns 재매핑 저장소) 결과가
  0..0xFFFFFFFE 밖이면 `-EOVERFLOW`. 숫자 id만 쓰고 uname/gname은 무시합니다(Docker와 같음).
- 순서: chown → chmod(chown이 setuid/setgid를 지우므로 뒤에) → xattr(`security.capability`는
  chown이 지우므로 그 뒤) → 시간(`futimens`/`utimensat(AT_SYMLINK_NOFOLLOW)`, atime이 없으면 mtime).
- 디렉터리의 mode와 시간은 `onEnd()`에서 마지막 엔트리 기준으로 한꺼번에 적용합니다. 읽기 전용
  디렉터리가 자기 내용 쓰기를 막지 않고, 자식 생성으로 바뀐 mtime도 복원됩니다. 루트 엔트리(`./`)는
  루트 디렉터리 자체의 메타데이터로 씁니다.
- 암묵적으로 만드는 부모 디렉터리는 0755, 소유자는 (0+shift, 0+shift)입니다.
- xattr: 파일과 디렉터리는 `fsetxattr`, 그 외(링크, 장치)는 `setxattrat(AT_SYMLINK_NOFOLLOW)`
  (Linux 6.13+), 없으면 `/proc/self/fd/<부모>/<이름>`에 `lsetxattr`. 실패는 기본적으로 알림
  (`xattrErrorsFatal`로 오류화).
- 장치: `mknodat`가 `EPERM`/`EACCES`이면 건너뛰고 `EXN_DEVICE_SKIPPED` 알림. `devices = false`면
  항상 건너뜀. FIFO는 항상 만듭니다.

### 레이어 whiteout (`EWhiteoutMode`)

| 모드 | `.wh.<name>` | `.wh..wh..opq` |
|---|---|---|
| `EWHT_NONE` | 그대로 일반 파일로 추출 | 그대로 추출 |
| `EWHT_OVERLAY` | `<name>`을 0/0 문자 장치로 만들고 헤더의 uid/gid(이동 적용) | 디렉터리에 `trusted.overlay.opaque=y` |
| `EWHT_OVERLAY_USERXATTR` | 빈 일반 파일 + `user.overlay.whiteout`, 부모에 `user.overlay.opaque=x`(이미 `y`가 아니면) | `user.overlay.opaque=y` |
| `EWHT_APPLY` | 이미 있는 `<name>` 트리를 지움 | 이 레이어가 풀지 않은 디렉터리 내용을 지움 |

- `EWHT_OVERLAY`는 레이어별 디렉터리(overlayfs lowerdir)용이며 mknod 권한이 필요합니다.
- `EWHT_OVERLAY_USERXATTR`는 권한 없는 overlayfs(`userxattr` 마운트 옵션)용입니다. 커널은 6.7부터
  "xwhiteout"(빈 파일 + `overlay.whiteout`, 부모 `overlay.opaque=x`)을 인식합니다.
- `EWHT_APPLY`는 평평한 디렉터리에 레이어를 차례로 덮어쓸 때(볼륨 복원, export) 씁니다. opaque
  처리는 Docker처럼 이 레이어에서 이미 풀린 경로(와 그 부모들)를 남기고 나머지를 지웁니다.
- `.wh..wh.plnk` 같은 aufs 메타데이터는 무시하고 알립니다.

## 디렉터리 → tar (`tree.hpp`)

- `WriteTree(root, writer, options)`: 이름순(바이트 비교)으로 걸어 결정적인 출력을 만듭니다.
  링크 수가 2 이상인 일반 파일은 (dev, ino)로 묶어 두 번째부터 하드링크 엔트리로 씁니다. 심볼릭
  링크는 따라가지 않습니다. 소켓은 건너뛰고 알립니다.
- `WriteTreeArchive(root, sink, compression, level, options, hooks)`: 완성된(압축) 아카이브를
  sink에 쓰고 `finish`까지 합니다. 훅으로 tar 바이트(diffID)와 압축 바이트(blob)를 동시에 봅니다.
- `CTreeTarSource`: 같은 걷기를 pull 방식으로 합니다. 한 번의 `read()`가 헤더 하나 또는 파일 데이터
  64 KiB 정도만 진행하므로 메모리가 일정합니다.
- 옵션: `prefix`(예: `layer/`), `includeRoot`, `xattrs`(전부 `SCHILY.xattr.*`로 기록),
  `preciseTimes`(기본은 Docker처럼 초 단위로 자름), `uidShift`/`gidShift`(디스크 id에서 뺌, 음수가
  되면 `-EOVERFLOW`), `format`, `filter`(false면 그 경로와 하위를 건너뜀), `notice`.
- `overlayWhiteouts = true`면 overlayfs upper 디렉터리를 레이어로 바꿉니다: 0/0 문자 장치와
  xwhiteout 파일 → `.wh.<name>`(0600, 크기 0), `overlay.opaque=y` 디렉터리 → 디렉터리 엔트리 뒤에
  `<dir>/.wh..wh..opq`. `trusted.overlay.*`/`user.overlay.*` xattr은 기록하지 않습니다.
- 읽는 중에 파일이 줄어들면 이미 헤더에 적은 크기까지 0으로 채웁니다(아카이브는 항상 유효).

## 사용하는 커널 인터페이스

`openat2`(RESOLVE_IN_ROOT, RESOLVE_NO_MAGICLINKS), `openat`(O_PATH, O_NOFOLLOW), `readlinkat`(빈 경로),
`fstatat`(AT_SYMLINK_NOFOLLOW), `mkdirat`, `mknodat`, `symlinkat`, `linkat`, `unlinkat`,
`fchownat`/`fchown`, `fchmodat`/`fchmod`, `utimensat`/`futimens`, `fsetxattr`/`fgetxattr`,
`setxattrat`/`getxattrat`/`listxattrat`(6.13+, 없으면 `/proc/self/fd` 경로의 `l*xattr`).

## 성능

Release(-O2) 빌드, 이 개발 머신 기준(테스트가 MB/s를 MESSAGE로 출력합니다. 단언은 하지 않음):

| 작업 | 처리량 | 참고(python zlib, 같은 데이터) |
|---|---|---|
| deflate 레벨 1 / 6 / 9 | 약 125 / 17 / 3 MB/s, 압축률 0.249 / 0.179 / 0.166 | 98 / 21 / 3.7 MB/s, 0.249 / 0.179 / 0.166 |
| inflate | 약 240~320 MB/s | 200~290 MB/s |
| CRC-32 | 약 2 GB/s | |
| zstd 해제 | 텍스트 340~520 MB/s, 반복 데이터 약 1 GB/s | |

Debug 빌드는 몇 배 느립니다(테스트는 Debug에서 데이터 크기를 줄임).

## 테스트

`ctest --test-dir build -L archive`(5개 실행 파일).

- `checksum`: CRC-32/Adler-32/XXH64 알려진 값, 조각 입력 = 한 번 입력.
- `deflate`: python `zlib`/`gzip`으로 미리 만든 벡터(레벨 0/1/6/9, Z_FIXED/HUFFMAN_ONLY/RLE/FILTERED,
  wbits 9, sync/full flush, 빈 입력, 다중 멤버, 모든 헤더 필드)를 1바이트 입력·1바이트 출력 등 여러
  조각으로 해제. 레벨 0~9 × gzip 왕복(빈 입력, 1바이트, 난수, 텍스트, 0, 반복, 혼합), 피보나치
  빈도(길이 제한 검증), 손상(CRC, ISIZE, Adler, 매직, 블록 타입 3, NLEN, 과다 할당 코드, 너무 먼 거리,
  뒤 쓰레기), 모든 잘림, 무작위 비트 뒤집기 1500회(성공 0회여야 함). 시스템 `gzip`이 있으면
  상호 운용(우리 출력 → `gzip -dc`, `gzip -9`/`-1` 다중 멤버 → 우리 해제). 처리량 출력.
- `zstd`: python-zstandard로 만든 벡터(레벨 1/3/9/19/22, 다중 블록, 크기 없음, 난수(raw), 0(RLE),
  4 MiB 반복으로 창 순환, 1 KiB 창, 다중 프레임 + skippable, 16 MiB 뒤를 참조하는 32 MiB 창 프레임)를
  여러 조각으로 해제. 손으로 만든 raw/RLE/체크섬/FCS 불일치/블록 초과/예약 비트/사전 프레임. 창 한도
  (`-EFBIG`), 잘림, 무작위 손상(체크섬 있는 벡터는 성공 0회), 처리량.
- `tar`: python `tarfile`의 GNU/PAX/ustar 아카이브(긴 이름·링크, base-256 uid, PAX xattr과
  `LIBARCHIVE.xattr`, 소수 mtime, 전역 헤더, 장치, FIFO, 하드링크)를 여러 조각으로 파싱. pull 리더.
  세 형식 쓰기 왕복, 10 GiB 크기 표현, 손상(체크섬, 8진수, 잘림, sparse, 거대 PAX, 잘못된 PAX 값),
  무작위 손상 3000회, 시스템 `tar`로 우리 아카이브 풀기.
- `extract`: 모든 타입과 메타데이터, `..` 탈출(거부와 skip), 절대 경로, 절대/상대 링크를 통한 쓰기,
  symlink-then-file, symlink-then-dir, 링크를 통한 하드링크, 루트 밖 하드링크(모두 openat2와 걷기 두
  방식), apply/overlay/userxattr whiteout, id 이동과 소유자 무시, `security.capability`를 포함한 xattr,
  장치 끄기, 트리 → tar → 추출 왕복(push, pull + gzip + 다이제스트 훅, prefix/filter), overlay upper →
  `.wh.` → overlay 왕복, 손상/잘린 tar.gz, 파이프를 통한 비동기 파이프라인, `CEncodeStream`/
  `CDecodeStream`, fd 기반 동기 파이프라인.

루트 권한이나 trusted/user xattr이 필요한 경우는 먼저 확인하고 없으면 `MESSAGE`를 남기고 건너뜁니다.
픽스처는 `modules/archive/tests/fixtures/gen_fixtures.py`로 다시 만들 수 있습니다(python-zstandard 필요).
기대 평문은 C++과 파이썬이 같은 xorshift32 생성기로 만들므로 픽스처에는 압축 결과만 들어 있습니다.

## 제한 사항

- zstd 압축은 없습니다(해제만). zstd/zlib 사전, zstd 레거시(v0.x) 프레임도 지원하지 않습니다.
- xz, bzip2 압축은 지원하지 않습니다(옛 `docker save`/`docker load`의 xz/bzip2 레이어 포함).
- deflate 압축기에 sync/full flush가 없습니다.
- gzip/zstd 스트림 뒤의 쓰레기 바이트(0 패딩 포함)는 오류입니다.
- tar sparse 파일, multi-volume 아카이브, 옛 GNU `N` 엔트리는 `-ENOTSUP`. 레코드(10240바이트)
  단위 패딩은 쓰지 않습니다.
- 추출: 하드링크 엔트리의 메타데이터는 대상 inode에 다시 적용하지 않습니다. uname/gname은 무시합니다.
  ctime은 설정할 수 없습니다. 이름 있는 부모가 루트 안에서 없는 곳을 가리키는 심볼릭 링크면
  `-ENOENT`입니다(GNU tar와 같음). 오류가 나면 이미 푼 파일은 남습니다(호출자가 정리).
- `EWHT_OVERLAY`는 mknod 권한이 필요하고, `EWHT_OVERLAY_USERXATTR`의 xwhiteout은 커널 6.7 이상에서
  overlayfs가 인식합니다.
- 6.13 미만 커널에서 링크·장치의 xattr은 `/proc`이 마운트되어 있어야 합니다.
- 파일시스템 연산과 코덱은 동기입니다. 비동기 파이프라인에서도 디스크 I/O는 이벤트 루프 스레드를
  잠시 점유합니다.
- 트리 쓰기는 sparse 파일의 구멍을 0으로 읽어 그대로 씁니다. 소켓은 건너뜁니다.
