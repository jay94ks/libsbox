# 코딩 컨벤션

이 문서는 [libcertpp의 코딩 컨벤션](https://github.com/jay94ks/libcertpp/blob/main/docs/coding-conventions.ko.md)을
libsbox에 맞게 옮긴 것입니다. 원칙은 libcertpp와 같고, 아래 "libcertpp와 다른 점"에 적은 항목만
libsbox의 목표(코루틴 API, 직접 시스템 콜, 모듈형 모노레포)를 위해 바꿨습니다. 새 코드는 이 문서를
따르고, 여기서 다루지 않는 세부 사항은 libcertpp 문서를 따릅니다.

## libcertpp와 다른 점

| 항목 | libcertpp | libsbox | 이유 |
|---|---|---|---|
| 언어 표준 | C++17 | **C++20** | 공개 API가 `co_await` 기반(`TTask<T>`) |
| 최상위 네임스페이스 | `certpp` | `sbox` | |
| 헤더 가드 | `__INCLUDE_CERTPP_<PATH>_HPP__` | `__INCLUDE_SBOX_<PATH>_HPP__` | 경로는 자신이 속한 `include/` 기준 |
| 내보내기 매크로 | `CERTPP_API` (dllexport/import) | `SBOX_API` (visibility) | 리눅스 전용. 공유 빌드에서만 `__SHARED_LIBSBOX__`로 켜짐 |
| 결과 코드 | `ERetCode` 열거형 | **`int32_t`: `SBOX_OK`(0) 또는 음수 errno** | 거의 모든 동작이 시스템 콜이고, 실패한 errno가 호출자와 OCI 런타임 오류 출력에 가장 유용한 정보 |
| 디렉터리 | `include/`, `src/`, `tests/` 한 벌 | 모듈마다 `src/`, `tests/`(필수 모듈의 헤더는 루트 `include/sbox/`, 선택 모듈의 헤더는 `modules/<m>/include/sbox/<m>/`) | 모듈 단위 개발·빌드·테스트 |
| 테스트 위치 | 루트 `tests/` | `modules/<m>/tests/` | 모듈별 라벨로 `ctest -L <m>` |
| 바이트 컨테이너 | `TArray`, `CBuffer`, `COctet` | `std::vector<uint8_t>`와 `TSpan`/`TReadOnlySpan` | 외부에 노출되는 컨테이너 종류를 줄임 |

## 파일 구성

- 헤더는 `#pragma once` 대신 헤더 가드를 씁니다. 가드 이름은 그 헤더가 속한 `include/` 디렉터리 기준
  상대 경로를 대문자로 바꾸고 영숫자가 아닌 문자를 `_`로 치환한 뒤 앞뒤를 이중 밑줄로 감쌉니다.
  - `include/sbox/core/task.hpp` → `__INCLUDE_SBOX_CORE_TASK_HPP__`
  - `modules/image/include/sbox/image/store.hpp` → `__INCLUDE_SBOX_IMAGE_STORE_HPP__`
- `.cpp`는 자신과 대응하는 공개 헤더를 가장 먼저 `<sbox/...>` 꺾쇠 경로로 포함합니다.
- 템플릿이 아닌 공개 헤더에는 같은 모듈의 `src/` 아래에 대응하는 `.cpp`(비어 있어도 됨)를 둡니다.
  전부 템플릿인 헤더(`core/task.hpp`)에는 두지 않습니다.
- 모든 공개 코드는 `namespace sbox { ... } // namespace sbox` 안에 둡니다.
- 중첩 네임스페이스는 자기만의 정체성과 네이밍 체계를 가진 모듈에만 허용됩니다. 두 번째 최상위 블록을
  여는 형태로 쓰고 `}`로만 닫습니다.
  ```cpp
  namespace sbox {
  namespace oci {

  }
  }
  ```
  - 중첩하지 않음(`sbox`): `core`(범용 배관), `box`(라이브러리의 중심 API: `CSandbox`, `SBoxPolicy`).
  - 중첩함: `oci`, `image`, `vol`, `net`, `vpn`, `http`, `tls`, `archive` 등 선택 모듈.
- 내부 구현 전용 타입은 `src/` 아래 비공개 헤더/소스 쌍으로 두고, 가드는 `__SRC_<MODULE>_<PATH>_HPP__`,
  포함은 `"..."` 상대 경로로 합니다. 내부 타입에는 `S/T/C/I/E` 접두사를 붙이지 않습니다(`PascalCase`).

## 타입

- `int`/`unsigned` 대신 `common.hpp`의 별칭(`sbox::uint32_t`, `sbox::size_t`, ...)을 씁니다.
  시스템 콜 인터페이스가 정확히 `int`, `pid_t`, `uid_t`를 요구하는 자리(파일 디스크립터, 시그널 번호,
  `ioctl` 인자)는 그 타입을 그대로 씁니다.
- C 헤더는 `common.hpp`에서만 `<stdint.h>` 형태로 포함하고, 다른 곳은 `<cstring>`처럼 C++ 형태를
  포함해 `std::`로 호출합니다. 리눅스 시스템 헤더(`<sys/...>`, `<linux/...>`, `<unistd.h>`)는 예외입니다.
- 접두사: 템플릿이 아닌 값 struct `S`, 템플릿 `T`, 상태를 가진 클래스 `C`, 순수 가상 인터페이스 `I`,
  열거형 `E`. 인터페이스는 `using <Name>Ptr = std::shared_ptr<I<Name>>;`와 `static ... create...()`
  팩토리를 둡니다. 모든 구현이 지원하지 않는 동작은 `-ENOTSUP`를 반환하는 기본 본문을 가진 가상
  메서드로 둡니다.
- 열거형은 `enum class`가 아닌 평범한 `enum`이며, 열거자는 열거형 이름의 짧은 대문자 약칭을
  접두사로 씁니다(`EBindMount` → `EBMNT_READ_ONLY`, `ENetworkMode` → `EBNET_NONE`).
  유효하지 않은 상태가 있으면 `..._INVALID`를 둡니다. 자명하지 않은 열거자에는
  `// --> Description.` 꼬리 주석을 답니다.
- 아웃오브라인 정의가 있는 타입과 자유 함수에만 `SBOX_API`를 붙입니다.
- 가벼운 헤더 전용 값 타입의 자명한 메서드는 `constexpr ... noexcept`로 둡니다.

## 결과 코드와 오류

- 실패할 수 있는 함수는 `int32_t`를 반환합니다: 성공은 `SBOX_OK`, 실패는 음수 errno(`-ENOENT`).
  개수를 함께 돌려주는 함수는 음이 아닌 값으로 돌려줍니다.
- I/O 결과는 `SIoResult { int32_t error; size_t bytes; }`로 돌려줍니다.
- 예외는 메모리 부족과 프로그래밍 오류에만 쓰고, 운영상 실패(파일 없음, 권한 없음, 타임아웃)는
  결과 코드로 돌려줍니다.

## 비동기

- 기다리는 동작은 모두 `TTask<T>`를 반환하는 코루틴이며 호출 스레드의 `CEventLoop`에서 돌아갑니다.
  `CEventLoop::current()`가 null인 곳(이벤트 루프 밖)에서 await하지 마십시오.
- 블로킹 `waitpid`, `SIGCHLD` 핸들러, `sleep` 류는 쓰지 않습니다. 프로세스 종료는 pidfd를
  `CEventLoop::waitFd`로 기다립니다.
- 스레드는 만들지 않습니다. 어쩔 수 없이 블로킹되는 호출(`getaddrinfo`)만 `CEventLoop::runBlocking`으로
  넘기며, fork할 프로세스에서는 그것도 쓰지 않습니다(`CSandbox::fork`의 규칙).
- 커널 제어 파일(cgroup, `/proc`)의 작은 동기 쓰기는 이벤트 루프 스레드에서 그대로 해도 됩니다.

## 버퍼 처리

- 원소 단위 루프로 채우거나 복사하지 말고 `std::memset`/`std::memcpy`/`std::memmove`를 씁니다.
  libcertpp 문서의 예외(constant-time 코드, 원소 단위 결합, 뒤집기, 조건부 복사)는 그대로 적용됩니다.
- 데이터는 가능한 한 복사하지 않습니다: span으로 넘기고, 소유권은 이동시키고, 여러 버퍼는
  `writev`/`sendmsg`로 보냅니다.
- 출력 span은 `const SByteSpan&`, 입력 span은 `const SReadOnlyByteSpan&`로 받습니다.

## 네이밍

- 네임스페이스 소문자. 공개 타입은 접두사 + `PascalCase`. 자유 함수 `PascalCase`
  (번역 단위 지역 `static`/익명 네임스페이스 헬퍼는 `camelCase` 허용). 멤버 메서드 `camelCase`.
  비공개 필드 `_camelCase`. `S` struct의 공개 필드는 접두사 없음. 상수와 열거자
  `SCREAMING_SNAKE_CASE`. 매크로는 `SBOX_` 또는 빌드 스위치용 `__...__`.
- 표준 헤더 매크로와 충돌할 법한 상수 이름은 뒤에 `_`를 붙입니다.
- getter/setter는 같은 이름을 overload합니다(`length()` / `length(value)`).

## 포맷팅

- 4칸 들여쓰기, 탭 금지. 여는 중괄호는 같은 줄. 멤버 사이 빈 줄 하나.
- 한 단계 네임스페이스는 `} // namespace sbox`로, 중첩 네임스페이스는 `}`로 닫습니다.
- 접근 지정자는 관련 멤버를 묶기 위해 반복해서 씁니다.
- 클래스 본문 안에서 정의하는 한 줄 접근자는 `inline`을 명시합니다.
- 소스와 헤더는 순수 ASCII입니다(문서 `.md`는 한글). em-dash 대신 `--`를 씁니다.
- 빈 `// --` 줄은 선언 안의 논리적 하위 그룹을 나누고, 문장 위의 `// -->` 주석은 그 줄의
  자명하지 않은 *이유*를 설명합니다.

## 문서 주석

- 모든 공개 struct, 클래스, 메서드, 자유 함수 위에 Javadoc 블록(`/** ... */`)을 둡니다. 한 줄 요약은
  필수이고 `@param`/`@return`은 자명하면 생략합니다. 아주 짧은 한 줄 접근자는 한 줄 요약만 씁니다.
- `.cpp` 정의 위에는 요약을 다시 적은 짧은 `/* ... */`를 둡니다.

## 버전

- `HEADER_VERSION`(`include/sbox/version.hpp`)과 루트 `CMakeLists.txt`의 `project(... VERSION ...)`를
  API/ABI가 바뀔 때 함께 올립니다. `GetLibraryVersion()`은 `HEADER_VERSION`을 돌려주므로 따로 고치지
  않습니다.

## 테스트

- 테스트는 `modules/<m>/tests/` 아래에 두고, 파일 경로는 테스트 대상의 헤더 경로를 반영합니다.
  각 파일이 독립 실행 파일이며 `DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN`을 정의한 뒤
  `<doctest/doctest.h>`를 포함합니다. CMake가 글로빙하므로 파일만 추가하면 됩니다.
- 테스트는 병렬로 안전해야 합니다: 포트 0, 고유한 임시 경로(`mkdtemp`), 고유한 cgroup/네트워크
  이름, 전역 상태 공유 금지.
- 루트 권한, 커널 기능(overlayfs, 사용자 네임스페이스, nftables, WireGuard 모듈)이 필요한 테스트는
  조건을 먼저 확인하고, 없으면 `MESSAGE`로 이유를 남긴 뒤 그 케이스를 건너뜁니다(실패시키지 않음).
- 모듈 구현이 컴파일될 때 그 모듈의 테스트를 한 번에 돌립니다: `ctest --test-dir build -j8 -L <m>`.
  마지막에는 전체를 `ctest -j8`로 한 번에 돌립니다. 테스트를 하나씩 따로 실행하며 시간을 끌지 않습니다.
