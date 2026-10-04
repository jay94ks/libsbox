# core 모듈

모든 모듈이 쓰는 기반입니다. 헤더는 `include/sbox/`(`common.hpp`, `version.hpp`)와
`include/sbox/core/`에 있고, CMake 타깃은 `sbox::core`입니다.

| 헤더 | 내용 |
|---|---|
| `common.hpp` | 타입 별칭, `SBOX_API`, 결과 코드 규칙(`SBOX_OK` / 음수 errno) |
| `version.hpp` | `SVersion`, `HEADER_VERSION`, `GetLibraryVersion()` |
| `core/span.hpp` | `TSpan<T>`, `TReadOnlySpan<T>`, `SByteSpan`, `SReadOnlyByteSpan`, `BytesOf`, `TextOf` |
| `core/task.hpp` | `TTask<T>`(지연 시작 코루틴), `CDetachedTask` |
| `core/eventloop.hpp` | `CEventLoop`: `run`, `spawn`, `post`, `waitFd`, `sleepFor`, `yield`, `cancelFd`, `runBlocking` |
| `core/fd.hpp` | `CFd`: 소유 디스크립터 |
| `core/stream.hpp` | `IStream`, `CStream`(비차단 디스크립터 스트림), `CPipe`, `SIoResult` |
| `core/socket.hpp` | `SEndpoint`, `ResolveEndpoints`, `CSocket`(SCM_RIGHTS 포함), `CListener`, `CDatagramSocket` |
| `core/json.hpp` | `CJson`: 순서 보존 객체, int64 정확도, 파서와 직렬화 |
| `core/file.hpp` | `CFile`: `readAll`, `writeSome`(커널 제어 파일), `writeAtomic`, `makeDirs`, `removeTree`, `join` |

## 이벤트 루프

- `CEventLoop`는 그것을 `run()`하는 스레드에 속하며, 그동안 `CEventLoop::current()`가 그 루프를
  돌려줍니다. `run(task)`는 task가 끝날 때까지 루프를 돌리고 결과를 돌려줍니다(예외는 다시 던짐).
- `waitFd(fd, events, timeoutMs)`는 epoll이 받는 모든 디스크립터(소켓, 파이프, pidfd, netlink, tun)를
  기다립니다. 한 디스크립터를 여러 코루틴이 동시에(읽기 하나, 쓰기 하나 등) 기다릴 수 있습니다.
  결과는 준비된 `EFDE_*` 비트(양수), `-ETIMEDOUT`, 또는 `cancelFd`/스트림 `close()`로 깨어난 경우
  `-ECANCELED`입니다.
- 관심 집합은 레벨 트리거이며, 기다리는 코루틴이 없어진 디스크립터는 즉시 epoll에서 빠집니다.
- 기다리는 중인 코루틴의 프레임을 파괴하지 마십시오(먼저 `cancelFd`나 `close()`로 깨웁니다).
- `post()`만 스레드 안전합니다. `runBlocking()`은 짧은 스레드를 만들기 때문에 fork할 프로세스에서는
  쓰지 않습니다.

## 스트림

- `IStream`은 `recv`/`send`/`close`와, 그 위의 `recvExact`/`recvAll`을 제공합니다. HTTP, TLS 같은 프로토콜
  코드는 `IStream`만 보고 동작하므로 평문 소켓(`CSocket`)과 TLS 세션을 같은 방식으로 씁니다.
- `recv`가 0바이트와 `SBOX_OK`를 돌려주면 EOF입니다. pty 마스터의 `EIO`도 EOF로 바꿉니다.
- `send`는 전체를 보낼 때까지 기다리며, 소켓에는 `MSG_NOSIGNAL`을 씁니다. 파이프에 쓰는 프로그램은
  `SIGPIPE`를 무시해야 합니다.

## JSON

- 객체 멤버는 삽입 순서를 유지하고 조회는 선형입니다(작은 문서 위주).
- 정수는 int64로 정확하게, 그 범위를 넘는 부호 없는 정수는 double로 둡니다.
- 중첩은 512단계로 제한합니다.
