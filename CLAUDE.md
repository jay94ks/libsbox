# CLAUDE.md

이 파일은 이 저장소에서 작업하는 Claude Code 세션을 위한 안내입니다.

## 프로젝트

libsbox: 리눅스 커널 기능만으로 프로그램을 격리해 실행하는 C++20 라이브러리(샌드박스, OCI 런타임,
이미지, 볼륨, 네트워크, VPN)와 그 위의 CLI 도구들. 구조와 모듈 목록은
[docs/architecture.md](docs/architecture.md)를 보십시오.

## 소유자의 규칙 (다시 논의하지 말 것)

- 코딩 컨벤션은 [docs/coding-conventions.md](docs/coding-conventions.md)를 따릅니다
  (libcertpp 컨벤션을 libsbox 목표에 맞게 조정한 것).
- 커널 모듈을 만들거나 고치지 않습니다. 있는 커널 기능만 쓰고, 없으면 사용자 공간 경로로 대체합니다.
- 이미지/스토리지/볼륨 설계는 Docker와 호환되어야 합니다.
- 암호화, 해시, 비대칭 암호화는 반드시 libcertpp(`thirdparty/libcertpp`, 타깃 `certpp::certpp`)를
  씁니다. 직접 구현하지 않습니다.
- 외부 종속성은 최소로, 신뢰할 수 있는 저장소만 git submodule로 `thirdparty/`에 둡니다.
- 비동기 기반은 core 모듈(`CEventLoop`, `TTask`)입니다. 스레드, SIGCHLD, 블로킹 waitpid를 쓰지 않습니다.
- CI는 없습니다. 검증은 로컬에서 `ctest -j`로 한 번에 돌립니다. 테스트를 하나씩 따로 돌리며 시간을
  끌지 않습니다.
- 문서는 따로 요청이 없으면 한글로 씁니다. 번역본은 `<이름>.<언어 코드>.md`(예: `README.en.md`)로 두고,
  원본 머리에 서로 전환하는 링크를 답니다.
- `docs/`의 설계 문서에는 마지막 상태만 씁니다. 과정 기록은 `docs/logs/`에 둡니다.
- 브랜치와 PR은 가능하면 모듈 단위로 만듭니다.

## 빌드와 테스트

```sh
git submodule update --init
cmake -S . -B build -DSBOX_WERROR=ON && cmake --build build -j
ctest --test-dir build -j8 --output-on-failure          # 전체
ctest --test-dir build -j8 -L <module>                  # 한 모듈
```

새 모듈은 `modules/<m>/CMakeLists.txt`에 `sbox_add_module(<m> DEPENDS ...)`만 쓰면 루트가 찾아냅니다.
새 CLI 도구는 `cli/<tool>/CMakeLists.txt`에 `sbox_add_tool(...)`을 씁니다. 공유 파일을 고칠 필요가
없으므로 모듈 작업끼리 충돌하지 않습니다.

## 문서 위치

- [docs/architecture.md](docs/architecture.md): 모듈, 의존 관계, 실행 모델, 위협 모델
- [docs/coding-conventions.md](docs/coding-conventions.md)
- `docs/<module>.md`: 모듈별 설계(현재 상태)
- [docs/limitations.md](docs/limitations.md): 모듈 전체의 제한 사항과 미구현 사항(모듈 문서의 "제한 사항" 절과 함께 갱신)
- `docs/logs/`: 작업 기록
