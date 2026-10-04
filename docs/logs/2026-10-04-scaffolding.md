# 2026-10-04 스캐폴딩

- 모노레포 골격: `include/sbox`, `modules/`, `cli/`, `docs/`, `thirdparty/`(doctest v2.4.12, libcertpp).
- 컨벤션 결정: libcertpp 컨벤션을 기본으로 하되 C++20, `sbox` 네임스페이스, 음수 errno 결과 코드,
  모듈별 디렉터리로 조정(docs/coding-conventions.md의 "libcertpp와 다른 점").
- 비동기 기반은 외부 라이브러리 없이 core 모듈에 직접 둠: 단일 스레드 epoll 루프. 스레드가 없어야
  `CSandbox::fork` 규칙이 지켜지기 때문.
- CMake: 모듈과 CLI 디렉터리를 글로빙해 모듈 작업이 공유 파일을 건드리지 않게 함.
- core 테스트(json, eventloop, file) 통과.
