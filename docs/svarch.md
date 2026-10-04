# svarch (Sandbox virtual architecture)

추후 확장으로 예정된 설계 자리입니다. 아직 구현은 없습니다.

## 목적

프로세스 격리(네임스페이스, seccomp, cgroups)는 커널 취약점을 통한 탈출을 막지 못합니다. svarch는
같은 OCI 번들과 `SBoxPolicy`를 가상 머신 안에서 구동하는 실행 백엔드로, 커널 경계 대신 하이퍼바이저
경계를 격리 수단으로 씁니다.

## 방향

- KVM(`/dev/kvm`)만 쓰고 커널 모듈은 추가하지 않습니다.
- 게스트는 최소 커널과 libsbox의 컨테이너 init으로 구성되고, 루트 파일시스템과 볼륨은 virtio로
  넘깁니다. 네트워크는 net 모듈의 탭/브릿지 경로를 그대로 씁니다.
- box 모듈의 실행 엔진 인터페이스 뒤에 백엔드로 들어가, `CSandbox`와 `oci::CRuntime` 호출자는 바꾸지
  않고 격리 수준만 고를 수 있게 합니다.
