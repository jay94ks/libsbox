# tls 모듈

TLS 클라이언트와 X.509 인증서 검증입니다. image 모듈이 컨테이너 레지스트리(registry-1.docker.io,
ghcr.io, quay.io, 사설 레지스트리)에서 HTTPS로 내려받을 때 쓰며, http 모듈은 https 커넥터 훅에
`ConnectTls`를 끼웁니다. 네임스페이스는 `sbox::tls`, CMake 타깃은 `sbox::tls`
(`sbox_add_module(tls DEPENDS core LINK certpp::certpp)`)입니다.

libcertpp에는 TLS 프로토콜이 없고 기본 요소만 있습니다. 이 모듈은 프로토콜(레코드 계층, 핸드셰이크
상태 기계, 키 스케줄, 경로 검증)만 구현하고, 해시·HMAC·HKDF·AEAD·키 합의·서명·난수·상수 시간 비교와
X.509 파싱은 전부 libcertpp를 부릅니다. 암호 기본 요소를 직접 구현한 곳은 없습니다.

## 공개 API

| 헤더 | 내용 |
|---|---|
| `sbox/tls/client.hpp` | `ConnectTls`, `STlsClientOptions`, `STlsReport`, `CTlsStream`, `ETlsVersion`, `TlsAlertName` |
| `sbox/tls/trust.hpp` | `CTrustStore` / `CTrustStorePtr`: 신뢰 앵커 집합(시스템 번들, PEM, 디렉터리, 부모 계층) |
| `sbox/tls/verify.hpp` | `VerifyServerChain`, `MatchDnsName`, `MatchCertificateHost`, `ParseIpLiteral`, `STlsVerifyParams` |

### 연결

```cpp
SBOX_API TTask<int32_t> ConnectTls(IStreamPtr transport, const STlsClientOptions& options, IStreamPtr& out);
```

`transport`는 이미 연결된 `IStream`(TCP `CSocket`, 프록시 CONNECT 터널, 다른 TLS 스트림 등)입니다.
성공하면 `out`에 `CTlsStream`(`IStream` 구현)이 들어오고, 이후 `recv`/`send`는 평문 애플리케이션
데이터를 주고받습니다. 옵션은 첫 중단 전에 복사하므로 호출자가 계속 들고 있을 필요가 없습니다.
실패하면 전송 스트림은 프로토콜상 쓸 수 없는 상태로 남으므로 호출자가 닫습니다.

```cpp
auto sock = std::make_shared<CSocket>();
co_await sock->connect(endpoint, 10000);

STlsClientOptions o;
o.serverName = "registry-1.docker.io";      // SNI + 인증서 호스트 검증
o.alpn = { "http/1.1" };                    // 기본값
STlsReport report;
o.report = &report;                         // 실패 이유, 경고(alert), 협상 결과

IStreamPtr tls;
int32_t rc = co_await ConnectTls(sock, o, tls);
if (rc != SBOX_OK) {
    // report.reason: "certificate verification failed: the server certificate does not match host ..."
}
```

`STlsClientOptions`:

| 필드 | 기본값 | 의미 |
|---|---|---|
| `serverName` | (필수) | SNI로 보내고(IP 리터럴이면 보내지 않음) 인증서 SAN과 대조할 이름 |
| `alpn` | `{"http/1.1"}` | 제안할 ALPN 목록. 비우면 확장을 보내지 않음 |
| `trustStore` | null → `CTrustStore::system()` | 신뢰 앵커 |
| `minVersion` / `maxVersion` | 1.2 / 1.3 | 허용 버전 범위 |
| `insecure` | `false` | 체인·유효기간·호스트 검증을 끔(아래 보안 참고) |
| `handshakeTimeoutMs` | 30000 | 핸드셰이크 전체 제한 시간(음수: 없음) |
| `clientCertificatePem` / `clientKeyPem` | 빈 값 | mTLS 클라이언트 인증서 체인(leaf 먼저)과 비암호화 개인 키(PKCS#8, SEC1 EC, PKCS#1 RSA) |
| `recordPadding` | 0 | TLS 1.3 내부 평문을 이 배수로 0 패딩(길이 은닉) |
| `verifyTimeSeconds` | 0(현재) | 유효기간 검사에 쓸 유닉스 시간(테스트용) |
| `report` | null | `STlsReport`를 받을 포인터 |

`STlsReport`: `error`, `reason`(사람이 읽는 실패 이유), `alertSent`/`alertReceived`(경고 번호, 없으면
-1), `version`, `cipherSuite`/`cipherSuiteName`, `group`, `signatureScheme`, `helloRetry`,
`clientCertificateSent`, `alpn`, `peerCertificates`(DER, leaf 먼저).

`CTlsStream` 추가 메서드: `shutdown()`(close_notify 전송, 한 번), `close()`(전송 스트림을 즉시 닫음,
close_notify 없음), `info()`(위 보고서), `lastError()`, `failureReason()`.

### 오류 코드

| 값 | 상황 |
|---|---|
| `-EPROTO` | 핸드셰이크 실패: 프로토콜 위반, 공통 매개변수 없음, 서버의 치명적 경고, Finished 불일치 |
| `-EPROTONOSUPPORT` | 허용 범위의 버전을 협상할 수 없음(서버의 protocol_version 경고 포함) |
| `-EKEYREJECTED` | 인증서 체인/호스트/유효기간 검증 실패, CertificateVerify·ServerKeyExchange 서명 불일치 |
| `-EBADMSG` | 레코드 인증 실패(bad_record_mac), 형식 오류, 크기 초과, 알 수 없는 레코드 타입 |
| `-ECONNRESET` | 핸드셰이크 중 전송 종료, 또는 close_notify 없는 EOF(잘림 공격 가능성) |
| `-ECONNABORTED` | 핸드셰이크 후 서버의 치명적 경고 |
| `-ETIMEDOUT` | 핸드셰이크 제한 시간 초과(핸드셰이크 후 `recv` 타임아웃은 연결을 망가뜨리지 않음) |
| `-EINVAL` | 잘못된 옵션(서버 이름 없음, 잘못된 버전 범위, 읽을 수 없거나 맞지 않는 클라이언트 키) |
| `-EPIPE` | `shutdown()` 이후 `send` |

우리가 실패를 감지하면 맞는 치명적 경고(decode_error, illegal_parameter, unexpected_message,
bad_record_mac, record_overflow, unknown_ca, certificate_expired, bad_certificate,
unsupported_certificate, decrypt_error, protocol_version, handshake_failure, missing_extension,
unsupported_extension ...)를 보내고, 그 번호는 `report.alertSent`에 남습니다.

### 신뢰 저장소

```cpp
auto store = CTrustStore::create(CTrustStore::system());          // 시스템 루트 위에 계층
store->addFile("/etc/docker/certs.d/myregistry:5000/ca.crt");      // Docker 방식의 레지스트리별 CA
o.trustStore = store;
```

- `CTrustStore::system()`은 프로세스에서 한 번 읽어 공유합니다. 위치: `$SSL_CERT_FILE`이 있으면 그 파일,
  없으면 `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`,
  `/etc/ssl/ca-bundle.pem`, `/etc/pki/tls/cacert.pem`, `/etc/ssl/cert.pem` 중 처음 있는 것.
  `$SSL_CERT_DIR`(콜론 구분)이 있으면 그 디렉터리들도, 번들 파일이 하나도 없으면 `/etc/ssl/certs`를
  읽습니다. 가로채기 프록시의 CA(`SSL_CERT_FILE=/root/.ccr/ca-bundle.crt`)는 이렇게 신뢰됩니다.
- `addPem`(파싱 실패 블록은 건너뜀), `addDer`, `addFile`(PEM 또는 DER), `addDirectory`(`*.pem`, `*.crt`,
  c_rehash 이름 `xxxxxxxx.N`). 같은 DER은 한 번만 들어갑니다.
- 앵커의 공개 키는 추가할 때 미리 만들어 두므로, 다 채운 저장소는 여러 스레드가 읽기만 해도 안전합니다.
  추가는 공유 전에 끝냅니다.
- 서버 인증서 자체를 넣으면(자체 서명 인증서 고정) 그 인증서에서 경로가 끝납니다.

## 프로토콜

### TLS 1.3 (RFC 8446)

- 스위트: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`.
- 그룹: x25519, secp256r1, secp384r1(supported_groups). 첫 ClientHello에는 x25519 키 공유만 넣고,
  서버가 다른 그룹을 원하면 HelloRetryRequest로 다시 보냅니다(쿠키 반향, message_hash 대체 트랜스크립트,
  두 번째 HRR 거부, HRR과 ServerHello의 스위트·그룹 일치 확인).
- 서명: ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512, ed25519,
  rsa_pss_rsae_sha256/384/512, rsa_pkcs1_sha256/384/512(인증서 서명용으로만 광고, 1.3 CertificateVerify
  에서는 거부). 1.3에서는 ECDSA 스킴의 곡선이 키와 같아야 합니다.
- 확장: server_name, supported_groups, signature_algorithms, ALPN, supported_versions, key_share,
  cookie(HRR 후). PSK/0-RTT/세션 티켓은 제안하지 않습니다.
- 미들박스 호환 모드(부록 D.4): 32바이트 임의 legacy_session_id, 두 번째 비행(또는 두 번째
  ClientHello) 직전 change_cipher_spec 전송, 서버 Finished 전의 평문 CCS(값 1)는 버림.
- 엄격한 상태 기계: ServerHello → EncryptedExtensions → [CertificateRequest] → Certificate →
  CertificateVerify → Finished 순서만 받습니다. 제안하지 않은 확장, 중복 확장, 그 메시지에 허용되지
  않는 확장, 메아리치지 않은 세션 ID, 제안하지 않은 스위트/그룹, 키 변경 경계를 넘는 핸드셰이크
  메시지, 다른 레코드 타입과 섞인 조각난 핸드셰이크 메시지를 모두 거부합니다.
- 핸드셰이크 후: NewSessionTicket은 형식만 확인하고 버리고, KeyUpdate는 수신 키를 갱신하며
  update_requested면 우리 송신 키도 갱신해 응답합니다. 송신 레코드가 2^23개에 이르면 스스로 KeyUpdate
  합니다(AES-GCM 한도 2^24.5보다 충분히 아래). 그 밖의 핸드셰이크 메시지(사후 인증 포함)는
  unexpected_message.

### TLS 1.2 (RFC 5246, 5288, 7905, 7627, 8422)

- 스위트: ECDHE_ECDSA/ECDHE_RSA × AES_128_GCM_SHA256, AES_256_GCM_SHA384, CHACHA20_POLY1305_SHA256.
  RSA 키 교환, CBC, RC4, 3DES, DHE, 익명 스위트는 없습니다.
- 그룹 x25519/secp256r1/secp384r1, 비압축 점만(ec_point_formats). ServerKeyExchange 서명은 위
  스킴(1.2에서는 PKCS#1 v1.5 허용, ECDSA 곡선과 스킴 해시는 독립)으로 검증합니다.
- extended_master_secret은 필수입니다(없으면 handshake_failure). renegotiation_info(빈 값)를 보내고,
  서버가 보내면 비어 있는지 확인합니다.
- TLS 1.3을 허용한 상태에서 서버가 1.2를 고르며 ServerHello.random 끝에 `DOWNGRD\x01`을 넣으면
  다운그레이드 공격으로 보고 거부합니다.
- 우리가 보낸 임의 세션 ID를 서버가 되돌리면(재개 시도) 거부합니다. 재협상은 하지 않습니다:
  HelloRequest에는 no_renegotiation 경고로 답합니다.
- AES-GCM 명시적 nonce는 레코드 순번입니다.

### 레코드 계층

- 평문 최대 2^14바이트로 조각내고, 수신은 1.3 암호문 2^14+256, 1.2 암호문 2^14+2048, 평문 2^14를
  넘으면 record_overflow. 복호화 후 평문이 2^14를 넘어도 거부합니다.
- 빈 핸드셰이크/경고 레코드 거부, 경고는 정확히 2바이트, 1.3에서 암호화된 CCS 거부, 키 설치 전
  애플리케이션 데이터 거부. 재조립된 핸드셰이크 메시지 하나는 최대 256 KiB.
- 송신은 쓰기 잠금(코루틴 FIFO)으로 직렬화되어, `recv` 안에서 생기는 KeyUpdate·경고가 다른 코루틴의
  `send`와 섞이지 않습니다. 한 `recv`와 한 `send`가 동시에 진행될 수 있습니다.

## 인증서 검증

`VerifyServerChain`(핸드셰이크가 부름):

1. leaf: 파싱 가능, 알 수 없는 critical 확장 없음, 유효기간 안, EKU가 있으면 serverAuth 또는
   anyExtendedKeyUsage, RSA 키 2048비트 이상, SAN이 호스트를 포함.
2. 호스트 대조(RFC 6125): SAN dNSName만 봅니다(CN 대체 없음). ASCII 대소문자 무시, 끝 점 하나 무시.
   와일드카드는 맨 왼쪽 레이블 전체(`*.example.com`)일 때만, 정확히 레이블 하나에 맞고, 뒤에 레이블이
   둘 이상 있어야 합니다(`*.com` 불가). 부분 와일드카드(`f*.example.com`) 불가. IP 리터럴(IPv4, IPv6,
   대괄호 허용)은 SAN iPAddress와 바이트 비교하고 dNSName과는 맞추지 않습니다.
3. 경로 구성: 현재 인증서의 issuer DER과 같은 subject DER을 가진 신뢰 앵커를 먼저, 다음으로 서버가 보낸
   나머지 인증서(순서 무관)를 후보로 삼아 libcertpp `CCert::verifyBy`로 서명을 확인하며 깊이 우선으로
   찾고, 막히면 되돌아가 다른 후보(교차 서명 루트)를 시도합니다. 중간 인증서 최대 8개, 체인 최대 16개.
4. 발급자 조건: 유효기간(루트 포함), BasicConstraints cA=true(앵커는 확장이 없어도 허용: v1 루트),
   pathLenConstraint, KeyUsage가 있으면 keyCertSign, EKU가 있으면 serverAuth/any, 중간 인증서의
   critical 확장, RSA 2048비트 이상. 앵커 아래 인증서의 MD5/SHA-1 서명은 거부합니다.
5. 이름 제약: 경로의 각 CA(앵커 포함)의 nameConstraints를 leaf SAN의 dNSName·iPAddress에 적용합니다
   (permitted/excluded, `.example.com` 형식 포함).

실패 사유마다 경고가 다릅니다: 발급자 없음 unknown_ca, 만료 certificate_expired, 호스트 불일치·CA 아님
등 bad_certificate, critical 확장·EKU unsupported_certificate, 약한 키 insufficient_security.

`insecure`이면 1~5를 건너뛰지만, 서버가 보낸 leaf의 키로 CertificateVerify/ServerKeyExchange 서명은
여전히 검증합니다(leaf가 파싱되지 않으면 실패).

## 보안 참고

- 재협상 없음(1.2 HelloRequest 거절), 0-RTT 없음, 세션 재개/PSK 없음, 압축 없음(null만 제안, 서버가
  다른 값을 고르면 거부).
- Finished 검증은 libcertpp `CSecure::equals`로 상수 시간 비교합니다. AEAD 태그 검증도 libcertpp가
  상수 시간으로 하고, 실패 시 버퍼를 건드리지 않습니다.
- 키 스케줄 비밀(핸드셰이크·마스터·트래픽 비밀, 프리마스터, 키 블록)과 받은 평문 버퍼는 다 쓴 뒤
  `CSecure::zero`로 지웁니다.
- 1.2는 확장 마스터 비밀을 강제하고 1.3 다운그레이드 표식을 확인합니다.
- X25519를 먼저 씁니다. libcertpp의 P-256/P-384 ECDH는 상수 시간이 아니라고 스스로 밝히고 있어,
  서버가 HRR로 요구하거나 1.2에서 고를 때만 씁니다(임시 키라 노출 창은 한 연결).
- `insecure`는 경로상의 누구든 서버를 사칭할 수 있게 합니다. Docker의 insecure-registries처럼 명시적으로
  설정된 경우와 테스트에서만 켭니다.
- X25519 결과가 0이면(작은 위수 점) 거부합니다. EC 점은 비압축 형식·길이를 확인하고 libcertpp가 곡선
  위 점인지 검증합니다.

## 테스트

`ctest --test-dir build -L tls`:

| 파일 | 내용 |
|---|---|
| `tests/rfc8448.cpp` | RFC 8448 3장 "Simple 1-RTT Handshake" 추적: X25519 공유 비밀, 핸드셰이크·마스터 비밀, 트래픽 키/IV, 서버 암호화 비행 복호화, RSA-PSS CertificateVerify, 서버·클라이언트 Finished, 클라이언트 Finished·앱 데이터·close_notify 레코드 바이트 일치, NewSessionTicket·앱 데이터 복호화, 변조·순서 위반 거부. TLS 1.2 PRF 벡터, 1.2 레코드 왕복 |
| `tests/verify.cpp` | 호스트 대조 표, IP 파싱, 저장소(중복, 디렉터리, `SSL_CERT_FILE`/`SSL_CERT_DIR`, 계층), openssl로 만든 인증서로 경로 검증(정상, 누락 발급자, 기간, EKU, CA 아님, pathlen, 이름 제약, critical 확장, SHA-1, RSA-1024, 자체 서명 고정, 교차 서명 되돌아가기) |
| `tests/loopback.cpp` | `openssl s_server` 자식 프로세스(포트 0)와 TLS 1.3 세 스위트, P-384/RSA-PSS/Ed25519 서버 키, TLS 1.2 여섯 스위트와 세 그룹, RSA PKCS#1 서명, HRR(P-256, P-384, stateless 쿠키), ALPN, 패딩, 와일드카드·IP 검증, 검증 실패와 insecure, 중간 인증서 누락, 버전 제한, mTLS(1.3/1.2, EC/RSA), KeyUpdate 양방향, 1 MiB 전송, 타임아웃, 비TLS 상대 |
| `tests/strict.cpp` | 각본대로 움직이는 가짜 서버: 다운그레이드 표식, 세션 ID, 미제안·중복 확장, 미제안 스위트, 구버전, EMS 없음, 재개 시도, 잘못된 키 공유, HRR 규칙, 레코드 위반, ClientHello 내용 |
| `tests/live.cpp` | `SBOX_TEST_NETWORK=1`일 때만: `HTTPS_PROXY`가 있으면 직접 쓴 CONNECT로 터널을 열고 registry-1.docker.io:443에 1.3/1.2/자동으로 접속해 `GET /v2/`가 401인지 확인 |

openssl 바이너리가 없으면 loopback/verify의 해당 케이스는 MESSAGE를 남기고 건너뜁니다.

## 빌드 메모

- libcertpp 헤더는 libsbox 경고 집합(`-Wshadow`)에서 경고를 내므로 `thirdparty/CMakeLists.txt`에서
  `certpp` 타깃에 `SYSTEM` 속성을 줍니다(소비자에게 시스템 헤더로 보임).
- 내부 헤더(`src/crypto.hpp`, `src/record.hpp`, `src/keyschedule.hpp`)의 함수는 테스트가 공유 빌드에서도
  링크되도록 `SBOX_API`로 내보냅니다. 공개 API는 아닙니다.

## 제한 사항

- 세션 재개(티켓, PSK), 0-RTT, 사후 클라이언트 인증(post_handshake_auth)을 지원하지 않습니다.
- 폐기 확인 없음: OCSP(stapling 포함), CRL, CT(SCT)를 보지 않습니다.
- 이름 제약은 leaf SAN의 DNS/IP 이름에만 적용합니다. directoryName·email·URI 제약과 인증서
  정책(certificatePolicies, policyConstraints, inhibitAnyPolicy)은 처리하지 않습니다(critical이어도 통과).
- 발급자/주체 이름은 DER 바이트로만 비교합니다(RFC 5280의 정규화 비교 없음). 실제 체인에서는 대개 같습니다.
- IDN은 A-label(punycode)로 넘겨야 합니다. 서버 이름에 포트를 넣지 않습니다.
- libcertpp가 모르는 키(RSASSA-PSS 전용 SPKI, Ed448 서버 키 등)를 가진 서버 인증서는 쓸 수 없습니다.
- max_fragment_length, record_size_limit, status_request, signature_algorithms_cert, certificate_authorities
  확장은 보내지 않습니다.
- `close()`는 동기라 close_notify를 보내지 않습니다. 깨끗한 종료가 필요하면 먼저 `co_await shutdown()`.
- 클라이언트 개인 키는 암호화되지 않은 PEM만 읽습니다.
- P-256/P-384 ECDH는 libcertpp 구현상 상수 시간이 아닙니다(위 보안 참고).
