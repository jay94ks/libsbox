# http 모듈

HTTP/1.1 클라이언트와 서버, URL 처리를 제공합니다. 네임스페이스는 `sbox::http`, 헤더는
`modules/http/include/sbox/http/`, CMake 타깃은 `sbox::http`(의존: core)입니다.

주 사용처는 다음과 같습니다.

- image 모듈: Registry API v2 클라이언트(HTTPS, Bearer 토큰 인증, CDN으로의 blob 리다이렉트, `Range` 재개, `Link` 페이지네이션)
- vol, net 모듈: Docker 플러그인 프로토콜 서버(`/run/docker/plugins/<name>.sock` 유닉스 소켓 위의 HTTP/1.1 POST JSON,
  `Content-Type: application/vnd.docker.plugins.v1.2+json`)
- CLI 도구: dockerd 같은 유닉스 소켓 API나 일반 HTTP(S) 호출

TLS는 이 모듈에 없습니다. https는 `ITlsConnector` 훅으로 tls 모듈(또는 테스트 대역)에 맡기므로 http 모듈은
tls 모듈에 의존하지 않습니다.

## 헤더

| 헤더 | 내용 |
|---|---|
| `http/url.hpp` | `SUrl`(RFC 3986 파싱/조립/참조 해석), `PercentEncode`/`PercentDecode`, `BuildQuery`/`ParseQuery`, `RemoveDotSegments`, `DefaultPort` |
| `http/headers.hpp` | `CHeaders`, `SplitHeaderList`, `SMediaType`, `SLink`/`ParseLinkHeader`, `SContentRange`, `FormatRange`/`ParseRange`, `FormatHttpDate` |
| `http/auth.hpp` | `Base64Encode`/`Base64Decode`, `EncodeBasicAuth`/`DecodeBasicAuth`, `SAuthChallenge`/`ParseAuthChallenges` |
| `http/message.hpp` | `IBodyReader`(본문 스트림), `SRequest`, `SResponse`, `ReasonPhrase` |
| `http/proxy.hpp` | `SProxyConfig`(HTTP(S)_PROXY / NO_PROXY) |
| `http/client.hpp` | `ITlsConnector`, `SClientOptions`, `CHttpClient` |
| `http/server.hpp` | `SServerOptions`, `SServerRequest`, `SServerResponse`, `THandler`, `CHttpServer` |

결과 코드는 libsbox 규칙대로 `SBOX_OK` 또는 음수 errno입니다. 이 모듈에서 쓰는 값:

| 값 | 뜻 |
|---|---|
| `-EINVAL` | URL/헤더 형식 오류(헤더 값의 CR/LF 포함) |
| `-EPROTONOSUPPORT` | 지원하지 않는 스킴, TLS 훅 없이 https, http가 아닌 프록시 |
| `-EBADMSG` | 잘못된 응답(상태 줄, 헤더, Content-Length, 청크 프레이밍) |
| `-EMSGSIZE` | 응답 헤더가 `maxHeaderBytes`를 넘음 |
| `-ENOTSUP` | 디코딩하지 않는 전송 코딩(gzip 등), 101 업그레이드 |
| `-ECONNRESET` | 응답 헤더 전/본문 도중 연결이 끊김(잘린 본문) |
| `-ETIMEDOUT` | 연결/헤더/본문 유휴 타임아웃 |
| `-ELOOP` | 리다이렉트 횟수 초과 |
| `-ECONNREFUSED` / `-EACCES` | 연결 거부, 프록시가 CONNECT를 거부(407이면 `-EACCES`) |
| `-EFBIG` | 본문이 한도를 넘음 |

## URL (`SUrl`)

- RFC 3986 구성 요소(scheme, userinfo, host, port, path, query, fragment)를 인코딩된 형태 그대로 보관하고,
  `hasAuthority`/`hasQuery`/`hasFragment`로 "빈 값"과 "없음"을 구분합니다(참조 해석과 재조립에 필요).
- 스킴은 소문자로, http/https(와 스킴 없는 참조)의 호스트도 소문자로 바꿉니다. `http+unix`처럼 호스트에
  대소문자를 구분하는 소켓 경로를 담는 스킴은 그대로 둡니다.
- IPv6 리터럴은 괄호 없이 저장하고(`"::1"`, 영역 ID는 `%25eth0`), `hostPort()`/`toString()`이 괄호를 붙입니다.
- 제어 문자, 공백, 비 ASCII 바이트, 잘못된 `%XX`, 65535를 넘는 포트, 잘못된 IP 리터럴은 거부합니다.
- `SUrl::resolve(base, ref, out)`은 RFC 3986 5.2(엄격 모드) 참조 해석이며, 5.4.1/5.4.2 예시 전부가 테스트에 있습니다.
  리다이렉트의 `Location`, Bearer `realm`, `Link`의 상대 참조 해석에 씁니다.
- `effectivePort()`(명시 포트 또는 80/443), `hostPort()`(Host 헤더 형태, 기본 포트 생략),
  `requestTarget()`(origin-form), `credentials()`(userinfo 디코딩).
- `BuildQuery`는 이름과 값을 컴포넌트로 인코딩(공백은 `%20`)하고 `ParseQuery`는 `+`를 공백으로 디코딩합니다.

## 헤더와 값 파서

- `CHeaders`: 이름 대소문자 무시, 순서와 중복 보존. `add`(추가), `set`(같은 이름을 하나로 교체, 첫 위치 유지),
  `remove`, `find`/`get`/`getAll`, `combined`(", "로 연결), `hasToken`(콤마 목록에서 토큰 찾기, 예: `Connection: close`).
- `SMediaType::parse`: `type/subtype; name=value` (이름 소문자화, 따옴표 값 해제), `essence()`로 비교.
- `ParseLinkHeader`: `<target>; rel="next"` 목록. `SLink::hasRel("next")`는 공백으로 구분된 rel 값을 봅니다.
  target은 해석하지 않은 참조이므로 요청 URL을 기준으로 `SUrl::resolve` 합니다.
- `SContentRange::parse`: `bytes a-b/N`, `bytes a-b/*`, `bytes */N`(416). `FormatRange(first[, last])`는
  `Range` 값을 만들고, 서버 쪽 `ParseRange`는 단일 범위(`a-b`, `a-`, `-n`)를 크기에 맞춰 잘라 줍니다(다중 범위는 `-EINVAL`).
- `ParseAuthChallenges`: `WWW-Authenticate`의 여러 챌린지를 파싱합니다. auth-param(이름 소문자, 따옴표 해제, `\` 이스케이프)과
  token68 형식을 모두 처리하고, 콤마 뒤의 `token =`은 같은 챌린지의 파라미터로, 그 밖의 토큰은 새 챌린지로 봅니다.
  Docker Hub의 `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"`
  은 `param("realm")`, `param("service")`, `param("scope")`로 꺼냅니다.
- Base64는 표준 알파벳과 패딩을 쓰는 작은 로컬 구현입니다(암호 기능이 아니므로 libcertpp에 의존하지 않음).
  디코딩은 패딩 생략을 허용하지만 공백이나 정규형이 아닌 남는 비트는 거부합니다.

## 본문 스트림 (`IBodyReader`)

받은 메시지(클라이언트의 응답, 서버의 요청)의 본문은 `IStream`을 구현한 `IBodyReader`로 읽습니다.

- 프레이밍(Content-Length, chunked와 trailer, 연결 종료까지)을 풀어 본문 바이트만 돌려줍니다. 버퍼에 남은 바이트가
  없으면 호출자의 버퍼로 바로 `recv`하므로, 수 GB blob도 64 KiB 단위로 디스크에 흘려 쓸 수 있습니다
  (테스트: 64 MiB 다운로드 중 최대 RSS 증가 약 0.5 MiB).
- 끝에 도달하면 `recv`가 0바이트와 `SBOX_OK`를 돌려주고 `isComplete()`가 참이 되며, chunked면 `trailers()`가 채워집니다.
- 클라이언트에서는 마지막 바이트를 읽는 순간 연결이 keep-alive 풀로 돌아갑니다. 끝까지 읽지 않고 `close()`하거나
  버리면 그 연결은 닫힙니다.
- 일찍 끊기면 `-ECONNRESET`, 프레이밍 오류는 `-EBADMSG`, 한도 초과는 `-EFBIG`.
- 편의 함수: `readText(out, limit)`, `readJson(out, limit)`, `discard(limit)`. 테스트/어댑터용으로
  `IBodyReader::createEmpty()`, `createFromBytes()`.

## 클라이언트 (`CHttpClient`)

```cpp
CHttpClient client(options);
SResponse res;
co_await client.get("https://registry-1.docker.io/v2/", res);
std::string text;
co_await res.readText(text);
```

- 요청(`SRequest`): `method`, `url`, `headers`, 메모리 본문(`body`, Content-Length로 보내며 리다이렉트/재시도 때 다시 보낼 수 있음)
  또는 스트림 본문(`setBodyStream(stream, length)`, 길이가 -1이면 chunked 업로드, 다시 보낼 수 없음), `unixSocket`,
  `followRedirects`. Host, User-Agent, Content-Length/Transfer-Encoding은 클라이언트가 채웁니다(사용자가 Host를 주면 그대로 사용).
  URL에 userinfo가 있으면 `Authorization: Basic`을 붙입니다. 헤더 이름이 토큰이 아니거나 값에 CR/LF가 있으면 `-EINVAL`.
- 64 KiB 이하의 메모리 본문은 헤더와 한 번에 보내고, 소켓에는 `TCP_NODELAY`를 켭니다.
- 응답 파싱: `HTTP/1.x SSS reason` 상태 줄, 1xx 중간 응답은 건너뜀, obs-fold는 공백으로 펼침, LF만 쓴 줄도 허용.
  HEAD/204/304는 본문 없음, `Transfer-Encoding`은 `chunked`만(그 밖의 코딩은 `-ENOTSUP`), 서로 다른 Content-Length는 `-EBADMSG`,
  길이가 없으면 연결 종료까지 읽습니다. `Transfer-Encoding`과 `Content-Length`가 함께 오면 chunked로 읽고 연결은 재사용하지 않습니다.
- Keep-alive 풀: (경로 종류, 스킴, 호스트, 포트, 프록시) 별로 유휴 연결을 `maxIdlePerHost`개까지 두고,
  `poolIdleTimeoutMs`가 지난 것은 버립니다. 풀에서 꺼낸 연결이 서버 쪽에서 이미 닫혀 응답 바이트 없이 실패하면,
  본문을 다시 보낼 수 있는 요청에 한해 새 연결로 한 번 재시도합니다.
- 리다이렉트(301/302/303/307/308, 최대 `maxRedirects`):
  - 303은 GET(HEAD는 HEAD 유지)으로, 301/302는 POST일 때만 GET으로 바꾸고 본문과 Content-* 헤더를 버립니다.
  - 307/308은 메서드와 본문을 유지합니다. 스트림 본문은 다시 보낼 수 없으므로 그 리다이렉트 응답을 그대로 돌려줍니다.
  - 오리진(스킴, 호스트, 포트)이 바뀌면 `Authorization`, `Cookie`, `Proxy-Authorization`, 사용자가 준 `Host`,
    `unixSocket`을 버립니다. 레지스트리가 blob GET을 CDN 호스트로 보낼 때 토큰이 새지 않습니다.
  - 리다이렉트 응답 본문은 1 MiB까지 비워 연결을 재사용합니다. `SResponse::url`은 최종 URL, `redirects`는 따라간 횟수입니다.
- 타임아웃(`SClientOptions`): `connectTimeoutMs`(주소마다, 프록시 CONNECT 교환 포함), `headerTimeoutMs`(요청을 보낸 뒤
  응답 헤더를 다 받을 때까지), `idleTimeoutMs`(요청 전송과 본문 읽기 중 무응답 간격). TLS 핸드셰이크 타임아웃은 훅의 몫입니다.
- 연결 경로:
  - `http`: core `ResolveEndpoints`로 해석한 주소를 차례로 `CSocket::connect`.
  - `https`: 같은 TCP 연결(또는 프록시 터널) 위에서 `ITlsConnector::connect(transport, serverName, out)`을 부릅니다.
    훅이 없으면 `-EPROTONOSUPPORT`. serverName은 URL 호스트(IPv6는 괄호 없음)이며 SNI와 인증서 검증에 씁니다.
  - 유닉스 소켓: `SRequest::unixSocket`에 경로를 주거나, `http+unix://%2Frun%2Fdocker.sock/info`처럼 퍼센트 인코딩한
    경로를 호스트로 씁니다(Host 헤더는 `localhost`).
- 프록시(`SProxyConfig`, 기본값은 직접 연결; 환경을 따르려면 `options.proxy = SProxyConfig::fromEnvironment()`):
  - `http_proxy`/`HTTP_PROXY`, `https_proxy`/`HTTPS_PROXY`, `all_proxy`/`ALL_PROXY`(둘 다 없을 때), `no_proxy`/`NO_PROXY`.
    소문자 이름이 우선이고, 스킴 없는 `host:port`도 받습니다. 프록시 자체는 평문 HTTP만 지원합니다.
  - http 대상은 프록시에 absolute-form(`GET http://host/path HTTP/1.1`)으로 보내고, https 대상은 `CONNECT host:port`
    터널을 연 뒤 그 안에서 TLS를 시작합니다(종단 간 TLS). 터널 응답 뒤에 이미 온 바이트도 보존합니다.
  - 프록시 URL의 userinfo는 `Proxy-Authorization: Basic`으로 보냅니다.
  - NO_PROXY: 콤마/공백 구분. `*`, 도메인(`example.com`, `.example.com`, `*.example.com`은 그 도메인과 하위 도메인),
    IP 리터럴, CIDR(`127.0.0.0/8`, `fd00::/8`), `host:port`. 이 머신의 NO_PROXY 형식을 그대로 처리합니다.
- 한 클라이언트는 한 이벤트 루프에서 씁니다. 여러 코루틴이 동시에 요청해도 되며 각자 다른 연결을 씁니다.

### TLS 훅 연결 예

tls 모듈의 `tls::ConnectTls(IStreamPtr transport, const STlsClientOptions&, IStreamPtr& out)`을 쓰는 어댑터:

```cpp
class CTlsHook : public http::ITlsConnector {
public:
    tls::STlsClientOptions base;

    TTask<int32_t> connect(IStreamPtr transport, const std::string& serverName, IStreamPtr& out) override {
        tls::STlsClientOptions opts = base;
        opts.serverName = serverName;
        co_return co_await tls::ConnectTls(std::move(transport), opts, out);
    }
};
```

## 서버 (`CHttpServer`)

```cpp
SServerOptions opts;
opts.jsonContentType = "application/vnd.docker.plugins.v1.2+json";
CHttpServer server(opts);
server.route("POST", "/Plugin.Activate", [](SServerRequest& req, SServerResponse& res) -> TTask<void> {
    CJson out = CJson::object();
    out.set("Implements", CJson::fromStrings({ "VolumeDriver" }));
    res.setJson(out);
    co_return;
});

CListener listener;
SEndpoint ep;
SEndpoint::fromUnix("/run/docker/plugins/myvol.sock", ep);
listener.listen(ep);
co_await server.serve(listener);   // 다른 코루틴에서 server.stop()
```

- `serve(listener)`가 accept 루프를 돌고 연결마다 코루틴을 `spawn`합니다. TCP와 유닉스 소켓 모두 됩니다.
  `maxConnections`를 넘는 연결은 accept 직후 닫습니다. 디스크립터가 부족하면 잠시 쉬고 계속합니다.
- 요청 파싱 한도: `maxHeaderBytes`(요청 줄이 넘으면 414, 헤더가 넘으면 431), `maxBodyBytes`(Content-Length가 넘으면 즉시 413,
  chunked는 읽는 중 `-EFBIG`이 나고 핸들러가 오류를 내지 않았다면 413으로 응답), `headerTimeoutMs`, `keepAliveTimeoutMs`(요청 사이 유휴),
  `bodyTimeoutMs`(본문 읽기/응답 쓰기 무응답 간격).
- 거부 규칙: 형식 오류, obs-fold, 이름과 콜론 사이 공백, HTTP/1.1인데 Host가 없거나 둘 이상, TE와 CL 동시 지정,
  서로 다른 Content-Length는 400; chunked가 아닌 전송 코딩은 501; HTTP/1이 아니면 505; `Expect`가 100-continue가 아니면 417.
  이런 응답 뒤에는 연결을 닫되, 쓰기 쪽만 먼저 닫고 남은 입력을 잠시 비워(lingering close) 응답이 RST로 사라지지 않게 합니다.
- Keep-alive: HTTP/1.1은 기본 유지(`Connection: close`면 닫음), HTTP/1.0은 `Connection: keep-alive`일 때만. 파이프라인된 요청은
  순서대로 처리합니다. 앞쪽 빈 줄 몇 개는 무시합니다. `Expect: 100-continue`면 핸들러 전에 `100 Continue`를 보냅니다.
- 핸들러가 읽지 않은 요청 본문은 256 KiB까지 버리고 연결을 유지하며, 그보다 크거나 오류가 나면 연결을 닫습니다.
- 라우터: 정확한 경로가 먼저, 그다음 가장 긴 접두사(`routePrefix`, 나머지는 `req.routeRest`). 메서드 `""`/`"*"`는 아무 메서드.
  HEAD는 HEAD 라우트가 없으면 GET 핸들러로 처리하고 본문은 보내지 않습니다. 경로는 맞는데 메서드가 다르면 405와 `Allow`,
  없는 경로는 `fallback` 또는 404. 핸들러가 예외를 던지면 500.
- `SServerRequest`: `method`, `target`, `path`(퍼센트 인코딩 유지), `query`, `routeRest`, `versionMinor`, `headers`, `body`, `peer`,
  `queryParam(name)`, `readText`, `readJson`(빈 본문은 빈 객체).
- `SServerResponse`: `status`, `headers`, 메모리 `body` 또는 `setStream(stream, length)`(길이 -1이면 HTTP/1.1에 chunked,
  HTTP/1.0에는 연결 종료로 구분), `setJson`(서버 옵션의 `jsonContentType`), `setText`, `closeConnection`.
  Content-Length, Transfer-Encoding, Connection은 서버가 정합니다(HEAD 응답에서 핸들러가 준 Content-Length만 예외).
  Date와 Server 헤더를 붙이고, 값에 CR/LF가 있는 헤더는 버립니다.
- 정지: `stop()`은 리스너와 유휴 연결을 닫고, 처리 중인 요청은 끝까지 마친 뒤 `Connection: close`로 응답하고 닫습니다.
  `stop(true)`는 처리 중인 연결도 닫습니다. `serve()`는 모든 연결이 끝난 뒤 돌아옵니다. `serve()`가 시작되기 전에 부른 `stop()`도
  유효합니다(다음 `serve()`가 곧바로 끝남). 정지 후 새 리스너로 다시 `serve()`할 수 있습니다.

## 내부 구조

- `src/wire.*`: 읽기 버퍼를 가진 `Connection`(줄 단위 읽기, 버퍼 우선 읽기), 헤더 블록 파서, 프레이밍 결정
  (`ResponseFraming`/`RequestFraming`, RFC 9112 6.3), 본문 디코더 `Body`, 스트림 본문 송신(`SendStreamBody`, chunked 인코더),
  CONNECT 뒤 남은 바이트를 앞에 붙이는 `PrefixStream`.
- `src/lex.*`: 토큰/따옴표 문자열/파라미터 파서.
- 클라이언트 상태(풀)는 `shared_ptr`로 두고 본문이 `weak_ptr`로 연결을 돌려주므로, 클라이언트가 먼저 사라져도
  남은 본문은 안전하게 읽을 수 있습니다(그 연결은 풀로 돌아가지 않고 닫힘).

## 테스트

`ctest --test-dir build -L http`: `url`(RFC 3986 5.4 벡터 포함), `headers`(헤더 모음, 미디어 타입, Link, Content-Range/Range,
날짜, base64/Basic, Docker Hub Bearer 챌린지, NO_PROXY), `wire`(chunked 경계 사례: 확장, trailer, 한 바이트씩 도착, LF만,
잘린 본문, 크기 오버플로, 한도), `client`(TCP/유닉스 소켓 왕복, keep-alive 재사용, 끊긴 풀 연결 재시도, 다른 호스트로의
리다이렉트에서 Authorization 제거, 리다이렉트 메서드 규칙, 64 MiB 스트리밍 다운로드와 32 MiB chunked 업로드, Range,
잘못된 응답 거부, 타임아웃, 테스트 안의 작은 프록시를 통한 CONNECT 터널과 absolute-form 전달), `server`(오류 상태 코드,
라우팅, 파이프라인, 100-continue, HTTP/1.0, 유휴 타임아웃, 정상/강제 정지, 연결 수 제한). 모든 테스트는 포트 0과
`mkdtemp` 경로를 써서 병렬로 안전합니다. 서로 다른 호스트는 127.0.0.1과 127.0.0.2로 만듭니다.

## 제한 사항

- HTTP/1.1만 지원합니다(HTTP/2, 업그레이드/웹소켓 없음; 101 응답은 `-ENOTSUP`).
- 응답의 `gzip`/`deflate` 같은 전송 코딩과 `Content-Encoding`을 풀지 않습니다(`Accept-Encoding`을 보내지 않음).
- 쿠키 저장소, 다이제스트/NTLM 인증, Bearer 토큰 획득 흐름은 없습니다. 챌린지 파싱과 Basic 인코딩만 제공하고
  토큰 교환은 image 모듈이 합니다.
- 프록시는 평문 HTTP 프록시만(HTTPS 프록시, SOCKS 없음), 프록시 인증은 Basic만.
- 주소는 해석된 순서대로 하나씩 시도합니다(Happy Eyeballs 없음). 이름 해석은 core `ResolveEndpoints`(getaddrinfo를 짧은
  스레드에서 실행)를 쓰므로 fork할 프로세스에서는 숫자 주소나 유닉스 소켓을 쓰십시오.
- TLS 핸드셰이크 타임아웃은 훅이 직접 처리해야 합니다.
- 서버의 Range 처리와 조건부 요청은 자동으로 하지 않습니다(`ParseRange`로 핸들러가 처리).
- 서버는 요청 대상의 경로를 디코딩하거나 정규화하지 않고 인코딩된 그대로 라우팅합니다.
