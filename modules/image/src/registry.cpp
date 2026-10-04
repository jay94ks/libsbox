#include <sbox/image/registry.hpp>
#include "join.hpp"
#include "util.hpp"
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/http/auth.hpp>
#include <sbox/http/headers.hpp>
#include <sbox/http/url.hpp>
#include <sbox/tls/client.hpp>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <algorithm>
#include <map>
#include <unistd.h>

namespace sbox {
namespace image {

    namespace {

        const char* const MANIFEST_ACCEPT =
            "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, "
            "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";

        constexpr size_t MANIFEST_LIMIT = size_t(4) << 20;

        /* Lower-cases ASCII. */
        std::string lower(std::string_view s) {
            std::string out(s);
            for (char& c : out) {
                if (c >= 'A' && c <= 'Z') {
                    c = char(c - 'A' + 'a');
                }
            }

            return out;
        }

        /* Strips a scheme and a path from a config.json key ("https://index.docker.io/v1/"). */
        std::string authKeyHost(std::string_view key) {
            size_t scheme = key.find("://");
            if (scheme != std::string_view::npos) {
                key = key.substr(scheme + 3);
            }

            size_t slash = key.find('/');
            if (slash != std::string_view::npos) {
                key = key.substr(0, slash);
            }

            return lower(key);
        }

        /*
         * IStream over a byte range of a file (push bodies).
         */
        class FileRangeStream : public IStream {
        private:
            CFd _fd;
            uint64_t _pos;
            uint64_t _end;
            std::function<void(uint64_t)> _onProgress;

        public:
            FileRangeStream(CFd fd, uint64_t offset, uint64_t length, std::function<void(uint64_t)> onProgress)
                : _fd(std::move(fd)), _pos(offset), _end(offset + length), _onProgress(std::move(onProgress)) {}

            TTask<SIoResult> recv(const SByteSpan& buffer, int64_t) override {
                if (!_fd.isValid()) {
                    co_return SIoResult{ -EBADF, 0 };
                }

                size_t want = size_t(std::min<uint64_t>(buffer.size, _end - _pos));
                if (want == 0) {
                    co_return SIoResult{ SBOX_OK, 0 };
                }

                ssize_t n;
                do {
                    n = ::pread(_fd.get(), buffer.data, want, off_t(_pos));
                } while (n < 0 && errno == EINTR);

                if (n < 0) {
                    co_return SIoResult{ -errno, 0 };
                }

                if (n == 0) {
                    co_return SIoResult{ -ENODATA, 0 };
                }

                _pos += uint64_t(n);
                if (_onProgress) {
                    _onProgress(uint64_t(n));
                }

                co_return SIoResult{ SBOX_OK, size_t(n) };
            }

            TTask<SIoResult> send(const SReadOnlyByteSpan&, int64_t) override {
                co_return SIoResult{ -ENOTSUP, 0 };
            }

            void close() noexcept override {
                _fd.reset();
            }
        };

        /*
         * TLS hook with per-host settings (insecure registries, certs.d CAs and client certs).
         */
        class RegistryTls : public http::ITlsConnector {
        public:
            struct HostConfig {
                tls::CTrustStorePtr trust;
                bool insecure = false;
                std::string certPem;
                std::string keyPem;
            };

            tls::CTrustStorePtr baseTrust;
            std::map<std::string, HostConfig> hosts;    // --> Keyed by host name (no port).
            std::string lastReason;

            TTask<int32_t> connect(IStreamPtr transport, const std::string& serverName, IStreamPtr& out) override {
                tls::STlsClientOptions o;
                o.serverName = serverName;
                o.trustStore = baseTrust;
                auto it = hosts.find(lower(serverName));
                if (it != hosts.end()) {
                    if (it->second.trust) {
                        o.trustStore = it->second.trust;
                    }

                    o.insecure = it->second.insecure;
                    o.clientCertificatePem = it->second.certPem;
                    o.clientKeyPem = it->second.keyPem;
                }

                tls::STlsReport report;
                o.report = &report;
                int32_t r = co_await tls::ConnectTls(std::move(transport), o, out);
                if (r != SBOX_OK) {
                    lastReason = "TLS handshake with " + serverName + " failed: " + report.reason;
                }

                co_return r;
            }
        };

        /* Returns a one-element scope list (no braced lists inside co_await: GCC 13 ICE). */
        std::vector<std::string> scopesOf(const std::string& scope) {
            return std::vector<std::string>(1, scope);
        }

        /* Strips the port from "host:port" / "[v6]:port". */
        std::string hostOnly(std::string_view hostPort) {
            if (!hostPort.empty() && hostPort.front() == '[') {
                size_t close = hostPort.find(']');
                return lower(hostPort.substr(1, close == std::string_view::npos ? std::string_view::npos : close - 1));
            }

            size_t colon = hostPort.rfind(':');
            return lower(colon == std::string_view::npos ? hostPort : hostPort.substr(0, colon));
        }

        /* Appends a query parameter to a URL text. */
        std::string addQuery(const std::string& url, std::string_view name, std::string_view value) {
            std::string out = url;
            out += url.find('?') == std::string::npos ? '?' : '&';
            out += http::PercentEncode(name);
            out += '=';
            out += http::PercentEncode(value);
            return out;
        }

        /*
         * One way to reach a registry.
         */
        struct Endpoint {
            std::string domain;         // --> Reference domain (credentials key).
            std::string host;           // --> host[:port] actually contacted.
            std::string scheme = "https";
            std::string prefix;         // --> Path prefix of a mirror URL ("" or "/something").
            bool mirror = false;
            bool insecureTls = false;
            bool httpFallback = false;
            bool pinged = false;
            bool pinging = false;       // --> A ping is in flight; concurrent requests wait for it.
            std::vector<http::SAuthChallenge> challenges;

            std::string base() const {
                return scheme + "://" + host + prefix;
            }
        };

        /*
         * A cached bearer token.
         */
        struct Token {
            std::string value;
            int64_t expiresMs = 0;
        };

    }

    /* Returns the Docker client configuration path. */
    std::string DockerConfigPath() {
        const char* dir = std::getenv("DOCKER_CONFIG");
        if (dir && *dir) {
            return CFile::join(dir, "config.json");
        }

        const char* home = std::getenv("HOME");
        return CFile::join(home && *home ? home : "/root", ".docker/config.json");
    }

    /* Looks up credentials in a Docker config.json. */
    int32_t LoadDockerCredentials(const std::string& configPath, std::string_view domain, SRegistryAuth& out) {
        out = SRegistryAuth();
        CJson cfg;
        int32_t r = ReadJsonFile(configPath, cfg, size_t(4) << 20);
        if (r != SBOX_OK) {
            return r == -EINVAL ? -EINVAL : -ENOENT;
        }

        const CJson* auths = cfg.find("auths");
        if (!auths || !auths->isObject()) {
            return -ENOENT;
        }

        std::vector<std::string> wanted;
        std::string d = lower(domain);
        if (d == DOCKER_HUB_DOMAIN || d == "index.docker.io" || d == DOCKER_HUB_REGISTRY) {
            wanted = { "index.docker.io", "docker.io", "registry-1.docker.io" };
        } else {
            wanted = { d };
        }

        for (size_t i = 0; i < auths->size(); ++i) {
            std::string host = authKeyHost(auths->keyAt(i));
            bool match = false;
            for (const std::string& w : wanted) {
                match = match || host == w;
            }

            if (!match) {
                continue;
            }

            const CJson& e = auths->at(i);
            std::string auth = e.get("auth").asString();
            if (!auth.empty()) {
                std::vector<uint8_t> raw;
                if (http::Base64Decode(auth, raw) != SBOX_OK) {
                    return -EINVAL;
                }

                std::string pair(raw.begin(), raw.end());
                size_t colon = pair.find(':');
                if (colon == std::string::npos) {
                    return -EINVAL;
                }

                out.username = pair.substr(0, colon);
                out.password = pair.substr(colon + 1);
                // --> "<token>" user with an identity token is how docker login stores OAuth.
                while (!out.password.empty() && (out.password.back() == '\n' || out.password.back() == '\r')) {
                    out.password.pop_back();
                }
            } else {
                out.username = e.get("username").asString();
                out.password = e.get("password").asString();
            }

            out.identityToken = e.get("identitytoken").asString();
            out.registryToken = e.get("registrytoken").asString();
            if (out.empty()) {
                continue;
            }

            return SBOX_OK;
        }

        return -ENOENT;
    }

    struct CRegistryClient::SImpl {
        SRegistryOptions options;
        std::shared_ptr<RegistryTls> tls;
        std::unique_ptr<http::CHttpClient> client;
        std::map<std::string, Token> tokens;
        std::map<std::string, std::shared_ptr<Endpoint>> endpoints;    // --> Keyed by scheme-independent base.
        std::map<std::string, SRegistryAuth> authCache;
        std::string lastError;

        explicit SImpl(SRegistryOptions o) : options(std::move(o)) {
            tls = std::make_shared<RegistryTls>();
            tls->baseTrust = options.trustStore;
            http::SClientOptions co;
            co.proxy = options.proxy;
            co.tls = tls;
            co.connectTimeoutMs = options.connectTimeoutMs;
            co.idleTimeoutMs = options.idleTimeoutMs;
            co.headerTimeoutMs = options.idleTimeoutMs;
            co.userAgent = options.userAgent;
            client = std::make_unique<http::CHttpClient>(co);
        }

        /* Sets the last error and returns `code`. */
        int32_t fail(int32_t code, std::string message) {
            lastError = std::move(message);
            return code;
        }

        /* Returns true when `host` (host[:port]) is in a list (exact host:port or bare host). */
        static bool listed(const std::vector<std::string>& list, std::string_view host) {
            std::string h = lower(host);
            std::string bare = hostOnly(host);
            for (const std::string& e : list) {
                std::string le = lower(e);
                size_t scheme = le.find("://");
                if (scheme != std::string::npos) {
                    le = le.substr(scheme + 3);
                }

                while (!le.empty() && le.back() == '/') {
                    le.pop_back();
                }

                if (le == h || le == bare) {
                    return true;
                }
            }

            return false;
        }

        /* Loads /etc/docker/certs.d/<host[:port]>/ for a host into the TLS hook. */
        void configureTls(const Endpoint& ep) {
            std::string name = hostOnly(ep.host);
            RegistryTls::HostConfig& hc = tls->hosts[name];
            hc.insecure = hc.insecure || ep.insecureTls;
            if (options.certsDir.empty()) {
                return;
            }

            for (const std::string& dirName : { ep.host, name }) {
                std::string dir = CFile::join(options.certsDir, dirName);
                std::vector<std::string> files;
                if (ListDirectory(dir, files) != SBOX_OK) {
                    continue;
                }

                std::sort(files.begin(), files.end());
                for (const std::string& f : files) {
                    std::string path = CFile::join(dir, f);
                    if (f.size() > 4 && f.compare(f.size() - 4, 4, ".crt") == 0) {
                        if (!hc.trust) {
                            hc.trust = tls::CTrustStore::create(options.trustStore ? options.trustStore : tls::CTrustStore::system());
                        }

                        hc.trust->addFile(path);
                    } else if (f.size() > 5 && f.compare(f.size() - 5, 5, ".cert") == 0 && hc.certPem.empty()) {
                        std::string keyPath = CFile::join(dir, f.substr(0, f.size() - 5) + ".key");
                        std::string cert;
                        std::string key;
                        if (CFile::readAll(path, cert) == SBOX_OK && CFile::readAll(keyPath, key) == SBOX_OK) {
                            hc.certPem = cert;
                            hc.keyPem = key;
                        }
                    }
                }

                break;
            }
        }

        /* Returns the endpoint object for a host (shared so ping and challenges are reused). */
        std::shared_ptr<Endpoint> endpointFor(const std::string& domain, const std::string& scheme, const std::string& host,
                                              const std::string& prefix, bool mirror) {
            std::string key = host + prefix + (mirror ? "#m" : "");
            auto it = endpoints.find(key);
            if (it != endpoints.end()) {
                return it->second;
            }

            auto ep = std::make_shared<Endpoint>();
            ep->domain = domain;
            ep->host = host;
            ep->scheme = scheme;
            ep->prefix = prefix;
            ep->mirror = mirror;
            if (scheme == "https") {
                bool insecure = listed(options.insecureRegistries, host) || IsLoopbackRegistry(host);
                if (listed(options.plainHttpRegistries, host)) {
                    ep->scheme = "http";
                } else if (insecure) {
                    ep->insecureTls = true;
                    ep->httpFallback = true;
                }
            }

            if (ep->scheme == "https") {
                configureTls(*ep);
            }

            endpoints[key] = ep;
            return ep;
        }

        /* Lists the endpoints to try for a domain (mirrors first unless `push`). */
        std::vector<std::shared_ptr<Endpoint>> endpointsFor(const std::string& domain, bool push) {
            std::vector<std::shared_ptr<Endpoint>> out;
            if (!push) {
                for (const std::string& m : options.mirrors) {
                    std::string target = DOCKER_HUB_DOMAIN;
                    std::string url = m;
                    size_t eq = m.find('=');
                    if (eq != std::string::npos && m.find("://") > eq) {
                        target = m.substr(0, eq);
                        url = m.substr(eq + 1);
                    }

                    if (target != domain) {
                        continue;
                    }

                    if (url.find("://") == std::string::npos) {
                        url = "https://" + url;
                    }

                    http::SUrl u;
                    if (http::SUrl::parse(url, u) != SBOX_OK || u.host.empty()) {
                        continue;
                    }

                    std::string prefix = u.path;
                    while (!prefix.empty() && prefix.back() == '/') {
                        prefix.pop_back();
                    }

                    std::string hostPort = u.isIpv6Host() ? "[" + u.host + "]" : u.host;
                    if (u.port >= 0) {
                        hostPort += ":" + std::to_string(u.port);
                    }

                    out.push_back(endpointFor(domain, u.scheme, hostPort, prefix, true));
                }
            }

            out.push_back(endpointFor(domain, "https", RegistryHost(domain), std::string(), false));
            return out;
        }

        /* Returns the credentials for a domain (explicit, then config.json). */
        SRegistryAuth credentialsFor(const std::string& domain) {
            auto it = authCache.find(domain);
            if (it != authCache.end()) {
                return it->second;
            }

            SRegistryAuth auth;
            bool found = false;
            for (const auto& [d, a] : options.credentials) {
                if (lower(d) == lower(domain) || (domain == DOCKER_HUB_DOMAIN && (d == "index.docker.io" || d == DOCKER_HUB_REGISTRY))) {
                    auth = a;
                    found = true;
                    break;
                }
            }

            if (!found) {
                LoadDockerCredentials(options.dockerConfig.empty() ? DockerConfigPath() : options.dockerConfig, domain, auth);
            }

            authCache[domain] = auth;
            return auth;
        }

        /* Reads a registry error body into a message. */
        static std::string errorMessage(const http::SResponse& res, const std::string& body) {
            std::string msg = std::to_string(res.status) + " " + res.reason;
            CJson j;
            if (!body.empty() && CJson::parse(body, j) == SBOX_OK) {
                const CJson& errors = j.get("errors");
                for (size_t i = 0; i < errors.size(); ++i) {
                    msg += ": " + errors.at(i).get("code").asString();
                    std::string m = errors.at(i).get("message").asString();
                    if (!m.empty()) {
                        msg += " (" + m + ")";
                    }
                }

                // --> Token servers answer {"details": "..."}.
                std::string details = j.get("details").asString();
                if (!details.empty()) {
                    msg += ": " + details;
                }
            }

            return msg;
        }

        /* Maps an HTTP status to an errno. */
        static int32_t statusError(int32_t status) {
            switch (status) {
            case 401:
            case 403: return -EACCES;
            case 404: return -ENOENT;
            case 405: return -ENOTSUP;
            case 408: return -ETIMEDOUT;
            case 409: return -EEXIST;
            case 413: return -EFBIG;
            case 416: return -ERANGE;
            case 429: return -EAGAIN;
            default: return status >= 500 ? -EIO : -EPROTO;
            }
        }

        /* Reads (and drops) a response body for an error message. */
        TTask<std::string> drainError(http::SResponse& res) {
            std::string body;
            if (res.body) {
                co_await res.body->readText(body, 65536);
            }

            co_return body;
        }

        /* Pings /v2/ once to learn the scheme and the authentication challenge. */
        TTask<int32_t> ping(Endpoint& ep) {
            while (ep.pinging) {
                co_await CEventLoop::current()->sleepFor(5);
            }

            if (ep.pinged) {
                co_return SBOX_OK;
            }

            ep.pinging = true;
            int32_t r = co_await pingOnce(ep);
            ep.pinging = false;
            co_return r;
        }

        /* Performs the ping (see ping()). */
        TTask<int32_t> pingOnce(Endpoint& ep) {

            while (true) {
                http::SResponse res;
                tls->lastReason.clear();
                int32_t r = co_await client->get(ep.base() + "/v2/", res);
                if (r == SBOX_OK) {
                    std::string body = co_await drainError(res);
                    if (res.status == 401) {
                        ep.challenges.clear();
                        for (const std::string& v : res.headers.getAll("WWW-Authenticate")) {
                            http::ParseAuthChallenges(v, ep.challenges);
                        }
                    } else if (!res.isSuccess()) {
                        // --> Some registries answer the ping with 404 (no v2 API at the root);
                        // treat other statuses as "no auth needed" and let real calls report errors.
                        if (res.status >= 500) {
                            co_return fail(statusError(res.status), "ping " + ep.base() + "/v2/: " + errorMessage(res, body));
                        }
                    }

                    ep.pinged = true;
                    co_return SBOX_OK;
                }

                if (ep.scheme == "https" && ep.httpFallback) {
                    // --> Insecure registry: HTTPS did not work, try plain HTTP (Docker's fallback).
                    ep.scheme = "http";
                    ep.httpFallback = false;
                    continue;
                }

                std::string why = tls->lastReason.empty() ? std::string(std::strerror(-r)) : tls->lastReason;
                co_return fail(r, "cannot reach " + ep.base() + "/v2/: " + why);
            }
        }

        /* Fetches (or reuses) a bearer token for a challenge and scopes. */
        TTask<int32_t> bearerToken(Endpoint& ep, const http::SAuthChallenge& ch, const std::vector<std::string>& scopes,
                                   std::string& token) {
            std::string realm = ch.param("realm");
            std::string service = ch.param("service");
            std::string key = realm + "|" + service;
            for (const std::string& s : scopes) {
                key += "|" + s;
            }

            auto it = tokens.find(key);
            if (it != tokens.end() && it->second.expiresMs > CEventLoop::nowMs()) {
                token = it->second.value;
                co_return SBOX_OK;
            }

            if (realm.empty()) {
                co_return fail(-EPROTO, "the registry's Bearer challenge has no realm");
            }

            SRegistryAuth auth = credentialsFor(ep.domain);
            if (!auth.registryToken.empty()) {
                token = auth.registryToken;
                co_return SBOX_OK;
            }

            http::SRequest req;
            std::string url = realm;
            if (!auth.identityToken.empty()) {
                // --> OAuth2 refresh token grant (what docker login stores as identitytoken).
                req.method = "POST";
                http::SQueryParams form = { { "grant_type", "refresh_token" }, { "refresh_token", auth.identityToken },
                                            { "service", service }, { "client_id", "sbox" } };
                std::string scopeText;
                for (const std::string& s : scopes) {
                    scopeText += (scopeText.empty() ? "" : " ") + s;
                }

                form.emplace_back("scope", scopeText);
                req.setBody(http::BuildQuery(form), "application/x-www-form-urlencoded");
            } else {
                if (!service.empty()) {
                    url = addQuery(url, "service", service);
                }

                for (const std::string& s : scopes) {
                    url = addQuery(url, "scope", s);
                }

                if (!auth.username.empty()) {
                    req.headers.set("Authorization", http::EncodeBasicAuth(auth.username, auth.password));
                }
            }

            if (req.setUrl(url) != SBOX_OK) {
                co_return fail(-EPROTO, "invalid token realm " + realm);
            }

            http::SResponse res;
            std::string body;
            int32_t r = co_await client->fetch(std::move(req), res, body, size_t(1) << 20);
            if (r != SBOX_OK) {
                co_return fail(r, "token request to " + realm + " failed: " +
                                  (tls->lastReason.empty() ? std::string(std::strerror(-r)) : tls->lastReason));
            }

            if (!res.isSuccess()) {
                co_return fail(statusError(res.status), "token request to " + realm + ": " + errorMessage(res, body));
            }

            CJson j;
            if (CJson::parse(body, j) != SBOX_OK) {
                co_return fail(-EPROTO, "token response is not JSON");
            }

            token = j.get("token").asString();
            if (token.empty()) {
                token = j.get("access_token").asString();
            }

            if (token.empty()) {
                co_return fail(-EPROTO, "token response has no token");
            }

            int64_t ttl = j.get("expires_in").asInt(60);
            if (ttl < 60) {
                ttl = 60;
            }

            // --> Renew a little early so a token never expires in the middle of a request.
            tokens[key] = Token{ token, CEventLoop::nowMs() + (ttl - 10) * 1000 };
            co_return SBOX_OK;
        }

        /* Adds the Authorization header for a request. */
        TTask<int32_t> authorize(Endpoint& ep, const std::vector<std::string>& scopes, http::CHeaders& headers) {
            for (const http::SAuthChallenge& ch : ep.challenges) {
                if (ch.isScheme("Bearer")) {
                    std::string token;
                    int32_t r = co_await bearerToken(ep, ch, scopes, token);
                    if (r != SBOX_OK) {
                        co_return r;
                    }

                    headers.set("Authorization", "Bearer " + token);
                    co_return SBOX_OK;
                }
            }

            for (const http::SAuthChallenge& ch : ep.challenges) {
                if (ch.isScheme("Basic")) {
                    SRegistryAuth auth = credentialsFor(ep.domain);
                    if (!auth.username.empty()) {
                        headers.set("Authorization", http::EncodeBasicAuth(auth.username, auth.password));
                    }

                    co_return SBOX_OK;
                }
            }

            co_return SBOX_OK;
        }

        /*
         * Sends a request to an endpoint with authentication. A 401 refreshes the challenge
         * (and the token) and retries once; `makeBody` recreates a streamed body for the retry.
         */
        TTask<int32_t> request(Endpoint& ep, std::string method, std::string url, http::CHeaders headers,
                               std::vector<std::string> scopes, http::SResponse& res,
                               std::function<void(http::SRequest&)> makeBody = nullptr, bool followRedirects = true) {
            int32_t r = co_await ping(ep);
            if (r != SBOX_OK) {
                co_return r;
            }

            // --> Paths are relative to the endpoint, resolved after the ping chose the scheme.
            if (!url.empty() && url[0] == '/') {
                url = ep.base() + url;
            }

            for (int32_t attempt = 0; attempt < 2; ++attempt) {
                http::SRequest req;
                req.method = method;
                if (req.setUrl(url) != SBOX_OK) {
                    co_return fail(-EINVAL, "invalid URL " + url);
                }

                req.headers = headers;
                req.followRedirects = followRedirects;
                r = co_await authorize(ep, scopes, req.headers);
                if (r != SBOX_OK) {
                    co_return r;
                }

                if (makeBody) {
                    makeBody(req);
                }

                tls->lastReason.clear();
                res = http::SResponse();
                r = co_await client->send(std::move(req), res);
                if (r != SBOX_OK) {
                    co_return fail(r, method + " " + url + ": " +
                                      (tls->lastReason.empty() ? std::string(std::strerror(-r)) : tls->lastReason));
                }

                if (res.status != 401 || attempt == 1) {
                    co_return SBOX_OK;
                }

                // --> Unauthorized: learn the (possibly scope-specific) challenge and retry once.
                std::vector<http::SAuthChallenge> fresh;
                for (const std::string& v : res.headers.getAll("WWW-Authenticate")) {
                    http::ParseAuthChallenges(v, fresh);
                }

                co_await drainError(res);
                if (fresh.empty()) {
                    co_return SBOX_OK;
                }

                ep.challenges = fresh;
                for (const http::SAuthChallenge& ch : fresh) {
                    std::string scope = ch.param("scope");
                    if (!scope.empty() && std::find(scopes.begin(), scopes.end(), scope) == scopes.end()) {
                        scopes.push_back(scope);
                    }
                }

                // --> Drop cached tokens of this realm: they were not good enough.
                for (auto it = tokens.begin(); it != tokens.end();) {
                    bool sameRealm = false;
                    for (const http::SAuthChallenge& ch : fresh) {
                        sameRealm = sameRealm || it->first.compare(0, ch.param("realm").size(), ch.param("realm")) == 0;
                    }

                    it = sameRealm ? tokens.erase(it) : std::next(it);
                }
            }

            co_return SBOX_OK;
        }

        /* Fetches a manifest by tag or digest. */
        TTask<int32_t> getManifest(Endpoint& ep, const std::string& repo, const std::string& tagOrDigest, const std::string& scope,
                                   std::string& body, std::string& mediaType, std::string& digest) {
            http::CHeaders h;
            h.set("Accept", MANIFEST_ACCEPT);
            http::SResponse res;
            std::string url = "/v2/" + repo + "/manifests/" + tagOrDigest;
            int32_t r = co_await request(ep, "GET", url, h, scopesOf(scope), res);
            if (r != SBOX_OK) {
                co_return r;
            }

            body.clear();
            r = co_await res.body->readText(body, MANIFEST_LIMIT);
            if (r != SBOX_OK) {
                co_return fail(r, "reading manifest " + repo + ":" + tagOrDigest + ": " + std::strerror(-r));
            }

            if (!res.isSuccess()) {
                co_return fail(statusError(res.status), "manifest " + repo + ":" + tagOrDigest + " from " + ep.base() + ": " +
                                                            errorMessage(res, body));
            }

            mediaType = res.headers.get("Content-Type");
            size_t semi = mediaType.find(';');
            if (semi != std::string::npos) {
                mediaType = mediaType.substr(0, semi);
            }

            while (!mediaType.empty() && mediaType.back() == ' ') {
                mediaType.pop_back();
            }

            bool byDigest = ValidateDigest(tagOrDigest) == SBOX_OK;
            EDigestAlgorithm alg = byDigest ? DigestAlgorithm(tagOrDigest) : EDIGEST_SHA256;
            digest = DigestOf(body, alg);
            if (byDigest && digest != tagOrDigest) {
                co_return fail(-EBADMSG, "manifest " + tagOrDigest + " from " + ep.base() + " has digest " + digest);
            }

            std::string header = res.headers.get("Docker-Content-Digest");
            if (!byDigest && !header.empty() && DigestAlgorithm(header) == EDIGEST_SHA256 && header != digest) {
                co_return fail(-EBADMSG, "manifest " + repo + ":" + tagOrDigest + " has digest " + digest +
                                             " but the registry announced " + header);
            }

            CJson j;
            if (CJson::parse(body, j) != SBOX_OK) {
                co_return fail(-EBADMSG, "manifest " + repo + ":" + tagOrDigest + " is not valid JSON");
            }

            std::string own = j.get("mediaType").asString();
            if (!own.empty()) {
                mediaType = own;
            }

            co_return SBOX_OK;
        }

        /* Emits a progress event. */
        void progress(EProgressPhase phase, const std::string& digest, const std::string& mediaType, uint64_t current,
                      uint64_t total, std::string message = std::string()) {
            if (!options.progress) {
                return;
            }

            SProgress p;
            p.phase = phase;
            p.digest = digest;
            p.mediaType = mediaType;
            p.current = current;
            p.total = total;
            p.message = std::move(message);
            options.progress(p);
        }

        /* Downloads one blob into the store (resuming, verifying). */
        TTask<int32_t> downloadBlob(Endpoint& ep, const std::string& repo, const std::string& scope, const SDescriptor& d,
                                    CContentStore& store, uint64_t& downloaded) {
            if (store.hasBlob(d.digest)) {
                progress(EPP_EXISTS, d.digest, d.mediaType, uint64_t(d.size), uint64_t(d.size));
                co_return SBOX_OK;
            }

            EDigestAlgorithm alg = DigestAlgorithm(d.digest);
            if (alg == EDIGEST_INVALID) {
                co_return fail(-ENOTSUP, "unsupported digest " + d.digest);
            }

            std::string ingestName = std::string(DigestAlgorithmName(alg)) + "-" + std::string(DigestHex(d.digest)) + ".partial";
            CBlobWriter w;
            bool announcedWait = false;
            while (true) {
                int32_t r = w.open(store, ingestName, true, alg);
                if (r == SBOX_OK) {
                    break;
                }

                if (r != -EBUSY) {
                    co_return fail(r, "cannot open ingest for " + d.digest + ": " + std::strerror(-r));
                }

                // --> Another process downloads the same blob: wait for it to finish.
                if (!announcedWait) {
                    progress(EPP_WAITING, d.digest, d.mediaType, 0, uint64_t(d.size));
                    announcedWait = true;
                }

                co_await CEventLoop::current()->sleepFor(200);
                if (store.hasBlob(d.digest)) {
                    progress(EPP_EXISTS, d.digest, d.mediaType, uint64_t(d.size), uint64_t(d.size));
                    co_return SBOX_OK;
                }
            }

            if (d.size >= 0 && w.offset() > uint64_t(d.size)) {
                w.truncate();
            }

            std::vector<uint8_t> buf(size_t(1) << 16);
            int32_t lastCode = SBOX_OK;
            for (int32_t attempt = 0; attempt < std::max(1, options.maxAttempts); ++attempt) {
                if (attempt > 0) {
                    progress(EPP_RETRYING, d.digest, d.mediaType, w.offset(), uint64_t(d.size), lastError);
                    co_await CEventLoop::current()->sleepFor(options.retryDelayMs * attempt);
                }

                if (d.size > 0 && w.offset() == uint64_t(d.size)) {
                    int32_t r = w.commit(d.digest, d.size);
                    if (r == SBOX_OK) {
                        progress(EPP_VERIFIED, d.digest, d.mediaType, uint64_t(d.size), uint64_t(d.size));
                        co_return SBOX_OK;
                    }

                    // --> A corrupt partial file: start over.
                    w.open(store, ingestName, false, alg);
                }

                http::CHeaders h;
                uint64_t offset = w.offset();
                if (offset > 0) {
                    h.set("Range", http::FormatRange(offset));
                }

                http::SResponse res;
                std::string url = "/v2/" + repo + "/blobs/" + d.digest;
                int32_t r = co_await request(ep, "GET", url, h, scopesOf(scope), res);
                if (r != SBOX_OK) {
                    lastCode = r;
                    continue;
                }

                if (res.status == 206) {
                    http::SContentRange cr;
                    if (http::SContentRange::parse(res.headers.get("Content-Range"), cr) != SBOX_OK || cr.first != offset) {
                        co_await res.body->discard(size_t(1) << 20);
                        res.body->close();
                        w.truncate();
                        lastCode = fail(-EPROTO, "bad Content-Range for " + d.digest);
                        continue;
                    }
                } else if (res.status == 200) {
                    if (offset > 0) {
                        w.truncate();
                    }
                } else if (res.status == 416) {
                    co_await drainError(res);
                    w.truncate();
                    lastCode = fail(-ERANGE, "range not satisfiable for " + d.digest);
                    continue;
                } else {
                    std::string body = co_await drainError(res);
                    int32_t code = statusError(res.status);
                    lastCode = fail(code, "blob " + d.digest + " from " + ep.base() + ": " + errorMessage(res, body));
                    if (code == -EACCES || code == -ENOENT || code == -ENOTSUP) {
                        co_return code;
                    }

                    continue;
                }

                uint64_t lastReport = 0;
                progress(EPP_DOWNLOADING, d.digest, d.mediaType, w.offset(), uint64_t(d.size));
                while (true) {
                    SIoResult io = co_await res.body->recv(SByteSpan(buf.data(), buf.size()));
                    if (!io.ok()) {
                        lastCode = fail(io.error, "download of " + d.digest + " interrupted: " + std::strerror(-io.error));
                        break;
                    }

                    if (io.bytes == 0) {
                        break;
                    }

                    r = w.write(SReadOnlyByteSpan(buf.data(), io.bytes));
                    if (r != SBOX_OK) {
                        res.body->close();
                        co_return fail(r, "writing " + d.digest + ": " + std::strerror(-r));
                    }

                    downloaded += io.bytes;
                    if (d.size >= 0 && w.offset() > uint64_t(d.size)) {
                        res.body->close();
                        lastCode = fail(-EBADMSG, "blob " + d.digest + " is larger than its descriptor says");
                        w.truncate();
                        break;
                    }

                    if (w.offset() - lastReport >= (uint64_t(1) << 19)) {
                        lastReport = w.offset();
                        progress(EPP_DOWNLOADING, d.digest, d.mediaType, w.offset(), uint64_t(d.size));
                    }
                }

                if (!res.body->isComplete()) {
                    res.body->close();
                    continue;
                }

                if (d.size >= 0 && w.offset() != uint64_t(d.size)) {
                    lastCode = fail(-EBADMSG, "blob " + d.digest + " ended at " + std::to_string(w.offset()) + " of " +
                                                   std::to_string(d.size) + " bytes");
                    if (w.offset() > uint64_t(d.size)) {
                        w.truncate();
                    }

                    continue;
                }

                r = w.commit(d.digest, d.size);
                if (r == SBOX_OK) {
                    progress(EPP_VERIFIED, d.digest, d.mediaType, uint64_t(d.size), uint64_t(d.size));
                    co_return SBOX_OK;
                }

                lastCode = fail(r, "blob " + d.digest + " failed verification (digest mismatch)");
                w.open(store, ingestName, false, alg);
            }

            co_return lastCode == SBOX_OK ? -EIO : lastCode;
        }

        /* Records which repository a blob came from (for cross-repository mounts on push). */
        void recordSource(CContentStore& store, const std::string& digest, const std::string& repoName) {
            CStoreLock lock(store);
            CJson db;
            if (store.readDb(db) != SBOX_OK) {
                return;
            }

            CJson& list = db["sources"][digest];
            for (size_t i = 0; i < list.size(); ++i) {
                if (list.at(i).asString() == repoName) {
                    return;
                }
            }

            list.push(repoName);
            store.writeDb(db);
        }
    };

    /* Creates a client. */
    CRegistryClient::CRegistryClient(SRegistryOptions options) : _impl(std::make_unique<SImpl>(std::move(options))) {}

    /* Destroys the client. */
    CRegistryClient::~CRegistryClient() = default;

    /* Returns the settings. */
    SRegistryOptions& CRegistryClient::options() noexcept {
        return _impl->options;
    }

    /* Returns the last error. */
    const std::string& CRegistryClient::lastError() const noexcept {
        return _impl->lastError;
    }

    /* Fetches a manifest document. */
    TTask<int32_t> CRegistryClient::fetchManifest(std::string reference, std::string& body, std::string& mediaType, std::string& digest) {
        SImpl& s = *_impl;
        SReference ref;
        if (ParseDockerReference(reference, ref) != SBOX_OK) {
            co_return s.fail(-EINVAL, "invalid reference format: " + reference);
        }

        std::string scope = "repository:" + ref.path + ":pull";
        int32_t r = -ENOENT;
        for (const auto& ep : s.endpointsFor(ref.domain, false)) {
            r = co_await s.getManifest(*ep, ref.path, ref.hasDigest() ? ref.digest : ref.tag, scope, body, mediaType, digest);
            if (r == SBOX_OK) {
                co_return SBOX_OK;
            }
        }

        co_return r;
    }

    /* Lists the tags of a repository. */
    TTask<int32_t> CRegistryClient::listTags(std::string repository, std::vector<std::string>& out) {
        SImpl& s = *_impl;
        out.clear();
        SReference ref;
        if (ParseNormalizedReference(repository, ref) != SBOX_OK) {
            co_return s.fail(-EINVAL, "invalid repository " + repository);
        }

        std::shared_ptr<Endpoint> ep = s.endpointsFor(ref.domain, true).back();
        std::string scope = "repository:" + ref.path + ":pull";
        std::string url = "/v2/" + ref.path + "/tags/list?n=1000";
        for (int32_t page = 0; page < 10000 && !url.empty(); ++page) {
            http::SResponse res;
            int32_t r = co_await s.request(*ep, "GET", url, http::CHeaders(), scopesOf(scope), res);
            if (r != SBOX_OK) {
                co_return r;
            }

            std::string body;
            r = co_await res.body->readText(body, size_t(16) << 20);
            if (r != SBOX_OK) {
                co_return s.fail(r, "reading the tag list");
            }

            if (!res.isSuccess()) {
                co_return s.fail(SImpl::statusError(res.status), "tags of " + ref.name() + ": " + SImpl::errorMessage(res, body));
            }

            CJson j;
            if (CJson::parse(body, j) != SBOX_OK) {
                co_return s.fail(-EBADMSG, "tag list is not JSON");
            }

            for (const std::string& t : j.get("tags").asStrings()) {
                out.push_back(t);
            }

            std::string next;
            std::vector<http::SLink> links;
            if (http::ParseLinkHeader(res.headers.combined("Link"), links) == SBOX_OK) {
                for (const http::SLink& l : links) {
                    if (l.hasRel("next")) {
                        http::SUrl resolved;
                        if (http::SUrl::resolve(res.url, l.target, resolved) == SBOX_OK) {
                            next = resolved.toString();
                        }
                    }
                }
            }

            url = next;
        }

        co_return SBOX_OK;
    }

    /* Pulls an image. */
    TTask<int32_t> CRegistryClient::pull(CContentStore& store, std::string reference, SPullResult& out) {
        SImpl& s = *_impl;
        out = SPullResult();
        SReference ref;
        if (ParseDockerReference(reference, ref) != SBOX_OK) {
            co_return s.fail(-EINVAL, "invalid reference format: " + reference);
        }

        out.reference = ref.toString();
        SPlatform want = s.options.platform.empty() ? HostPlatform() : s.options.platform.normalized();
        std::string scope = "repository:" + ref.path + ":pull";
        std::string tagOrDigest = ref.hasDigest() ? ref.digest : ref.tag;
        s.progress(EPP_RESOLVING, std::string(), std::string(), 0, 0, out.reference);

        CLease lease;
        int32_t r = lease.open(store);
        if (r != SBOX_OK) {
            co_return s.fail(r, std::string("cannot create a lease in the store: ") + std::strerror(-r));
        }

        // --> Resolve the reference on the first endpoint that has it (mirrors first).
        std::shared_ptr<Endpoint> ep;
        std::string topBody;
        std::string topType;
        std::string topDigest;
        r = -ENOENT;
        for (const auto& candidate : s.endpointsFor(ref.domain, false)) {
            r = co_await s.getManifest(*candidate, ref.path, tagOrDigest, scope, topBody, topType, topDigest);
            if (r == SBOX_OK) {
                ep = candidate;
                break;
            }

            // --> Authentication and digest errors from the registry itself are final.
            if (!candidate->mirror) {
                co_return r;
            }
        }

        if (!ep) {
            co_return r;
        }

        out.endpoint = ep->base();
        out.resolvedDigest = topDigest;
        CJson top;
        CJson::parse(topBody, top);
        EManifestKind kind = ClassifyManifest(top, topType);
        if (kind == EMK_SCHEMA1) {
            co_return s.fail(-EPROTONOSUPPORT, "the manifest of " + out.reference +
                                                   " uses Docker image manifest schema 1, which is deprecated and not supported; "
                                                   "rebuild or re-push the image with a current client");
        }

        std::string manifestBody = topBody;
        std::string manifestType = topType;
        std::string manifestDigest = topDigest;
        if (kind == EMK_INDEX) {
            SIndex index;
            if (SIndex::fromJson(top, index) != SBOX_OK) {
                co_return s.fail(-EBADMSG, "malformed image index for " + out.reference);
            }

            int32_t pick = index.select(want);
            if (pick < 0) {
                std::string have;
                for (const SDescriptor& d : index.manifests) {
                    if (d.hasPlatform && d.platform.os != "unknown") {
                        have += (have.empty() ? "" : ", ") + d.platform.toString();
                    }
                }

                co_return s.fail(-ENOEXEC, "no matching manifest for " + want.toString() + " in the manifest list entries (" + have + ")");
            }

            const SDescriptor& chosen = index.manifests[size_t(pick)];
            r = co_await s.getManifest(*ep, ref.path, chosen.digest, scope, manifestBody, manifestType, manifestDigest);
            if (r != SBOX_OK) {
                co_return r;
            }

            if (chosen.size >= 0 && uint64_t(chosen.size) != manifestBody.size()) {
                co_return s.fail(-EBADMSG, "manifest " + chosen.digest + " has the wrong size");
            }

            CJson mj;
            CJson::parse(manifestBody, mj);
            if (ClassifyManifest(mj, manifestType) != EMK_MANIFEST) {
                co_return s.fail(-EBADMSG, "the platform entry " + chosen.digest + " is not an image manifest");
            }

            // --> Keep the index too: it is what the tag resolved to (RepoDigests).
            std::string stored;
            store.writeBlob(BytesOf(topBody), stored, topDigest);
            lease.addBlob(topDigest);
            top = std::move(mj);
        } else if (kind != EMK_MANIFEST) {
            co_return s.fail(-EBADMSG, "unrecognized manifest (" + topType + ") for " + out.reference);
        }

        SManifest manifest;
        if (SManifest::fromJson(top, manifest) != SBOX_OK) {
            co_return s.fail(-EBADMSG, "malformed image manifest " + manifestDigest);
        }

        if (manifest.config.mediaType != MT_OCI_CONFIG && manifest.config.mediaType != MT_DOCKER_CONFIG) {
            co_return s.fail(-ENOTSUP, "manifest " + manifestDigest + " is not a container image (config type " +
                                           manifest.config.mediaType + ")");
        }

        for (const SDescriptor& l : manifest.layers) {
            if (!IsLayerMediaType(l.mediaType)) {
                co_return s.fail(-ENOTSUP, "unsupported layer media type " + l.mediaType);
            }
        }

        s.progress(EPP_RESOLVED, manifestDigest, manifestType, 0, 0, out.reference);
        std::string stored;
        r = store.writeBlob(BytesOf(manifestBody), stored, manifestDigest);
        if (r != SBOX_OK) {
            co_return s.fail(r, std::string("storing the manifest: ") + std::strerror(-r));
        }

        lease.addBlob(manifestDigest);

        // --> Config first (small), then the layers concurrently.
        uint64_t downloaded = 0;
        lease.addBlob(manifest.config.digest);
        r = co_await s.downloadBlob(*ep, ref.path, scope, manifest.config, store, downloaded);
        if (r != SBOX_OK) {
            co_return r;
        }

        CJson cj;
        SImageConfig config;
        if (store.readJsonBlob(manifest.config.digest, cj) != SBOX_OK || SImageConfig::fromJson(cj, config) != SBOX_OK) {
            co_return s.fail(-EBADMSG, "malformed image config " + manifest.config.digest);
        }

        if (config.diffIds.size() != manifest.layers.size()) {
            co_return s.fail(-EBADMSG, "the image config lists " + std::to_string(config.diffIds.size()) + " diffIDs for " +
                                           std::to_string(manifest.layers.size()) + " layers");
        }

        for (const SDescriptor& l : manifest.layers) {
            lease.addBlob(l.digest);
        }

        Endpoint* epRaw = ep.get();
        CContentStore* storePtr = &store;
        uint64_t* counter = &downloaded;
        const std::vector<SDescriptor>* layers = &manifest.layers;
        r = co_await RunConcurrently(manifest.layers.size(), size_t(std::max(1, s.options.maxConcurrentDownloads)),
                                     [&s, epRaw, storePtr, counter, layers, repo = ref.path, scope](size_t i) -> TTask<int32_t> {
                                         return s.downloadBlob(*epRaw, repo, scope, (*layers)[i], *storePtr, *counter);
                                     });
        if (r != SBOX_OK) {
            co_return r;
        }

        out.downloadedBytes = downloaded;
        for (const SDescriptor& l : manifest.layers) {
            s.recordSource(store, l.digest, ref.name());
        }

        SDescriptor manifestDesc;
        manifestDesc.mediaType = manifest.mediaType.empty() ? manifestType : manifest.mediaType;
        manifestDesc.digest = manifestDigest;
        manifestDesc.size = int64_t(manifestBody.size());
        manifestDesc.platform = config.platform();
        manifestDesc.hasPlatform = !config.os.empty();

        SImageInfo info;
        r = store.loadImage(manifestDesc, info);
        if (r != SBOX_OK) {
            co_return s.fail(r, "the pulled image cannot be read back");
        }

        if (s.options.unpack) {
            SSnapshotterOptions so = s.options.snapshotter;
            if (!so.progress) {
                so.progress = s.options.progress;
            }

            CContentStorePtr shared(std::shared_ptr<CContentStore>(), &store);
            CSnapshotter snap(shared, so);
            std::string parent;
            for (size_t i = 0; i < manifest.layers.size(); ++i) {
                std::string chain;
                r = snap.unpackLayer(manifest.layers[i], config.diffIds[i], parent, chain);
                if (r != SBOX_OK) {
                    co_return s.fail(r, snap.lastError());
                }

                lease.addSnapshot(chain);
                parent = chain;
            }
        } else {
            // --> Without unpacking, still verify nothing; diffIDs are checked when unpacked.
        }

        // --> Name the image: the tag (or name@digest), plus the repo digest the tag resolved to.
        r = store.setRecord(out.reference, manifestDesc);
        if (r == SBOX_OK && ref.hasTag()) {
            r = store.setRecord(ref.name() + "@" + topDigest, manifestDesc);
        }

        if (r != SBOX_OK) {
            co_return s.fail(r, std::string("updating index.json: ") + std::strerror(-r));
        }

        out.manifestDigest = manifestDigest;
        out.imageId = manifest.config.digest;
        store.loadImage(manifestDesc, out.image);
        s.progress(EPP_DONE, manifestDigest, manifestDesc.mediaType, downloaded, downloaded, out.reference);
        co_return SBOX_OK;
    }

    /* Pushes a local image. */
    TTask<int32_t> CRegistryClient::push(CContentStore& store, std::string source, std::string target, SPushResult& out) {
        SImpl& s = *_impl;
        out = SPushResult();
        SImageInfo info;
        int32_t r = store.resolve(source, info);
        if (r != SBOX_OK) {
            co_return s.fail(r, "no such image: " + source);
        }

        SReference ref;
        if (ParseDockerReference(target.empty() ? source : target, ref) != SBOX_OK) {
            co_return s.fail(-EINVAL, "invalid reference format: " + (target.empty() ? source : target));
        }

        out.reference = ref.toString();
        std::shared_ptr<Endpoint> ep = s.endpointsFor(ref.domain, true).back();
        std::string pushScope = "repository:" + ref.path + ":pull,push";

        CJson db;
        store.readDb(db);
        std::vector<SDescriptor> blobs = info.manifest.layers;
        blobs.push_back(info.manifest.config);

        Endpoint* epRaw = ep.get();
        CContentStore* storePtr = &store;
        SPushResult* res = &out;
        const std::vector<SDescriptor>* blobList = &blobs;
        const CJson* dbPtr = &db;
        std::string repo = ref.path;
        std::string domain = ref.domain;
        auto job = [&s, epRaw, storePtr, res, blobList, dbPtr, repo, domain, pushScope](size_t i) -> TTask<int32_t> {
            const SDescriptor d = (*blobList)[i];
            Endpoint& e = *epRaw;
            std::string blobsUrl = "/v2/" + repo + "/blobs/";

            http::SResponse head;
            int32_t rr = co_await s.request(e, "HEAD", blobsUrl + d.digest, http::CHeaders(), scopesOf(pushScope), head);
            if (rr != SBOX_OK) {
                co_return rr;
            }

            if (head.body) {
                head.body->close();
            }

            if (head.status == 200) {
                ++res->blobsExisting;
                s.progress(EPP_EXISTS, d.digest, d.mediaType, uint64_t(d.size), uint64_t(d.size));
                co_return SBOX_OK;
            }

            // --> Cross-repository mount from a repository of the same registry the blob came from.
            std::string location;
            std::string from;
            for (const std::string& src : dbPtr->get("sources").get(d.digest).asStrings()) {
                SReference sr;
                if (SReference::parse(src, sr) == SBOX_OK && sr.domain == domain && sr.path != repo) {
                    from = sr.path;
                    break;
                }
            }

            std::string uploads = blobsUrl + "uploads/";
            std::vector<std::string> scopes = scopesOf(pushScope);
            std::string postUrl = uploads;
            if (!from.empty()) {
                postUrl = addQuery(addQuery(uploads, "mount", d.digest), "from", from);
                scopes.push_back("repository:" + from + ":pull");
            }

            http::SResponse post;
            rr = co_await s.request(e, "POST", postUrl, http::CHeaders(), scopes, post, [](http::SRequest& q) { q.setBody(std::string_view()); });
            if (rr != SBOX_OK) {
                co_return rr;
            }

            std::string postBody = co_await s.drainError(post);
            if (post.status == 201) {
                ++res->blobsMounted;
                s.progress(EPP_MOUNTED, d.digest, d.mediaType, uint64_t(d.size), uint64_t(d.size), from);
                co_return SBOX_OK;
            }

            if (post.status != 202) {
                co_return s.fail(SImpl::statusError(post.status), "starting the upload of " + d.digest + ": " +
                                                                       SImpl::errorMessage(post, postBody));
            }

            http::SUrl loc;
            if (http::SUrl::resolve(post.url, post.headers.get("Location"), loc) != SBOX_OK || loc.host.empty()) {
                co_return s.fail(-EPROTO, "upload of " + d.digest + ": the registry sent no usable Location");
            }

            location = loc.toString();
            std::string path = storePtr->blobPath(d.digest);
            uint64_t size = uint64_t(d.size);
            uint64_t sent = 0;
            auto onProgress = [&s, &sent, d, size, res](uint64_t n) {
                sent += n;
                res->uploadedBytes += n;
                s.progress(EPP_UPLOADING, d.digest, d.mediaType, sent, size);
            };

            int64_t chunk = s.options.uploadChunkSize;
            if (chunk > 0) {
                for (uint64_t off = 0; off < size; off += uint64_t(chunk)) {
                    uint64_t len = std::min<uint64_t>(uint64_t(chunk), size - off);
                    http::CHeaders h;
                    h.set("Content-Type", "application/octet-stream");
                    h.set("Content-Range", std::to_string(off) + "-" + std::to_string(off + len - 1));
                    http::SResponse patch;
                    rr = co_await s.request(e, "PATCH", location, h, scopesOf(pushScope), patch,
                                            [path, off, len, onProgress](http::SRequest& q) {
                                                q.setBodyStream(std::make_shared<FileRangeStream>(
                                                                    CFd(::open(path.c_str(), O_RDONLY | O_CLOEXEC)), off, len, onProgress),
                                                                int64_t(len));
                                            });
                    if (rr != SBOX_OK) {
                        co_return rr;
                    }

                    std::string pb = co_await s.drainError(patch);
                    if (patch.status != 202 && patch.status != 204) {
                        co_return s.fail(SImpl::statusError(patch.status), "uploading a chunk of " + d.digest + ": " +
                                                                                SImpl::errorMessage(patch, pb));
                    }

                    http::SUrl next;
                    if (http::SUrl::resolve(patch.url, patch.headers.get("Location"), next) == SBOX_OK && !next.host.empty()) {
                        location = next.toString();
                    }
                }

                http::SResponse put;
                rr = co_await s.request(e, "PUT", addQuery(location, "digest", d.digest), http::CHeaders(), scopesOf(pushScope), put,
                                        [](http::SRequest& q) { q.headers.set("Content-Length", "0"); });
                if (rr != SBOX_OK) {
                    co_return rr;
                }

                std::string pb = co_await s.drainError(put);
                if (put.status != 201 && put.status != 204) {
                    co_return s.fail(SImpl::statusError(put.status), "finishing the upload of " + d.digest + ": " +
                                                                          SImpl::errorMessage(put, pb));
                }
            } else {
                http::CHeaders h;
                h.set("Content-Type", "application/octet-stream");
                http::SResponse put;
                rr = co_await s.request(e, "PUT", addQuery(location, "digest", d.digest), h, scopesOf(pushScope), put,
                                        [path, size, onProgress](http::SRequest& q) {
                                            q.setBodyStream(std::make_shared<FileRangeStream>(
                                                                CFd(::open(path.c_str(), O_RDONLY | O_CLOEXEC)), 0, size, onProgress),
                                                            int64_t(size));
                                        });
                if (rr != SBOX_OK) {
                    co_return rr;
                }

                std::string pb = co_await s.drainError(put);
                if (put.status != 201 && put.status != 204) {
                    co_return s.fail(SImpl::statusError(put.status), "uploading " + d.digest + ": " + SImpl::errorMessage(put, pb));
                }
            }

            ++res->blobsUploaded;
            s.progress(EPP_PUSHED, d.digest, d.mediaType, size, size);
            co_return SBOX_OK;
        };

        r = co_await RunConcurrently(blobs.size(), size_t(std::max(1, s.options.maxConcurrentUploads)), job);
        if (r != SBOX_OK) {
            co_return r;
        }

        // --> The manifest bytes go up unchanged so its digest stays the image's digest.
        std::string manifestBody;
        r = store.readBlob(info.manifestDigest, manifestBody, MANIFEST_LIMIT);
        if (r != SBOX_OK) {
            co_return s.fail(r, "reading manifest " + info.manifestDigest);
        }

        std::string mediaType = info.manifest.mediaType.empty() ? std::string(MT_OCI_MANIFEST) : info.manifest.mediaType;
        std::string tagOrDigest = ref.hasDigest() ? ref.digest : ref.tag;
        http::CHeaders h;
        h.set("Content-Type", mediaType);
        http::SResponse put;
        r = co_await s.request(*ep, "PUT", "/v2/" + ref.path + "/manifests/" + tagOrDigest, h, scopesOf(pushScope), put,
                               [manifestBody](http::SRequest& q) { q.setBody(manifestBody); });
        if (r != SBOX_OK) {
            co_return r;
        }

        std::string pb = co_await s.drainError(put);
        if (put.status != 201 && put.status != 200 && put.status != 202) {
            co_return s.fail(SImpl::statusError(put.status), "pushing the manifest: " + SImpl::errorMessage(put, pb));
        }

        std::string announced = put.headers.get("Docker-Content-Digest");
        if (!announced.empty() && announced != info.manifestDigest) {
            co_return s.fail(-EBADMSG, "the registry stored the manifest as " + announced + ", expected " + info.manifestDigest);
        }

        out.manifestDigest = info.manifestDigest;
        for (const SDescriptor& d : blobs) {
            s.recordSource(store, d.digest, ref.name());
        }

        s.progress(EPP_DONE, info.manifestDigest, mediaType, out.uploadedBytes, out.uploadedBytes, out.reference);
        co_return SBOX_OK;
    }

}
}
