# 사용법

libsbox의 명령줄 도구로 이미지를 받아 컨테이너를 돌리고, Docker/containerd에 붙이고, 볼륨과 네트워크를
연결하는 방법입니다. 각 도구의 전체 옵션과 동작은 모듈 문서([oci.md](oci.md), [image.md](image.md),
[vol.md](vol.md), [net.md](net.md), [vpn-wg.md](vpn-wg.md))를 보십시오. 여기의 흐름은 `e2e` 테스트
([e2e.md](e2e.md))가 그대로 실행해 확인합니다.

| 도구 | 하는 일 |
|---|---|
| `sbox`, `sboxrun` | runc 호환 OCI 런타임(같은 바이너리, 이름만 다름). `sboxrun`은 dockerd/containerd 등록용 |
| `sbox-image` | 이미지 pull/push/load/save, 스냅샷, OCI 번들 만들기 |
| `sboxvol` | 이름 있는 볼륨 관리, 백업/복원, Docker 볼륨 플러그인 데몬 |
| `sboxnet` | Docker 원격 네트워크 + IPAM 플러그인 데몬 |
| `sbox-cni` | CNI 1.0 플러그인 |
| `sbox-wg` | WireGuard 인터페이스(커널 또는 사용자 공간), 키와 클라이언트 설정 |

## 빠른 시작

### 설치

```sh
git submodule update --init
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
sudo install -m 0755 build/bin/sbox build/bin/sboxrun build/bin/sbox-image build/bin/sboxvol \
     build/bin/sboxnet build/bin/sbox-wg /usr/local/bin/
sudo install -D -m 0755 build/bin/sbox-cni /opt/cni/bin/sbox-cni
```

### 이미지를 받아 `sbox`로 실행하기

```sh
# 1. 이미지 받기 (저장소: /var/lib/sbox/image, 프록시는 HTTPS_PROXY/NO_PROXY를 따름)
sudo sbox-image pull alpine:3.20
sudo sbox-image images

# 2. OCI 번들 만들기: DIR/config.json + DIR/rootfs (overlay를 쓸 수 있으면 overlay 마운트)
#    "--" 뒤는 이미지의 Cmd를 바꿉니다.
sudo sbox-image bundle alpine:3.20 /srv/c/hello -- /bin/echo hello
sudo sbox-image bundle --env MODE=prod --user nobody --read-only alpine:3.20 /srv/c/app -- /bin/sh -c 'id; env'

# 3. 전경 실행 (끝나면 컨테이너 상태를 지움; 종료 코드가 그대로 돌아옴)
sudo sbox run --bundle /srv/c/hello hello1

# 4. 분리 실행과 수명 주기 (runc와 같은 명령)
sudo sbox-image bundle alpine:3.20 /srv/c/web -- /bin/sleep 3600
sudo sbox create --bundle /srv/c/web web       # 상태 created (init가 start를 기다림)
sudo sbox start web                             # running
sudo sbox state web                             # runc 형식 JSON
sudo sbox exec web /bin/ps                      # 실행 중인 컨테이너에 프로세스 추가
sudo sbox list
sudo sbox kill web KILL
sudo sbox delete web                            # 멈춘 컨테이너 지우기 (실행 중이면 --force)
#    또는 한 번에: sudo sbox run --detach --bundle /srv/c/web web

# 5. 컨테이너 루트 정리 (overlay 언마운트 후 삭제)
sudo sbox-image ps
sudo sbox-image rm <ID>                         # bundle이 출력한 ID
```

- `sbox-image --snapshotter copy`는 overlay 대신 레이어를 한 디렉터리에 펼칩니다(overlay가 없는 커널,
  권한 없는 사용자). `docker save` 파일은 `sbox-image load -i image.tar`로, 내보내기는
  `sbox-image save -o image.tar alpine:3.20`입니다. 컨테이너 루트의 변경은
  `sbox-image commit <ID> myimage:1`로 새 이미지가 됩니다(overlay만).
- 사설 레지스트리: `--insecure-registry HOST:PORT`(검증 없는 HTTPS 후 HTTP), `--plain-http HOST:PORT`,
  인증서는 `/etc/docker/certs.d/<host:port>/`, 자격 증명은 `~/.docker/config.json`의 `auths`.
- rootless: 권한 없는 사용자도 같은 명령을 씁니다. 저장소는 `$XDG_DATA_HOME/sbox/image`, 상태는
  `$XDG_RUNTIME_DIR/sbox`이고, `bundle`이 자동으로 복사 스냅샷과 rootless 설정(자기 uid → 0 매핑)을
  고릅니다. 위임된 cgroup이 없으면 경고 후 cgroup 없이 실행합니다.

### dockerd / containerd에 `sboxrun` 등록

dockerd(`/etc/docker/daemon.json`):

```json
{
  "runtimes": { "sboxrun": { "path": "/usr/local/bin/sboxrun" } }
}
```

```sh
sudo systemctl reload docker        # 또는 restart
docker run --runtime=sboxrun --rm alpine echo hello
# 기본 런타임으로 쓰려면 daemon.json에 "default-runtime": "sboxrun"
```

containerd 2.x(`/etc/containerd/config.toml`, CRI):

```toml
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.sboxrun]
  runtime_type = "io.containerd.runc.v2"
  [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.sboxrun.options]
    BinaryName = "/usr/local/bin/sboxrun"
```

containerd 1.x는 `[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.sboxrun]`에 같은 값을 씁니다.
Kubernetes에서는 `RuntimeClass`(`handler: sboxrun`)로 고릅니다. `ctr`는
`ctr run --runc-binary /usr/local/bin/sboxrun ...`, nerdctl은 `nerdctl run --runtime /usr/local/bin/sboxrun ...`.

### 볼륨

```sh
sudo sboxvol create data                                     # /var/lib/sbox/volumes/data/_data
sudo sboxvol create --opt type=tmpfs --opt device=tmpfs --opt o=size=100m scratch
sudo sboxvol create --opt type=none --opt device=/srv/shared --opt o=bind shared
sudo sboxvol ls
sudo sboxvol inspect data
sudo sboxvol backup data /backup/data.tgz                    # 또는 - 로 표준 출력
sudo sboxvol restore --label restored=yes data2 /backup/data.tgz
sudo sboxvol rm data2
```

Docker 볼륨 플러그인으로 쓰기:

```sh
sudo sboxvol serve &                                         # /run/docker/plugins/sboxvol.sock
docker volume create -d sboxvol data
docker run --rm -v data:/data alpine sh -c 'echo hi > /data/x'
docker run --rm --mount type=volume,src=data,dst=/data,volume-driver=sboxvol alpine cat /data/x
```

`sbox` 번들에 볼륨 붙이기: `sbox`/`sbox-image bundle` 명령줄에는 `-v` 옵션이 없으므로 config.json의
`mounts`에 bind 항목을 넣습니다(디렉터리 볼륨의 `_data`를 그대로 씀). 라이브러리에서는
`vol::PrepareContainerMounts`가 `-v`/`--mount`/`--tmpfs` 문자열을 같은 항목으로 바꾸고, 볼륨을 만들고
(익명 포함), 이미지 내용을 copy-up하고, tmpfs/장치 볼륨을 마운트하며 사용자를 기록합니다.

```sh
DATA=$(sudo sboxvol inspect data | jq -r '.[0].Mountpoint')
jq --arg src "$DATA" '.mounts += [{"destination":"/data","type":"bind","source":$src,"options":["rbind","rw","rprivate"]},
                                  {"destination":"/scratch","type":"tmpfs","source":"tmpfs","options":["nosuid","nodev","noexec","size=64m"]}]' \
   /srv/c/app/config.json | sudo tee /srv/c/app/config.json.new >/dev/null && sudo mv /srv/c/app/config.json.new /srv/c/app/config.json
sudo sbox run --bundle /srv/c/app app1
```

(이렇게 직접 bind하면 볼륨의 사용자 기록이 남지 않으므로 tmpfs/NFS/장치 볼륨은 `sboxvol` 플러그인이나
라이브러리 경로로 붙이십시오.)

### 네트워크

#### Docker 네트워크 플러그인

```sh
sudo sboxnet &                                               # /run/docker/plugins/sboxnet.sock, 상태 /var/lib/sbox/net
docker network create -d sboxnet --ipam-driver sboxnet --subnet 10.10.0.0/24 sboxlan
docker run --rm --network sboxlan -p 8080:80 nginx
```

#### `sbox-cni` 설정 예

`/etc/cni/net.d/10-sbox.conflist`(containerd CRI, Podman, nerdctl이 읽음; 플러그인 바이너리는
`/opt/cni/bin/sbox-cni`):

```json
{
  "cniVersion": "1.0.0",
  "name": "podnet",
  "plugins": [
    {
      "type": "sbox-cni",
      "driver": "bridge",
      "bridge": "cni0",
      "ipMasq": true,
      "mtu": 1500,
      "stateDir": "/var/lib/sbox/net",
      "ipam": {
        "type": "sbox",
        "ranges": [[{ "subnet": "10.99.0.0/24", "rangeStart": "10.99.0.10", "gateway": "10.99.0.1" }]],
        "routes": [{ "dst": "0.0.0.0/0" }]
      },
      "capabilities": { "portMappings": true }
    }
  ]
}
```

물리 LAN 주소를 줄 때(macvlan, 정적 범위 또는 DHCP):

```json
{ "cniVersion": "1.0.0", "name": "lan", "type": "sbox-cni",
  "driver": "macvlan", "master": "eth0", "mode": "bridge",
  "ipam": { "type": "sbox", "subnet": "192.168.1.0/24", "rangeStart": "192.168.1.200",
            "rangeEnd": "192.168.1.220", "gateway": "192.168.1.1" } }
```

(`"ipam": { "type": "dhcp" }`이면 LAN의 DHCP 서버에서 받습니다.)

#### `sbox`로 만든 컨테이너를 네트워크에 붙이기

런타임은 runc처럼 네트워크를 만들지 않습니다. 네임스페이스를 먼저 만들어 CNI로 연결하고, 그 경로를
config.json에 넣습니다.

```sh
sudo ip netns add web                                         # /var/run/netns/web
sudo env CNI_COMMAND=ADD CNI_CONTAINERID=web CNI_NETNS=/var/run/netns/web CNI_IFNAME=eth0 \
     CNI_PATH=/opt/cni/bin /opt/cni/bin/sbox-cni < podnet.conf    # 단일 플러그인 설정(위 plugins[0]에 cniVersion, name 추가)
# 포트 매핑은 설정에 "runtimeConfig": {"portMappings": [{"hostPort": 8080, "containerPort": 80, "protocol": "tcp"}]}

sudo sbox-image bundle nginx:alpine /srv/c/web
jq '(.linux.namespaces[] | select(.type == "network")).path = "/var/run/netns/web"' /srv/c/web/config.json \
   | sudo tee /srv/c/web/config.json.new >/dev/null && sudo mv /srv/c/web/config.json.new /srv/c/web/config.json
sudo sbox run --detach --bundle /srv/c/web web
curl http://127.0.0.1:8080/

# 정리
sudo sbox delete --force web
sudo env CNI_COMMAND=DEL CNI_CONTAINERID=web CNI_NETNS=/var/run/netns/web CNI_IFNAME=eth0 \
     CNI_PATH=/opt/cni/bin /opt/cni/bin/sbox-cni < podnet.conf
sudo ip netns del web
```

라이브러리에서는 `net::CNetns::create`(또는 `createNamed`) + `net::CNetworkManager::connect(network, netnsPath,
...)`가 같은 일을 하며, 같은 netns를 `CSandbox`에도 `SBoxPolicy::network = EBNET_NAMESPACE`,
`netnsPath`로 넘길 수 있습니다.

### `sbox-wg`: 호스트 사이 WireGuard

두 호스트(A: 192.0.2.1, B: 192.0.2.2)를 터널(10.9.0.0/24)로 잇는 예입니다. 커널 `wireguard` 모듈이 있으면
커널 장치를, 없으면 사용자 공간 장치를 씁니다(사용자 공간이면 `up`이 전경에서 돌므로 서비스로 띄움).

```sh
# 각 호스트에서 키 만들기
sbox-wg genkey | tee a.key | sbox-wg pubkey > a.pub          # B에서는 b.key, b.pub

# A의 /etc/sbox/wg0.conf (wg-quick 형식)
[Interface]
PrivateKey = <a.key 내용>
Address = 10.9.0.1/24
ListenPort = 51820

[Peer]
PublicKey = <b.pub 내용>
Endpoint = 192.0.2.2:51820
AllowedIPs = 10.9.0.2/32, 10.210.2.0/24
PersistentKeepalive = 25

# 올리고 확인
sudo sbox-wg up /etc/sbox/wg0.conf            # 이름은 파일 이름(wg0), --mode kernel|userspace로 강제 가능
sudo sbox-wg show wg0
sudo sbox-wg showconf wg0
```

B도 같은 형식(Address 10.9.0.2/24, 피어는 A)으로 올립니다. 공식 앱(Windows/macOS/iOS/Android)용 클라이언트
설정은 `sbox-wg client-config --endpoint 192.0.2.1:51820 --address 10.9.0.10/32 --server-config
/etc/sbox/wg0.conf --append-to /etc/sbox/wg0.conf > phone.conf`로 만들고 `qrencode -t ansiutf8 < phone.conf`로
QR 코드로 옮깁니다.

#### 호스트 간 컨테이너 오버레이 (`wg-overlay` 드라이버)

여러 호스트의 컨테이너를 한 대역(예: 10.210.0.0/16)에 두려면 vpn 모듈의 `CWgOverlayDriver`를
`CNetworkManager`에 등록합니다. 각 호스트가 호스트 서브넷 하나(10.210.1.0/24, 10.210.2.0/24 ...)를 맡고,
다른 호스트를 WireGuard 피어로 둡니다. 지금은 라이브러리 API로 만듭니다(`sboxnet`/`sbox-cni`는 이 드라이버를
등록하지 않음). 사용자 공간 장치는 네트워크를 만든 프로세스에서 돌므로 오래 사는 데몬에서 만드십시오.

```cpp
net::SNetworkManagerOptions o;
o.stateDir = net::DefaultNetworkStateDir();
net::CNetworkManager mgr(o);
auto overlay = std::make_shared<vpn::CWgOverlayDriver>();
mgr.registerDriver(overlay);
co_await overlay->restore(mgr);                          // 재시작 뒤 기존 오버레이 장치 복구

vpn::SWgOverlayConfig c;                                  // 호스트 A
net::SIpPrefix::parse("10.210.1.0/24", c.hostSubnet);
vpn::SWgKey::fromBase64(myPrivateKeyBase64, c.privateKey);  // sbox-wg genkey로 만든 키
c.listenPort = 51820;
vpn::SWgOverlayHost b;
b.name = "host-b";
vpn::SWgKey::fromBase64(hostBPublicKeyBase64, b.publicKey);
b.endpoint = "192.0.2.2:51820";
net::SIpPrefix::parse("10.210.2.0/24", b.subnet);
b.persistentKeepalive = 25;
c.peers.push_back(b);

net::SIpPrefix overlayRange;
net::SIpPrefix::parse("10.210.0.0/16", overlayRange);
net::SNetworkCreate req;
vpn::MakeWgOverlayNetwork("ov", overlayRange, c, req);
net::SNetwork network;
co_await mgr.createNetwork(req, network);

// 컨테이너 연결은 브릿지와 같음: netns를 만들어 connect하고 config.json의 network 경로로 넘김
net::SEndpointCreate ep;
ep.containerId = "web";
net::SNetworkEndpoint out;
co_await mgr.connect("ov", "/var/run/netns/web", ep, out);
```

필드 이름과 실행 중 호스트 추가(`addHost`/`removeHost`), 설정 파일 형식(`sbox.wg.overlay.file`)은
[vpn-wg.md](vpn-wg.md)를 보십시오.

## CSandbox (라이브러리)

신뢰할 수 없는 프로그램 하나를 격리해 돌리는 C++ API는 README의 예제와 [box.md](box.md) 4장을 보십시오.
merged-/usr 호스트에서 `/usr`만 bind해도 `/bin`, `/lib*`가 따라오지만, `/etc`를 거치는 링크(예:
`/usr/bin/python3 -> /etc/alternatives/python3`)를 쓰는 프로그램은 `/etc`도 마운트해야 하므로
`SBoxPolicy::systemMounts()`(읽기 전용 `/usr`, `/bin`, `/sbin`, `/lib*`, `/etc`)에서 시작하는 것이 안전합니다.
