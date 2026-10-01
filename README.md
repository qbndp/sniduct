# sniduct

Android 透明代理转发器：把 App 的 TCP/443 流量经手机侧 iptables DNAT 引到本机，提取 TLS SNI 后通过 HTTP CONNECT 隧道交给**任意**抓包代理（mitmproxy / Charles / Fiddler / Burp / 自建代理均可）。App 无感知、不需要 VPN 虚拟网卡，因此能绕过常见的 VPN / 代理检测。

```
App ──→ 手机 iptables DNAT ──→ 本机监听 (:8088)
                                      │
                                      ↓
                              读取 TLS ClientHello SNI
                                      │
                              Skip 域名 ──→ 直连真实服务器
                                      │
                                      ↓
                          CONNECT host:443 ──→ 上游抓包代理 (:auto)
```

本工具不绑定任何抓包软件：上游只要是一个能应答 `CONNECT` 的 HTTP 代理即可。

## 特点

- **纯控制台界面**：`rich` 彩色输出 + 交互式命令行，可脚本化、可 TTY/SSH 运行。
- **模块化**：config / adbkit / upstream / rules / forwarder / core / cli 各管一段。
- **自动适应地址 / 端口变化**：
  - `listen.host=auto`：每次启动自动探测「通往设备的本机地址」。
  - 固定 IP 失效时自动回落（`fallback_auto`）。
  - `upstream.port=auto`：采纳 `HTTPS_PROXY` / `HTTP_PROXY` 等环境变量，取不到再扫描候选端口，并且**只认真的能应答 HTTP CONNECT 的端口**——避免把手机流量灌给本机别的代理。
  - 后台巡检线程会跟随本机地址、上游代理地址变化热重绑。
- **安全清理**：只删除带 `SNIDUCT` 标记或形态明确属于自己的 DNAT / QUIC 规则，绝不 `iptables -F OUTPUT`；旧名字留下的规则也能被识别并清扫。

## 环境

- PC：Python ≥3.10、ADB（在 PATH 或配置里指定）、一个上游 HTTP 抓包代理
- 手机：已 Root，ADB 已连接，抓包代理的 CA 证书已装为系统信任证书（要 MITM 才需要）

## 安装与运行

> 注意：`uv sync` 只同步依赖，不会把 `sniduct` 命令注册到系统 PATH。首次使用请用 `uv run sniduct ...`；若想直接输入 `sniduct`，执行 `uv pip install -e .`。

```bash
# 克隆/进入项目后同步依赖
uv sync

# 方式一：每次用 uv run（推荐，不需要把包装到全局）
uv run sniduct doctor
uv run sniduct up

# 方式二：安装 editable 包到当前环境，之后可直接输入 sniduct
uv pip install -e .
sniduct doctor
sniduct up
```

## 快速开始

```bash
# 1. 先启动你的抓包代理（HTTP 代理端口，默认端口会被自动探测）

# 2. 检查环境
uv run sniduct doctor

# 3. 选择抓包范围：全部应用
uv run sniduct scope all
# 或者指定应用（先用 apps 查序号/包名）
uv run sniduct apps 淘宝
uv run sniduct scope com.taobao.taobao

# 4. 前台启动，Ctrl-C 停止并自动清理
uv run sniduct up
```

也可以进入交互式控制台：

```bash
uv run sniduct
# sniduct> doctor
# sniduct> scope all
# sniduct> up
# sniduct> stop
# sniduct> exit
```

## 上游代理怎么指定

三种方式，优先级从高到低：

```bash
# 1. 显式写死：最可控，探测失败也会照用（只报连通性错误）
uv run sniduct upstream 127.0.0.1:8080

# 2. 环境变量（仅在 upstream.host = auto 时生效）
export HTTPS_PROXY=http://127.0.0.1:8080

# 3. 自动扫描（默认）：候选端口里第一个能应答 HTTP CONNECT 的
uv run sniduct upstream auto
```

内置候选端口：`8080, 8888, 8081, 9090, 9000, 3128, 8118, 18080, 7890, 10809, 10808, 1080`。
可在配置里用 `upstream.probe_ports` 覆盖（比如只留你自己的端口，避免误命中别的代理）：

```bash
uv run sniduct upstream 8080          # 只指定端口，地址保持 auto
uv run sniduct config                  # 查看当前解析结果
```

自动命中的端口会连「来源」一起写进日志，方便你一眼确认选对了没有。

## 配置文件 `sniduct.json`

默认位置：仓库根目录 `sniduct.json`（源码模式）。已安装到环境里时回落到用户配置目录
（Windows `%APPDATA%\sniduct\sniduct.json`，其它平台 `$XDG_CONFIG_HOME/sniduct/sniduct.json`）。
也可以用环境变量 `SNIDUCT_CONFIG` 指定任意路径，或用 `-c/--config` 覆盖。

| 字段 | 说明 | 推荐值 |
|---|---|---|
| `listen.host` | 监听地址；`auto` 自动探测 | `auto` |
| `listen.port` | 监听端口 | `8088` |
| `listen.port_auto` | 端口被占用时自动挑空闲端口 | `false` |
| `listen.fallback_auto` | 固定 IP 失效时自动回落 | `true` |
| `upstream.host` | 上游代理地址；`auto` = 允许环境变量，缺省 `127.0.0.1` | `auto` |
| `upstream.port` | 上游代理端口；`auto` 自动探测 | `auto` |
| `upstream.probe_ports` | 自定义候选端口；空 = 用内置列表 | `[]` |
| `adb` | ADB 可执行文件路径 | `adb` |
| `device` | ADB 设备序列号；空则自动选第一个在线 | `""` |
| `target_apps` | `["*"]` 抓全部；`["com.x.y"]` 抓指定 | `["*"]` |
| `skip_snis` | 不交给抓包代理、直接透传的域名 | `[]` |
| `block_quic` | 拦截 UDP/443，逼 App 回落 TCP | `true` |

模板见仓库里的 `sniduct.example.json`；`sniduct.json` 本身已被 `.gitignore` 忽略（含设备序列号等本机信息）。

### 命令行直接改配置

```bash
uv run sniduct listen auto                # 自动探测
uv run sniduct listen 192.168.1.5:8088    # 固定地址
uv run sniduct upstream 8080              # 固定上游端口
uv run sniduct skip add security.xxx.com
uv run sniduct quic off
```

## 命令速查

| 命令 | 作用 |
|---|---|
| `sniduct` | 进入交互式控制台 |
| `sniduct up` | 前台启动转发 |
| `sniduct stop` | 停止并清理规则（等价 `exit`） |
| `sniduct doctor` | 环境自检 |
| `sniduct status --deep` | 状态 + 手机 iptables 现状 |
| `sniduct apps [关键字] [-n 10]` | 列出应用 |
| `sniduct scope all / none / <包名...>` | 设置抓包范围 |
| `sniduct skip add / rm <域名>` | 管理 Skip 域名 |
| `sniduct device [序列号]` | 查看/切换设备 |
| `sniduct listen [host][:port]` | 设置监听地址 |
| `sniduct upstream [host][:port]` | 设置上游代理地址 |
| `sniduct nat` | 查看手机 nat OUTPUT |
| `sniduct clean` | 仅清理本工具的残留规则 |
| `sniduct watch` | 实时状态面板，按 `q` 退出 |

## 换网 / IP 变了怎么办

- `listen.host=auto` 时，每次启动和后台巡检都会重新探测可用地址，DNAT 会自动跟到新地址。
- `upstream.host=auto` 时，环境变量与候选端口都会重新解析；上游代理换端口也不用改配置。
- 如果固定了地址或端口，但发现连不上，先执行 `uv run sniduct doctor` 看哪一步失败。

## 强制退出后的残留规则

正常 `Ctrl-C` 会触发清理。若用任务管理器、`-Force` 强杀等导致规则残留，执行：

```bash
uv run sniduct clean
```

## 常见问题

- **抓不到包**：先 `doctor` 确认「上游代理可连接」；再确认设备上装的是**抓包代理自己的** CA 证书（系统信任区），且 `block_quic=true` 已让 App 回落 TCP。
- **能连上但流量没进代理**：本机可能同时开着多个代理，自动扫描命中了别的端口——用 `sniduct upstream <host:port>` 写死，或把 `upstream.probe_ports` 收窄成你自己的端口。
- **设备换了、配置里序列号失效**：会自动改用第一个在线设备并写回配置；也可以 `sniduct device <序列号>` 手动切。
