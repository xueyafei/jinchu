# 小火箭

个人侧载用的 iOS VPN / 代理客户端（**不是** App Store 产品，也**没有**内置服务器）。你自己粘贴 `ss://`、订阅链接或手动填节点。

本仓库是在 **Linux、没有 Xcode / 没有 iOS SDK** 的机器上写的源码与工程文件，**不能在这台电脑上编译或真机运行**。请把项目拷到 Mac，用 Xcode 打开。

## 它能做什么

- 中文界面，深色分组列表，首页大开关 + 当前节点延迟与流量（原创 UI，未使用任何商业客户端的图标或美术资源）。
- 解析并保存：`ss://`、`vmess://`、`vless://`、`trojan://`、`hysteria2://` / `hy2://`、`socks://`、`http://`。
- 订阅：Base64 URI 列表、Clash YAML（`proxies`）、SIP008 JSON。
- 连接模式：全局 / 规则 / 直连；规则为 PROXY / DIRECT / REJECT（域名后缀、关键词、完整域名、IP CIDR）；精简国内直连后缀，**不附带巨大 geoip.dat**。
- App 通过 `NETunnelProviderManager` 安装并启动 Packet Tunnel；首次连接会弹出系统 VPN 许可。
- 扩展读取 App Group（`group.app.xiaohuojian.vpn`）里的 `tunnel-config.json`，并写出 `sing-box.json`。

## v1 隧道在设备上真正转发什么

**已接线、可走 TCP 的出站：**

| 协议 | 说明 |
|------|------|
| Shadowsocks AEAD | `chacha20-ietf-poly1305`、`aes-256-gcm`、`aes-128-gcm`（CryptoKit + HKDF-SHA1） |
| Trojan | TLS + SHA224 握手，TCP |
| SOCKS5 / HTTP CONNECT | 含可选用户名密码 |
| 直连 | 规则命中 DIRECT 或连接模式=直连 |

数据面是扩展内的用户态 IPv4/TCP 中继（SYN 跟踪、把载荷交给出站）。UDP 仅把 **53 端口 DNS** 旁路到你配置的 DNS。这不是完整内核 TCP/IP 栈（乱序重传、窗口缩放有限），浏览 HTTPS 等常见 TCP 应用是它的目标。

**只解析 + 写入 sing-box JSON，v1 原生不出站：**

- VMess、VLESS、Hysteria2：配置页可保存，连接时会提示该类型需 libbox。把 `Libbox.xcframework` 丢进工程后，让扩展加载 App Group 里的 `sing-box.json` 即可（见 `Vendor/README.md`）。

不要指望模拟器测 TUN：Simulator **不能**完整测试 Packet Tunnel。

## 付费开发者账号 vs 免费 Personal Team

Packet Tunnel（`packet-tunnel-provider` Network Extension）**通常需要加入 Apple Developer Program 的付费账号**。免费 Personal Team 往往签不出带 Network Extension 的 App，表现为：

- 无法安装扩展，或一连接就 `configurationInvalid`
- 系统设置里看不到 VPN 开关

请在 Xcode 里把 **XiaoHuoJian** 和 **PacketTunnel** 两个 target 的 Team 都设成同一个付费团队，并确认 App Group `group.app.xiaohuojian.vpn` 已在开发者后台启用。

## 在 iPhone 上运行

1. 把本目录拷到 Mac（或解压 `xiaohuojian.zip`）。
2. 双击 `XiaoHuoJian.xcodeproj`。若你安装了 [XcodeGen](https://github.com/yonaskolb/XcodeGen)，也可以 `xcodegen generate` 用 `project.yml` 重新生成工程。
3. 选中两个 target → Signing & Capabilities → 选择你的 **Team**（付费）。必要时用 Xcode 自动管理签名。
4. 用数据线连接 iPhone，信任此电脑；在手机上信任该开发者证书（设置 → 通用 → VPN 与设备管理）。
5. 顶部 Run 目标选 **XiaoHuoJian** 和你的真机，点运行。
6. 打开 App → 配置 → 代理，添加节点（见下）→ 回首页打开大开关 → 系统弹出「允许 VPN」时点允许。

## 添加节点

**粘贴分享链接（推荐）**

- 配置 → 代理 → 「+」→ 粘贴分享链接，一行一个，例如：
  - `ss://aes-256-gcm:password@203.0.113.10:8388#家里`
  - `trojan://password@host:443?sni=host#TJ`
- 或在「添加节点」表单顶部把整段 URI 填进去点「从链接填充」。

**订阅**

- 配置 → 订阅 → 添加 `https://…` 订阅 URL。
- 支持：整页 Base64 后是一堆 URI；Clash YAML 的 `proxies:`；SIP008 JSON。
- 更新订阅会 **替换该订阅分组** 下的节点，不影响你手动添加的其它分组。

**手动表单**

覆盖 SS / VMess / VLESS / Trojan / Hysteria2 / SOCKS5 / HTTP 的常用字段（服务器、端口、密码或 UUID、TLS/SNI、ws path 等）。

## 工程结构

```
App/            SwiftUI 主程序（首页 / 配置 / 数据 / 设置）
PacketTunnel/   NEPacketTunnelProvider + TCP 中继 + 出站
Shared/         模型、URI 解析、存储、规则、sing-box JSON
ParserTests/    可在 Linux 上跑的 Python 解析测试
Vendor/         后续 libbox / hev-socks5-tunnel 说明（v1 未克隆大仓库）
project.yml     XcodeGen 规格
XiaoHuoJian.xcodeproj  已生成，可直接打开
```

标识符：

- App：`app.xiaohuojian.vpn` 显示名「小火箭」
- 扩展：`app.xiaohuojian.vpn.tunnel`
- App Group：`group.app.xiaohuojian.vpn`

## Linux 上自检（本机已跑过）

```bash
python3 ParserTests/test_parsers.py
python3 -m py_compile ParserTests/*.py scripts/*.py
python3 scripts/check_swift.py
```

## 安全与使用边界

- 仅供你自己的节点、自己的设备。没有流量劫持、没有越狱工具、没有扫描别人的服务。
- 加密实现用系统 CryptoKit / CommonCrypto，没有拷贝专有客户端代码。
