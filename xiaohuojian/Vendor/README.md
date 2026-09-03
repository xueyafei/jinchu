# Vendor

v1 不内置第三方核心源码。

## 当前数据面（已接线）

Packet Tunnel 扩展内是原创的用户态 IPv4/TCP 中继：

- 出站：Shadowsocks AEAD（`chacha20-ietf-poly1305`、`aes-256-gcm`、`aes-128-gcm`，CryptoKit）
- 出站：Trojan（TLS + SHA224 握手）
- 出站：SOCKS5、HTTP CONNECT、直连
- DNS UDP/53 旁路到配置的 DNS

连接时会把 `sing-box.json` 写到 App Group 容器。

## 以后接入 libbox / sing-box

1. 用官方或自编译的 `Libbox.xcframework`（不要把整棵巨大仓库拷进本项目）。
2. 在 `PacketTunnelProvider.startTunnel` 里启动 libbox，让它读取 App Group 里的 `sing-box.json`。
3. 可以关掉 Swift TCP 中继（`PacketLoop`）。

VMess / VLESS / Hysteria2 已解析并写入 sing-box JSON，原生 Swift 出站尚未实现，必须等 libbox 或自行补协议。

## 可选：hev-socks5-tunnel

若要把 TUN→SOCKS 换成成熟 C 栈：把 [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) 源码放进 `Vendor/hev-socks5-tunnel`，在扩展 target 编译，并在本机起一个 SOCKS5 inbound，把现有 SS/Trojan 客户端接到该 inbound。体积比 libbox 小，但仍需在 Mac 上用 Xcode 编 C。

本仓库故意不克隆该仓库，以免在无 iOS SDK 的 Linux 上留下无法验证的巨大依赖。
