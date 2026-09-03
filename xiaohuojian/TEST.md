# 测试清单

## Linux（无 Xcode）

- [x] `python3 ParserTests/test_parsers.py` — ss / vmess / vless / trojan / hy2 / socks / http 往返 + Clash YAML + Base64 订阅 + SIP008
- [x] `python3 -m py_compile ParserTests/parser_lib.py ParserTests/test_parsers.py scripts/generate_xcodeproj.py scripts/check_swift.py`
- [x] `python3 scripts/check_swift.py` — 每个 `.swift` 非空、括号配平
- [x] 工程已打包 `/workspace/xiaohuojian.zip`

## Mac / Xcode

- [ ] 打开 `XiaoHuoJian.xcodeproj` 无缺失文件引用
- [ ] 两个 target 都能选到同一个付费 Team
- [ ] App Group `group.app.xiaohuojian.vpn` 在 Signing 里显示正常
- [ ] 真机安装成功，扩展 `PacketTunnel.appex` 打进包内

## 真机功能

- [ ] 首页四个 Tab：首页 / 配置 / 数据 / 设置，中文深色
- [ ] 粘贴 `ss://`（chacha20 或 aes-256-gcm）保存并出现在节点列表
- [ ] 粘贴 `trojan://`、`vless://`、`vmess://`、`hy2://` 能解析
- [ ] 订阅 URL 更新后替换该分组
- [ ] TCP 延迟测试在节点右侧显示 ms
- [ ] 首次连接弹出 VPN 许可
- [ ] SS/Trojan 连接后，Safari 能打开网页（全局模式）
- [ ] 规则模式：`.cn` 等直连后缀不走节点；局域网排除
- [ ] 数据页会话/累计流量会变
- [ ] VMess/VLESS/HY2 连接时有明确提示（v1 原生不出站），且 App Group 出现 `sing-box.json`
- [ ] 模拟器：确认无法完整测 TUN（预期限制）

## 免费个人团队（预期失败）

- [ ] Personal Team 无法加载 Packet Tunnel 时，App 能显示可读错误而不是白屏
