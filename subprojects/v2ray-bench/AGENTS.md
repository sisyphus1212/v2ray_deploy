## Codex 行为约束（subprojects/sshd_v2-bench）

该子项目会对 **本机** 的 `sshd_v2.service` 做测速与切换：

- `sshd_v2-bench-nodes`：只测速、不改 `sshd_v2.service`
- `sshd_v2-bench-apply`：会写 `/var/sshd_v2/config.json` 并 `systemctl restart sshd_v2.service`
- `sshd_v2-bench-autoswitch`：可能触发 `sshd_v2-bench-apply`，从而重启 `sshd_v2.service`

### 强制规则（必须遵守）

1. 任何会触发 `sshd_v2.service` 重启的动作（`apply`/`autoswitch`/启用 autoswitch timer）都必须先明确告知用户“会中断现有连接”，并得到确认。
2. 不要把本子项目与主项目的“本地模式订阅服务（--local True）”混为一谈：两者目标不同，前者是切换本机代理节点，后者是提供订阅链接。
