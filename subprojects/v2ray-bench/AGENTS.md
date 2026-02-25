## Codex 行为约束（subprojects/v2ray-bench）

该子项目会对 **本机** 的 `v2ray.service` 做测速与切换：

- `v2ray-bench-nodes`：只测速、不改 `v2ray.service`
- `v2ray-bench-apply`：会写 `/usr/local/etc/v2ray/config.json` 并 `systemctl restart v2ray.service`
- `v2ray-bench-autoswitch`：可能触发 `v2ray-bench-apply`，从而重启 `v2ray.service`

### 强制规则（必须遵守）

1. 任何会触发 `v2ray.service` 重启的动作（`apply`/`autoswitch`/启用 autoswitch timer）都必须先明确告知用户“会中断现有连接”，并得到确认。
2. 不要把本子项目与 `v2ray_deploy` 的“本地模式订阅服务（--local True）”混为一谈：两者目标不同，前者是切换本机代理节点，后者是提供订阅链接。

