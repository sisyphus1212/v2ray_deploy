## Codex 行为约束（v2ray_deploy）

本目录同时包含两种运行模式，风险等级完全不同：

- **本地模式（订阅服务）**：`--local True`  
  只提供订阅接口（当前仅开放 `/local-fast-ip`），不应对代理机做任何配置/重启操作。
- **远程模式（运维/配置）**：不传 `--local True`（即 `--local False` 语义）  
  可能通过 SSH/iptables/systemd 修改远端代理机配置与服务，风险高。

### 强制规则（必须遵守）

1. **每次涉及运行/部署/修改服务启动方式之前，必须先明确选择模式**：`--local True` 或 “远程模式（不带 --local True）”。不允许默认猜测。
2. **默认只能执行本地模式**。除非用户明确要求并确认，否则不得执行远程模式相关命令（包括启动远程模式的 systemd unit、执行会修改远端主机的脚本、运行 `proxy_mgt.py` 的远程分支等）。
3. 当用户选择远程模式时，必须二次确认目标代理机（例如 `PROXY_HOST_ADD/PROXY_HOST_SSH_PORT`）并提示会带来服务重启/iptables 改动的影响。

### 子项目提醒（v2ray-bench）

本仓库包含子项目 `subprojects/v2ray-bench`，它会对**本机**的 `v2ray.service` 做测速/切换：

- `apply`/`autoswitch` 会写 `/usr/local/etc/v2ray/config.json` 并重启 `v2ray.service`
- 因此任何涉及启用 `v2ray-bench-autoswitch.timer`、运行 `v2ray-bench-apply` 的操作，都必须先明确告知会短暂中断现有连接，并得到用户确认
