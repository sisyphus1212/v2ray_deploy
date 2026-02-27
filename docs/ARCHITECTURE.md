# v2ray_deploy 架构说明

## 1. 系统目标

本仓库主要做两件事：

1. 提供 vmess 订阅（核心接口：`/local-fast-ip`）。
2. （可选）在本机做 v2ray 节点测速/自动切换（子项目 `v2ray-bench`）。

## 2. 运行模式（最重要）

### 本地模式（默认推荐）

- 启动参数：`--local True`
- 只允许接口：`/local-fast-ip`
- 不应修改远端代理机配置，不执行远端 SSH 运维逻辑

### 远程模式（高风险）

- 启动方式：不传 `--local True`
- 会走远端执行器（SSH）、可能改远端 v2ray 配置/iptables/systemd
- 仅在明确确认目标主机后使用

---

## 3. 总体架构图

```mermaid
flowchart TD
  U[Client/订阅消费者] -->|HTTP :5000 /local-fast-ip| S[v2ray_deploy Flask 服务]
  S -->|读取| R[/root/CloudflareST/results.csv]
  T[v2ray-deploy-fastip.timer] --> F[v2ray-deploy-fastip.service]
  F --> G[scripts/get_fast_ip.sh]
  G --> R

  subgraph LocalHost[同一台主机]
    S
    T
    F
    G
    R
    V[v2ray.service 客户端]
  end

  B[v2ray-bench(可选)] -->|测速日志| L[/var/log/v2ray-bench.tsv]
  B -->|apply/autoswitch 时| V
  V -->|HTTP代理 127.0.0.1:8080| TG[https://api.telegram.org]
```

---

## 4. 模块与文件映射

### 4.1 订阅服务模块（v2ray_deploy）

- 真实入口：`app/proxy_mgt.py`
- 兼容入口：`proxy_mgt.py`（wrapper，转发到 `app/proxy_mgt.py`）
- systemd：
  - `systemd/v2ray-deploy-local.service`
  - `systemd/v2ray-deploy-fastip.service`
  - `systemd/v2ray-deploy-fastip.timer`
- 脚本：
  - `scripts/get_fast_ip.sh`（更新 CloudflareST 结果，支持本机下载/远端下载回传两种路径）
  - 顶层 `get_fast_ip.sh`（wrapper）

### 4.2 本机代理模块（v2ray 客户端）

- 配置文件：`/usr/local/etc/v2ray/config.json`
- 服务单元：`/etc/systemd/system/v2ray.service`（仓库模板：`systemd/v2ray.service`）
- 常见入站：
  - `127.0.0.1:8080`（本机 HTTP 代理探活入口）
  - `0.0.0.0:18080`（对外暴露代理入口，按需）

### 4.3 子项目模块（v2ray-bench）

- 目录：`subprojects/v2ray-bench`
- 二进制脚本：
  - `bin/v2ray-bench-nodes`
  - `bin/v2ray-bench-apply`
  - `bin/v2ray-bench-autoswitch`
  - `bin/v2ray-bench-show`
- 日志：`/var/log/v2ray-bench.tsv`
- systemd（可选）：
  - `v2ray-bench-nodes.timer`
  - `v2ray-bench-autoswitch.timer`

> 注意：`apply`/`autoswitch` 会改 `/usr/local/etc/v2ray/config.json` 并重启 `v2ray.service`。

---

## 5. 配置文件说明（重点）

### 5.1 `proxy_mgt.env` / `/etc/proxy_mgt.env`

核心字段（常用）：

- `PROXY_MGT_BIND`：订阅服务监听地址（如 `127.0.0.1` 或 `0.0.0.0`）
- `PROXY_MGT_PORT`：订阅服务端口（默认 `5000`）
- `PROXY_V2_UUID` / `PROXY_V2_ALTERID` / `PROXY_V2_CF_URI` / `PROXY_V2_CF_PORT`：生成 vmess 节点时使用
- `V2_ORDER_IP`：`/local-fast-ip` 拉取基础 vmess 模板时的可选来源

远程模式字段（高风险分支使用）：

- `PROXY_HOST_SSH_USER`
- `PROXY_HOST_ADD`
- `PROXY_HOST_SSH_PASSWORD`
- `PROXY_HOST_SSH_PORT`

### 5.2 v2ray 客户端配置

- `/usr/local/etc/v2ray/config.json`
- 由 v2ray 自身运行；若启用 `v2ray-bench-apply/autoswitch`，该文件会被动态更新

### 5.3 Fast IP 数据文件

- `/root/CloudflareST/results.csv`
- 由 `get_fast_ip.sh` 产出，`/local-fast-ip` 接口直接读取此文件
- 下载路径说明：
  - 默认（若远端目标已配置）：先在远端代理机下载，再通过 `scp` 拉回本机后执行
  - 若远端目标未配置：本机直接下载 CloudflareSpeedTest 并执行测速
  - 远端下载机来源：读取 `/etc/proxy_mgt.env` 中的 `PROXY_HOST_*` 字段（`PROXY_HOST_ADD`、`PROXY_HOST_SSH_PORT`、`PROXY_HOST_SSH_USER`、`PROXY_HOST_SSH_PASSWORD`）

---

## 6. 请求/数据流（本地模式）

1. `v2ray-deploy-fastip.timer` 定时触发 `v2ray-deploy-fastip.service`
2. service 调用 `scripts/get_fast_ip.sh`
3. 脚本更新 `/root/CloudflareST/results.csv`
4. 客户端访问 `http://<host>:5000/local-fast-ip`
5. Flask 读取 `results.csv` + 环境变量，拼接 vmess 列表返回

部署检查（fastip）：

1. `/etc/proxy_mgt.env` 中应包含完整的 `PROXY_HOST_*` 字段
2. `v2ray-deploy-fastip.service` 启动日志中应出现 `Remote target detected -> download on remote host then scp back`

### 6.1 get_fast_ip 下载分支

```mermaid
flowchart LR
  A[get_fast_ip.sh] --> B{PROXY_HOST_* 完整?}
  B -- No --> C[本机下载 CloudflareSpeedTest]
  B -- Yes --> D[远端代理机下载 CloudflareSpeedTest]
  D --> E[scp 回传到本机 /root/CloudflareST]
  C --> F[本机执行测速]
  E --> F
  F --> G[/root/CloudflareST/results.csv]
```

远端机器自动选择规则：

1. 脚本优先加载 `/etc/proxy_mgt.env`
2. 读取 `PROXY_HOST_ADD/PROXY_HOST_SSH_PORT/PROXY_HOST_SSH_USER/PROXY_HOST_SSH_PASSWORD`
3. 用该组参数执行远端 `wget`，再 `scp` 回本机

---

## 7. 验收基线（建议固定）

1. 订阅服务可用：
   - `curl http://127.0.0.1:5000/local-fast-ip | head`
2. 本机代理连通硬性条件：
   - `curl -I --max-time 15 -x http://127.0.0.1:8080 https://api.telegram.org/`
3. 对外代理端口监听（若要求暴露）：
   - `ss -lntp | grep ':18080 '`
4. systemd 状态：
   - `systemctl is-active v2ray`
   - `systemctl is-active v2ray-deploy-local.service`

---

## 8. 常见复杂点（避坑）

1. `--local True` 下 `/fast_ip`、`/allow-ip` 返回 404 是设计行为。
2. 本机访问正常但公网访问异常时，先核对公网 IP 是否对应当前机器。
3. `v2ray-bench` 的 `autoswitch` 会触发服务重启，必须在低峰执行或先确认业务影响。
4. 同机若有 Docker/其他服务占用 `8080`，请保持“本机探活端口”和“对外代理端口”分离。
5. 若 CloudflareST 看起来“卡死/跑很久”，优先排查 `scripts/get_fast_ip.sh`：
   - `timeout` 是否为 `1800`（30 分钟）
   - `-sl`（由 `--speed` 控制）是否为 `1`
   这两项过于激进（timeout 太小或 speed 阈值太高）会显著增加失败概率。
