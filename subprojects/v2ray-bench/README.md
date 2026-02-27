# sshd_v2-bench：SSHD_V2 节点测速与一键切换（带日志）

该工程把两件事做成可复用的脚本，并支持可选的 systemd 定时自动化：

1) **测速（不影响现网业务）**：对订阅里的各个节点做下载测速，取最快前 N 条，追加写入 `/var/log/sshd_v2-bench.tsv`。  
2) **切换（让业务生效）**：从 `/var/log/sshd_v2-bench.tsv` 选择本轮第 1/2/… 名，把该节点写入 `/var/sshd_v2/config.json` 的 `outbound tag=proxy`，然后重启 `sshd_v2.service` 生效。

> 重要：  
> - **测速阶段**不会修改 `/var/sshd_v2/config.json`，也不会重启 `sshd_v2.service`。  
> - **切换阶段**需要重启 `sshd_v2.service`，会短暂中断现有连接（通常几秒级）。

---

## 目录结构

- `bin/sshd_v2-bench-nodes`：测速脚本（Python3）
- `bin/sshd_v2-bench-apply`：应用脚本（Python3）
- `bin/sshd_v2-bench-autoswitch`：测速+条件切换（Python3）
- `scripts/install.sh`：安装到 `/usr/local/bin`
- `scripts/uninstall.sh`：卸载
- `systemd/`：可选 systemd service/timer 模板

---

## 依赖与约定

- 运行环境：Linux + Python 3（本机已用 `python3` 验证）
- 需要命令：`sshd_v2`、`curl`、`systemctl`（应用阶段）
- 默认假设你的运行 SSHD_V2 配置在：`/var/sshd_v2/config.json`
- 默认日志文件：`/var/log/sshd_v2-bench.tsv`
- 订阅 URL：  
  - 未显式传 `--url` 时，`sshd_v2-bench-nodes` 会读取 `/var/sshd_v2/subscriptions.txt` 的第一行。  
  - 若 URL 临时不可用（如 503），会回退读取本地缓存：`/var/sshd_v2/subscription*.raw`（如果存在）。

---

## 安装

在该工程目录执行：

```bash
sudo ./scripts/install.sh
```

安装产物：

- `/usr/local/bin/sshd_v2-bench-nodes`
- `/usr/local/bin/sshd_v2-bench-apply`
- `/usr/local/bin/sshd_v2-bench-autoswitch`
- `/usr/local/bin/sshd_v2-bench-show`

可选：连同 systemd 定时任务一起“一键安装并启用”（二选一）：

```bash
sudo ./scripts/install.sh --with-systemd --enable-autoswitch
```

或只启用“定时测速”（不自动切换）：

```bash
sudo ./scripts/install.sh --with-systemd --enable-nodes
```

如果希望安装后立刻跑一轮（可能会切换并重启 `sshd_v2.service`，请在低峰执行）：

```bash
sudo ./scripts/install.sh --with-systemd --enable-autoswitch --run-once
```

---

## 使用：测速（不影响 sshd_v2.service）

默认跑完整订阅并输出最快前 5 名，同时把每轮最快前 5 名追加到 `/var/log/sshd_v2-bench.tsv`：

```bash
sudo sshd_v2-bench-nodes --top 5 --log-top 5 --show-ip
```

常用参数：

- `--url URL`：只测速某一个订阅 URL（不指定则读取 `/var/sshd_v2/subscriptions.txt` 的**所有** URL 逐个测速，并在所有节点里排序取最快）
- `--max-nodes N`：只测前 N 个节点（调试/快速）
- `--bytes BYTES`：测速下载大小（默认 2,000,000，越小越快、越不“占带宽”）
- `--timeout SECONDS`：每个节点测速最大耗时（默认 20）
- `--connect-timeout SECONDS`：连接超时（默认 8）
- `--log-file PATH`：日志输出文件（默认 `/var/log/sshd_v2-bench.tsv`）
- `--max-log-rows N`：日志最多保留最近 N 条数据行（默认 200，0=不限制）
- `--no-log`：不写日志（只输出到 stdout）
- `--refresh`：强制从 URL 拉订阅（不走本地缓存回退）

说明：

- `sshd_v2-bench-nodes` 的测速是通过“**临时启动一份独立 sshd_v2 进程**”（随机本地端口）实现，且会 `nice -n 19` 以降低对业务的 CPU 抢占。
- 但测速下载本身会占用带宽；如担心影响其它业务，请调小 `--bytes` 或减少 `--max-nodes`，或放到低峰运行。

---

## 使用：从日志选择并切换节点（让业务生效）

应用“最新一轮”的第 1 名（默认方法：直接使用 TSV 里的 `vmess_uri`，**避免订阅变化导致 idx 对不上**）：

```bash
sudo sshd_v2-bench-apply --rank 1
```

安全机制（默认开启）：

- **切换前预检**：会单独启动一个临时 `sshd_v2`（随机本地端口）去连接目标节点，并用代理请求 `https://www.google.com/generate_204` 探活；失败则不会切换
- **切换后验活+回滚**：切换并重启 `sshd_v2.service` 后，会再次探活；若失败则自动回滚到切换前的 `config.json` 并重启恢复

可选参数：

- `--no-preflight`：跳过切换前预检（不建议）
- `--no-rollback`：切换后探活失败不自动回滚（不建议）
- `--probe-url/--probe-timeout/--connect-timeout`：自定义探活

应用最新一轮第 2/3/4/5 名：

```bash
sudo sshd_v2-bench-apply --rank 2
```

只预演（不写配置、不重启服务）：

```bash
sudo sshd_v2-bench-apply --rank 1 --dry-run
```

切换会做的事：

1) 在 `/var/sshd_v2/config.json` 内找到 `outbound` 中 `tag=proxy` 的那一项  
2) 用 `vmess_uri` 解码出来的参数更新 `proxy` 的 `settings.vnext` 和 `streamSettings`  
3) 用 `sshd_v2 test -config` 校验新配置  
4) 备份原配置为：`/var/sshd_v2/config.json.bak-bench-<时间>-<round_id>`  
5) 原子替换 `config.json` 并 `systemctl restart sshd_v2.service`

锁：

- 为避免并发应用，脚本会使用锁文件：`/var/lock/sshd_v2-bench-apply.lock`

---

## 使用：自动测速 + 条件切换（仅更快才切）

该命令会做：

1) 运行一次 `sshd_v2-bench-nodes` 写入 `/var/log/sshd_v2-bench.tsv`（记录本轮最快前 N 名及完整 `vmess_uri`）
2) 再用当前正在运行的代理（`http://127.0.0.1:8080`）做一次同样的下载测速
3) 只有当“新最快节点速度”满足阈值条件，才会调用 `sshd_v2-bench-apply` 切换并重启 `sshd_v2.service`

示例（只要新最快 > 当前就切换）：

```bash
sudo sshd_v2-bench-autoswitch --min-delta-bps 1
```

示例（要求至少快 20% 才切换）：

```bash
sudo sshd_v2-bench-autoswitch --min-improvement 0.20
```

示例（要求至少快 300000 B/s 才切换）：

```bash
sudo sshd_v2-bench-autoswitch --min-delta-bps 300000
```

只预演（不切换）：

```bash
sudo sshd_v2-bench-autoswitch --dry-run
```

---

## 日志格式：/var/log/sshd_v2-bench.tsv

TSV 表头（脚本会自动补表头）：

- `round_id`：本轮唯一标识（时间+pid）
- `started_at`：本轮开始时间
- `url`：订阅 URL
- `rank`：本轮名次（1=最快）
- `idx`：节点在“本轮解析出的订阅列表”中的序号
- `addr/port`：节点地址与端口
- `http_code`：测速请求的 HTTP code
- `speed_Bps`：下载速度（Bytes/s）
- `time_s`：测速耗时（秒）
- `exit_ip`：出口 IP（`--show-ip` 才会填）
- `ps`：订阅备注
- `vmess_uri`：该节点的完整 `vmess://...`（敏感信息）

安全提醒：

- `vmess_uri` 内包含 UUID 等敏感信息，请限制 `/var/log/sshd_v2-bench.tsv` 的读取权限；如要避免落盘敏感信息，运行测速时加 `--no-log`。

---

## 可选：systemd 定时任务

工程内提供了模板（需要你自行安装到 `/etc/systemd/system/`）：

- 只测速：`systemd/sshd_v2-bench-nodes.service` + `systemd/sshd_v2-bench-nodes.timer`
- 自动测速并“条件切换”（仅当新最快比当前运行更快时才切换）：`systemd/sshd_v2-bench-autoswitch.service` + `systemd/sshd_v2-bench-autoswitch.timer`

安装示例（按需二选一）：

```bash
sudo cp -a ./systemd/sshd_v2-bench-nodes.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sshd_v2-bench-nodes.timer
```

或自动切换版本：

```bash
sudo cp -a ./systemd/sshd_v2-bench-autoswitch.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sshd_v2-bench-autoswitch.timer
```

说明：`sshd_v2-bench-autoswitch.service` 默认调用 `/usr/local/bin/sshd_v2-bench-autoswitch`，它会先跑一次测速写日志，然后对比“当前代理的测速速度”和“本轮最快节点速度”；只有当最快节点确实更快时才会调用 `sshd_v2-bench-apply` 切换并重启 `sshd_v2.service`。

查看执行日志：

```bash
sudo journalctl -u sshd_v2-bench-nodes.service -n 200 --no-pager
sudo journalctl -u sshd_v2-bench-autoswitch.service -n 200 --no-pager
```

---

## 常用排错

1) 日志无法写入 `/var/log/sshd_v2-bench.tsv`  
   - 用 `sudo` 跑 `sshd_v2-bench-nodes`，或改 `--log-file` 到可写路径。

2) `sshd_v2-bench-apply` 应用后代理短暂不可用  
   - `systemctl restart sshd_v2.service` 后通常需要 1–2 秒建立新连接，再 `curl` 测一次。

3) 想避免“订阅变化导致 idx 错位”  
   - 使用默认 `--method vmess`（已经是默认），它直接用 TSV 记录的 `vmess_uri` 应用。

---

## 许可

内部自用脚本，无额外许可声明（如需开源协议可再补）。
