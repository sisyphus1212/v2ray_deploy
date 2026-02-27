# sshd_v2 客户端部署逻辑（替代 v2ray）

## 目标

在客户端机器上使用本地二进制 `sshd_v2` 运行代理能力，替代默认 `v2ray`，并保持可运维、可回滚。

## 设计原则

1. 保留 systemd 管理，不手工后台跑进程。
2. 配置与二进制解耦：
   - 二进制：`/usr/local/bin/sshd_v2`
   - 配置：`/var/sshd_v2/config.json`
3. 明确运行用户，避免 root 常驻：
   - `User=ssh_v2`
   - `Group=ssh_v2`
4. 明确日志目录权限，避免“启动即失败”。

---

## 推荐部署步骤

### 1) 准备二进制

```bash
install -m 0755 ./sshd_v2 /usr/local/bin/sshd_v2
```

### 2) 准备配置目录

```bash
mkdir -p /var/sshd_v2
cp -f /root/v2ray_deploy/templates/sshd_v2/config.json.template /var/sshd_v2/config.json
```

然后按你的上游节点信息替换模板中的占位符：

- `REPLACE_SERVER_ADDRESS`
- `REPLACE_UUID`
- `REPLACE_SNI`
- `REPLACE_HOST`

示例（按实际值替换）：

```bash
sed -i 's/REPLACE_SERVER_ADDRESS/104.18.140.122/g' /var/sshd_v2/config.json
sed -i 's/REPLACE_UUID/e6485a9f-8641-4589-8166-ac6ed4680b4b/g' /var/sshd_v2/config.json
sed -i 's/REPLACE_SNI/1111.sisyphus12.eu.org/g' /var/sshd_v2/config.json
sed -i 's/REPLACE_HOST/1111.sisyphus12.eu.org/g' /var/sshd_v2/config.json
```

### 2.1) 准备订阅来源文件（给 bench/自动切换使用）

```bash
mkdir -p /var/sshd_v2
cat > /var/sshd_v2/subscriptions.txt << 'EOF'
http://127.0.0.1:5000/local-fast-ip
EOF
chmod 0644 /var/sshd_v2/subscriptions.txt
```

说明：

- 若 `sshd_v2-bench-nodes` 不传 `--url`，会默认读取 `/var/sshd_v2/subscriptions.txt`。
- 文件缺失时会报 `no subscription URLs found`，容易被误判为“订阅接口失效”。

### 3) 准备运行用户与权限

```bash
id -u ssh_v2 >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -M ssh_v2
chown -R ssh_v2:ssh_v2 /var/sshd_v2
chmod 0750 /var/sshd_v2
chmod 0640 /var/sshd_v2/config.json
```

### 4) 准备日志目录（关键）

配置里建议使用：

- `/var/log/ssh_v2/access.log`
- `/var/log/ssh_v2/error.log`

并创建权限：

```bash
mkdir -p /var/log/ssh_v2
touch /var/log/ssh_v2/access.log /var/log/ssh_v2/error.log
chown -R ssh_v2:ssh_v2 /var/log/ssh_v2
chmod 0750 /var/log/ssh_v2
chmod 0640 /var/log/ssh_v2/access.log /var/log/ssh_v2/error.log
```

### 5) 创建 systemd 服务

建议独立 unit：`/etc/systemd/system/sshd_v2.service`

```ini
[Unit]
Description=SSHD_V2 Service
After=network.target nss-lookup.target

[Service]
User=ssh_v2
Group=ssh_v2
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/bin/bash -lc "CFG=/var/sshd_v2/config.json /usr/local/bin/sshd_v2"
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
```

### 6) 启动与验证

```bash
systemctl daemon-reload
systemctl enable --now sshd_v2.service
systemctl is-active sshd_v2.service
ss -lntp | egrep ':44678 |:44679 '
curl -I --max-time 20 -x http://127.0.0.1:44678 https://api.telegram.org/
```

### 7) 可选：启用 Telegram APK 探活（每 10 秒）

```bash
cp -f /root/v2ray_deploy/systemd/sshd_v2-telegram-probe.service /etc/systemd/system/
cp -f /root/v2ray_deploy/systemd/sshd_v2-telegram-probe.timer /etc/systemd/system/
cp -f /root/v2ray_deploy/systemd/sshd_v2-probe-recover.service /etc/systemd/system/
chmod +x /root/v2ray_deploy/scripts/sshd_v2_telegram_probe.sh
chmod +x /root/v2ray_deploy/scripts/sshd_v2_probe_recover.sh
systemctl daemon-reload
systemctl enable --now sshd_v2-telegram-probe.timer
systemctl status sshd_v2-telegram-probe.timer --no-pager
journalctl -u sshd_v2-telegram-probe.service -n 20 --no-pager
tail -n 20 /var/log/sshd_v2-telegram-probe.log
```

说明：

- 探测地址：`https://api.openai.com/`
- 默认走代理：`http://127.0.0.1:44678`
- 只判定“可连通”：`curl` 返回非 `000` 即视为成功
- 若探活失败（service 返回非 0），会自动触发 `sshd_v2-probe-recover.service`：
  - 快速测速：`sshd_v2-bench-nodes --bytes 500000 --timeout 12 --max-nodes 5 --top 1`
  - 自动切换：`sshd_v2-bench-apply --rank 1 --method vmess`
  - 恢复日志：`/var/log/sshd_v2-probe-recover.log`

---

## 与服务端部署逻辑对齐的注意点（避免重复踩坑）

1. `systemctl status <oneshot service>` 显示 `inactive (dead)` 不等于失败；要区分 timer/oneshot 与常驻服务。
2. 改用户后最常见失败是日志权限不足（`permission denied`）；先修 `/var/log/ssh_v2` 权限。
3. 端口冲突要先查（例如 `8080` 常被 Docker 占用），不要盲目改监听。
4. 进程名显示有两层：
   - `argv[0]`（可用 `exec -a` 伪装）
   - `comm`（看 `ss` 常显示可执行名）
   若希望 `ss` 里显示 `sshd_v2`，应直接用 `/usr/local/bin/sshd_v2` 启动。
5. 若替换 `/usr/local/bin/v2ray`，必须先备份；推荐独立 `sshd_v2.service`，回滚更简单。

---

## 回滚策略

1. 停止并禁用 `sshd_v2.service`：

```bash
systemctl disable --now sshd_v2.service
```

2. 恢复原 `v2ray.service`（如果你有备份二进制）并启动：

```bash
systemctl restart v2ray
```

3. 验证监听与连通性恢复。
