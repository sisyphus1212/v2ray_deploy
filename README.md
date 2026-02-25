# v2ray_deploy

该项目用于生成/提供 vmess 订阅（包含 fast_ip/local-fast-ip 等），并支持两种运行模式：

- **本地模式（订阅服务）**：`--local True`（推荐在本机使用）
- **远程模式（运维/配置）**：不带 `--local True`（会改远端代理机配置，谨慎使用）

> 注意：请不要让两个实例同时跑“远程模式”去管理同一台代理机，否则会互相抢配置。

## 子项目：v2ray-bench（本机测速/自动切换）

本仓库内还包含子项目 `subprojects/v2ray-bench`，它解决的是另一件事：

- `v2ray_deploy`：提供订阅服务（本地模式仅 `/local-fast-ip`），不负责切换本机 `v2ray.service` 的节点
- `v2ray-bench`：对**本机** `v2ray.service` 做节点测速，并支持“仅当更快才切换”的自动更新（会重启 `v2ray.service`）

常见混淆点：

- 你把客户端订阅指向 `v2ray_deploy`，只是“拿到一串 vmess 节点”；真正切换到哪个节点，需要用 `v2ray-subscribe` 或 `v2ray-bench-apply`
- `v2ray-bench-autoswitch` 可能会重启本机 `v2ray.service`，会短暂中断现有连接（通常几秒）

#原理
```
代理配置服务：proxy-mgmt.service
cf快速ip定期获取服务：cloudflare_fast_ip.service
```

# 目录结构（已整理）

- `app/proxy_mgt.py`：Flask 服务主程序（真实实现）
- `proxy_mgt.py`：兼容入口（wrapper，供已有 systemd/脚本继续使用）
- `scripts/`：脚本（真实实现）
- `*.sh`：兼容入口（wrapper）
- `systemd/`：systemd unit 模板
- `env/`：示例配置/模板

# 安装依赖（推荐 ~/.env）
建议用 venv（系统 Python 可能启用了 PEP668，禁止直接 `pip3 install` 到全局环境）：

```bash
python3 -m venv ~/.env
~/.env/bin/pip install flask
```

# 本地模式（推荐）：只提供 /local-fast-ip

本地模式下服务仅开放：

- `http://127.0.0.1:5000/local-fast-ip`

其它接口（如 `/fast_ip`、`/aliva`）会返回 404，避免本机承担远程运维/配置功能。

# 本地加速(wsl)
export V2_ORDER_IP="x.x.x.x"

bash ./l_get_fast_ip_0.sh #公司网速限制的用这个

bash ./l_get_fast_ip_2.sh #公司网速限制大于5M的用这个

bash ./l_get_fast_ip_no_limit.sh #没有网速限制的用这个

# 容器运行
TODO

# 订阅方式
### 云服务器订阅
假设运行proxy-mgmt_init.sh这个脚本的主机公网ip为:7.7.7.7

订阅链接为http://7.7.7.7:5000/allow-ip

### 本地加速订阅（本地模式）
订阅链接为http://127.0.0.1:5000/local-fast-ip

订阅链接为http://本机ip:5000/local-fast-ip

## 本机部署（systemd，自启动）

### 1) 准备环境变量文件

修改 `proxy_mgt.env` 后复制为：

```bash
sudo cp -a ./proxy_mgt.env /etc/proxy_mgt.env
```

建议只监听本机回环地址（避免把订阅暴露到局域网/公网）：

```bash
echo 'PROXY_MGT_BIND=127.0.0.1' | sudo tee -a /etc/proxy_mgt.env
echo 'PROXY_MGT_PORT=5000' | sudo tee -a /etc/proxy_mgt.env
```

### 2) 安装依赖
推荐用 venv（同上，示例使用 `~/.env`）：

```bash
python3 -m venv ~/.env
~/.env/bin/pip install flask
```

### 3) 安装并启用 systemd 服务

```bash
sudo cp -a ./systemd/v2ray-deploy-local.service /etc/systemd/system/
sudo cp -a ./systemd/v2ray-deploy-fastip.service /etc/systemd/system/
sudo cp -a ./systemd/v2ray-deploy-fastip.timer /etc/systemd/system/
sudo systemctl daemon-reload

# 定时更新 CloudflareST results.csv（生成 /root/CloudflareST/results.csv）
sudo systemctl enable --now v2ray-deploy-fastip.timer

# 启动本地订阅服务（Flask）
sudo systemctl enable --now v2ray-deploy-local.service
```

首次建议手动跑一轮 fast ip 生成（用于驱动 `/local-fast-ip` 的 IP 列表）：

```bash
sudo systemctl start v2ray-deploy-fastip.service
```

### 4) 验证

```bash
curl -s http://127.0.0.1:5000/local-fast-ip | head
```

查看日志：

```bash
sudo journalctl -u v2ray-deploy-local.service -n 200 --no-pager
sudo journalctl -u v2ray-deploy-fastip.service -n 200 --no-pager
```

# v2ray 代理状态监测
TODO

# 流量查询
订阅链接为http://7.7.7.7:5000//statics

# IP 切换

TODO

# 区域切换

TODO

# 客户端测速地址修改

```
将guiConfigs/guiNConfig.json http 测试链接改成这个

https://codeload.github.com/qemu/qemu/tar.gz/refs/tags/v1.6.0-rc2
```

# DEBUG

(set -a; . /etc/proxy_mgt.env; set +a; env  ~/.env/bin/python /root/v2ray_deploy/proxy_mgt.py --local True)
