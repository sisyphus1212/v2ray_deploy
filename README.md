项目目的:打造v2ray高级防封解决方案

# 安装依赖
pip install flask

# 云服务器部署方式
修改proxy_mgt.env中的主机信息和代理信息
cp proxy_mgt.env /etc/proxy_mgt.env
sh ./proxy-mgmt_init.sh

# 本地加速(wsl)
bash ./l_get_fast_ip_0.sh #公司网速限制的用这个
bash ./l_get_fast_ip_2.sh #公司网速限制大于5M的用这个
bash ./local_start_get.sh #没有网速限制的用这个

# 容器运行
TODO

# 订阅方式
### 云服务器订阅
假设运行proxy-mgmt_init.sh这个脚本的主机公网ip为:7.7.7.7
订阅链接为http://7.7.7.7:5000/allow-ip

### 本地加速订阅
订阅链接为http://127.0.0.1:5000/local-fast-ip
订阅链接为http://本机ip:5000/local-fast-ip


# 流量查询

TODO

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

(set -a; . /etc/proxy_mgt.env; set +a; env  /usr/bin/python3 /root/v2ray_deploy/proxy_mgt.py --password NONE --user NONE --host NONE --port NONE)
