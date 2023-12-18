项目目的:打造v2ray高级防封解决方案

# 部署方式

运行sh ./proxy-mgmt_init.sh
修改proxy_mgt.env中的主机信息

# 订阅方式

假设运行proxy-mgmt_init.sh这个脚本的主机公网ip为:7.7.7.7
订阅链接为http://7.7.7.7:5000//allow-ip

# 流量查询

TODO

# IP 切换

TODO

# 区域切换

TODO

# 客户端测速地址修改

```
guiConfigs/guiNConfig.json
```

https://codeload.github.com/qemu/qemu/tar.gz/refs/tags/v1.6.0-rc2

# debug

(set -a; . /etc/proxy_mgt.env; set +a; env  /usr/bin/python3 /root/v2ray_deploy/proxy_mgt.py --password NONE --user NONE --host NONE --port NONE)
