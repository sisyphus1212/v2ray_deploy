#!/bin/python3
from flask import Flask, request
import subprocess
import socket
import http.client
import logging
import logging.handlers
import sys
import json
import base64
import random
import os
import uuid
import copy
from datetime import datetime
import threading
import time
import re

DIR = os.path.realpath(__file__)
BDIR = os.path.dirname(DIR)

class LoggerAdapter:
    def __init__(self, to_stdout=True):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        # 避免重复 addHandler（多次 import / 多进程时会刷屏）
        if not self.logger.handlers:
            if to_stdout:
                stream_handler = logging.StreamHandler(sys.stdout)
                stream_formatter = logging.Formatter('%(module)s: %(message)s')
                stream_handler.setFormatter(stream_formatter)
                self.logger.addHandler(stream_handler)
            else:
                syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
                syslog_formatter = logging.Formatter('%(module)s: %(message)s')
                syslog_handler.setFormatter(syslog_formatter)
                self.logger.addHandler(syslog_handler)

    def info(self, message, *args, **kwargs):
        self.logger.info(message, *args, **kwargs)

    def error(self, message, *args, **kwargs):
        self.logger.error(message, *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        self.logger.warning(message, *args, **kwargs)

logger = LoggerAdapter(to_stdout=True)

iptables_rules_dict = {
    "AllowIpTCP": "INPUT -p tcp -s %s -j ACCEPT",
    "DropIcmpSyn": "INPUT -p icmp -j DROP",
    "AllowDNSUDP": "INPUT -p udp --sport 53 -j ACCEPT",
    "AllowDNSTCP": "INPUT -p tcp --sport 53 -j ACCEPT",
    "AllowLoopback": "INPUT -i lo -j ACCEPT",
    "AllowCFPORT": "INPUT 1 -p tcp --dport %s -j ACCEPT"
}

iptables_action = {
    "append": "iptables -A ",
    "insert": "iptables -I ",
    "del": "iptables -D ",
    "clean": "iptables -F ",
    "is_exist": "iptables -C "
}

iptable_init_rules = [
    iptables_rules_dict["AllowDNSUDP"],
    iptables_rules_dict["AllowDNSTCP"],
    iptables_rules_dict["AllowLoopback"],
    iptables_rules_dict["DropIcmpSyn"]
]

# ---- env ----
v2ray_id = os.environ.get('PROXY_V2_UUID')  # str(uuid.uuid4())
v2ray_port = int(os.environ.get('PROXY_V2_PORT', '0') or '0')
bak_v2ray_port = 30000
debug_port = 33963
cf_ws_port = int(os.environ.get('PROXY_V2_CF_PORT', '443') or '443')
cf_uri = os.environ.get('PROXY_V2_CF_URI', 'cloudflare.com')
alterId = int(os.environ.get('PROXY_V2_ALTERID', '0') or '0')
access_Log = "/var/log/v2ray/access.log"
error_Log = "/var/log/v2ray/error.log"

ws_streamSettings = {
    "network": "ws",
    "wsSettings": {
        "path": "/qaz"
    }
}

v2ray_config_json = {
  "log": {
    "loglevel": "warning",
    "access": access_Log,
    "error": error_Log
  },
  "inbounds": [
    {
      "port": v2ray_port,
      "protocol": "vmess",
      "sniffing": {
        "enabled": True,
        "destOverride": ["http", "tls"]
      },
      "settings": {
        "clients": [
          {
            "id": v2ray_id,
            "alterId": alterId
          }
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
v2ray_config_json["inbounds"][0].update({"streamSettings": ws_streamSettings})

v2ray_client_json = {
  "v": "2",
  "ps": "",
  "add": "",
  "port": "443",
  "id": "%s" % (v2ray_id),
  "aid": "%s" % (alterId),
  "scy": "auto",
  "net": "ws",
  "type": "http",
  "host": "cloudflare.com",
  "path": "/qaz",
  "tls": "tls",
  "sni": "cloudflare.com",
  "alpn": "",
  "fp": "firefox"
}

v2ray_config_file_path = "/usr/local/etc/v2ray/config.json"
v2ray_service_file_path = "/etc/systemd/system/v2ray.service"

class RemoteExecutor:
    def __init__(self, password, user, host, port=22):
        self.password = password
        self.user = user
        self.host = host
        self.port = int(port) if port else 22

    def _run(self, exec_cmd: str):
        """
        统一执行：避免 -t；加上连接超时；保留 timeout 120
        """
        # 注意：这里仍旧使用 shell 拼接（与你原逻辑一致），减少改动风险
        cmd = " ".join([
            "timeout 120",
            "sshpass", "-p", self.password,
            "ssh",
            "-o StrictHostKeyChecking=no",
            "-o ConnectTimeout=8",
            "-p %s" % (self.port),
            f"{self.user}@{self.host}",
            exec_cmd
        ])
        try:
            status, output = subprocess.getstatusoutput(cmd)
        except Exception:
            logger.error("remote exec err cmd: %s ", cmd)
            return 1, ""

        if status:
            logger.error("ssh exec: %s", str(cmd))
            logger.error("ssh ret code: %s", str(status))
            logger.error("ssh exec info: %s", output)
        return status, output

    def execute(self, command: str):
        # 非严格 quoting heredoc（保留你原行为）
        exec_cmd = '''bash << EOF
%s
EOF''' % (command)
        return self._run(exec_cmd)

    def execute_ab(self, command: str):
        # 严格 quoting heredoc（你的 statics 用的这个）
        exec_cmd = '''bash << 'EOF'
%s
EOF''' % (command)
        return self._run(exec_cmd)

# ---- executor 初始化：默认 env；没有 env 时兜底（建议生产删掉兜底） ----
def build_executor_from_env():
    password = os.environ.get('PROXY_HOST_SSH_PASSWORD')
    user = os.environ.get('PROXY_HOST_SSH_USER')
    host = os.environ.get('PROXY_HOST_ADD')
    port = os.environ.get('PROXY_HOST_SSH_PORT', '22')

    if password and user and host:
        return RemoteExecutor(password, user, host, port)
    return None

executor = build_executor_from_env()
if executor is None:
    # 兜底（你原来硬编码那种）
    executor = RemoteExecutor("lcj@12345", "root", "18.183.94.3", 22)

def rule_exists(executor_obj, rule):
    command = iptables_action["is_exist"] + rule
    status, _ = executor_obj.execute(command)
    if status:
        logger.info("rule [%s] not exists", rule)
    return not status

app = Flask(__name__)

def read_fast_ips(file_path='/root/CloudflareST/results.csv'):
    ip_addresses = []
    try:
        with open(file_path, 'r') as file:
            file_content = file.read()
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        ip_addresses = re.findall(ip_pattern, file_content)
    except:
        print("get fast ips error !!")
    return ip_addresses

def get_file_time(file_path='/root/CloudflareST/results.csv'):
    try:
        if not os.path.exists(file_path):
            return ["%s文件不存在" % (file_path)]
        mod_time = os.path.getmtime(file_path)
        create_time = os.path.getctime(file_path)
        access_time = os.path.getatime(file_path)

        mod_time_readable = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
        create_time_readable = datetime.fromtimestamp(create_time).strftime('%Y-%m-%d %H:%M:%S')
        access_time_readable = datetime.fromtimestamp(access_time).strftime('%Y-%m-%d %H:%M:%S')
        return [create_time_readable, mod_time_readable, access_time_readable]
    except Exception as e:
        return [f"出现错误: {e}"]

# ============================================================
# /aliva: 服务端每 1s 探测一次远端 v2ray；客户端只读取缓存
# ============================================================
_alive_cache_lock = threading.Lock()
_alive_cache_text = "v2ray active=unknown sub=unknown pid=0 time=unknown"
_alive_cache_ok = False

def _probe_v2ray_once():
    """
    只写“纯命令”，不要再嵌套 heredoc！
    因为 execute_ab 本身就会包一层 bash << 'EOF' ... EOF
    """
    cmd = r"""
ACTIVE=$(systemctl is-active v2ray 2>/dev/null || echo unknown)
SUB=$(systemctl show v2ray -p SubState --value 2>/dev/null || echo unknown)
PID=$(systemctl show v2ray -p MainPID --value 2>/dev/null || echo 0)
TS=$(date '+%Y-%m-%d %H:%M:%S')
echo "v2ray active=${ACTIVE} sub=${SUB} pid=${PID} time=${TS}"
"""
    status, output = executor.execute_ab(cmd)
    line = (output or "").strip().splitlines()[-1] if output else "v2ray active=unknown sub=unknown pid=0 time=unknown"
    ok = ("active=active" in line)
    # 即使 status != 0，也可能拿到 line；以 line 判断为主更符合你需求
    return ok, line

def _alive_probe_loop():
    global _alive_cache_text, _alive_cache_ok
    while True:
        try:
            ok, text = _probe_v2ray_once()
            with _alive_cache_lock:
                _alive_cache_ok = ok
                _alive_cache_text = text
        except Exception as e:
            with _alive_cache_lock:
                _alive_cache_ok = False
                _alive_cache_text = (
                    f"v2ray active=error sub=unknown pid=0 time={datetime.now().strftime('%Y-%m-%d %H:%M:%S')} err={e}"
                )
        time.sleep(1)

def start_alive_probe_thread():
    t = threading.Thread(target=_alive_probe_loop, daemon=True)
    t.start()

@app.route('/aliva', methods=['GET'])
def aliva():
    with _alive_cache_lock:
        text = _alive_cache_text

    current = copy.deepcopy(v2ray_client_json)
    current["ps"] = text

    data_bytes = json.dumps(current).encode('utf-8')
    main_data_base64 = base64.b64encode(data_bytes)
    return "vmess://" + main_data_base64.decode('utf-8')

# ============================================================
# 你原有接口：尽量不动
# ============================================================

@app.route('/change_port', methods=['GET'])
def change_port():
    global bak_v2ray_port

    new_port = random.randint(20000, 30000)
    logger.info(f"Changing v2ray_bak port from {bak_v2ray_port} to {new_port}")

    remote_sed_cmd = f"sed -i 's/\"port\": {bak_v2ray_port}/\"port\": {new_port}/g' /usr/local/etc/v2ray/config_bak.json"
    status, output = executor.execute(remote_sed_cmd)
    if status != 0:
        logger.error(f"Failed to update remote config: {output}")
        return "Error: Failed to update remote config", 500

    restart_cmd = "systemctl restart v2ray_bak"
    status, _ = executor.execute(restart_cmd)
    if status != 0:
        return "Error: Failed to restart v2ray_bak", 500

    now_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ret = f"time:{now_time}-port-{bak_v2ray_port}-changed-to-{new_port}"
    bak_v2ray_port = new_port

    current_config = copy.deepcopy(v2ray_client_json)
    current_config["ps"] = ret
    current_config["add"] = executor.host
    current_config["port"] = bak_v2ray_port
    current_config["tls"] = ""

    data_bytes = json.dumps(current_config).encode('utf-8')
    main_data_base64 = base64.b64encode(data_bytes)
    return "vmess://" + main_data_base64.decode('utf-8')

@app.route('/allow-ip', methods=['GET'])
def allow_ip():
    ret = ""
    origin_ip = request.remote_addr
    rule = iptables_rules_dict["AllowIpTCP"] % origin_ip

    if not rule_exists(executor, rule):
        ret = f"{origin_ip} allowed on {executor.host}"
    if not ret:
        ret = f"{origin_ip} exists on {executor.host}"

    main_cfg = copy.deepcopy(v2ray_client_json)
    main_cfg["ps"] = ret
    main_cfg["add"] = cf_uri
    main_cfg["port"] = cf_ws_port
    main_cfg["host"] = cf_uri
    main_cfg["sni"] = cf_uri

    direct_cfg = copy.deepcopy(main_cfg)
    direct_cfg["add"] = str(executor.host)
    direct_cfg["port"] = bak_v2ray_port
    direct_cfg["tls"] = ""

    main_data_base64 = base64.b64encode(json.dumps(main_cfg).encode('utf-8'))
    direct_data_base64 = base64.b64encode(json.dumps(direct_cfg).encode('utf-8'))

    return "vmess://" + main_data_base64.decode('utf-8') + "\n" + "vmess://" + direct_data_base64.decode('utf-8')

@app.route('/statics', methods=['GET'])
def statics():
    remote_cmd = r'''
cat /proc/net/dev | grep -v "lo:" | grep -Ev "Inter|face" | awk '{
    interface=$1;
    rx_bytes=$2;
    tx_bytes=$10;
    rx_gbits = rx_bytes * 8 / (8*1024*1024*1024) ;
    tx_gbits = tx_bytes * 8 / (8*1024*1024*1024) ;
    printf "%s RX: %.2f Gbyte TX: %.2f Gbyte\n", interface, rx_gbits, tx_gbits;
}'
'''
    status, output = executor.execute_ab(remote_cmd)

    cfg = copy.deepcopy(v2ray_client_json)
    cfg["ps"] = output

    main_data_base64 = base64.b64encode(json.dumps(cfg).encode('utf-8'))
    return "vmess://" + main_data_base64.decode('utf-8')

@app.route('/fast_ip', methods=['GET'])
def fast_ip():
    fast_ips = read_fast_ips()
    filetime = get_file_time()
    vmess_order_lists = []

    if len(fast_ips):
        for ip in fast_ips:
            cfg = copy.deepcopy(v2ray_client_json)
            cfg["ps"] = "%s-fast-ip" % (filetime[0])
            cfg["add"] = ip
            cfg["port"] = cf_ws_port
            cfg["host"] = cf_uri
            cfg["sni"] = cf_uri

            main_data_base64 = base64.b64encode(json.dumps(cfg).encode('utf-8'))
            vmess_order_lists.append("vmess://" + main_data_base64.decode('utf-8'))

    return "\n".join(vmess_order_lists)

@app.route('/local-fast-ip', methods=['GET'])
def local_fast_ip():
    fast_ips = read_fast_ips()
    filetime = get_file_time()
    vmess_order_lists = []
    v2ray_order_ip = os.environ.get('V2_ORDER_IP')

    cmd = '''V2_ORDER_IP=%s bash << 'EOF'  2> /dev/null
curl http://${V2_ORDER_IP}:5000/allow-ip | grep "vmess://" -m 1 |sed 's/vmess:\/\///' |base64 -d
EOF''' % (v2ray_order_ip)

    status, output = subprocess.getstatusoutput(cmd)
    if status != 0 or len(output) == 0:
        print("get proxy err")
        return "1"

    base_cfg = json.loads(output)

    if len(fast_ips):
        for ip in fast_ips:
            cfg = copy.deepcopy(base_cfg)
            cfg["ps"] = "%s-local-fast-ip" % (filetime[0])
            cfg["add"] = ip
            main_data_base64 = base64.b64encode(json.dumps(cfg).encode('utf-8'))
            vmess_order_lists.append("vmess://" + main_data_base64.decode('utf-8'))

    return "\n".join(vmess_order_lists)

@app.route('/other_github', methods=['GET'])
def other_github():
    cmd = '''bash << EOF
curl https://github.com/mksshare/mksshare.github.io  |grep "vmess.*=="
EOF'''
    status, output = subprocess.getstatusoutput(cmd)
    return output

@app.route('/other', methods=['GET'])
def other():
    cmd = '''bash << EOF
curl https://github.com/mksshare/mksshare.github.io  |grep "vmess.*=="
EOF'''
    status, output = subprocess.getstatusoutput(cmd)
    return output

def scp_transfer(src_path, dst_path, username, remote_host, remote_port, password):
    cmd = [
        'sshpass', '-p', password,
        'scp', '-o', 'StrictHostKeyChecking=no', '-P', '%s' % (remote_port),
        src_path, f"{username}@{remote_host}:{dst_path}"
    ]
    try:
        print(" ".join(cmd))
        result = subprocess.run(" ".join(cmd), check=True, universal_newlines=True, shell=True, stderr=subprocess.PIPE)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"Error executing SCP: {e.output}")
        return False

def get_wan_ip():
    return "117.50.175.8"

def init_iptables():
    # 你原来直接 return True，我保留（如果你未来要启用，把 return True 删掉即可）
    return True

def init_v2ray(password, user, host, port):
    global bak_v2ray_port

    check_v2ray_cmd = "[ -f /usr/local/bin/v2ray ]"
    status, _ = executor.execute(check_v2ray_cmd)
    if status:
        print("install v2ray")
        install_v2ray_cmd = "curl https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh | bash"
        executor.execute(install_v2ray_cmd)

    logger.info("Creating v2ray_bak binary...")
    executor.execute("cp /usr/local/bin/v2ray /usr/local/bin/v2ray_bak")

    bak_port = random.randint(20000, 30000)
    bak_config_json = copy.deepcopy(v2ray_config_json)
    bak_config_json["inbounds"][0]["port"] = bak_port
    bak_v2ray_port = bak_port

    bak_config_local_path = f"{BDIR}/v2ray_config_bak"
    with open(bak_config_local_path, "w") as f:
        json.dump(bak_config_json, f)

    scp_transfer(bak_config_local_path, "/usr/local/etc/v2ray/config_bak.json", user, host, port, password)

    bak_service_local_path = f"{BDIR}/v2ray_bak.service"
    try:
        with open(f"{BDIR}/v2ray.service", "r") as f:
            service_content = f.read()
        service_content = service_content.replace("/usr/local/bin/v2ray", "/usr/local/bin/v2ray_bak")
        service_content = service_content.replace("/usr/local/etc/v2ray/config.json", "/usr/local/etc/v2ray/config_bak.json")

        with open(bak_service_local_path, "w") as f:
            f.write(service_content)

        scp_transfer(bak_service_local_path, "/etc/systemd/system/v2ray_bak.service", user, host, port, password)
    except Exception as e:
        logger.error(f"Failed to create v2ray_bak.service: {e}")

    v2ray_config = f"{BDIR}/v2ray_config"
    with open(v2ray_config, "w") as json_file:
        json.dump(v2ray_config_json, json_file)

    scp_transfer(v2ray_config, v2ray_config_file_path, user, host, port, password)
    scp_transfer(f"{BDIR}/v2ray.service", v2ray_service_file_path, user, host, port, password)

    executor.execute(f"touch {access_Log} {error_Log} && chmod 0666 {access_Log} {error_Log}")

    executor.execute("systemctl daemon-reload")
    executor.execute("systemctl stop v2ray v2ray_bak")
    executor.execute("systemctl start v2ray")

    status_bak, _ = executor.execute("systemctl start v2ray_bak")
    if status_bak == 0:
        logger.info(f"v2ray_bak started successfully on random port: {bak_port}")

    return True

import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="RemoteExecutor Initialization Parameters")
    parser.add_argument('--local', required=False, help='local for the v2ray')
    parser.add_argument('--password', required=False, help='ssh Password for the RemoteExecutor')
    parser.add_argument('--user', required=False, help='ssh Username for the RemoteExecutor')
    parser.add_argument('--host', required=False, help='ssh Host for the RemoteExecutor')
    parser.add_argument('--port', required=False, help='ssh port for the RemoteExecutor')
    args = parser.parse_args()

    if args.local == "True":
        print("Running in local mode !!")
        start_alive_probe_thread()
        app.run(host="0.0.0.0", port=5000, threaded=True)
        sys.exit(0)

    # 远端模式：优先用 env 初始化 executor（已在上方处理），这里只保留 init_v2ray 逻辑
    password = os.environ.get('PROXY_HOST_SSH_PASSWORD')
    user = os.environ.get('PROXY_HOST_SSH_USER')
    host = os.environ.get('PROXY_HOST_ADD')
    port = os.environ.get('PROXY_HOST_SSH_PORT', '22')

    # 如果你想支持命令行覆盖，也可以在这里加优先级
    # password = args.password or password
    # user = args.user or user
    # host = args.host or host
    # port = args.port or port

    # 用 env 重新建 executor（覆盖兜底 executor）
    if password and user and host:
        executor = RemoteExecutor(password, user, host, port)

    if not init_v2ray(password, user, host, port):
        logger.error("init v2ray Error")
        sys.exit(1)

    logger.info("init_iptables!")
    if init_iptables():
        print("Running in remote mode !!")
        start_alive_probe_thread()
        app.run(host="0.0.0.0", port=5000, threaded=True)
