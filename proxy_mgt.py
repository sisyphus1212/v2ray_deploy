#!/bin/python3
from flask import Flask, request
import subprocess
import socket
import http.client
import logging                 # ✅ FIX: 你原来漏了这个，会直接 NameError
import logging.handlers
import sys
import json
import base64
import random
import os
import uuid
import copy
from datetime import datetime

DIR = os.path.realpath(__file__)
BDIR = os.path.dirname(DIR)

class LoggerAdapter:
    def __init__(self, to_stdout=True):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        # ✅ FIX(非逻辑改动): 防止多次初始化重复加 handler 导致日志重复
        if self.logger.handlers:
            return

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

# 创建logger实例
logger = LoggerAdapter(to_stdout=True)

iptables_rules_dict = {
    "AllowIpTCP": "INPUT -p tcp -s %s -j ACCEPT",
    #"DropTCPSyn": "INPUT -p tcp --syn -j DROP",
    "DropIcmpSyn": "INPUT -p icmp -j DROP",
    "AllowDNSUDP": "INPUT -p udp --sport 53 -j ACCEPT",
    "AllowDNSTCP": "INPUT -p tcp --sport 53 -j ACCEPT",
    "AllowLoopback": "INPUT -i lo -j ACCEPT",
    "AllowCFPORT": "INPUT 1 -p tcp --dport %s -j ACCEPT"
}

iptables_action = {
    "append" : "iptables -A ",
    "insert" : "iptables -I ",
    "del" : "iptables -D ",
    "clean" : "iptables -F ",
    "is_exist": "iptables -C "
}

iptable_init_rules = [
    iptables_rules_dict["AllowDNSUDP"],
    iptables_rules_dict["AllowDNSTCP"],
    iptables_rules_dict["AllowLoopback"],
    #iptables_rules_dict["DropTCPSyn"],
    iptables_rules_dict["DropIcmpSyn"]
]

v2ray_id = os.environ.get('PROXY_V2_UUID') #str(uuid.uuid4())
v2ray_port = int(os.environ.get('PROXY_V2_PORT')) #random.randint(10000,40000)
bak_v2ray_port = 30000
debug_port = 33963 #random.randint(10000,40000)
cf_ws_port = int(os.environ.get('PROXY_V2_CF_PORT'))
cf_uri = os.environ.get('PROXY_V2_CF_URI')
alterId = int(os.environ.get('PROXY_V2_ALTERID')) #random.randint(20,100)
access_Log = "/var/log/v2ray/access.log"
error_Log = "/var/log/v2ray/error.log"

tcp_streamSettings = {
    "network": "tcp",
    "tcpSettings": {
        "header": {
        "type": "http",
        "response": {
            "version": "1.1",
            "status": "200",
            "reason": "OK",
            "headers": {
            "Content-Type": ["application/octet-stream", "application/x-msdownload", "text/html", "application/x-shockwave-flash"],
            "Transfer-Encoding": ["chunked"],
            "Connection": ["keep-alive"],
            "Pragma": "no-cache"
            }
        }
        }
    }
}

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
  "inbounds":[
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
      },
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
  "id": "%s"%(v2ray_id),
  "aid": "%s"%(alterId),
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
        self.port = port

    def execute(self, command):
        exec_cmd = '''bash << EOF
%s
EOF'''%(command)
        cmd = " ".join(["timeout 120 sshpass", "-p", self.password,
                        "ssh -o StrictHostKeyChecking=no -p %s -t"%(self.port),
                        f"{self.user}@{self.host}", exec_cmd])
        status, output = 1, 0
        try:
            status, output = subprocess.getstatusoutput(cmd)
        except:
            logger.error("remote exec err cmd: %s ", cmd)

        if status:
            logger.error("ssh exec: %s", str(cmd))
            logger.error("ssh ret code: %s", str(status))
            logger.error("ssh exec info: %s", output)
        return status, output

    def execute_ab(self, command):
        exec_cmd = '''bash << 'EOF'
%s
EOF'''%(command)
        cmd = " ".join(["timeout 120 sshpass", "-p", self.password,
                        "ssh -o StrictHostKeyChecking=no -p %s -t"%(self.port),
                        f"{self.user}@{self.host}", exec_cmd])
        status, output = 1, 0
        try:
            status, output = subprocess.getstatusoutput(cmd)
        except:
            logger.error("remote exec err cmd: %s ", cmd)

        if status:
            logger.error("ssh exec: %s", str(cmd))
            logger.error("ssh ret code: %s", str(status))
            logger.error("ssh exec info: %s", output)
        return status, output

executor = RemoteExecutor("lcj@12345", "root", "18.183.94.3")

def rule_exists(executor, rule):
    """检查 iptables 规则是否存在。"""
    command = iptables_action["is_exist"] + rule
    status, output = executor.execute(command)
    if status:
        logger.info("rule [%s] not exists", rule)
    return not status

app = Flask(__name__)

def read_fast_ips(file_path='/root/CloudflareST/results.csv'):
    import re
    ip_addresses = []
    try:
        with open(file_path, 'r') as file:
            file_content = file.read()

        # 使用正则表达式提取IP地址
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        ip_addresses = re.findall(ip_pattern, file_content)
    except:
        print("get fast ips error !!")
    return ip_addresses

def get_file_time(file_path='/root/CloudflareST/results.csv'):
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return ["%s文件不存在"%(file_path)]

        # 获取文件的最后修改时间
        mod_time = os.path.getmtime(file_path)
        # 获取文件的创建时间
        create_time = os.path.getctime(file_path)
        # 获取文件的最后访问时间
        access_time = os.path.getatime(file_path)

        # 格式化时间戳
        mod_time_readable = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
        create_time_readable = datetime.fromtimestamp(create_time).strftime('%Y-%m-%d %H:%M:%S')
        access_time_readable = datetime.fromtimestamp(access_time).strftime('%Y-%m-%d %H:%M:%S')

        return [create_time_readable, mod_time_readable, access_time_readable]

    except Exception as e:
        # 返回异常信息
        return [f"出现错误: {e}"]

import threading
import time
# ---- 全局缓存：由后台线程每 1s 更新一次 ----
_alive_cache_lock = threading.Lock()
_alive_cache_text = "v2ray active=unknown sub=unknown pid=0 time=unknown"
_alive_cache_ok = False

def _probe_v2ray_once():
    """
    探测一次远端 v2ray 状态，返回 (ok(bool), text(str))
    """
    # ✅ FIX: 这里不能再套一层 heredoc（execute_ab 已经套了）
    cmd = r"""
ACTIVE=$(systemctl is-active v2ray 2>/dev/null || echo unknown)
SUB=$(systemctl show v2ray -p SubState --value 2>/dev/null || echo unknown)
PID=$(systemctl show v2ray -p MainPID --value 2>/dev/null || echo 0)
TS=$(date '+%Y-%m-%d %H:%M:%S')
echo "v2ray active=${ACTIVE} sub=${SUB} pid=${PID} time=${TS}"
"""
    status, output = executor.execute_ab(cmd)

    line = (output or "").strip().splitlines()[-1] if output else "v2ray active=unknown sub=unknown pid=0 time=unknown"
    # 以 is-active==active 作为存活判断
    ok = ("active=active" in line)
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
                _alive_cache_text = f"v2ray active=error sub=unknown pid=0 time={datetime.now().strftime('%Y-%m-%d %H:%M:%S')} err={e}"
        time.sleep(1)

def start_alive_probe_thread():
    t = threading.Thread(target=_alive_probe_loop, daemon=True)
    t.start()

@app.route('/aliva', methods=['GET'])
def aliva():
    with _alive_cache_lock:
        ok = _alive_cache_ok
        text = _alive_cache_text

    current = copy.deepcopy(v2ray_client_json)
    current["ps"] = text

    data_bytes = json.dumps(current).encode('utf-8')
    main_data_base64 = base64.b64encode(data_bytes)
    return "vmess://" + main_data_base64.decode('utf-8')

@app.route('/change_port', methods=['GET'])
def change_port():
    global bak_v2ray_port

    # 1. 生成新端口并执行远程修改 (20000-30000 范围)
    new_port = random.randint(20000, 30000)
    logger.info(f"Changing v2ray_bak port from {bak_v2ray_port} to {new_port}")

    # 远程 sed 修改配置文件
    remote_sed_cmd = f"sed -i 's/\"port\": {bak_v2ray_port}/\"port\": {new_port}/g' /usr/local/etc/v2ray/config_bak.json"
    status, output = executor.execute(remote_sed_cmd)

    if status != 0:
        logger.error(f"Failed to update remote config: {output}")
        return "Error: Failed to update remote config", 500

    # 重启备份服务
    restart_cmd = "systemctl restart v2ray_bak"
    status, _ = executor.execute(restart_cmd)
    if status != 0:
        return "Error: Failed to restart v2ray_bak", 500

    now_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ret = f"time:{now_time}-port-{bak_v2ray_port}-changed-to-{new_port}"
    bak_v2ray_port = new_port

    current_config = copy.deepcopy(v2ray_client_json)
    current_config["ps"] = ret          # 仅仅通过 ps 返回修改后的信息
    current_config["add"] = executor.host
    current_config["port"] = bak_v2ray_port
    current_config["tls"] = ""

    # 编码并返回
    data_bytes = json.dumps(current_config).encode('utf-8')
    main_data_base64 = base64.b64encode(data_bytes)

    return "vmess://" + main_data_base64.decode('utf-8')

@app.route('/allow-ip', methods=['GET'])
def allow_ip():
    ret = ""
    origin_ip = request.remote_addr
    rule = iptables_rules_dict["AllowIpTCP"] % origin_ip
    if not rule_exists(executor, rule):
        #remote_cmd = iptables_action["insert"] +  rule
        #status, output = executor.execute(remote_cmd)
        ret = f"{origin_ip} allowed on {executor.host}"
    if not ret:
        ret = f"{origin_ip} exists on {executor.host}"
    v2ray_client_json["ps"] = ret
    #v2ray_client_json["add"] = str(executor.host)
    #v2ray_client_json["port"] = str(executor.host)
    v2ray_client_json["add"] = cf_uri
    v2ray_client_json["port"] = cf_ws_port
    v2ray_client_json["host"] = cf_uri
    v2ray_client_json["sni"] = cf_uri
    v2ray_client_direct_json = copy.deepcopy(v2ray_client_json)
    v2ray_client_direct_json["add"] = str(executor.host)
    v2ray_client_direct_json["port"] = bak_v2ray_port
    v2ray_client_direct_json["tls"] = ""
    data_bytes = json.dumps(v2ray_client_json).encode('utf-8')  # 将字符串转换为字节
    main_data_base64 = base64.b64encode(data_bytes)
    data_bytes = json.dumps(v2ray_client_direct_json).encode('utf-8')  # 将字符串转换为字节
    main_direct_data_base64 = base64.b64encode(data_bytes)
    print(main_direct_data_base64)
    return "vmess://" + str(main_data_base64.decode('utf-8')) + "\n" + "vmess://" + str(main_direct_data_base64.decode('utf-8'))

@app.route('/statics', methods=['GET'])
def statics():
    remote_cmd='''
cat /proc/net/dev | grep -v "lo:" | grep -Ev "Inter|face" | awk '{
    interface=$1;
    rx_bytes=$2;
    tx_bytes=$10;
    rx_gbits = rx_bytes * 8 / (8*1024*1024*1024) ;
    tx_gbits = tx_bytes * 8 / (8*1024*1024*1024) ;
    printf "%s RX: %.2f Gbyte TX: %.2f Gbyte\\n", interface, rx_gbits, tx_gbits;
}'
'''
    status, output=executor.execute_ab(remote_cmd);
    v2ray_client_json["ps"] = output
    data_bytes = json.dumps(v2ray_client_json).encode('utf-8')  # 将字符串转换为字节
    main_data_base64 = base64.b64encode(data_bytes)
    print(main_data_base64)
    return "vmess://" + str(main_data_base64.decode('utf-8'))

@app.route('/fast_ip', methods=['GET'])
def fast_ip():
    fast_ips = read_fast_ips()
    filetime = get_file_time()
    vmess_order_lists = []
    if len(fast_ips):
        for ip in fast_ips:
            ret = "%s-fast-ip"%(filetime[0])
            v2ray_client_json["ps"] = ret
            v2ray_client_json["add"] = ip
            v2ray_client_json["port"] = cf_ws_port
            v2ray_client_json["host"] = cf_uri
            v2ray_client_json["sni"] = cf_uri
            data_bytes = json.dumps(v2ray_client_json).encode('utf-8')  # 将字符串转换为字节
            main_data_base64 = base64.b64encode(data_bytes)
            vmess_order_lists.append("vmess://" + str(main_data_base64.decode('utf-8')))
    print("\n".join(vmess_order_lists))
    return "\n".join(vmess_order_lists)

@app.route('/local-fast-ip', methods=['GET'])
def local_fast_ip():
    fast_ips = read_fast_ips()
    filetime = get_file_time()
    vmess_order_lists = []
    v2ray_order_ip = os.environ.get('V2_ORDER_IP')
    cmd = '''V2_ORDER_IP=%s bash << 'EOF'  2> /dev/null
    curl http://${V2_ORDER_IP}:5000/allow-ip | grep "vmess://" -m 1 |sed 's/vmess:\/\///' |base64 -d
EOF'''%(v2ray_order_ip)
    v2ray_client_json = ""
    status, output = subprocess.getstatusoutput(cmd)
    if status != 0 or len(output) == 0:
        print("get proxy err")
        return 1
    else :
        v2ray_client_json = json.loads(output)

    if len(fast_ips):
        for ip in fast_ips:
            ret = "%s-local-fast-ip"%(filetime[0])
            v2ray_client_json["ps"] = ret
            v2ray_client_json["add"] = ip
            #v2ray_client_json["port"] = cf_ws_port
            #v2ray_client_json["host"] = cf_uri
            #v2ray_client_json["sni"] = cf_uri
            data_bytes = json.dumps(v2ray_client_json).encode('utf-8')  # 将字符串转换为字节
            main_data_base64 = base64.b64encode(data_bytes)
            vmess_order_lists.append("vmess://" + str(main_data_base64.decode('utf-8')))

    print("\n".join(vmess_order_lists))
    return "\n".join(vmess_order_lists)

@app.route('/other_github', methods=['GET'])
def other_github():
    cmd = '''bash << EOF
        curl https://github.com/mksshare/mksshare.github.io  |grep "vmess.*=="
EOF'''
    try:
        status, output = subprocess.getstatusoutput(cmd)
    except:
        logger.error("remote exec err cmd: %s ", cmd)
    return output

@app.route('/other', methods=['GET'])
def other():
    cmd = '''bash << EOF
        curl https://github.com/mksshare/mksshare.github.io  |grep "vmess.*=="
EOF'''
    try:
        status, output = subprocess.getstatusoutput(cmd)
    except:
        logger.error("remote exec err cmd: %s ", cmd)
    return output

def scp_transfer(src_path,  dst_path, username, remote_host, remote_port, password):
    """
    Transfer a file or directory using scp with sshpass.
    """
    cmd = [
        'sshpass', '-p', password,
        'scp', '-o', 'StrictHostKeyChecking=no', '-P' , '%s'%(remote_port),
        src_path, f"{username}@{remote_host}:{dst_path}"
    ]

    try:
        print(" ".join(cmd))
        result = subprocess.run(" ".join(cmd), check=True,universal_newlines=True, shell=True,stderr=subprocess.PIPE)
        if result.returncode == 0:
            return True
    except subprocess.CalledProcessError as e:
        print(f"Error executing SCP: {e.output}")
        return False
    return False

def get_wan_ip():
    return "117.50.175.8"

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def init_iptables():
    return True

def init_v2ray(password, user, host, port):
    # --- 原有安装逻辑保持不变 ---
    global bak_v2ray_port
    check_v2ray_cmd = "[ -f /usr/local/bin/v2ray ]"
    status, output = executor.execute(check_v2ray_cmd)
    if status:
        print("install v2ray")
        install_v2ray_cmd = "curl https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh | bash"
        executor.execute(install_v2ray_cmd)

    # --- 1. 复制二进制文件 (v2ray_bak) ---
    logger.info("Creating v2ray_bak binary...")
    copy_bin_cmd = "cp /usr/local/bin/v2ray /usr/local/bin/v2ray_bak"
    executor.execute(copy_bin_cmd)

    # --- 2. 处理 BAK 配置文件 (随机端口) ---
    bak_port = random.randint(20000, 30000)
    bak_config_json = copy.deepcopy(v2ray_config_json)
    bak_config_json["inbounds"][0]["port"] = bak_port  # 设置随机端口
    bak_v2ray_port = bak_port

    bak_config_local_path = f"{BDIR}/v2ray_config_bak"
    with open(bak_config_local_path, "w") as f:
        json.dump(bak_config_json, f)

    # 上传 BAK 配置
    scp_transfer(bak_config_local_path, "/usr/local/etc/v2ray/config_bak.json", user, host, port, password)

    # --- 3. 处理 BAK 服务文件 ---
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

    # --- 4. 原有的主服务逻辑 (保持并上传主配置) ---
    v2ray_config = f"{BDIR}/v2ray_config"
    with open(v2ray_config, "w") as json_file:
        json.dump(v2ray_config_json, json_file)

    scp_transfer(v2ray_config, v2ray_config_file_path, user, host, port, password)
    scp_transfer(f"{BDIR}/v2ray.service", v2ray_service_file_path, user, host, port, password)

    # --- 5. 初始化日志与启动 ---
    executor.execute(f"touch {access_Log} {error_Log} && chmod 0666 {access_Log} {error_Log}")

    executor.execute("systemctl daemon-reload")
    executor.execute("systemctl stop v2ray v2ray_bak") # 停止旧的
    executor.execute("systemctl start v2ray")

    # 启动备份服务
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
        exit(0)

    password = os.environ.get('PROXY_HOST_SSH_PASSWORD')
    user = os.environ.get('PROXY_HOST_SSH_USER')
    host = os.environ.get('PROXY_HOST_ADD')
    port = os.environ.get('PROXY_HOST_SSH_PORT')
    executor = RemoteExecutor(password, user, host, port)  # 使用外部参数来初始化
    if not init_v2ray(password, user, host, port):
        logger.error(f"init v2ray Error")
        exit(1)

    logger.info("init_iptables!")
    if init_iptables():
        print("Running in remote mode !!")
        start_alive_probe_thread()
        app.run(host="0.0.0.0", port=5000, threaded=True)
