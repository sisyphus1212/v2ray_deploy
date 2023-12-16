from flask import Flask, request
import subprocess
import socket
import http.client
import logging.handlers
import sys
import json
import base64
import random
import os

DIR = os.path.realpath(__file__)
BDIR = os.path.dirname(DIR)

class LoggerAdapter:
    def __init__(self, to_stdout=True):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

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
    "DropTCPSyn": "INPUT -p tcp --syn -j DROP",
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
    iptables_rules_dict["DropTCPSyn"],
    iptables_rules_dict["DropIcmpSyn"]
]

v2ray_id = "a17a1af7-efa5-42ca-b7e9-aa35282d737f"
v2ray_port = 33964 #random.randint(10000,40000)
alterId = 56
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
        ],
        "detour": {
          "to": "dynamicPort"
        }
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
  "port": "%s"%(v2ray_port),
  "id": "%s"%(v2ray_id),
  "aid": "%s"%(alterId),
  "scy": "auto",
  "net": "ws",
  "type": "http",
  "host": "cloudflare.com",
  "path": "/qaz",
  "tls": "",
  "sni": "cloudflare.com",
  "alpn": "",
  "fp": ""
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
        cmd = " ".join(["timeout 120 sshpass", "-p", self.password, "ssh -o StrictHostKeyChecking=no -p %s -t"%(self.port), f"{self.user}@{self.host}", exec_cmd])
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

@app.route('/allow-ip', methods=['GET'])
def allow_ip():
    ret = ""
    origin_ip = request.remote_addr
    rule = iptables_rules_dict["AllowIpTCP"] % origin_ip
    if not rule_exists(executor, rule):
        remote_cmd = iptables_action["insert"] +  rule
        status, output = executor.execute(remote_cmd)
        ret = f"{origin_ip} allowed on {executor.host}"
    if not ret:
        ret = f"{origin_ip} exists on {executor.host}"
    v2ray_client_json["ps"] = ret
    v2ray_client_json["add"] = str(executor.host)
    data_bytes = json.dumps(v2ray_client_json).encode('utf-8')  # 将字符串转换为字节
    data_base64 = base64.b64encode(data_bytes)
    return "vmess://" + str(data_base64.decode('utf-8'))

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

    :param src_path:  Source path of the file/directory.
    :param dst_path:   Destination path on the remote server.
    :param username:    Remote server username.
    :param remote_host: kRemote server hostname or IP address.
    :param password: Password for the remote server.
    :return: True if transfer was successful, False otherwise.
    """

    # Construct the scp command with sshpass
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
    conn = http.client.HTTPSConnection("api.ipify.org")
    conn.request("GET", "/")
    response = conn.getresponse()
    return response.read().decode()

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
    status = 0
    IPAddr = get_wan_ip()
    logger.info("init: Your Computer IP Address is: %s", IPAddr)
    append_rules = [iptables_rules_dict["AllowIpTCP"] % IPAddr] + iptable_init_rules

    remote_cmd = []
    for rule in append_rules:
        if not rule_exists(executor, rule):
            remote_cmd.append(iptables_action["append"] + rule)

    #clean_rule=iptables_action["clean"]
    #TODO

    # insert rule : permit v2ray_port
    remote_cmd.append(iptables_rules_dict["AllowCFPORT"] % v2ray_port)
    for cmd in remote_cmd:
        status, output = executor.execute(cmd)
        if status:
            logger.error("init: append local ip to remote iptables rules error")
            logger.error("init: %s", cmd)
    return True if not status else False

def init_v2ray(password, user, host, port):
    # Step 1: Check if v2ray service exists
    check_v2ray_cmd = "[ -f /usr/local/bin/v2ray ]"
    status, output = executor.execute(check_v2ray_cmd)
    if status:  # If the output is empty, v2ray service does not exist
        # Download and execute the installation script remotely
        print("install v2ray")
        install_v2ray_cmd = "curl https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh | bash"
        status, install_output = executor.execute(install_v2ray_cmd)
        if status:
            logger.error(f"Failed to download and execute the V2Ray installation script. Error: {install_output}")
            return False
        print("install v2ray successfully")

    remove_old_cmd =  "[ -f /etc/systemd/system/v2ray.service.d/10-donot_touch_single_conf.conf ] && rm /etc/systemd/system/v2ray.service.d/10-donot_touch_single_conf.conf || exit 0"
    status, install_output = executor.execute(remove_old_cmd)
    if status:
        logger.error(f"Failed to update v2ray service . Error: {install_output}")
        return False
    print("remove v2ray service successfully")

    v2ray_config = "%s/v2ray_config"%(BDIR)
    with open(v2ray_config, "w") as json_file:
        json.dump(v2ray_config_json, json_file)

    if scp_transfer("%s/v2ray_config"%(BDIR), v2ray_config_file_path, user, host, port, password):
        logger.info("v2ray_config transferred successfully!")
    else:
        logger.error("v2ray_config transfer failed.")

    if scp_transfer("%s/v2ray.service"%(BDIR), v2ray_service_file_path, user, host, port, password):
        logger.info("v2ray_config transferred successfully!")
    else:
        logger.error("v2ray.service transfer failed.")

    access_Log_check = "touch %s && chmod 0666 %s"%(access_Log, access_Log)
    error_Log_check = "touch %s && chmod 0666 %s"%(error_Log, error_Log)
    status, _ = executor.execute(error_Log_check)
    if status != 0:
        print("error_Log config err")
        return False

    status, _ = executor.execute(access_Log_check)
    if status != 0:
        print("access_Log config err")
        return False

    reload_system_config = "systemctl daemon-reload"
    status, output = executor.execute(reload_system_config)
    if status:
        logger.error(f"systemctl daemon-reload Error: {output}")
        return False

    check_v2ray_cmd = "systemctl stop v2ray"
    status, output = executor.execute(check_v2ray_cmd)
    if status != 0:
        logger.error(f"v2ray stop err: {output}")
        # If v2ray service is not active, download and execute the installation script remotely
    start_v2ray_cmd = "systemctl start v2ray"
    status, output = executor.execute(start_v2ray_cmd)
    if status:
        logger.error(f"Failed to start v2ray Error: {output}")
        return False
    print("v2ray start successfully: at %s:%d!"%(host, v2ray_port))


import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="RemoteExecutor Initialization Parameters")
    parser.add_argument('--password', required=True, help='Password for the RemoteExecutor')
    parser.add_argument('--user', required=True, help='Username for the RemoteExecutor')
    parser.add_argument('--host', required=True, help='Host for the RemoteExecutor')
    parser.add_argument('--port', required=True, help='port for the RemoteExecutor')

    args = parser.parse_args()

    executor = RemoteExecutor(args.password, args.user, args.host, args.port)  # 使用外部参数来初始化
    if init_v2ray(args.password, args.user, args.host, args.port):
        logger.error(f"init v2ray Error")
        exit(1)

    if init_iptables():
        app.run(host="0.0.0.0", port=5000)


