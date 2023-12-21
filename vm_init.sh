#!/bin/bash
PRIVATE_KEY=$1
SERVER_ADDRESS=$3
USER_NAME=$2
SSH_PORT=$3
NEW_SSH_PORT=$4
NEW_PASSWD=$5

if [ "$#" -ne 5 ]; then
    echo "Usage: $0 PRIVATE_KEY USER_NAME SERVER_ADDRESS SSH_PORT NEW_SSH_PORT NEW_PASSWD"
    exit 1
fi

ssh -i  ${PRIVATE_KEY} -t ${PROXY_HOST_SSH_USER}@${PROXY_HOST_ADD} sudo bash << EOF
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
apt update
apt install whois iptables curl jq -y
mkpasswd -m sha-512 ${PROXY_HOST_SSH_PASSWORD} | xargs -I {} usermod -p {} root  || { echo "mkpasswd failed"; exit 1; }
sed -i 's/#Port 22/Port ${PROXY_HOST_SSH_PORT}/' /etc/ssh/sshd_config
systemctl restart sshd
EOF

echo << EOF > /etc/proxy_mgt.env
PROXY_HOST_SSH_USER=${PROXY_HOST_SSH_USER}
PROXY_HOST_ADD=${PROXY_HOST_ADD}
PROXY_HOST_SSH_PASSWORD=${PROXY_HOST_SSH_PASSWORD}
PROXY_HOST_SSH_PORT=${PROXY_HOST_SSH_PORT}
#v2ray and cf config
PROXY_V2_UUID=${PROXY_V2_UUID}
PROXY_V2_ALTERID=${PROXY_V2_ALTERID}
PROXY_V2_PORT=${PROXY_V2_PORT}
PROXY_V2_CF_URI=${PROXY_V2_CF_URI}
PROXY_V2_CF_PORT=${PROXY_V2_CF_PORT}
EOF

bash ./proxy-mgmt_init.sh
