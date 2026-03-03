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

ssh -i  ${PRIVATE_KEY} -t ${USER_NAME}@${SERVER_ADDRESS} sudo bash << EOF
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
apt install whois -y
mkpasswd -m sha-512 ${NEW_PASSWD} | xargs -I {} usermod -p {} root  || { echo "mkpasswd failed"; exit 1; }
sed -i 's/#Port 22/Port ${NEW_SSH_PORT}/' /etc/ssh/sshd_config
systemctl restart sshd
EOF

echo << EOF > /etc/proxy_mgt.env
PROXY_USER="root"
PROXY_PASSWORD=${NEW_PASSWD}
PROXY_HOST=${SERVER_ADDRESS}
PROXY_PORT=${NEW_SSH_PORT}
EOF

bash ./proxy-mgmt_init.sh
