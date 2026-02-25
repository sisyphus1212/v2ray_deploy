#!/usr/bin/bash
#SSH_KEY=$1
#PROXY_HOST_ADDRESS=$3
#PROXY_HOST_SSH_USER=$2
#PROXY_HOST_OLD_SSH_PORT=$3
#PROXY_HOST_OLD_SSH_PASSWORD=$4
#PROXY_HOST_SSH_PORT=$5
#PROXY_HOST_SSH_PASSWORD=$6
declare -A args

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help)
            echo "Usage: ./vm_init.sh [options]
Options:
  --help            Show this help message
  --ssh_key         Path to SSH key
  --host_address    Host IP address
  --user_name       User name for SSH
  --ssh_port        SSH port number
  --passwd          Password for SSH
  --new_ssh_port    New SSH port number
  --new_passwd      New password for SSH
  --proxy_v2_uuid   Proxy v2 UUID
  --proxy_v2_alterid Proxy v2 AlterId
  --proxy_v2_port   Proxy v2 port number
  --proxy_v2_cf_uri Proxy v2 Cloudflare URI
  --proxy_v2_cf_port Proxy v2 Cloudflare port number"
            exit 0
            ;;
        --ssh_key|--host_address|--user_name|--ssh_port|--passwd|--new_ssh_port|--new_passwd|--proxy_v2_uuid|--proxy_v2_alterid|--proxy_v2_port|--proxy_v2_cf_uri|--proxy_v2_cf_port)
            args[$1]=$2
            shift 2
            ;;
        *)
            echo "Unrecognized option or argument: $1" >&2
            exit 1
            ;;
    esac
done

# Assigning the values to variables
SSH_KEY=${args[--ssh_key]}
PROXY_HOST_ADDRESS=${args[--host_address]}
PROXY_HOST_SSH_USER=${args[--user_name]}
PROXY_HOST_OLD_SSH_PORT=${args[--ssh_port]}
PROXY_HOST_OLD_SSH_PASSWORD=${args[--passwd]}
PROXY_HOST_SSH_PORT=${args[--new_ssh_port]}
PROXY_HOST_SSH_PASSWORD=${args[--new_passwd]}
PROXY_V2_UUID=${args[--proxy_v2_uuid]}
PROXY_V2_ALTERID=${args[--proxy_v2_alterid]}
PROXY_V2_PORT=${args[--proxy_v2_port]}
PROXY_V2_CF_URI=${args[--proxy_v2_cf_uri]}
PROXY_V2_CF_PORT=${args[--proxy_v2_cf_port]}

if [ -z $SSH_KEY ]; then
    SSH_OPT="sshpass -p ${PROXY_HOST_OLD_SSH_PASSWORD} ssh -o StrictHostKeyChecking=no -p ${PROXY_HOST_OLD_SSH_PORT} -t ${PROXY_HOST_SSH_USER}@${PROXY_HOST_ADDRESS}"
else
    SSH_OPT="ssh -i  -o StrictHostKeyChecking=no ${SSH_KEY} -t ${PROXY_HOST_SSH_USER}@${PROXY_HOST_ADDRESS}"
fi

cat << EOF
PROXY_HOST_SSH_USER=${PROXY_HOST_SSH_USER}
PROXY_HOST_ADD=${PROXY_HOST_ADDRESS}
PROXY_HOST_SSH_PASSWORD=${PROXY_HOST_SSH_PASSWORD}
PROXY_HOST_SSH_PORT=${PROXY_HOST_SSH_PORT}
#v2ray and cf config
PROXY_V2_UUID=${PROXY_V2_UUID}
PROXY_V2_ALTERID=${PROXY_V2_ALTERID}
PROXY_V2_PORT=${PROXY_V2_PORT}
PROXY_V2_CF_URI=${PROXY_V2_CF_URI}
PROXY_V2_CF_PORT=${PROXY_V2_CF_PORT}
EOF

${SSH_OPT} sudo bash << EOF
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
apt update
apt install whois iptables curl jq -y
mkpasswd -m sha-512 ${PROXY_HOST_SSH_PASSWORD} | xargs -I {} usermod -p {} root  || { echo "mkpasswd failed"; exit 1; }
sed -i 's/#Port 22/Port ${PROXY_HOST_SSH_PORT}/' /etc/ssh/sshd_config
systemctl restart sshd
EOF

cat << EOF > /etc/proxy_mgt.env
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

#bash ./proxy-mgmt_init.sh
