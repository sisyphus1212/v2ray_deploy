#!/bin/bash
SCRIPT=$(pwd)/get_fast_ip.sh
[ $1 ] && speed=$1 || speed=5
[ $2 ] && timeout=$2 || timeout=300
CMD="$SCRIPT --speed ${speed} --timeout ${timeout}"

BACKENDSH=/run/v2ray_deploy/cloudflare_fast_ip_backend.sh
chmod  0777 ${BACKENDSH}
mkdir -p `dirname $BACKENDSH`
chmod
cat << EOF > ${BACKENDSH}
#!/bin/bash
set -a
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
http_proxy=$http_proxy
https_proxy=$https_proxy
set +a
bash ${CMD}
EOF

if [ -n "$(pidof systemd)" ]; then
    sed  -i "s|ExecStart=cmd|ExecStart=${BACKENDSH}|g" ./cloudflare_fast_ip.service
    cp -f ./cloudflare_fast_ip.service /etc/systemd/system/cloudflare_fast_ip.service
    cp ./cloudflare_fast_ip.timer /etc/systemd/system/cloudflare_fast_ip.timer
    sudo systemctl daemon-reload
    sudo systemctl start cloudflare_fast_ip.timer
    sudo systemctl enable cloudflare_fast_ip.timer
    sudo systemctl stop cloudflare_fast_ip.service
    sudo systemctl start cloudflare_fast_ip.service
else
    sudo service cron status
    sudo service cron start
    sudo service cron status
    bash ${CMD}
    (crontab -l 2>/dev/null; echo "*/300 * * * * ${BACKENDSH}") | crontab -
fi

if python3 -c "import flask" &>/dev/null; then
    echo "flask is installed."
else
    pip3 install flask
fi

(set -a; . ./proxy_mgt.env; set +a; env python3 ./proxy_mgt.py --local True)