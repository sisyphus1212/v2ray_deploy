#!/usr/bin/bash
sed -i "s#/path/to/proxy_mgt.py#$(pwd)/proxy_mgt.py#g" ./proxy-mgmt.service
cp -f  ./proxy-mgmt_restart.service /etc/systemd/system/proxy-mgmt_restart.service
cp -f  ./proxy-mgmt_restart.timer /etc/systemd/system/proxy-mgmt_restart.timer
cp -f  ./proxy-mgmt.service /etc/systemd/system/proxy-mgmt.service

SCRIPT=$(pwd)/get_fast_ip.sh
[ $1 ] && speed=$1 || speed=5
[ $2 ] && timeout=$2 || timeout=300
CMD="$SCRIPT --speed ${speed} --timeout ${timeout}"

BACKENDSH=/run/v2ray_deploy/cloudflare_fast_ip_backend.sh
mkdir -p `dirname $BACKENDSH`
touch ${BACKENDSH}
chmod  0777 ${BACKENDSH}

cat << EOF > ${BACKENDSH}
#!/usr/bin/bash
set -a
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
http_proxy=$http_proxy
https_proxy=$https_proxy
GET_REMOTE=$GET_REMOTE
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
    (crontab -l 2>/dev/null | grep -v "$BACKENDSH") | crontab -
    (crontab -l 2>/dev/null; echo "*/300 * * * * ${BACKENDSH}") | crontab -
    crontab -l | sort | uniq | crontab -
fi

bash ./kill_all.sh
sudo systemctl daemon-reload
sudo systemctl start proxy-mgmt_restart.timer
sudo systemctl enable proxy-mgmt_restart.timer
sudo systemctl stop proxy-mgmt.service
sudo systemctl start proxy-mgmt.service