#!/bin/bash
SCRIPT=$(pwd)/get_fast_ip.sh
[ $1 ] && speed=$1 || speed=5
[ $2 ] && timeout=$2 || timeout=300
CMD="$SCRIPT --speed ${speed} --timeout ${timeout}"
bash ${CMD}

if [ -n "$(pidof systemd)" ]; then
    sudo service cron status
    sudo service cron start
    sudo service cron status
    (crontab -l 2>/dev/null; echo "0 */1 * * * ${CMD}") | crontab -
else
    sed  -i "s|ExecStart=cmd|ExecStart=${CMD}|g" ./cloudflare_fast_ip.service
    cp -f ./cloudflare_fast_ip.service /etc/systemd/system/cloudflare_fast_ip.service
    cp ./cloudflare_fast_ip.timer /etc/systemd/system/cloudflare_fast_ip.timer
    sudo systemctl daemon-reload
    sudo systemctl start cloudflare_fast_ip.timer
    sudo systemctl enable cloudflare_fast_ip.timer
    sudo systemctl stop cloudflare_fast_ip.service
    sudo systemctl start cloudflare_fast_ip.service
fi

(set -a; . ./proxy_mgt.env; set +a; env python3 ./proxy_mgt.py --local True)