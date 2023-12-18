#!/bin/bash

sudo service cron status
sudo service cron start
sudo service cron status
SCRIPT=$(pwd)/get_fast_ip.sh
[ $1 ] && speed=$1 || speed=5
[ $2 ] && timeout=$2 || timeout=300
CMD="$SCRIPT --speed ${speed} --timeout ${timeout}"
bash ${CMD}
(crontab -l 2>/dev/null; echo "0 */1 * * * ${CMD}") | crontab -
(set -a; . ./proxy_mgt.env; set +a; env python3 ./proxy_mgt.py --local True)