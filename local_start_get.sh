#!/bin/bash

sudo service cron status
sudo service cron start
sudo service cron status
SCRIPT=$(pwd)/get_fast_ip.sh
[ $1 ] && speed=$1 || speed=5
[ $2 ] && timeout=$2 || timeout=300
bash  $SCRIPT --speed ${speed} --timeout ${timeout}
(crontab -l 2>/dev/null; echo "0 */1 * * * $SCRIPT") | crontab -
python3 ./proxy_mgt.py --local True