sudo service cron status
SCRIPT=$(pwd)/get_fast_ip.sh
(crontab -l 2>/dev/null; echo "0 */1 * * * $SCRIPT") | crontab -
python3 ./proxy_mgt.py --local True