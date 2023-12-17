sed -i "s#/path/to/proxy_mgt.py#$(pwd)/proxy_mgt.py#g" ./proxy-mgmt.service
cp -f  ./proxy-mgmt_restart.service /etc/systemd/system/proxy-mgmt_restart.service
cp -f  ./proxy-mgmt_restart.timer /etc/systemd/system/proxy-mgmt_restart.timer
cp -f  ./proxy-mgmt.service /etc/systemd/system/proxy-mgmt.service
SCRIPT=$(pwd)/get_fast_ip.sh
chmod 0777 $SCRIPT
bash $SCRIPT
(crontab -l 2>/dev/null; echo "0 */3 * * * $SCRIPT") | crontab -
crontab -l | sort | uniq | crontab -
sudo systemctl daemon-reload
sudo systemctl start proxy-mgmt_restart.timer
sudo systemctl enable proxy-mgmt_restart.timer
sudo systemctl start proxy-mgmt.service
