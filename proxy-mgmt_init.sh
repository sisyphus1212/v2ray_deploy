sed -i "s#/path/to/proxy_mgt.py#$(pwd)/proxy_mgt.py#g" ./proxy-mgmt.service
cp -f  ./proxy-mgmt_restart.service /etc/systemd/system/proxy-mgmt_restart.service
cp -f  ./proxy-mgmt_restart.timer /etc/systemd/system/proxy-mgmt_restart.timer
cp -f  ./proxy-mgmt.service /etc/systemd/system/proxy-mgmt.service
sudo systemctl daemon-reload
sudo systemctl start proxy-mgmt_restart.timer
sudo systemctl enable proxy-mgmt_restart.timer
sudo systemctl start proxy-mgmt.service
