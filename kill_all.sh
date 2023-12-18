#!/bin/bash

filter_and_kill_processes() {
  local keywords=("get_fast_ip.sh" "CloudflareST" "proxy_mgt.py" "local_start_get")

  for keyword in "${keywords[@]}"; do
    pids=$(pgrep -f "$keyword")

    if [ -n "$pids" ]; then
      echo "Killing processes with keyword: $keyword"
      kill -9 $pids
    else
      echo "No processes found with keyword: $keyword"
    fi
  done
  (crontab -l 2>/dev/null |grep -v "get_fast_ip.sh") | crontab -
}

filter_and_kill_processes

