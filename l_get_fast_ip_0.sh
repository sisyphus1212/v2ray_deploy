#!/bin/bash

LOG="/root/v2ray_fastip_runing.log"
touch $LOG
size_limit=$((10*1024*1024))
if [ -e "$LOG" ]; then
    file_size=$(stat -c %s "$LOG")
    if [ "$file_size" -gt "$size_limit" ]; then
        rm "$LOG"
        echo "File $LOG deleted."
    fi
fi

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
}

filter_and_kill_processes
nohup bash local_start_get.sh 0.2 350 >> $LOG 2>&1 &