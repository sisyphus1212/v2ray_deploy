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

. ./kill_all.sh
nohup bash cloudflare_fast_ip.sh 0.1 350 >> $LOG 2>&1 &