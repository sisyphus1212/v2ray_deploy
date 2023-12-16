#!/bin/bash

# 最大重试次数
MAX_RETRIES=5

# 当前重试次数
count=0

# 一个函数，包含原脚本的主要逻辑
run_my_script() {
    CloudflareST_PATH=/root/CloudflareST
    mkdir -p ${CloudflareST_PATH}

    # 进入文件夹（后续更新，只需要从这里重复下面的下载、解压命令即可）
    cd ${CloudflareST_PATH}

    rm CloudflareST_linux_amd64.tar.gz -f
    # 下载 CloudflareST 压缩包（自行根据需求替换 URL 中 [版本号] 和 [文件名]）
    #wget -N https://github.com/XIU2/CloudflareSpeedTest/releases/download/latest && tar -zxf CloudflareST_linux_amd64.tar.gz || exit 1
    # 如果你是在国内服务器上下载，那么请使用下面这几个镜像加速：
    curl -s https://api.github.com/repos/XIU2/CloudflareSpeedTest/releases/latest | jq -r '.assets[].browser_download_url' | grep "linux_amd64" | xargs -n 1 -I {} wget  {} && tar -zxf CloudflareST_linux_amd64.tar.gz || return 1
    # wget -N https://download.fgit.gq/XIU2/CloudflareSpeedTest/releases/download/v2.2.4/CloudflareST_linux_amd64.tar.gz
    # wget -N https://ghproxy.com/https://github.com/XIU2/CloudflareSpeedTest/releases/download/v2.2.4/CloudflareST_linux_amd64.tar.gz
    # 如果下载失败的话，尝试删除 -N 参数（如果是为了更新，则记得提前删除旧压缩包 rm CloudflareST_linux_amd64.tar.gz ）

    # 赋予执行权限
    chmod +x CloudflareST

    # 运行（不带参数）
    ./CloudflareST -tl 350 -sl 5 -dn 20 -o ./output  -url https://gh.con.sh/https://github.com/AaronFeng753/Waifu2x-Extension-GUI/releases/download/v2.21.12/Waifu2x-Extension-GUI-v2.21.12-Portable.7z || return 1
    mv ./output results.csv
    return 0
}

# 尝试运行脚本，直到成功或达到最大重试次数
while [ $count -lt $MAX_RETRIES ]; do
    run_my_script
    RETVAL=$?

    # 检查脚本执行是否成功
    if [ $RETVAL -eq 0 ]; then
        echo "脚本执行成功"
        exit 0
    else
        echo "脚本执行失败，尝试重新执行"
        ((count++))
    fi
done

echo "脚本在尝试了 $MAX_RETRIES 次后依然失败"
exit 1
