#!/usr/bin/bash

# 最大重试次数
MAX_RETRIES=5

# 当前重试次数
count=0
SPEEDTEST_URL="https://speedtest.sisyphus1212.life/"

SPEEDTEST_LIMIT=5
TIME_LIMIT=300
# Loop through the arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --help)
      # Handle the --help option
      echo "Usage: ./myscript.sh [--help] [--speed <value>] [--testurl <value>] [--timeout <value>]"
      exit 0
      ;;
    --speed)
      # Handle the --speed option and its value
      SPEEDTEST_LIMIT="$2"
      shift 2
      ;;
    --testurl)
      # Handle the --time option and its value
      SPEEDTEST_URL="$2"
      shift 2
      ;;
    --timeout)
      # Handle the --time option and its value
      TIME_LIMIT="$2"
      shift 2
      ;;
    *)
      # Unrecognized option or argument
      echo "Unrecognized option or argument: $1" >&2
      exit 1
      ;;
  esac
done

# 一个函数，包含原脚本的主要逻辑
run_my_script() {
   . /etc/proxy_mgt.env
    CloudflareST_PATH=/root/CloudflareST
    mkdir -p ${CloudflareST_PATH}

    # 进入文件夹（后续更新，只需要从这里重复下面的下载、解压命令即可）
    cd ${CloudflareST_PATH}

    rm ./* -rf
    # 下载 CloudflareST 压缩包（自行根据需求替换 URL 中 [版本号] 和 [文件名]）
    #wget -N https://github.com/XIU2/CloudflareSpeedTest/releases/download/latest && tar -zxf CloudflareST_linux_amd64.tar.gz || exit 1
    # 如果你是在国内服务器上下载，那么请使用下面这几个镜像加速：
    if [ $GET_REMOTE ]; then
      sshpass -p $PROXY_HOST_SSH_PASSWORD ssh -p $PROXY_HOST_SSH_PORT $PROXY_HOST_SSH_USER@$PROXY_HOST_ADD bash << EOF
      rm CloudflareST_linux_amd64*
      curl -s https://api.github.com/repos/XIU2/CloudflareSpeedTest/releases/latest | jq -r '.assets[].browser_download_url' | grep "linux_amd64" | xargs -n 1 -I {} wget  {}
EOF
      [ $? -gt 0 ] && return 1
      sshpass -p $PROXY_HOST_SSH_PASSWORD scp -P $PROXY_HOST_SSH_PORT $PROXY_HOST_SSH_USER@$PROXY_HOST_ADD:/root/CloudflareST_linux_amd64.tar.gz /root/CloudflareST_linux_amd64.tar.gz
      [ $? -gt 0 ] && return 1
      tar -zxf CloudflareST_linux_amd64.tar.gz
      [ $? -gt 0 ] && return 1
    else
      curl -s https://api.github.com/repos/XIU2/CloudflareSpeedTest/releases/latest | jq -r '.assets[].browser_download_url' | grep "linux_amd64" | xargs -n 1 -I {} wget  {} && tar -zxf CloudflareST_linux_amd64.tar.gz || return 1
    fi

    # wget -N https://download.fgit.gq/XIU2/CloudflareSpeedTest/releases/download/v2.2.4/CloudflareST_linux_amd64.tar.gz
    # wget -N https://ghproxy.com/https://github.com/XIU2/CloudflareSpeedTest/releases/download/v2.2.4/CloudflareST_linux_amd64.tar.gz
    # 如果下载失败的话，尝试删除 -N 参数（如果是为了更新，则记得提前删除旧压缩包 rm CloudflareST_linux_amd64.tar.gz ）

    # 赋予执行权限
    chmod +x CloudflareST

    # 运行（不带参数）
    # 地区：CGD,MAA,CNX,CGP,CMB,DAC,FUO,FUK,FOC,CAN,HAK,HAN,SJW,SGN,HKG,HYD,ISB,CGK,JSR,TNA,JHB,KNU,KHH,KHI,KTM,KHV,CCU,KJA,KUL,LHE,PKX,LHW,LYA,MFM,MLE,MDL,MNL,BOM,NAG,OKA,DEL,KIX,PAT,PNH,TAO,ICN,SHA,SIN,URT,TPE,TAS,PBH,TSN,NRT,ULN,VTE,KHN,RGN,EVN,JOG,CGO,CGQ,ZGN,CGY,WHU,HYN,COK,XMN,DPS,CNN,SZX,KWE,WUX,HGH,CZX,KMG,AMS,ATH,BCN,BEG,TXL,BTS,BRU,OTP,BUD,KIV,CPH,ORK,DUB,DUS,EDI,FRA,GVA,GOT,HAM,HEL,IST
   # 中国：CGD,FUO,FUK,FOC,CAN,HAK,SJW,TNA,PKX,LHW,LYA,TAO,SHA,TSN,KHN,CGO,CGQ,ZGN,WHU,HYN,COK,XMN,DPS,CNN,SZX,KWE,WUX,HGH,CZX,KMG
    #NO_CHINA_AREA="AMD,ALA,BLR,BKK,BWN,BBI,CEB,IXC,MAA,CNX,CGP,CMB,DAC,FUK,HAN,SGN,HKG,HYD,ISB,CGK,JSR,JHB,KNU,KHH,KHI,KTM,KHV,CCU,KJA,KUL,LHE,MFM,MLE,MDL,MNL,BOM,NAG,OKA,DEL,KIX,PAT,PNH,ICN,SIN,URT,TPE,TAS,PBH,NRT,ULN,VTE,RGN,EVN,JOG,CGY,COK,DPS,CNN,AMS,ATH,BCN,BEG"
    ASIA="CGD,FUO,FUK,FOC,CAN,HAK,SJW,TNA,PKX,LHW,LYA,TAO,SHA,TSN,KHN,CGO,CGQ,ZGN,WHU,HYN,COK,XMN,DPS,CNN,SZX,KWE,WUX,HGH,CZX,KMG"
    CFCOLO="" #"-cfcolo ${ASIA}"
    (https_proxy= http_proxy= timeout 600 ./CloudflareST -tl ${TIME_LIMIT} -sl ${SPEEDTEST_LIMIT} -dn 13  $CFCOLO -url  ${SPEEDTEST_URL} -o ./output)  || return 1
    mv ./output results.csv
    return 0
}

# 尝试运行脚本，直到成功或达到最大重试次数
while [ $count -lt 6 ]; do
    run_my_script
    RETVAL=$?
    # 检查脚本执行是否成功
    if [ $RETVAL -eq 0 ]; then
        echo "脚本执行成功"
        exit 0
    else
        echo "脚本执行失败，尝试重新执行"
        ((count++))
        if [ $count -gt 3 ]; then
            if [ $SPEEDTEST_LIMIT -gt 1 ]; then
                SPEEDTEST_LIMIT=1
            fi
            SPEEDTEST_URL="https://gh.con.sh/https://github.com/AaronFeng753/Waifu2x-Extension-GUI/releases/download/v2.21.12/Waifu2x-Extension-GUI-v2.21.12-Portable.7z"
        fi
    fi
done

echo "脚本在尝试了 $MAX_RETRIES 次后依然失败"
exit 1
