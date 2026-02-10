#!/usr/bin/env bash
set -u

# 最大重试次数
MAX_RETRIES=5
count=0

SPEEDTEST_URL="https://speedtest.sisyphus1212.life/"
SPEEDTEST_LIMIT=5
TIME_LIMIT=300

CFST_TGZ="CloudflareST_linux_amd64.tar.gz"
CFST_URL="https://github.com/XIU2/CloudflareSpeedTest/releases/latest/download/${CFST_TGZ}"
# 国内/网络不稳可切换镜像（保持 latest/download，不依赖版本号）
# CFST_URL="https://ghproxy.com/https://github.com/XIU2/CloudflareSpeedTest/releases/latest/download/${CFST_TGZ}"

usage() {
  echo "Usage: $0 [--help] [--speed <value>] [--testurl <value>] [--timeout <value>]"
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --help)
      usage
      exit 0
      ;;
    --speed)
      SPEEDTEST_LIMIT="$2"
      shift 2
      ;;
    --testurl)
      SPEEDTEST_URL="$2"
      shift 2
      ;;
    --timeout)
      TIME_LIMIT="$2"
      shift 2
      ;;
    *)
      echo "Unrecognized option or argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

download_local() {
  local dst_dir="$1"
  cd "$dst_dir" || return 1
  rm -rf ./*

  # 下载最新版本（不依赖 GitHub API/jq）
  wget -O "${CFST_TGZ}" -L "${CFST_URL}" || return 1
  tar -zxf "${CFST_TGZ}" || return 1
  chmod +x CloudflareST || return 1
  return 0
}

download_via_remote() {
  # 在远端下载到 /root/${CFST_TGZ} 然后 scp 回来解压
  # 这里保持你原逻辑：由 PROXY_HOST_* 决定远端
  sshpass -p "${PROXY_HOST_SSH_PASSWORD}" \
    ssh -o StrictHostKeyChecking=no -p "${PROXY_HOST_SSH_PORT}" \
    "${PROXY_HOST_SSH_USER}@${PROXY_HOST_ADD}" bash << EOF
set -e
cd /root
rm -f ${CFST_TGZ}
wget -O ${CFST_TGZ} -L "${CFST_URL}"
EOF
  [ $? -gt 0 ] && return 1

  sshpass -p "${PROXY_HOST_SSH_PASSWORD}" \
    scp -o StrictHostKeyChecking=no -P "${PROXY_HOST_SSH_PORT}" \
    "${PROXY_HOST_SSH_USER}@${PROXY_HOST_ADD}:/root/${CFST_TGZ}" \
    "/root/CloudflareST/${CFST_TGZ}" || return 1

  cd /root/CloudflareST || return 1
  tar -zxf "${CFST_TGZ}" || return 1
  chmod +x CloudflareST || return 1
  return 0
}

run_my_script() {
  local env_path=/etc/proxy_mgt.env
  [ -f "${env_path}" ] && . "${env_path}"

  local CloudflareST_PATH=/root/CloudflareST
  mkdir -p "${CloudflareST_PATH}"

  # 下载/解压 CloudflareST
  if [ -n "${GET_REMOTE:-}" ]; then
    # GET_REMOTE 非空 => 走远端下载
    download_via_remote || return 1
  else
    download_local "${CloudflareST_PATH}" || return 1
  fi

  # 地区参数（保持你原来结构）
  ASIA="CGD,FUO,FUK,FOC,CAN,HAK,SJW,TNA,PKX,LHW,LYA,TAO,SHA,TSN,KHN,CGO,CGQ,ZGN,WHU,HYN,COK,XMN,DPS,CNN,SZX,KWE,WUX,HGH,CZX,KMG"
  CFCOLO="" # "-cfcolo ${ASIA}"

  cd "${CloudflareST_PATH}" || return 1

  # 运行 CloudflareST
  (https_proxy= http_proxy= timeout 600 ./CloudflareST \
      -tl "${TIME_LIMIT}" \
      -sl "${SPEEDTEST_LIMIT}" \
      -dn 13 \
      ${CFCOLO} \
      -url "${SPEEDTEST_URL}" \
      -o ./output) || return 1

  mv ./output results.csv || return 1
  return 0
}

# 重试主循环（保持你原来的“最多 6 次”行为不变）
while [ $count -lt 6 ]; do
  run_my_script
  RETVAL=$?
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
