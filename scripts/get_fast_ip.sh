#!/usr/bin/env bash
# get_fast_ip.sh
# 目标：保持原有逻辑不变，只是把关键步骤加日志，并且下载用 latest/download（不依赖版本号）
# 关键要求：只有 CloudflareST 真正成功且产出 ./output 后，才 mv ./output -> results.csv

MAX_RETRIES=5
count=0

SPEEDTEST_URL="https://speedtest.sisyphus1212.life/"
SPEEDTEST_LIMIT=5
TIME_LIMIT=300

CFST_TGZ="cfst_linux_amd64.tar.gz"
CFST_URL="https://github.com/XIU2/CloudflareSpeedTest/releases/latest/download/${CFST_TGZ}"
# 国内/网络不稳可替换为镜像（保持 latest/download，不依赖版本号）
# CFST_URL="https://ghproxy.com/https://github.com/XIU2/CloudflareSpeedTest/releases/latest/download/${CFST_TGZ}"

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

run_noproxy() {
  env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY "$@"
}

die() {
  log "ERROR: $*"
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help)
      echo "Usage: $0 [--help] [--speed <value>] [--testurl <value>] [--timeout <value>]"
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
      exit 1
      ;;
  esac
done

run_my_script() {
    env_path=/etc/proxy_mgt.env
    if [ -f "${env_path}" ]; then
      log "Load env: ${env_path}"
      # shellcheck disable=SC1090
      . "${env_path}"
    else
      log "Env file not found: ${env_path} (continue)"
    fi

    # Avoid system proxy env vars affecting CloudflareST/wget/curl behavior.
    unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY

    CloudflareST_PATH=/root/CloudflareST
    log "Prepare dir: ${CloudflareST_PATH}"
    mkdir -p "${CloudflareST_PATH}" || return 1
    cd "${CloudflareST_PATH}" || return 1

    log "Clean old files in ${CloudflareST_PATH}"
    rm -rf ./*

    log "Download URL: ${CFST_URL}"
    if [ -n "${GET_REMOTE:-}" ]; then
      log "GET_REMOTE enabled -> download on remote host then scp back"
      log "Remote: ${PROXY_HOST_SSH_USER}@${PROXY_HOST_ADD}:${PROXY_HOST_SSH_PORT}"

      log "Remote download start..."
      sshpass -p "${PROXY_HOST_SSH_PASSWORD}" \
        ssh -o StrictHostKeyChecking=no -p "${PROXY_HOST_SSH_PORT}" \
        "${PROXY_HOST_SSH_USER}@${PROXY_HOST_ADD}" bash << EOF
set -e
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY
rm -f /root/${CFST_TGZ}
env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY wget -O /root/${CFST_TGZ} -L "${CFST_URL}"
ls -lh /root/${CFST_TGZ}
EOF
      [ $? -gt 0 ] && die "Remote download failed" || log "Remote download OK"

      log "SCP back start -> ${CloudflareST_PATH}/${CFST_TGZ}"
      sshpass -p "${PROXY_HOST_SSH_PASSWORD}" \
        scp -o StrictHostKeyChecking=no -P "${PROXY_HOST_SSH_PORT}" \
        "${PROXY_HOST_SSH_USER}@${PROXY_HOST_ADD}:/root/${CFST_TGZ}" \
        "${CloudflareST_PATH}/${CFST_TGZ}" || die "SCP back failed"
      log "SCP back OK"

      log "Extract tar: ${CFST_TGZ}"
      tar -zxf "${CFST_TGZ}" || die "tar extract failed"
      log "Extract OK"
    else
      log "GET_REMOTE disabled -> download locally"
      log "Local download start..."
      run_noproxy wget -O "${CFST_TGZ}" -L "${CFST_URL}" || die "Local download failed"
      log "Local download OK: $(ls -lh "${CFST_TGZ}" 2>/dev/null | awk '{print $5, $9}')"

      log "Extract tar: ${CFST_TGZ}"
      tar -zxf "${CFST_TGZ}" || die "tar extract failed"
      log "Extract OK"
    fi

    log "Detect CloudflareST binary..."
    CF_BIN=""
    if [ -f "./CloudflareST" ]; then
      CF_BIN="./CloudflareST"
    elif [ -f "./cfst" ]; then
      CF_BIN="./cfst"
    else
      CF_BIN="$(find . -maxdepth 1 -type f \( -name 'CloudflareST' -o -name 'cfst' \) | head -n 1)"
    fi
    [ -z "${CF_BIN}" ] && die "Binary not found after extract"
    log "Binary: ${CF_BIN}"

    log "chmod +x ${CF_BIN}"
    chmod +x "${CF_BIN}" || die "chmod failed"

    ASIA="CGD,FUO,FUK,FOC,CAN,HAK,SJW,TNA,PKX,LHW,LYA,TAO,SHA,TSN,KHN,CGO,CGQ,ZGN,WHU,HYN,COK,XMN,DPS,CNN,SZX,KWE,WUX,HGH,CZX,KMG"
    CFCOLO="" # "-cfcolo ${ASIA}"

    log "Run CloudflareST..."
    log "Params: -tl ${TIME_LIMIT} -sl ${SPEEDTEST_LIMIT} -dn 13 ${CFCOLO} -url ${SPEEDTEST_URL}"

    # 组装参数（避免 CFCOLO 为空时分词/参数问题）
    args=(-tl "${TIME_LIMIT}" -sl "${SPEEDTEST_LIMIT}" -dn 13 -url "${SPEEDTEST_URL}" -o ./output)
    if [ -n "${CFCOLO}" ]; then
      # CFCOLO 形如 "-cfcolo xxx" 才追加
      # shellcheck disable=SC2206
      args+=(${CFCOLO})
    fi

    # 成功判定：命令成功 + output 文件存在且非空
    (run_noproxy timeout 600 "${CF_BIN}" "${args[@]}") \
      || die "CloudflareST run failed"
    [ -s ./output ] || die "CloudflareST returned success but ./output missing/empty"

    log "CloudflareST run OK, save output -> results.csv"
    mv -f ./output results.csv || die "mv output to results.csv failed"

    log "Done. Results: ${CloudflareST_PATH}/results.csv (mtime: $(date -r results.csv '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo unknown))"
    return 0
}

log "Start. speed=${SPEEDTEST_LIMIT} timeout=${TIME_LIMIT} testurl=${SPEEDTEST_URL}"

while [ $count -lt 6 ]; do
    log "Attempt $((count+1))/6"
    run_my_script
    RETVAL=$?
    if [ $RETVAL -eq 0 ]; then
        log "SUCCESS"
        exit 0
    else
        log "FAIL (retval=${RETVAL}) -> retry"
        ((count++))
        if [ $count -gt 3 ]; then
            log "Retries > 3: adjust params: SPEEDTEST_LIMIT=1 and change SPEEDTEST_URL"
            if [ $SPEEDTEST_LIMIT -gt 1 ]; then
                SPEEDTEST_LIMIT=1
            fi
            SPEEDTEST_URL="https://gh.con.sh/https://github.com/AaronFeng753/Waifu2x-Extension-GUI/releases/download/v2.21.12/Waifu2x-Extension-GUI-v2.21.12-Portable.7z"
            log "New params: speed=${SPEEDTEST_LIMIT} testurl=${SPEEDTEST_URL}"
        fi
    fi
done

log "FAILED after tries: ${MAX_RETRIES} (note: loop is 6 attempts as in original logic)"
exit 1
