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
CFST_PROXY_PREFIXES=(
  "https://ghproxy.vip/"
  "https://gh-proxy.com/"
  "https://ghfast.top/"
  "https://gh.ddlc.top/"
)
CFST_MAX_AGE_DAYS=3
download_via_proxy_local() {
  local dst="$1"
  local p url
  for p in "${CFST_PROXY_PREFIXES[@]}"; do
    url="${p}${CFST_URL}"
    log "Try proxy URL: ${url}"
    if run_noproxy wget -O "${dst}" -L --tries=1 --timeout=60 "${url}"; then
      log "Proxy download OK"
      return 0
    fi
  done
  return 1
}

is_file_older_than_days() {
  local file="$1"
  local days="$2"
  [ ! -f "${file}" ] && return 0
  local now mtime max_age
  now="$(date +%s)"
  mtime="$(date -r "${file}" +%s 2>/dev/null || echo 0)"
  max_age=$((days * 24 * 3600))
  [ $((now - mtime)) -gt "${max_age}" ]
}

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

    log "Clean runtime files in ${CloudflareST_PATH} (keep ${CFST_TGZ})"
    rm -f ./output ./results.csv ./CloudflareST ./cfst

    log "Primary download URL: ${CFST_URL}"
    download_ok=0
    if is_file_older_than_days "${CFST_TGZ}" "${CFST_MAX_AGE_DAYS}"; then
      log "CFST archive missing or older than ${CFST_MAX_AGE_DAYS} days -> start download"
      if [ -n "${PROXY_HOST_ADD:-}" ] && [ -n "${PROXY_HOST_SSH_PORT:-}" ] && [ -n "${PROXY_HOST_SSH_USER:-}" ] && [ -n "${PROXY_HOST_SSH_PASSWORD:-}" ]; then
      log "Step1 remote download"
      log "Remote: ${PROXY_HOST_SSH_USER}@${PROXY_HOST_ADD}:${PROXY_HOST_SSH_PORT}"
      sshpass -p "${PROXY_HOST_SSH_PASSWORD}" \
        ssh -o StrictHostKeyChecking=no -p "${PROXY_HOST_SSH_PORT}" \
        "${PROXY_HOST_SSH_USER}@${PROXY_HOST_ADD}" \
        CFST_TGZ="${CFST_TGZ}" CFST_URL="${CFST_URL}" bash << 'EOF'
set -e
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY
rm -f /root/${CFST_TGZ}
download_ok=0
urls=(
  "${CFST_URL}"
  "https://ghproxy.vip/${CFST_URL}"
  "https://gh-proxy.com/${CFST_URL}"
  "https://ghproxy.net/${CFST_URL}"
  "https://ghproxy.cc/${CFST_URL}"
)
for u in "${urls[@]}"; do
  echo "[remote] try: ${u}"
  if env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY \
    wget -O /root/${CFST_TGZ} -L --tries=1 --timeout=60 "${u}"; then
    download_ok=1
    break
  fi
done
[ "$download_ok" -eq 1 ] || exit 2
ls -lh /root/${CFST_TGZ}
EOF
      if [ $? -eq 0 ]; then
        log "Remote download OK"
        sshpass -p "${PROXY_HOST_SSH_PASSWORD}" \
          scp -o StrictHostKeyChecking=no -P "${PROXY_HOST_SSH_PORT}" \
          "${PROXY_HOST_SSH_USER}@${PROXY_HOST_ADD}:/root/${CFST_TGZ}" \
          "${CloudflareST_PATH}/${CFST_TGZ}" && download_ok=1
      fi
      fi

      if [ "${download_ok}" -eq 0 ]; then
        log "Step2 proxy download"
        download_via_proxy_local "${CFST_TGZ}" && download_ok=1
      fi

      if [ "${download_ok}" -eq 0 ]; then
        log "Step3 direct http download"
        run_noproxy wget -O "${CFST_TGZ}" -L --tries=1 --timeout=60 "${CFST_URL}" && download_ok=1
      fi
    else
      log "Reuse local ${CFST_TGZ}: age <= ${CFST_MAX_AGE_DAYS} days, skip download"
      download_ok=1
    fi

    [ "${download_ok}" -eq 1 ] || die "All download methods failed: remote/proxy/http"

    log "Extract tar: ${CFST_TGZ}"
    tar -zxf "${CFST_TGZ}" || die "tar extract failed"
    log "Extract OK"

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
    (run_noproxy timeout 1800 "${CF_BIN}" "${args[@]}") \
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
