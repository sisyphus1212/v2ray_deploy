#!/usr/bin/env bash
set -euo pipefail

PROXY_URL="${PROXY_URL:-http://127.0.0.1:44678}"
TARGET_URL="${TARGET_URL:-https://api.openai.com/}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5}"
MAX_TIME="${MAX_TIME:-10}"
LOG_FILE="${LOG_FILE:-/var/log/sshd_v2-telegram-probe.log}"
RETRIES="${RETRIES:-3}"
RETRY_SLEEP="${RETRY_SLEEP:-1}"

ts="$(date '+%Y-%m-%d %H:%M:%S')"
last_code="000"
for i in $(seq 1 "${RETRIES}"); do
  http_code="$(curl -L -I -sS -o /dev/null -w '%{http_code}' \
    -x "${PROXY_URL}" \
    --connect-timeout "${CONNECT_TIMEOUT}" \
    --max-time "${MAX_TIME}" \
    "${TARGET_URL}" || true)"
  if [[ -n "${http_code}" && "${http_code}" != "000" ]]; then
    echo "[${ts}] OK target=${TARGET_URL} proxy=${PROXY_URL} code=${http_code} attempt=${i}/${RETRIES}" >> "${LOG_FILE}"
    exit 0
  fi
  last_code="${http_code:-000}"
  sleep "${RETRY_SLEEP}"
done

echo "[${ts}] FAIL target=${TARGET_URL} proxy=${PROXY_URL} code=${last_code} attempts=${RETRIES}" >> "${LOG_FILE}"
exit 1
