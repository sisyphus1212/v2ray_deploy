#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="${LOG_FILE:-/var/log/sshd_v2-probe-recover.log}"
LOCK_FILE="${LOCK_FILE:-/run/sshd_v2-probe-recover.lock}"

SUBSCRIPTIONS_FILE="${SUBSCRIPTIONS_FILE:-/var/sshd_v2/subscriptions.txt}"
BENCH_BYTES="${BENCH_BYTES:-500000}"
BENCH_TIMEOUT="${BENCH_TIMEOUT:-12}"
BENCH_CONNECT_TIMEOUT="${BENCH_CONNECT_TIMEOUT:-4}"
BENCH_MAX_NODES="${BENCH_MAX_NODES:-5}"

ts="$(date '+%Y-%m-%d %H:%M:%S')"
mkdir -p /run

exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
  echo "[${ts}] SKIP lock_busy" >> "${LOG_FILE}"
  exit 0
fi

echo "[${ts}] START recover bench_bytes=${BENCH_BYTES} bench_timeout=${BENCH_TIMEOUT}" >> "${LOG_FILE}"

if [[ ! -s "${SUBSCRIPTIONS_FILE}" ]]; then
  echo "[${ts}] FAIL missing_subscriptions file=${SUBSCRIPTIONS_FILE}" >> "${LOG_FILE}"
  exit 1
fi

if ! /usr/local/bin/sshd_v2-bench-nodes \
  --bytes "${BENCH_BYTES}" \
  --timeout "${BENCH_TIMEOUT}" \
  --connect-timeout "${BENCH_CONNECT_TIMEOUT}" \
  --max-nodes "${BENCH_MAX_NODES}" \
  --top 1 \
  --log-top 1 \
  --show-ip >> "${LOG_FILE}" 2>&1; then
  echo "[${ts}] FAIL bench_nodes" >> "${LOG_FILE}"
  exit 1
fi

if ! /usr/local/bin/sshd_v2-bench-apply \
  --rank 1 \
  --method vmess \
  --connect-timeout "${BENCH_CONNECT_TIMEOUT}" \
  --probe-timeout 8 \
  --preflight-retries 1 \
  --postcheck-retries 1 >> "${LOG_FILE}" 2>&1; then
  echo "[${ts}] FAIL bench_apply" >> "${LOG_FILE}"
  exit 1
fi

echo "[${ts}] SUCCESS recovered" >> "${LOG_FILE}"
