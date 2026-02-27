#!/usr/bin/env bash
set -euo pipefail

PREFIX_BIN="${PREFIX_BIN:-/usr/local/bin}"
LOG_FILE="${LOG_FILE:-/var/log/sshd_v2-bench.tsv}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

WITH_SYSTEMD=0
ENABLE_AUTOSWITCH=0
ENABLE_NODES=0
RUN_ONCE=0

usage() {
  cat <<'EOF'
Usage:
  sudo ./scripts/install.sh [--with-systemd] [--enable-autoswitch|--enable-nodes] [--run-once]

Options:
  --with-systemd        Copy systemd unit files into /etc/systemd/system
  --enable-autoswitch   Enable+start sshd_v2-bench-autoswitch.timer (requires --with-systemd)
  --enable-nodes        Enable+start sshd_v2-bench-nodes.timer (requires --with-systemd)
  --run-once            Start the corresponding .service once after enabling timer

Env:
  PREFIX_BIN=/usr/local/bin
  LOG_FILE=/var/log/sshd_v2-bench.tsv
  SYSTEMD_DIR=/etc/systemd/system
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-systemd) WITH_SYSTEMD=1; shift ;;
    --enable-autoswitch) ENABLE_AUTOSWITCH=1; shift ;;
    --enable-nodes) ENABLE_NODES=1; shift ;;
    --run-once) RUN_ONCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "未知参数: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${ENABLE_AUTOSWITCH}" -eq 1 && "${ENABLE_NODES}" -eq 1 ]]; then
  echo "不能同时启用 --enable-autoswitch 与 --enable-nodes（请选择其一）" >&2
  exit 2
fi

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "需要 root 权限（请用 sudo 运行）" >&2
    exit 1
  fi
}

need_root

install -m 0755 "${REPO_DIR}/bin/sshd_v2-bench-nodes" "${PREFIX_BIN}/sshd_v2-bench-nodes"
install -m 0755 "${REPO_DIR}/bin/sshd_v2-bench-apply" "${PREFIX_BIN}/sshd_v2-bench-apply"
install -m 0755 "${REPO_DIR}/bin/sshd_v2-bench-autoswitch" "${PREFIX_BIN}/sshd_v2-bench-autoswitch"

mkdir -p "$(dirname "${LOG_FILE}")"
touch "${LOG_FILE}"
chmod 0640 "${LOG_FILE}" || true

echo "ok: installed ${PREFIX_BIN}/sshd_v2-bench-nodes"
echo "ok: installed ${PREFIX_BIN}/sshd_v2-bench-apply"
echo "ok: installed ${PREFIX_BIN}/sshd_v2-bench-autoswitch"
echo "ok: ensured log file ${LOG_FILE}"

if [[ "${WITH_SYSTEMD}" -eq 1 ]]; then
  install -m 0644 "${REPO_DIR}/systemd/sshd_v2-bench-nodes.service" "${SYSTEMD_DIR}/sshd_v2-bench-nodes.service"
  install -m 0644 "${REPO_DIR}/systemd/sshd_v2-bench-nodes.timer" "${SYSTEMD_DIR}/sshd_v2-bench-nodes.timer"
  install -m 0644 "${REPO_DIR}/systemd/sshd_v2-bench-autoswitch.service" "${SYSTEMD_DIR}/sshd_v2-bench-autoswitch.service"
  install -m 0644 "${REPO_DIR}/systemd/sshd_v2-bench-autoswitch.timer" "${SYSTEMD_DIR}/sshd_v2-bench-autoswitch.timer"
  systemctl daemon-reload
  echo "ok: installed systemd units to ${SYSTEMD_DIR}"

  if [[ "${ENABLE_AUTOSWITCH}" -eq 1 ]]; then
    systemctl enable --now sshd_v2-bench-autoswitch.timer
    echo "ok: enabled sshd_v2-bench-autoswitch.timer"
    if [[ "${RUN_ONCE}" -eq 1 ]]; then
      systemctl start sshd_v2-bench-autoswitch.service
      echo "ok: started sshd_v2-bench-autoswitch.service"
    fi
  fi

  if [[ "${ENABLE_NODES}" -eq 1 ]]; then
    systemctl enable --now sshd_v2-bench-nodes.timer
    echo "ok: enabled sshd_v2-bench-nodes.timer"
    if [[ "${RUN_ONCE}" -eq 1 ]]; then
      systemctl start sshd_v2-bench-nodes.service
      echo "ok: started sshd_v2-bench-nodes.service"
    fi
  fi
fi
