#!/usr/bin/env bash
set -euo pipefail

PREFIX_BIN="${PREFIX_BIN:-/usr/local/bin}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"

REMOVE_SYSTEMD=0

usage() {
  cat <<'EOF'
Usage:
  sudo ./scripts/uninstall.sh [--remove-systemd]

Options:
  --remove-systemd   Disable timers/services and remove unit files from /etc/systemd/system

Env:
  PREFIX_BIN=/usr/local/bin
  SYSTEMD_DIR=/etc/systemd/system
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remove-systemd) REMOVE_SYSTEMD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "未知参数: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "需要 root 权限（请用 sudo 运行）" >&2
    exit 1
  fi
}

need_root

rm -f "${PREFIX_BIN}/v2ray-bench-nodes" "${PREFIX_BIN}/v2ray-bench-apply" "${PREFIX_BIN}/v2ray-bench-autoswitch"
echo "ok: removed ${PREFIX_BIN}/v2ray-bench-nodes, ${PREFIX_BIN}/v2ray-bench-apply, ${PREFIX_BIN}/v2ray-bench-autoswitch"

if [[ "${REMOVE_SYSTEMD}" -eq 1 ]]; then
  systemctl disable --now v2ray-bench-autoswitch.timer 2>/dev/null || true
  systemctl disable --now v2ray-bench-nodes.timer 2>/dev/null || true
  systemctl disable --now v2ray-bench-autoswitch.service 2>/dev/null || true
  systemctl disable --now v2ray-bench-nodes.service 2>/dev/null || true

  rm -f \
    "${SYSTEMD_DIR}/v2ray-bench-autoswitch.service" \
    "${SYSTEMD_DIR}/v2ray-bench-autoswitch.timer" \
    "${SYSTEMD_DIR}/v2ray-bench-nodes.service" \
    "${SYSTEMD_DIR}/v2ray-bench-nodes.timer"
  systemctl daemon-reload || true
  echo "ok: removed systemd units from ${SYSTEMD_DIR}"
fi
