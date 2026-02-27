---
name: v2ray-deploy-local-client-guard
description: >
  Project-local deployment guard for v2ray client + v2ray_deploy local mode.
  Enforces explicit mode selection, outbound proxy listen check, and Telegram
  connectivity acceptance criteria.
---

# v2ray-deploy-local-client-guard

## Goal

When deploying on a target host, ensure all of the following are true:

1. `v2ray_deploy` runs in local mode: `--local True`.
2. Subscription service bind/port are explicit (`PROXY_MGT_BIND` / `PROXY_MGT_PORT`).
3. Public proxy port is exposed on `0.0.0.0` (default expected: `18080`).
4. Hard acceptance command succeeds:
   - `curl -I --max-time 15 -x http://127.0.0.1:8080 https://api.telegram.org/`

## Mandatory Safety Rules

1. Always state mode explicitly before service changes:
   - local mode: `--local True`
   - remote mode: no `--local True` (high risk)
2. Default to local mode only.
3. If user requests `v2ray-bench-autoswitch.timer` or `v2ray-bench-apply`, warn that
   this may restart `v2ray.service` and cause short interruption; require confirmation.

## Execution Checklist (Host-Scoped)

1. Confirm target host exists and is reachable via Ansible.
2. Sync latest project code to target host.
3. Ensure `/etc/proxy_mgt.env` contains:
   - `PROXY_MGT_BIND=0.0.0.0` (or user-specified)
   - `PROXY_MGT_PORT=5000` (or user-specified)
4. Restart and verify `v2ray-deploy-local.service`.
5. Verify `/local-fast-ip` from localhost and public IP.
6. Verify `v2ray` inbound listeners:
   - local http proxy: `127.0.0.1:8080`
   - public http proxy: `0.0.0.0:18080` (or user-specified)
7. Run hard acceptance command:
   - `curl -I --max-time 15 -x http://127.0.0.1:8080 https://api.telegram.org/`
8. Report pass/fail with exact command evidence.
9. Verify v2ray-bench binaries include:
   - `v2ray-bench-nodes`
   - `v2ray-bench-apply`
   - `v2ray-bench-autoswitch`
   - `v2ray-bench-show`
10. If `v2ray-bench-show` is missing but repository has `subprojects/v2ray-bench/bin/v2ray-bench-show`,
    install it explicitly to `/usr/local/bin/v2ray-bench-show` with executable permission.

## Recommended Verification Commands

```bash
systemctl is-active v2ray-deploy-local.service
systemctl is-active v2ray
ss -lntp | egrep ':5000 |:8080 |:18080 '
curl -sS --max-time 20 http://127.0.0.1:5000/local-fast-ip | head -n 3
curl -I --max-time 15 -x http://127.0.0.1:8080 https://api.telegram.org/
ls -l /usr/local/bin/v2ray-bench-nodes /usr/local/bin/v2ray-bench-apply /usr/local/bin/v2ray-bench-autoswitch /usr/local/bin/v2ray-bench-show
```

## Troubleshooting Notes

1. If local endpoint is OK but public endpoint fails, verify current host public IP
   (avoid DNS/NAT/stale-IP confusion).
2. If `:8080` cannot be exposed on `0.0.0.0`, check port conflicts (common with Docker).
3. Keep `127.0.0.1:8080` as the canonical health-check path even when public proxy uses
   a different port (e.g. `18080`).
4. Current `scripts/install.sh` may omit `v2ray-bench-show` in some revisions; treat
   `/usr/local/bin/v2ray-bench-show` as a required post-install check.
