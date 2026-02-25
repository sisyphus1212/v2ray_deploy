#!/usr/bin/env bash
set -euo pipefail
exec /usr/bin/env bash "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/scripts/proxy-mgmt_init.sh" "$@"

