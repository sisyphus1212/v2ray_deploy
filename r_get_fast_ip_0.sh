#!/usr/bin/env bash
set -euo pipefail
exec /usr/bin/env bash "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/scripts/r_get_fast_ip_0.sh" "$@"

