#!/usr/bin/env bash
set -euo pipefail
exec /usr/bin/env bash "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/scripts/get_fast_ip.sh" "$@"

