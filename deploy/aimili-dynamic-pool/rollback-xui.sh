#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"
db_path="${1:?用法: rollback-xui.sh <x-ui.db> <runtime.json> [--dry-run]}"
runtime_path="${2:?用法: rollback-xui.sh <x-ui.db> <runtime.json> [--dry-run]}"
shift 2

exec python3 "$repo_root/scripts/rollback_xui_dynamic_pool.py" \
  --db "$db_path" \
  --runtime "$runtime_path" \
  "$@"
