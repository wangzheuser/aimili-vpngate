#!/usr/bin/env bash
set -u

# 多出口运行自检：只读取系统状态，不会修改 TUN、路由或 OpenVPN 进程。
SLOT_DEV_BASE="${SLOT_DEV_BASE:-120}"
SLOT_TABLE_BASE="${SLOT_TABLE_BASE:-200}"
SLOT_PORT_BASE="${SLOT_PORT_BASE:-17929}"
SLOT_PROXY_HOST="${SLOT_PROXY_HOST:-127.0.0.1}"
MAX_EXIT_SLOTS="${MAX_EXIT_SLOTS:-16}"
VPNGATE_DATA_DIR="${VPNGATE_DATA_DIR:-/data}"
SLOTS_FILE="${VPNGATE_DATA_DIR}/slots.json"

failures=0
checked=0
log() { printf '[multiexit-selfcheck] %s\n' "$*"; }
fail() { log "FAIL: $*"; failures=$((failures + 1)); }

if ! command -v ip >/dev/null 2>&1; then
  fail "缺少 ip 命令"
  exit "$failures"
fi

active_slots=""
if [ -f "$SLOTS_FILE" ] && command -v python3 >/dev/null 2>&1; then
  active_slots="$(python3 - "$SLOTS_FILE" <<'PY'
import json, sys
try:
    payload = json.load(open(sys.argv[1], encoding='utf-8'))
    for slot in payload.get('slots', []):
        if isinstance(slot, dict) and str(slot.get('status', '')) in ('up', 'pending'):
            print(int(slot.get('slot', -1)))
except Exception:
    pass
PY
)"
fi
if [ -z "$active_slots" ]; then
  configured="${MULTI_EXIT_SLOTS:-0}"
  for ((i=0; i<configured && i<MAX_EXIT_SLOTS; i++)); do active_slots="${active_slots}${i}"$'\n'; done
fi

while IFS= read -r index; do
  [ -n "$index" ] || continue
  case "$index" in
    ''|*[!0-9]*) continue ;;
  esac
  checked=$((checked + 1))
  device="tun$((SLOT_DEV_BASE + index))"
  table="$((SLOT_TABLE_BASE + index))"
  port="$((SLOT_PORT_BASE + index))"

  if ip link show "$device" >/dev/null 2>&1; then log "槽位 $index: $device 存在"; else fail "槽位 $index: $device 不存在"; fi
  if ip route show table "$table" | grep -q .; then log "槽位 $index: 路由表 $table 有默认路由"; else fail "槽位 $index: 路由表 $table 为空"; fi
  if ip rule show | grep -Eq "(oif $device|lookup $table|to all.*$table)"; then log "槽位 $index: 规则指向 $device/$table"; else fail "槽位 $index: 未找到指向 $device/$table 的 ip rule"; fi

  if command -v ss >/dev/null 2>&1; then
    if ss -ltn "sport = :$port" | tail -n +2 | grep -q .; then log "槽位 $index: 代理端口 $port 正在监听"; else fail "槽位 $index: 代理端口 $port 未监听"; fi
  else
    fail "缺少 ss 命令，无法检查代理端口 $port"
  fi

  if command -v curl >/dev/null 2>&1; then
    exit_ip="$(curl --noproxy '' --max-time 12 -fsS -x "http://${SLOT_PROXY_HOST}:${port}" https://api.ipify.org 2>/dev/null || true)"
    if printf '%s' "$exit_ip" | grep -Eq '^[0-9a-fA-F:.]+$'; then log "槽位 $index: 真实出口 IP $exit_ip"; else fail "槽位 $index: 无法通过代理获取真实出口 IP"; fi
  else
    fail "缺少 curl 命令，无法检查槽位 $index 的真实出口"
  fi
done <<EOF
$active_slots
EOF

if [ "$checked" -eq 0 ]; then
  log "未发现启用的多出口槽位；基础检查通过"
fi
if [ "$failures" -eq 0 ]; then
  log "PASS: 检查完成（槽位 $checked 个）"
else
  log "FAIL: 共 $failures 项检查失败"
fi
exit "$failures"
