#!/usr/bin/env bash
# node-tune.sh — sing-box 节点层提速（RelayForge）
#
# 针对代理服务本身（而非内核）的优化，改动前自动备份、改完校验、失败自动回滚：
#   1. 日志级别降到 warn（减少磁盘 IO 与日志体积；仅当当前为 debug/info）
#   2. TCP 类入站开启 TCP FastOpen（ss/vmess/vless/trojan/anytls）
#   3. 为配置过的日志文件生成 logrotate 规则（防止日志撑爆小盘 VPS）
#
# 用法：sudo ./node-tune.sh [--rollback] [--config-dir /etc/sing-box]
set -euo pipefail

CONF_DIR=/etc/sing-box
ROLLBACK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --rollback) ROLLBACK=1; shift ;;
    --config-dir) CONF_DIR="$2"; shift 2 ;;
    *) echo "[x] unknown arg: $1"; exit 1 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "[x] must run as root"; exit 1; }
command -v python3 >/dev/null || { echo "[x] python3 required"; exit 1; }

SB=/etc/sing-box/bin/sing-box
[ -x "$SB" ] || SB=$(command -v sing-box 2>/dev/null || true)
[ -n "$SB" ] || { echo "[x] sing-box not found"; exit 1; }

# ---------- locate config files ----------
FILES=()
[ -f "$CONF_DIR/config.json" ] && FILES+=("$CONF_DIR/config.json")
if [ -d "$CONF_DIR/conf" ]; then
  while IFS= read -r f; do FILES+=("$f"); done < <(find "$CONF_DIR/conf" -maxdepth 1 -name '*.json' 2>/dev/null)
fi
[ ${#FILES[@]} -gt 0 ] || { echo "[x] no config files under $CONF_DIR"; exit 1; }
echo "[i] configs: ${FILES[*]}"

if [ "$ROLLBACK" = 1 ]; then
  RESTORED=0
  for f in "${FILES[@]}"; do
    b="$f.node-tune.bak"
    if [ -f "$b" ]; then cp "$b" "$f"; rm -f "$b"; RESTORED=$((RESTORED+1)); fi
  done
  rm -f /etc/logrotate.d/relayforge-singbox
  systemctl restart sing-box 2>/dev/null || true
  echo "[i] rollback done ($RESTORED files restored)"
  exit 0
fi

# ---------- backup ----------
TS=$(date +%s)
for f in "${FILES[@]}"; do cp "$f" "$f.node-tune.bak"; done
LOG_FILES=()

# ---------- modify configs ----------
CHANGED=$(python3 - "${FILES[@]}" <<'PYEOF'
import sys, json

TCP_TYPES = {"shadowsocks", "vmess", "vless", "trojan", "anytls"}
changed = []
for path in sys.argv[1:]:
    try:
        cfg = json.load(open(path))
    except Exception as e:
        print(f"[skip] {path}: {e}", file=sys.stderr); continue
    touched = []

    # 1. lower log verbosity (disk IO)
    log = cfg.get("log")
    if isinstance(log, dict) and log.get("level") in ("debug", "info"):
        log["level"] = "warn"
        touched.append("log.level->warn")

    # 2. TCP FastOpen on TCP-based inbounds
    for ib in cfg.get("inbounds", []) or []:
        if ib.get("type") in TCP_TYPES and not ib.get("tcp_fast_open"):
            ib["tcp_fast_open"] = True
            touched.append(f"tfo:{ib.get('tag','?')}")

    if touched:
        json.dump(cfg, open(path, "w"), indent=2, ensure_ascii=False)
        changed.append(f"{path}: {', '.join(touched)}")
        # remember log output files for logrotate
        if isinstance(log, dict) and log.get("output"):
            print(log["output"])
print("\n".join(changed))
PYEOF
) || true

if [ -z "$CHANGED" ]; then
  echo "[i] nothing to tune (configs already optimal or empty)"
  exit 0
fi
echo "[i] changed:"
printf '%s\n' "$CHANGED" | sed 's/^/    /'

# ---------- validate & restart, auto-rollback on failure ----------
LOAD_ARGS="-c $CONF_DIR/config.json -C $CONF_DIR/conf"
[ -f "$CONF_DIR/config.json" ] || LOAD_ARGS="-C $CONF_DIR/conf"
if ! "$SB" check $LOAD_ARGS 2>/dev/null; then
  echo "[x] config check FAILED after tuning — rolling back"
  for f in "${FILES[@]}"; do [ -f "$f.node-tune.bak" ] && cp "$f.node-tune.bak" "$f"; done
  exit 1
fi
systemctl restart sing-box
sleep 2
if ! systemctl is-active --quiet sing-box; then
  echo "[x] sing-box failed after tuning — rolling back"
  for f in "${FILES[@]}"; do [ -f "$f.node-tune.bak" ] && cp "$f.node-tune.bak" "$f"; done
  systemctl restart sing-box
  echo "[!] restored, service active: $(systemctl is-active sing-box)"
  exit 1
fi
echo "[i] sing-box restarted OK"

# ---------- logrotate ----------
LOG_OUT=$(printf '%s\n' "$CHANGED" | grep -oE '/[^ :]+' | head -1)
if [ -n "$LOG_OUT" ] && [ -f "$LOG_OUT" ] && [ ! -f /etc/logrotate.d/relayforge-singbox ]; then
  cat > /etc/logrotate.d/relayforge-singbox <<EOF
$LOG_OUT {
    daily
    rotate 3
    maxsize 20M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
  echo "[i] logrotate rule added for $LOG_OUT (daily, 3 copies, 20M cap)"
fi

echo ""
echo "[i] done. rollback anytime:  sudo $0 --rollback"
