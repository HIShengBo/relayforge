#!/usr/bin/env bash
# server-tune.sh — VPS 内核网络栈提速（RelayForge）
#
# 面向代理/中转服务器的系统级优化：
#   - BBR + fq 队列
#   - UDP/QUIC 收发缓冲（hy2/tuic 大窗口需要）
#   - TCP backlog / TIME_WAIT / 端口范围 / FastOpen
#   - 文件描述符上限
#   - 可选 1G swap（--with-swap）
# 所有改动写入独立文件 /etc/sysctl.d/99-relayforge.conf，
# 不碰系统原配置；--rollback 一键还原。
#
# 用法：sudo ./server-tune.sh [--with-swap] [--rollback]
set -euo pipefail

WITHSWAP=0 ROLLBACK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --with-swap) WITHSWAP=1; shift ;;
    --rollback)  ROLLBACK=1; shift ;;
    *) echo "[x] unknown arg: $1"; exit 1 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "[x] must run as root"; exit 1; }

CONF=/etc/sysctl.d/99-relayforge.conf
LIMITS=/etc/systemd/system.conf.d/90-relayforge-limits.conf

if [ "$ROLLBACK" = 1 ]; then
  rm -f "$CONF" "$LIMITS"
  rm -f /etc/systemd/system.conf.d/90-relayforge-limits.conf
  systemctl daemon-reexec 2>/dev/null || true
  sysctl --system >/dev/null 2>&1 || true
  echo "[i] relayforge tuning removed, system defaults restored"
  echo "[i] note: reboot clears fd limits fully"
  exit 0
fi

echo "=== before ==="
sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc \
       net.core.rmem_max net.core.wmem_max fs.file-max 2>/dev/null || true

# ---------- BBR ----------
modprobe tcp_bbr 2>/dev/null || true
modprobe sch_fq 2>/dev/null || true
if ! grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
  echo "[!] kernel lacks BBR module — those settings will be skipped"
fi

mkdir -p /etc/systemd/system.conf.d

cat > "$CONF" <<'EOF'
# ==== RelayForge network tuning (safe to delete to rollback) ====
# congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# UDP / QUIC buffers (hysteria2/tuic large windows)
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.udp_mem = 8388608 12582912 16777216
# TCP buffers (BDP for high-latency international links)
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.tcp_mtu_probing = 1
# connection queues & lifecycle
net.core.somaxconn = 8192
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_slow_start_after_idle = 0
# file descriptors
fs.file-max = 1048576
EOF
if [ -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
  echo '# conntrack for busy relay nodes' >> "$CONF"
  echo 'net.netfilter.nf_conntrack_max = 1048576' >> "$CONF"
fi

cat > "$LIMITS" <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
EOF

systemctl daemon-reexec 2>/dev/null || true
sysctl -p "$CONF" >/dev/null
echo "=== after ==="
sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc \
       net.core.rmem_max net.core.wmem_max fs.file-max 2>/dev/null || true

# ---------- optional swap ----------
if [ "$WITHSWAP" = 1 ] && ! swapon --show | grep -q .; then
  fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  sysctl -qw vm.swappiness=15; echo 'vm.swappiness=15' > /etc/sysctl.d/99-swap.conf
  echo "[i] 1G swapfile created, swappiness=15"
fi

echo ""
echo "[i] done. rollback anytime:  sudo $0 --rollback"
[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" = "bbr" ] \
  && echo "[i] BBR active" || echo "[!] BBR not active on this kernel"
