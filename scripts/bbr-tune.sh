#!/usr/bin/env bash
# bbr-tune.sh — 启用 BBR + fq 并调大 TCP 缓冲
# 场景: 代理/中转服务器的高延迟大带宽链路 (中美 RTT ~150ms+)
# 验证: Debian 12, kernel 6.1 (MULTACOM VPS), 2026-09
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "请用 root 运行"; exit 1; }

# 加载 bbr 内核模块
modprobe tcp_bbr 2>/dev/null || true

# 持久化内核参数
CONF=/etc/sysctl.d/99-proxy-tune.conf
cat > "$CONF" <<'CONF'
# BBR + fq: proxy/relay 高延迟链路调优 (relayforge)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# TCP 缓冲上限 208KB -> 16MB, 匹配高 BDP (BDP = 带宽 x RTT)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
CONF

# 开机自动加载模块
grep -qx 'tcp_bbr' /etc/modules 2>/dev/null || echo tcp_bbr >> /etc/modules

# 立即生效
sysctl --system >/dev/null

# 校验
cc=$(sysctl -n net.ipv4.tcp_congestion_control)
qdisc=$(sysctl -n net.core.default_qdisc)
echo "tcp_congestion_control = $cc"
echo "net.core.default_qdisc = $qdisc"
if [[ $cc == bbr ]]; then
    echo "OK: BBR 已生效"
else
    echo "警告: BBR 未生效, 检查内核是否支持 (uname -r >= 4.9)"
    exit 1
fi
