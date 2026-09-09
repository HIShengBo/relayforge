#!/usr/bin/env bash
# setup-relay.sh — sing-box 多协议中转一键部署（v4, RelayForge）
#
# 入口协议（任选子集，端口逐个自定义，全部转发到任意落地）：
#   hy2        Hysteria2            UDP/QUIC, 丢包线路首选
#   anytls     AnyTLS               TLS 流动+填充, 抗流量分析
#   tuic       TUIC v5              标准 QUIC + BBR
#   ss         Shadowsocks-2022     blake3-gcm, 抗重放
#   vmess      VMess + WS + TLS     老牌兼容
#   vless      VLESS + REALITY + Vision   抗主动探测(TCP)
#   trojan     Trojan + TLS         HTTPS 伪装
#   hysteria   Hysteria v1          QUIC, 老客户端兼容
#   shadowtls  ShadowTLS v3 + SS2022      TLS 伪装隧道
#   naive      NaiveProxy (HTTP/2)  浏览器指纹伪装 (无自动穿透自检)
#
# 落地：--landing 贴任意分享链接（vless/vmess/trojan/ss/hy2/tuic/anytls），
#       或 --landing direct 不转发就地出口。
# 整套配置在 /etc/sing-box/conf/relay.json，删除该文件重启即回滚。
# 依赖：root, sing-box >= 1.12, python3, openssl
set -euo pipefail

LANDING="" DRYRUN=0 WITHSWAP=0 FORCE=0 NOFIREWALL=0
PROTO_SPEC="hy2,anytls,tuic,ss"
PUBLIC_IP="" CERT="" KEY="" UNIT="sing-box"

# default port table (empty = random port assigned at runtime)
P_HY2=""; P_ANYTLS=""; P_TUIC=""; P_SS=""
P_VMESS=""; P_VLESS=""; P_TROJAN=""; P_HY1=""
P_STLS=""; P_NAIVE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --landing)     LANDING="$2"; shift 2 ;;
    --protocols)   PROTO_SPEC="$2"; shift 2 ;;
    --hy2-port)    P_HY2="$2"; shift 2 ;;
    --anytls-port) P_ANYTLS="$2"; shift 2 ;;
    --tuic-port)   P_TUIC="$2"; shift 2 ;;
    --ss-port)     P_SS="$2"; shift 2 ;;
    --vmess-port)  P_VMESS="$2"; shift 2 ;;
    --vless-port)  P_VLESS="$2"; shift 2 ;;
    --trojan-port) P_TROJAN="$2"; shift 2 ;;
    --hysteria-port) P_HY1="$2"; shift 2 ;;
    --shadowtls-port) P_STLS="$2"; shift 2 ;;
    --naive-port)  P_NAIVE="$2"; shift 2 ;;
    --dry-run)     DRYRUN=1; shift ;;
    --with-swap)   WITHSWAP=1; shift ;;
    --force)       FORCE=1; shift ;;
    --public-ip)   PUBLIC_IP="$2"; shift 2 ;;
    --cert)        CERT="$2"; shift 2 ;;
    --key)         KEY="$2"; shift 2 ;;
    --unit)        UNIT="$2"; shift 2 ;;
    --no-firewall) NOFIREWALL=1; shift ;;
    *) echo "[x] unknown arg: $1"; exit 1 ;;
  esac
done

[ "$(id -u)" = 0 ] || { echo "[x] must run as root"; exit 1; }
[ -n "$LANDING" ] || { echo "[x] --landing is required (share link or 'direct')"; exit 1; }
command -v python3 >/dev/null || { echo "[x] python3 required"; exit 1; }
command -v openssl >/dev/null || { echo "[x] openssl required"; exit 1; }

# NOFIREWALL=1: skip automatic firewall openings
# ---------- distro compatibility layer ----------
# open firewall ports (firewalld / ufw / nft / iptables) — order matters:
# firewalld > ufw > raw nft/iptables. Skipped entirely with --no-firewall.
open_fw_tcp()  { fw_open_port "$1" tcp; }
open_fw_udp()  { fw_open_port "$1" udp; }

fw_open_port() {
  local port=$1 proto=$2
  # firewalld (RHEL/Rocky/Alma/Fedora/openSUSE)
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1 \
      && firewall-cmd --reload >/dev/null 2>&1 \
      && { echo "[fw] firewalld allow ${port}/${proto}"; return; }
    echo "[!] firewalld present but failed to open ${port}/${proto}"; return
  fi
  # ufw (Ubuntu/Debian)
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "${port}/${proto}" >/dev/null 2>&1 && { echo "[fw] ufw allow ${port}/${proto}"; return; }
  fi
  # nftables with an active ruleset
  if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1 && [ -n "$(nft list ruleset 2>/dev/null)" ]; then
    if nft add rule inet filter input tcp dport "$port" accept 2>/dev/null && [ "$proto" = tcp ]; then
      echo "[fw] nft allow ${port}/tcp (non-persistent!)"; return
    fi
    if nft add rule inet filter input udp dport "$port" accept 2>/dev/null && [ "$proto" = udp ]; then
      echo "[fw] nft allow ${port}/udp (non-persistent!)"; return
    fi
  fi
  # iptables (legacy or via nft backend) — only if a non-empty INPUT policy chain exists
  if command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP\|^-P INPUT REJECT'; then
    iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null \
      && echo "[fw] iptables allow ${port}/${proto} (non-persistent!)" && return
  fi
  # no active firewall found — nothing to do
  return 0
}

fw_detect() {
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then echo firewalld
  elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then echo ufw
  elif command -v nft >/dev/null 2>&1 && [ -n "$(nft list ruleset 2>/dev/null)" ]; then echo nftables
  elif command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP\|^-P INPUT REJECT'; then echo iptables
  else echo none
  fi
}

# SELinux (RHEL family): label cert/key paths so sing-box can read them
selinux_fix_certs() {
  if [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
    local d; d=$(dirname "$CERT")
    if command -v restorecon >/dev/null 2>&1; then
      restorecon -R "$d" 2>/dev/null || true
      echo "[i] SELinux: restorecon applied to $d"
    fi
    if command -v semanage >/dev/null 2>&1; then
      semanage fcontext -a -t cert_t "$CERT" 2>/dev/null || true
      semanage fcontext -a -t cert_t "$KEY" 2>/dev/null || true
      restorecon "$CERT" "$KEY" 2>/dev/null || true
      echo "[i] SELinux: cert_t labels applied"
    else
      echo "[!] SELinux enforcing: install policycoreutils-python-utils for persistent labels"
      echo "    (dnf install policycoreutils-python-utils) then re-run this script"
    fi
    # cert_t relabel after generation; generic fallback
    chcon -t cert_t "$CERT" "$KEY" 2>/dev/null || true
  fi
}

FW_MODE=$(fw_detect)
echo "[i] firewall: $FW_MODE"
case "$FW_MODE" in
  firewalld|ufw) ;;
  nftables|iptables) echo "[!] active packet firewall detected; ports will be opened non-persistently (lost on reboot)" ;;
esac

# ---------- protocol selection ----------
IFS=',' read -ra PROTO_LIST <<< "$PROTO_SPEC"
for p in "${PROTO_LIST[@]}"; do
  case "$p" in
    hy2|anytls|tuic|ss|vmess|vless|trojan|hysteria|shadowtls|naive) ;;
    *) echo "[x] unknown protocol '$p'"; echo "    valid: hy2,anytls,tuic,ss,vmess,vless,trojan,hysteria,shadowtls,naive"; exit 1 ;;
  esac
done
[ ${#PROTO_LIST[@]} -gt 0 ] || { echo "[x] empty --protocols"; exit 1; }

# ---------- locate sing-box ----------
SB=/etc/sing-box/bin/sing-box
[ -x "$SB" ] || SB=$(command -v sing-box 2>/dev/null || true)
[ -n "$SB" ] || { echo "[x] sing-box not found"; exit 1; }
echo "[i] sing-box: $("$SB" version 2>/dev/null | head -1)"

CONF_DIR=/etc/sing-box
mkdir -p "$CONF_DIR/conf"

# ---------- optional swap ----------
if [ "$WITHSWAP" = 1 ] && ! swapon --show | grep -q .; then
  fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  sysctl -qw vm.swappiness=15; echo 'vm.swappiness=15' > /etc/sysctl.d/99-swap.conf
  echo "[i] 1G swapfile created, swappiness=15"
fi

# ---------- port assignment ----------
declare -A PORT
declare -A EXPLICIT
EXPLICIT[hy2]=$P_HY2; EXPLICIT[anytls]=$P_ANYTLS; EXPLICIT[tuic]=$P_TUIC; EXPLICIT[ss]=$P_SS
EXPLICIT[vmess]=$P_VMESS; EXPLICIT[vless]=$P_VLESS; EXPLICIT[trojan]=$P_TROJAN
EXPLICIT[hysteria]=$P_HY1; EXPLICIT[shadowtls]=$P_STLS; EXPLICIT[naive]=$P_NAIVE

# value_taken PORT_KEY: 0 if port already assigned to another protocol
port_dup() {
  local n=$1 q
  for q in "${!PORT[@]}"; do [ "${PORT[$q]}" = "$n" ] && return 0; done
  return 1
}

for p in "${PROTO_LIST[@]}"; do
  if [ -n "${EXPLICIT[$p]}" ]; then
    PORT[$p]=${EXPLICIT[$p]}
  else
    # random available port in 10000-64999, unique within this deployment
    while :; do
      n=$(( ((RANDOM<<15) | RANDOM) % 55000 + 10000 ))
      port_dup "$n" && continue
      ss -tulnp 2>/dev/null | grep -E ":$n " | grep -vq 'sing-box' && continue
      PORT[$p]=$n
      break
    done
    echo "[i] $p -> port ${PORT[$p]} (random)"
  fi
done

# duplicate value check (explicit collisions)
DUPS=$(for p in "${PROTO_LIST[@]}"; do echo "${PORT[$p]}"; done | sort | uniq -d)
[ -z "$DUPS" ] || { echo "[x] duplicate ports assigned: $DUPS"; exit 1; }
for p in "${!PORT[@]}"; do
  n=${PORT[$p]}
  [ "$n" -ge 1 ] && [ "$n" -le 65535 ] || { echo "[x] port $n ($p) out of range"; exit 1; }
  if ss -tulnp | grep -E ":$n " | grep -vq 'sing-box'; then
    echo "[x] port $n ($p) used by another process:"; ss -tulnp | grep -E ":$n "; exit 1
  fi
done
for p in "${PROTO_LIST[@]}"; do echo "[i] $p -> port ${PORT[$p]}"; done

# ---------- firewall: open selected ports ----------
# transport per protocol: tcp / udp / both
fw_proto() {
  case "$1" in
    hy2|tuic|hysteria) echo udp ;;
    ss)                echo both ;;
    *)                 echo tcp ;;
  esac
}
if [ "$NOFIREWALL" = 1 ]; then
  echo "[i] firewall handling skipped (--no-firewall)"
elif [ "$FW_MODE" = "none" ]; then
  echo "[i] no active firewall detected, nothing to open"
elif [ "$DRYRUN" = 0 ]; then
  for p in "${PROTO_LIST[@]}"; do
    case "$(fw_proto "$p")" in
      udp)  open_fw_udp "${PORT[$p]}" ;;
      both) open_fw_tcp "${PORT[$p]}"; open_fw_udp "${PORT[$p]}" ;;
      tcp)  open_fw_tcp "${PORT[$p]}" ;;
    esac
  done
else
  echo "[i] dry-run: firewall would be opened for selected ports"
fi

# shadowtls inner ss port (loopback only, random)
STLS_INNER=$((30000 + RANDOM % 20000))
while ss -tlnp | grep -q ":$STLS_INNER "; do STLS_INNER=$((30000 + RANDOM % 20000)); done

# ---------- parse landing: any share link, or 'direct' ----------
LANDING_OUT=$(python3 - "$LANDING" <<'PYEOF'
import sys, json, base64
from urllib.parse import urlsplit, parse_qs, unquote

link = sys.argv[1].strip()
scheme = link.split('://', 1)[0].lower() if '://' in link else 'direct'

def b64d(s):
    s = s.strip().replace('-', '+').replace('_', '/')
    return base64.b64decode(s + '=' * (-len(s) % 4)).decode('utf-8', 'replace')

def tls_block(q, sni_fallback='', insecure=False):
    t = {"enabled": True}
    sni = (q.get('sni', [''])[0] or sni_fallback)
    if sni: t["server_name"] = sni
    fp = q.get('fp', [''])[0]
    if q.get('security', [''])[0] == 'reality' and q.get('pbk'):
        t["reality"] = {"enabled": True,
                        "public_key": q['pbk'][0],
                        "short_id": q.get('sid', [''])[0]}
        fp = fp or 'chrome'   # sing-box reality client requires uTLS
    if fp:
        t["utls"] = {"enabled": True, "fingerprint": fp}
    if insecure or q.get('insecure', ['0'])[0] in ('1', 'true'):
        t["insecure"] = True
    return t

def transport_block(q):
    net = q.get('type', ['tcp'])[0]
    if net == 'ws':
        t = {"type": "ws", "path": unquote(q.get('path', ['/'])[0])}
        if q.get('host'): t["headers"] = {"Host": q['host'][0]}
        return t
    if net == 'grpc':
        return {"type": "grpc", "service_name": unquote(q.get('serviceName', [''])[0])}
    return None

if scheme == 'direct':
    print(json.dumps({"direct": True})); sys.exit()

out = None
if scheme == 'vless':
    u = urlsplit(link); q = parse_qs(u.query)
    out = {"type": "vless", "server": u.hostname, "server_port": u.port or 443, "uuid": unquote(u.username or '')}
    if q.get('flow'): out["flow"] = q['flow'][0]
    if q.get('security', [''])[0] in ('tls', 'reality') or q.get('pbk'):
        out["tls"] = tls_block(q)
    tb = transport_block(q)
    if tb: out["transport"] = tb
elif scheme == 'vmess':
    j = json.loads(b64d(link.split('://', 1)[1].split('#', 1)[0]))
    out = {"type": "vmess", "server": j["add"], "server_port": int(j["port"]),
           "uuid": j["id"], "security": j.get("scy") or "auto"}
    if str(j.get("aid", 0)) not in ('0', ''):
        out["alter_id"] = int(j["aid"])
    if str(j.get("tls", '')) == 'tls':
        out["tls"] = {"enabled": True}
        sni = j.get('sni') or j.get('host')
        if sni: out["tls"]["server_name"] = sni
    if j.get("net") == 'ws':
        t = {"type": "ws", "path": j.get("path", "/")}
        if j.get("host"): t["headers"] = {"Host": j["host"]}
        out["transport"] = t
elif scheme == 'trojan':
    u = urlsplit(link); q = parse_qs(u.query)
    out = {"type": "trojan", "server": u.hostname, "server_port": u.port or 443,
           "password": unquote(u.username or '')}
    out["tls"] = tls_block(q, sni_fallback=u.hostname)
    tb = transport_block(q)
    if tb: out["transport"] = tb
elif scheme == 'ss':
    body = link.split('://', 1)[1].split('#', 1)[0]
    if '@' in body:
        userinfo, hostport = body.rsplit('@', 1)
        try:
            dec = b64d(userinfo)
            if ':' in dec and '@' not in dec: userinfo = dec
        except Exception:
            pass
    else:
        userinfo, hostport = b64d(body).rsplit('@', 1)
    method, pwd = userinfo.split(':', 1)
    host, port = hostport.rsplit(':', 1)
    out = {"type": "shadowsocks", "server": host, "server_port": int(port),
           "method": method, "password": pwd}
elif scheme in ('hy2', 'hysteria2'):
    u = urlsplit(link); q = parse_qs(u.query)
    pwd = unquote(u.username or '')
    if u.password: pwd += ':' + unquote(u.password)
    out = {"type": "hysteria2", "server": u.hostname, "server_port": u.port or 443, "password": pwd}
    out["tls"] = tls_block(q, sni_fallback=u.hostname, insecure=True)
elif scheme == 'tuic':
    u = urlsplit(link); q = parse_qs(u.query)
    out = {"type": "tuic", "server": u.hostname, "server_port": u.port or 443,
           "uuid": unquote(u.username or ''), "password": unquote(u.password or '')}
    if q.get('congestion_control'): out["congestion_control"] = q['congestion_control'][0]
    out["tls"] = tls_block(q, sni_fallback=u.hostname, insecure=True)
elif scheme == 'anytls':
    u = urlsplit(link); q = parse_qs(u.query)
    out = {"type": "anytls", "server": u.hostname, "server_port": u.port or 443,
           "password": unquote(u.username or '')}
    out["tls"] = tls_block(q, sni_fallback=u.hostname, insecure=True)
else:
    sys.stderr.write("unsupported scheme: %s\n" % scheme); sys.exit(2)

out["tag"] = "landing"
print(json.dumps(out))
PYEOF
) || { echo "[x] cannot parse --landing"; exit 1; }

IS_DIRECT=0
printf '%s' "$LANDING_OUT" | grep -q '"direct"' && IS_DIRECT=1
if [ "$IS_DIRECT" = 1 ]; then
  echo "[i] landing: DIRECT (no forwarding, exit = this machine)"
else
  L_SERVER=$(printf '%s' "$LANDING_OUT" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("server",""))')
  L_TYPE=$(printf '%s' "$LANDING_OUT" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("type",""))')
  echo "[i] landing: $L_TYPE -> $L_SERVER"
fi

# ---------- TLS cert for inbounds (reuse or self-sign) ----------
if [ -z "$CERT" ] || [ -z "$KEY" ]; then
  CERT=/etc/sing-box/bin/tls.cer; KEY=/etc/sing-box/bin/tls.key
  if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    mkdir -p /etc/sing-box/bin
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout "$KEY" -out "$CERT" -days 3650 -subj "/CN=tls" 2>/dev/null
    echo "[i] self-signed cert generated (clients need insecure=1)"
  fi
fi
selinux_fix_certs

# ---------- credentials ----------
HAS() { printf '%s\n' "${PROTO_LIST[@]}" | grep -qx "$1"; }

ANYTLS_PASS=$(openssl rand -hex 12)
TUIC_UUID=$(cat /proc/sys/kernel/random/uuid); TUIC_PASS=$(openssl rand -hex 12)
SS_PASS=$(openssl rand -base64 16 | tr -d '\n')
HY2_PASS=$(openssl rand -hex 12)
VMESS_UUID=$(cat /proc/sys/kernel/random/uuid); WS_PATH="/$(openssl rand -hex 4)"
VLESS_UUID=$(cat /proc/sys/kernel/random/uuid); VLESS_SID=$(openssl rand -hex 4)
TROJAN_PASS=$(openssl rand -hex 12)
HY1_PASS=$(openssl rand -hex 12)
STLS_PASS=$(openssl rand -base64 16 | tr -d '\n'); STLS_SS_PASS=$(openssl rand -base64 16 | tr -d '\n')
NAIVE_PASS=$(openssl rand -hex 12)

if HAS vless; then
  KP=$("$SB" generate reality-keypair)
  VLESS_PK=$(printf '%s' "$KP" | awk '/PrivateKey/{print $2}')
  VLESS_PUB=$(printf '%s' "$KP" | awk '/PublicKey/{print $2}')
fi

if [ "$DRYRUN" = 0 ] && [ "$FORCE" = 0 ] && [ -f "$CONF_DIR/conf/relay.json" ]; then
  echo "[x] $CONF_DIR/conf/relay.json already exists (use --force to overwrite)"; exit 1
fi

# ---------- generate inbound JSON per protocol ----------
gen_inbound() {
  case "$1" in
    hy2)    cat <<EOF
    {
      "tag": "hy2-relay-in", "type": "hysteria2", "listen": "::", "listen_port": ${PORT[hy2]},
      "users": [ { "password": "$HY2_PASS" } ],
      "tls": { "enabled": true, "alpn": [ "h3" ], "key_path": "$KEY", "certificate_path": "$CERT" }
    }
EOF
;;
    anytls) cat <<EOF
    {
      "tag": "anytls-relay-in", "type": "anytls", "listen": "::", "listen_port": ${PORT[anytls]},
      "users": [ { "password": "$ANYTLS_PASS" } ],
      "tls": { "enabled": true, "key_path": "$KEY", "certificate_path": "$CERT" }
    }
EOF
;;
    tuic)   cat <<EOF
    {
      "tag": "tuic-relay-in", "type": "tuic", "listen": "::", "listen_port": ${PORT[tuic]},
      "users": [ { "uuid": "$TUIC_UUID", "password": "$TUIC_PASS" } ],
      "congestion_control": "bbr",
      "tls": { "enabled": true, "alpn": [ "h3" ], "key_path": "$KEY", "certificate_path": "$CERT" }
    }
EOF
;;
    ss)     cat <<EOF
    {
      "tag": "ss2022-relay-in", "type": "shadowsocks", "listen": "::", "listen_port": ${PORT[ss]},
      "method": "2022-blake3-aes-128-gcm", "password": "$SS_PASS"
    }
EOF
;;
    vmess)  cat <<EOF
    {
      "tag": "vmess-relay-in", "type": "vmess", "listen": "::", "listen_port": ${PORT[vmess]},
      "users": [ { "uuid": "$VMESS_UUID" } ],
      "tls": { "enabled": true, "key_path": "$KEY", "certificate_path": "$CERT" },
      "transport": { "type": "ws", "path": "$WS_PATH" }
    }
EOF
;;
    vless)  cat <<EOF
    {
      "tag": "vless-relay-in", "type": "vless", "listen": "::", "listen_port": ${PORT[vless]},
      "users": [ { "uuid": "$VLESS_UUID", "flow": "xtls-rprx-vision" } ],
      "tls": {
        "enabled": true,
        "server_name": "www.amazon.com",
        "reality": {
          "enabled": true,
          "handshake": { "server": "www.amazon.com", "server_port": 443 },
          "private_key": "$VLESS_PK",
          "short_id": [ "$VLESS_SID" ]
        }
      }
    }
EOF
;;
    trojan) cat <<EOF
    {
      "tag": "trojan-relay-in", "type": "trojan", "listen": "::", "listen_port": ${PORT[trojan]},
      "users": [ { "password": "$TROJAN_PASS" } ],
      "tls": { "enabled": true, "alpn": [ "h2", "http/1.1" ], "key_path": "$KEY", "certificate_path": "$CERT" }
    }
EOF
;;
    hysteria) cat <<EOF
    {
      "tag": "hy1-relay-in", "type": "hysteria", "listen": "::", "listen_port": ${PORT[hysteria]},
      "up_mbps": 100, "down_mbps": 100,
      "users": [ { "auth_str": "relay:$HY1_PASS" } ],
      "tls": { "enabled": true, "key_path": "$KEY", "certificate_path": "$CERT" }
    }
EOF
;;
    shadowtls) cat <<EOF
    {
      "tag": "shadowtls-relay-in", "type": "shadowtls", "listen": "::", "listen_port": ${PORT[shadowtls]},
      "version": 3,
      "users": [ { "password": "$STLS_PASS" } ],
      "handshake": { "server": "www.bing.com", "server_port": 443 },
      "detour": "ss-st-inner"
    },
    {
      "tag": "ss-st-inner", "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": $STLS_INNER,
      "method": "2022-blake3-aes-128-gcm", "password": "$STLS_SS_PASS"
    }
EOF
;;
    naive)  cat <<EOF
    {
      "tag": "naive-relay-in", "type": "naive", "listen": "::", "listen_port": ${PORT[naive]},
      "users": [ { "username": "naive", "password": "$NAIVE_PASS" } ],
      "tls": { "enabled": true, "key_path": "$KEY", "certificate_path": "$CERT" }
    }
EOF
;;
  esac
}

INBOUNDS_JSON=""
for p in "${PROTO_LIST[@]}"; do
  part=$(gen_inbound "$p")
  [ -n "$INBOUNDS_JSON" ] && INBOUNDS_JSON="$INBOUNDS_JSON,
$part" || INBOUNDS_JSON="$part"
done
INBOUNDS_JSON="$INBOUNDS_JSON,
    { \"tag\": \"socks-local\", \"type\": \"socks\", \"listen\": \"127.0.0.1\", \"listen_port\": 1080 }"

# inbound tag per protocol (keep in sync with gen_inbound)
tag_of() {
  case "$1" in
    ss) echo "ss2022-relay-in" ;;
    hysteria) echo "hy1-relay-in" ;;
    *) echo "$1-relay-in" ;;
  esac
}

ROUTE_IN=""
for p in "${PROTO_LIST[@]}"; do
  [ -n "$ROUTE_IN" ] && ROUTE_IN="$ROUTE_IN, "
  ROUTE_IN="$ROUTE_IN\"$(tag_of "$p")\""
done
# shadowtls inner ss inbound also needs explicit routing (default outbound is direct)
HAS shadowtls && ROUTE_IN="$ROUTE_IN, \"ss-st-inner\""
ROUTE_IN="$ROUTE_IN, \"socks-local\""

if [ "$IS_DIRECT" = 1 ]; then
  TAIL_BLOCK='  "outbounds": [ { "type": "direct", "tag": "direct-out" } ]'
else
  TAIL_BLOCK=$(cat <<EOF
  "outbounds": [
    $LANDING_OUT
  ],
  "route": {
    "rules": [
      { "inbound": [ $ROUTE_IN ], "action": "route", "outbound": "landing" }
    ]
  }
EOF
)
fi

OUT_JSON=$(mktemp /tmp/relay.XXXX.json)
cat > "$OUT_JSON" <<EOF
{
  "inbounds": [
$INBOUNDS_JSON
  ],
$TAIL_BLOCK
}
EOF

echo "[i] config written: $OUT_JSON"
"$SB" check -c "$OUT_JSON" || { echo "[x] config check failed"; exit 1; }
echo "[i] config check OK"
if [ "$DRYRUN" = 1 ]; then
  echo "[i] landing outbound JSON: $LANDING_OUT"
  echo "[i] dry-run mode, not applied. Apply manually:"
  echo "    cp $OUT_JSON $CONF_DIR/conf/relay.json && systemctl restart $UNIT"
  exit 0
fi

mv "$OUT_JSON" "$CONF_DIR/conf/relay.json"
systemctl restart "$UNIT"
sleep 2
systemctl is-active --quiet "$UNIT" || { echo "[x] sing-box failed to start, check journalctl -u $UNIT"; exit 1; }
echo "[i] sing-box restarted, ports:"
for p in "${PROTO_LIST[@]}"; do
  ss -tlnup | grep -E ":${PORT[$p]} " | awk -v proto="$p" '{print "    [" proto "] " $1, $5}'
done

# ---------- end-to-end test (naive has no sing-box outbound, skipped) ----------
[ -n "$PUBLIC_IP" ] || PUBLIC_IP=$(curl -s --max-time 8 api.ipify.org || hostname -I | awk '{print $1}')

if [ "$IS_DIRECT" = 1 ]; then
  EXPECT_IP="$PUBLIC_IP"; STRICT=1
elif printf '%s' "$L_SERVER" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
  EXPECT_IP="$L_SERVER"; STRICT=1
else
  EXPECT_IP="$L_SERVER"; STRICT=0
fi

TPORT_BASE=$((20000 + RANDOM % 20000))
T_IN="" T_OUT="" T_RULE="" T_SPECS=()
tport=$TPORT_BASE
for p in "${PROTO_LIST[@]}"; do
  [ "$p" = "naive" ] && continue   # no naive outbound in sing-box
  mtag="m-$p"; otag="o-$p"; tp=$tport
  T_IN="${T_IN}{ \"type\": \"mixed\", \"tag\": \"$mtag\", \"listen\": \"127.0.0.1\", \"listen_port\": $tp },"
  case "$p" in
    hy2) T_OUT="${T_OUT}{ \"type\": \"hysteria2\", \"tag\": \"$otag\", \"server\": \"127.0.0.1\", \"server_port\": ${PORT[$p]}, \"password\": \"$HY2_PASS\",
      \"tls\": { \"enabled\": true, \"server_name\": \"tls\", \"insecure\": true, \"alpn\": [ \"h3\" ] } },"
;;
    anytls) T_OUT="${T_OUT}{ \"type\": \"anytls\", \"tag\": \"$otag\", \"server\": \"127.0.0.1\", \"server_port\": ${PORT[$p]}, \"password\": \"$ANYTLS_PASS\",
      \"tls\": { \"enabled\": true, \"server_name\": \"tls\", \"insecure\": true, \"utls\": { \"enabled\": true, \"fingerprint\": \"chrome\" } } },"
;;
    tuic) T_OUT="${T_OUT}{ \"type\": \"tuic\", \"tag\": \"$otag\", \"server\": \"127.0.0.1\", \"server_port\": ${PORT[$p]}, \"uuid\": \"$TUIC_UUID\", \"password\": \"$TUIC_PASS\", \"congestion_control\": \"bbr\",
      \"tls\": { \"enabled\": true, \"server_name\": \"tls\", \"insecure\": true, \"alpn\": [ \"h3\" ] } },"
;;
    ss) T_OUT="${T_OUT}{ \"type\": \"shadowsocks\", \"tag\": \"$otag\", \"server\": \"127.0.0.1\", \"server_port\": ${PORT[$p]}, \"method\": \"2022-blake3-aes-128-gcm\", \"password\": \"$SS_PASS\" },"
;;
    vmess) T_OUT="${T_OUT}{ \"type\": \"vmess\", \"tag\": \"$otag\", \"server\": \"127.0.0.1\", \"server_port\": ${PORT[$p]}, \"uuid\": \"$VMESS_UUID\", \"security\": \"auto\",
      \"tls\": { \"enabled\": true, \"server_name\": \"tls\", \"insecure\": true }, \"transport\": { \"type\": \"ws\", \"path\": \"$WS_PATH\" } },"
;;
    vless) T_OUT="${T_OUT}{ \"type\": \"vless\", \"tag\": \"$otag\", \"server\": \"127.0.0.1\", \"server_port\": ${PORT[$p]}, \"uuid\": \"$VLESS_UUID\", \"flow\": \"xtls-rprx-vision\",
      \"tls\": { \"enabled\": true, \"server_name\": \"www.amazon.com\", \"utls\": { \"enabled\": true, \"fingerprint\": \"chrome\" },
        \"reality\": { \"enabled\": true, \"public_key\": \"$VLESS_PUB\", \"short_id\": \"$VLESS_SID\" } } },"
;;
    trojan) T_OUT="${T_OUT}{ \"type\": \"trojan\", \"tag\": \"$otag\", \"server\": \"127.0.0.1\", \"server_port\": ${PORT[$p]}, \"password\": \"$TROJAN_PASS\",
      \"tls\": { \"enabled\": true, \"server_name\": \"tls\", \"insecure\": true } },"
;;
    hysteria) T_OUT="${T_OUT}{ \"type\": \"hysteria\", \"tag\": \"$otag\", \"server\": \"127.0.0.1\", \"server_port\": ${PORT[$p]}, \"auth_str\": \"relay:$HY1_PASS\", \"up_mbps\": 100, \"down_mbps\": 100,
      \"tls\": { \"enabled\": true, \"server_name\": \"tls\", \"insecure\": true } },"
;;
    shadowtls) T_OUT="${T_OUT}{ \"type\": \"shadowsocks\", \"tag\": \"$otag\", \"server\": \"127.0.0.1\", \"server_port\": ${PORT[$p]}, \"method\": \"2022-blake3-aes-128-gcm\", \"password\": \"$STLS_SS_PASS\", \"detour\": \"$otag-st\" },
      { \"type\": \"shadowtls\", \"tag\": \"$otag-st\", \"server\": \"127.0.0.1\", \"server_port\": ${PORT[$p]}, \"version\": 3, \"password\": \"$STLS_PASS\",
      \"tls\": { \"enabled\": true, \"server_name\": \"www.bing.com\", \"insecure\": true } },"
;;
  esac
  T_RULE="${T_RULE}{ \"inbound\": [ \"$mtag\" ], \"action\": \"route\", \"outbound\": \"$otag\" },"
  T_SPECS+=("$p:$tp")
  tport=$((tport+1))
done
T_IN=${T_IN%,}; T_OUT=${T_OUT%,}; T_RULE=${T_RULE%,}

TJ=$(mktemp /tmp/relay-test.XXXX.json)
cat > "$TJ" <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [ $T_IN ],
  "outbounds": [ $T_OUT ],
  "route": { "rules": [ $T_RULE ] }
}
EOF
"$SB" check -c "$TJ" >/dev/null

FAIL=0
if [ -n "$T_IN" ]; then
  "$SB" run -c "$TJ" >"$TJ.log" 2>&1 &
  TEST_PID=$!
  sleep 2
  if ! kill -0 "$TEST_PID" 2>/dev/null; then
    echo "[x] test client failed to start:"; tail -5 "$TJ.log"; rm -f "$TJ" "$TJ.log"; exit 1
  fi
  for spec in "${T_SPECS[@]}"; do
    p=${spec%%:*}; tp=${spec##*:}
    got=$(curl -s --socks5-hostname 127.0.0.1:$tp --max-time 20 https://api.ipify.org || echo TIMEOUT)
    echo "[test] $p exit -> $got"
    if [ "$STRICT" = 1 ]; then
      if [ "$got" = "$EXPECT_IP" ]; then continue; fi
      FAIL=1
      echo "    -- test client log:"; tail -5 "$TJ.log" | sed 's/^/    /'
    else
      echo "    (landing is a domain '$EXPECT_IP' — please verify exit manually)"
    fi
  done
  kill "$TEST_PID" 2>/dev/null || true
  for i in 1 2 3 4 5; do kill -0 "$TEST_PID" 2>/dev/null || break; sleep 1; done
  kill -9 "$TEST_PID" 2>/dev/null || true
  pkill -f "$TJ" 2>/dev/null || true
  wait "$TEST_PID" 2>/dev/null || true
fi
rm -f "$TJ" "$TJ.log"

# ---------- share links ----------
echo ""
echo "================ share links ================"
for p in "${PROTO_LIST[@]}"; do
  case "$p" in
    hy2)    echo "hysteria2://$HY2_PASS@$PUBLIC_IP:${PORT[$p]}/?sni=tls&insecure=1#JP-HY2" ;;
    anytls) echo "anytls://$ANYTLS_PASS@$PUBLIC_IP:${PORT[$p]}/?sni=tls&insecure=1&fp=chrome#JP-ANYTLS" ;;
    tuic)   echo "tuic://$TUIC_UUID:$TUIC_PASS@$PUBLIC_IP:${PORT[$p]}?sni=tls&alpn=h3&congestion_control=bbr&udp_relay_mode=native&insecure=1#JP-TUIC" ;;
    ss)     SS_B64=$(echo -n "2022-blake3-aes-128-gcm:$SS_PASS" | base64 -w0)
            echo "ss://$SS_B64@$PUBLIC_IP:${PORT[$p]}#JP-SS22" ;;
    vmess)  VM=$(python3 -c "import json;print(json.dumps({'v':'2','ps':'JP-VMESS','add':'$PUBLIC_IP','port':'${PORT[$p]}','id':'$VMESS_UUID','aid':'0','scy':'auto','net':'ws','host':'','path':'$WS_PATH','tls':'tls','sni':'tls'},separators=(',',':')))")
            echo "vmess://$(echo -n "$VM" | base64 -w0)" ;;
    vless)  echo "vless://$VLESS_UUID@$PUBLIC_IP:${PORT[$p]}?security=reality&sni=www.amazon.com&fp=chrome&pbk=$VLESS_PUB&sid=$VLESS_SID&flow=xtls-rprx-vision#JP-VLESS" ;;
    trojan) echo "trojan://$TROJAN_PASS@$PUBLIC_IP:${PORT[$p]}?sni=tls&insecure=1#JP-TROJAN" ;;
    hysteria) AUTH_B64=$(echo -n "relay:$HY1_PASS" | base64 -w0)
              echo "hysteria://$PUBLIC_IP:${PORT[$p]}?auth=$AUTH_B64&peer=tls&insecure=1#JP-HY1" ;;
    naive)  echo "naive+https://naive:$NAIVE_PASS@$PUBLIC_IP:${PORT[$p]}?sni=tls&insecure=1#JP-NAIVE" ;;
    shadowtls) echo "# shadowtls v3 — client uses ss outbound detoured through shadowtls:"
              echo "{\"type\":\"shadowsocks\",\"method\":\"2022-blake3-aes-128-gcm\",\"password\":\"$STLS_SS_PASS\",\"detour\":\"stls\"}"
              echo "{\"type\":\"shadowtls\",\"tag\":\"stls\",\"server\":\"$PUBLIC_IP\",\"server_port\":${PORT[$p]},\"version\":3,\"password\":\"$STLS_PASS\",\"tls\":{\"enabled\":true,\"server_name\":\"www.bing.com\",\"insecure\":true}}" ;;
  esac
done
echo "============================================="
[ "$FAIL" = 0 ] && echo "[i] ALL PROTOCOLS VERIFIED, exit = $EXPECT_IP" || echo "[!] some protocol test failed — check journalctl -u $UNIT"
