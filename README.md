# RelayForge

[中文](#中文) | [English](#english)

---

## 中文

**RelayForge** — 一套 VPS 中转/代理节点锻造工具箱：多协议中转一键部署 + 服务器内核提速 + 节点配置提速。全部脚本零依赖框架（仅 bash + sing-box + python3），所有改动独立成文件、可一键回滚。

## 脚本

### 1. `setup-relay.sh` — 多协议中转一键部署

在一台 VPS 上批量部署入口协议，全部转发到任意落地节点（贴分享链接即可），自动生成可直接导入客户端的分享链接。

**支持的入口协议（任选子集）：**

| key | 协议 | 传输 | 特点 | 默认端口 |
|---|---|---|---|---|
| `hy2` | Hysteria2 | UDP/QUIC | 丢包线路跑量首选（Brutal） | 随机 |
| `anytls` | AnyTLS | TCP/TLS | 抗流量分析 | 随机 |
| `tuic` | TUIC v5 | UDP/QUIC | 标准 QUIC + BBR | 随机 |
| `ss` | Shadowsocks-2022 | TCP/UDP | blake3-gcm，抗重放 | 随机 |
| `vmess` | VMess + WS + TLS | TCP | 老牌、兼容性最好 | 随机 |
| `vless` | VLESS + REALITY + Vision | TCP | 抗主动探测 | 随机 |
| `trojan` | Trojan + TLS | TCP | HTTPS 伪装 | 随机 |
| `hysteria` | Hysteria v1 | UDP/QUIC | 老客户端兼容 | 随机 |
| `shadowtls` | ShadowTLS v3 + SS2022 | TCP | TLS 伪装隧道 | 随机 |
| `naive` | NaiveProxy (HTTP/2) | TCP | 浏览器指纹伪装* | 随机 |

**端口规则**：不指定时每个协议自动随机分配可用端口（10000-64999，避开占用与冲突）；需要固定端口时用 `--xx-port` 逐个指定。

\* naive 无 sing-box outbound，跳过自动穿透自检，其余协议全部实测。

**落地出口**：`--landing` 支持任意常见分享链接（vless / vmess / trojan / ss / hysteria2 / tuic / anytls，REALITY、WS、gRPC 自动识别），或 `direct`（不转发，就地出口）。

**示例：**

```bash
# 中转：东京机转发到任意落地
sudo ./setup-relay.sh \
  --landing "vless://uuid@1.2.3.4:443?security=reality&sni=xx&pbk=xx&sid=xx" \
  --protocols hy2,anytls,vless --anytls-port 35543

# 不转发，纯自用多协议节点
sudo ./setup-relay.sh --landing direct --protocols hy2,ss --ss-port 35555

# 只生成配置校验，不生效
sudo ./setup-relay.sh --dry-run --landing "ss://..."
```

**回滚：** `rm /etc/sing-box/conf/relay.json && systemctl restart sing-box`

### 2. `server-tune.sh` — 服务器内核提速

内核网络栈调优，面向代理/中转场景：BBR + fq、UDP/QUIC 大缓冲（hy2/tuic 需要）、TCP backlog、FastOpen、TIME_WAIT 复用、文件描述符上限、可选 swap。改动全部集中在 `/etc/sysctl.d/99-relayforge.conf`，不碰系统原配置。

```bash
sudo ./server-tune.sh --with-swap   # 提速 + 顺带加 swap（小内存 VPS 防 OOM）
sudo ./server-tune.sh --rollback    # 一键还原
```

### 3. `node-tune.sh` — 节点配置提速

代理软件层的优化（sing-box）：日志降级减少磁盘 IO、TCP 入站开启 FastOpen、生成 logrotate 规则防止日志撑爆小盘。改前自动备份、改完 `sing-box check` 校验、失败自动回滚。

```bash
sudo ./node-tune.sh
sudo ./node-tune.sh --rollback
```

## 环境要求

- Debian / Ubuntu（其他 systemd 发行版理论可用）
- sing-box >= 1.12（AnyTLS/ShadowTLS v3 需要 1.12+，实测 1.14）
- python3、openssl、curl

## 安全提醒

- 所有生成的链接/凭据等于节点钥匙，注意保管，不要公开。
- `insecure=1` 出现在使用自签证书的链接上；有真证书的机器请用 `--cert/--key` 传入并自行调整链接。
- 请遵守所在地区法律法规，本工具仅供学习与合法用途。

## English

**RelayForge** is a toolbox for VPS relay/proxy nodes: one-shot multi-protocol relay deployment, kernel-level server tuning, and sing-box node tuning. Zero framework dependencies (bash + sing-box + python3); every change is isolated in its own file and reversible with `--rollback`.

See script headers for full usage. Deploy 10 inbound protocols (Hysteria2 / AnyTLS / TUIC v5 / Shadowsocks-2022 / VMess+WS / VLESS-REALITY-Vision / Trojan / Hysteria v1 / ShadowTLS v3 / NaiveProxy) forwarding to any share-link landing, or run `--landing direct` for plain self-use nodes.

## License

MIT
