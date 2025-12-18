#!/usr/bin/env bash
set -euo pipefail

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "❌ 缺少命令：$1"; exit 1; }; }
need_cmd docker
need_cmd python3

tty_read() {
  local prompt="$1" __outvar="$2"
  local v=""
  read -r -p "$prompt" v </dev/tty || true
  printf -v "$__outvar" '%s' "$v"
}

select_macvlan_or_exit() {
  mapfile -t MACVLAN_LIST < <(docker network ls --format '{{.Name}}' | grep -E '^macvlan' || true)
  if [ ${#MACVLAN_LIST[@]} -eq 0 ]; then
    echo "❌ 未找到任何以 macvlan 开头的 Docker 网络"
    return 1
  fi

  echo "可用的 macvlan 网络："
  for i in "${!MACVLAN_LIST[@]}"; do
    echo "  $i) ${MACVLAN_LIST[$i]}"
  done

  local idx
  tty_read "请输入要使用的 macvlan 序号（回车退出）: " idx
  if [ -z "$idx" ]; then return 2; fi
  if [[ ! "$idx" =~ ^[0-9]+$ ]] || [ "$idx" -lt 0 ] || [ "$idx" -ge ${#MACVLAN_LIST[@]} ]; then
    echo "❌ 无效选择：$idx"
    return 1
  fi

  SELECTED_MACVLAN="${MACVLAN_LIST[$idx]}"
  echo "📡 选中的 macvlan 网络: $SELECTED_MACVLAN"
  return 0
}

get_network_ipam_kv() {
  local net="$1"
  docker network inspect "$net" | python3 -c '
import json,sys,ipaddress
data=json.load(sys.stdin)[0]
cfgs=(data.get("IPAM") or {}).get("Config") or []

v4_sub=v4_gw=v4_rng=""
v6_sub=v6_gw=v6_rng=""

for c in cfgs:
    subnet=c.get("Subnet") or ""
    gw=c.get("Gateway") or ""
    rng=c.get("IPRange") or ""
    if not subnet:
        continue
    try:
        n=ipaddress.ip_network(subnet, strict=False)
    except Exception:
        continue
    if n.version==4 and not v4_sub:
        v4_sub, v4_gw, v4_rng = subnet, gw, rng
    if n.version==6 and not v6_sub:
        v6_sub, v6_gw, v6_rng = subnet, gw, rng

print(f"V4_SUBNET={v4_sub}")
print(f"V4_GW={v4_gw}")
print(f"V4_RANGE={v4_rng}")
print(f"V6_SUBNET={v6_sub}")
print(f"V6_GW={v6_gw}")
print(f"V6_RANGE={v6_rng}")
'
}

# /23 默认用第二个 /24：10.86.20.0/23 -> 10.86.21.x
calc_ipv4_by_last_octet() {
  local subnet="$1" last="$2"
  python3 - "$subnet" "$last" <<'PY'
import sys, ipaddress
net = ipaddress.ip_network(sys.argv[1], strict=False)
last = int(sys.argv[2])

if net.version != 4:
    raise SystemExit("NOT_V4_SUBNET")

base = int(net.network_address)

if net.prefixlen == 23:
    base += 256

ip_int = (base & ~0xFF) | last
ip = ipaddress.ip_address(ip_int)

if ip not in net:
    raise SystemExit(f"OUT_OF_SUBNET:{ip}")
if ip == net.network_address or ip == net.broadcast_address:
    raise SystemExit(f"RESERVED:{ip}")

print(str(ip))
PY
}

make_mac_from_ipv4() {
  local ipv4="$1"
  python3 - "$ipv4" <<'PY'
import sys
o=list(map(int, sys.argv[1].split(".")))
mac=[0x86,0x88,0x0a,o[1],o[2],o[3]]
print(":".join(f"{b:02x}" for b in mac))
PY
}

# IPv6: fd10:86:20::21:120（用 IPv4 第三段/第四段拼）
make_ipv6_from_v6subnet_and_ipv4() {
  local v6_subnet="$1" ipv4="$2"
  python3 - "$v6_subnet" "$ipv4" <<'PY'
import sys, ipaddress
n = ipaddress.ip_network(sys.argv[1], strict=False)
o = sys.argv[2].split(".")
o3 = int(o[2])
o4 = int(o[3])
prefix = str(n.network_address)
print(f"{prefix}{o3}:{o4}" if prefix.endswith("::") else f"{prefix}::{o3}:{o4}")
PY
}

main() {
  echo "🔧 临时运行 mihomo（选 macvlan + 算 IP/GW；跳过 rm 目录、跳过 git clone）"

  select_macvlan_or_exit
  case $? in
    0) ;;
    2) echo "✅ 已退出"; exit 0 ;;
    *) exit 1 ;;
  esac

  echo "🔎 读取 $SELECTED_MACVLAN 的 IPAM..."
  eval "$(get_network_ipam_kv "$SELECTED_MACVLAN")"

  echo "📌 网络信息："
  echo "  V4_SUBNET=$V4_SUBNET"
  echo "  V4_GW    =$V4_GW"
  echo "  V6_SUBNET=$V6_SUBNET"
  echo "  V6_GW    =$V6_GW"
  echo

  [ -n "${V4_SUBNET}" ] || { echo "❌ 该 macvlan 没有 IPv4 Subnet，无法计算"; exit 1; }

  local mihomo_last
  tty_read "请输入 mihomo IPv4 最后一段（1-254，回车默认 120）: " mihomo_last
  [ -n "$mihomo_last" ] || mihomo_last=120
  if [[ ! "$mihomo_last" =~ ^[0-9]+$ ]] || [ "$mihomo_last" -lt 1 ] || [ "$mihomo_last" -gt 254 ]; then
    echo "❌ 无效的最后一段：$mihomo_last"; exit 1
  fi

  local mihomo mihomo6 mihomomac gateway
  mihomo="$(calc_ipv4_by_last_octet "$V4_SUBNET" "$mihomo_last")"
  mihomomac="$(make_mac_from_ipv4 "$mihomo")"
  gateway="${V4_GW:-}"

  mihomo6=""
  if [ -n "${V6_SUBNET}" ]; then
    mihomo6="$(make_ipv6_from_v6subnet_and_ipv4 "$V6_SUBNET" "$mihomo")"
  fi

  echo "🧮 计算结果："
  echo "  Network : $SELECTED_MACVLAN"
  echo "  IPv4    : $mihomo"
  echo "  MAC     : $mihomomac"
  echo "  Gateway : ${gateway:-<空>}"
  echo "  IPv6    : ${mihomo6:-<未启用>}"
  echo

  local dockerapps
  tty_read "即将安装 mihomo，请输入存储目录(例如 /data/dockerapps)，回车退出: " dockerapps
  if [ -z "$dockerapps" ]; then echo "✅ 已退出"; exit 0; fi

  mkdir -p "$dockerapps"
  cd "$dockerapps"

  local mihomo_dir="${dockerapps}/mihomo"
  [ -d "$mihomo_dir" ] || { echo "❌ 未找到 $mihomo_dir（请确认已手动放置仓库）"; exit 1; }
  cd "$mihomo_dir"

  if [ -f "config.yaml" ] && [ -n "$gateway" ] && [ "$gateway" != "null" ]; then
    sed -i "s|10\.0\.0\.1|${gateway}|g" config.yaml
  fi

  [ -f "docker-compose.yml" ] || { echo "❌ 未找到 docker-compose.yml（在 $mihomo_dir）"; exit 1; }

  cat > .env <<EOF
MACVLAN_NET=${SELECTED_MACVLAN}
mihomo4=${mihomo}
mihomo6=${mihomo6}
mihomomac=${mihomomac}
dockerapps=${dockerapps}
EOF

  echo "✅ 已生成 .env："
  cat .env
  echo

  docker rm -f mihomo >/dev/null 2>&1 || true
  if [ -n "$mihomo6" ] && [ -f "docker-compose.ipv6.yml" ]; then
    docker compose -f docker-compose.yml -f docker-compose.ipv6.yml up -d
  else
    docker compose -f docker-compose.yml up -d
  fi

  echo "✅ mihomo 已启动！访问地址：http://${mihomo}:9090/ui/  密码：admin"
  echo "IPv6：${mihomo6:-未启用}"
}

main