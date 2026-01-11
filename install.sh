#!/bin/bash

# ========== 环境准备 ==========

install_dependencies() {
    echo "🔧 检查并安装依赖（自动适配系统）..."

    deps=(ipcalc curl jq git)

    # 统一检测函数
    need_install() {
        ! command -v "$1" >/dev/null 2>&1
    }

    # === 1️⃣ Debian / Ubuntu / Armbian ===
    if command -v apt-get >/dev/null 2>&1; then
        echo "📦 使用 apt-get 安装依赖"
        local to_install=()
        for dep in "${deps[@]}"; do
            if need_install "$dep"; then
                to_install+=("$dep")
            else
                echo "✅ $dep 已安装"
            fi
        done

        if [ ${#to_install[@]} -gt 0 ]; then
            echo "⬇️ 正在安装缺少的依赖: ${to_install[*]}"
            apt-get update
            apt-get install -y "${to_install[@]}"
        fi
        return 0
    fi

    # === 2️⃣ 群晖 / 飞牛 OS（Entware）===
    if [ -x /opt/bin/opkg ]; then
        echo "📦 使用 Entware(opkg) 安装依赖"
        export PATH=/opt/bin:$PATH

        local to_install=()
        for dep in "${deps[@]}"; do
            if need_install "$dep"; then
                to_install+=("$dep")
            else
                echo "✅ $dep 已安装"
            fi
        done
        
        if [ ${#to_install[@]} -gt 0 ]; then
             echo "⬇️ 正在安装缺少的依赖: ${to_install[*]}"
            /opt/bin/opkg update
            /opt/bin/opkg install "${to_install[@]}"
        fi

        # 兼容 Entware git 没 wrapper 的情况
        if [ ! -x /opt/bin/git ] && [ -x /opt/lib/git-core/git ]; then
            ln -sf /opt/lib/git-core/git /opt/bin/git
        fi
        return 0
    fi

    # === 3️⃣ 兜底 ===
    echo "❌ 未识别的系统，无法自动安装依赖"
    echo "👉 请手动安装：${deps[*]}"
    return 1
}

echo "⚠️ 请以 root 权限运行本脚本"

# ========== 主菜单 ==========

function show_menu() {
    clear
    echo "============================"
    echo "欢迎使用armbian一键旁路由脚本"
    echo "本脚本提供以下功能："
    echo "----------------------------"
    echo "0）显示菜单"
    echo "1）显示操作系统信息"
    echo "2）显示网卡信息"
    echo "3）显示磁盘信息"
    echo "4）显示docker信息"
    echo "5）格式化磁盘并挂载"
    echo "7）安装docker"
    echo "8）创建macvlan（包括ipv4+ipv6）"
    echo "9）清理macvlan"
    echo "10）安装portainer面板"
    echo "11）安装librespeed测速"
    echo "14）安装adguardhome"
    echo "19）安装mosdns"
    echo "20）安装mihomo"
    echo "20）安装ddns-go(依赖mihomo完成在外回家)"
    echo "45）安装samba"
    echo "70) 迁移docker目录"
    echo "71) 优化docker日志"
    echo "90）创建macvlan bridge"
    echo "91）清理macvlan bridge"
    echo "97）安装watchtower自动更新"
    echo "98）强制使用watchtower更新一次镜像"
    echo "99）退出"
    echo "============================"
}

# ========== 工具函数 ==========

# 全局保存用户选择的 macvlan 网络名
SELECTED_MACVLAN=""

# 选择macvlan
select_macvlan_or_exit() {
    mapfile -t macvlan_networks < <(docker network ls --format '{{.Name}}' | grep '^macvlan' || true)
    if [ ${#macvlan_networks[@]} -eq 0 ]; then
        echo "❌ 未发现任何以 macvlan 开头的 Docker 网络，请先创建 macvlan 网络。"
        return 1
    fi

    echo "可用的 macvlan 网络："
    for i in "${!macvlan_networks[@]}"; do
        echo "  $i) ${macvlan_networks[$i]}"
    done

    read -r -p "请输入要使用的 macvlan 序号（回车退出安装）: " choice
    if [ -z "$choice" ]; then
        echo "✅ 已退出安装。"
        return 2
    fi
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 0 ] || [ "$choice" -ge "${#macvlan_networks[@]}" ]; then
        echo "❌ 无效的序号：$choice"
        return 1
    fi

    SELECTED_MACVLAN="${macvlan_networks[$choice]}"
    echo "📡 选中的 macvlan 网络: $SELECTED_MACVLAN"
    return 0
}

# 计算IP地址对应MAC地址
ip_to_mac() {
  # IPv4 -> MAC: 02:<ip1hex>:<ip2hex>:<ip3hex>:<ip4hex>:86
  # 例：10.0.10.254 -> 02:0a:56:14:fe:86
  local ip1 ip2 ip3 ip4
  IFS='.' read -r ip1 ip2 ip3 ip4 <<< "$1"

  # 基本校验（避免空/非数字）
  if [[ ! "$ip1" =~ ^[0-9]+$ || ! "$ip2" =~ ^[0-9]+$ || ! "$ip3" =~ ^[0-9]+$ || ! "$ip4" =~ ^[0-9]+$ ]]; then
    echo ""
    return 1
  fi
  if (( ip1<0 || ip1>255 || ip2<0 || ip2>255 || ip3<0 || ip3>255 || ip4<0 || ip4>255 )); then
    echo ""
    return 1
  fi

  printf '02:%02x:%02x:%02x:%02x:86\n' "$ip1" "$ip2" "$ip3" "$ip4"
}

# 计算IPv4对应IPv6前缀
ipv4_to_ipv6_prefix() {
  local ip=$1
  local first_octet=$(echo $ip | cut -d'.' -f1)
  local second_octet=$(echo $ip | cut -d'.' -f2)
  local third_octet=$(echo $ip | cut -d'.' -f3)

  if [[ "$first_octet" == "10" ]]; then
    prefix="fd10"
  elif [[ "$first_octet" == "172" ]]; then
    prefix="fd17"
  elif [[ "$first_octet" == "192" ]]; then
    prefix="fd19"
  else
    prefix="fd00"
  fi

  echo "${prefix}:${second_octet}:${third_octet}"
}

# 获取网卡子网
get_subnet_v4() {
  local ip=$1
  local iface=$2
  local cidr=$(ip route | grep -v "^default" | grep "$iface" | grep "$ip" | awk '{print $1}')
  
  if [ -z "$cidr" ]; then
    local prefix_len=$(ip -4 addr show $iface | grep inet | awk '{print $2}' | cut -d'/' -f2)
    local ipcalc_out
    # 移除 -n 选项以提高兼容性（Busybox ipcalc 可能不支持，或者输出不同）
    ipcalc_out=$(ipcalc "$ip/$prefix_len" 2>/dev/null)

    # 1. 尝试 Debian 格式 (Network: 192.168.1.0/24)
    cidr=$(echo "$ipcalc_out" | grep "Network:" | awk '{print $2}')

    # 2. 尝试 Busybox/Entware 格式 (NETWORK=192.168.1.0 + PREFIX=24)
    if [ -z "$cidr" ]; then
      local net_val prefix_val
      net_val=$(echo "$ipcalc_out" | grep "NETWORK=" | cut -d= -f2)
      prefix_val=$(echo "$ipcalc_out" | grep "PREFIX=" | cut -d= -f2)
      if [ -n "$net_val" ] && [ -n "$prefix_val" ]; then
        cidr="${net_val}/${prefix_val}"
      fi
    fi
  fi
  echo $cidr
}

# ---- IPv4 计算工具 ----
ipv4_to_int() { local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24)+(b<<16)+(c<<8)+d )); }

mask_from_len() { local l="$1"; echo $(( (0xFFFFFFFF << (32-l)) & 0xFFFFFFFF )); }

cidr_contains_ip() {
  local ip="$1" cidr="$2" net="${cidr%/*}" len="${cidr#*/}"
  local ipi neti mask; ipi=$(ipv4_to_int "$ip"); neti=$(ipv4_to_int "$net"); mask=$(mask_from_len "$len")
  (( (ipi & mask) == (neti & mask) ))
}

macvlan_ipv6_enabled() {
  # 用法：macvlan_ipv6_enabled "macvlan_name"  ; 返回 0=启用且有IPv6子网，1=否则
  local net="$1"
  docker network inspect "$net" 2>/dev/null | jq -e \
    '.[0].EnableIPv6==true and (.[0].IPAM.Config[]?.Subnet | test(":"))' \
    >/dev/null 2>&1
}

write_env_file() {
  local path="$1"; shift
  # 用法：write_env_file ".env" "k1=v1" "k2=v2" ...
  : > "$path" || return 1
  for line in "$@"; do
    printf '%s\n' "$line" >> "$path" || return 1
  done
}

calculate_ip_mac() {
  local last_octet=$1
  local net_name="${2:-${SELECTED_MACVLAN:-macvlan}}"

  if [[ ! "$last_octet" =~ ^[0-9]+$ ]]; then
    echo "❌ calculate_ip_mac 输入无效: $last_octet"
    return 1
  fi

  # 1) 获取 docker 网络配置（改为可选网络名）
  network_info=$(docker network inspect "$net_name" 2>/dev/null) || {
    echo "❌ 无法读取网络信息：$net_name"
    return 1
  }

  # 2) IPv4：优先 IPRange，否则 Subnet
  local iprange subnet gateway
  iprange=$(echo "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Subnet | test(":") | not) | (.IPRange // empty)' | head -n1)
  subnet=$(echo  "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Subnet | test(":") | not) | .Subnet' | head -n1)
  gateway=$(echo "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Subnet | test(":") | not) | (.Gateway // empty)' | head -n1)

  local base4
  if [ -n "$iprange" ] && [ "$iprange" != "null" ]; then
    base4=$(echo "$iprange" | cut -d'/' -f1)
  else
    base4=$(echo "$subnet" | cut -d'/' -f1)
  fi
  if [ -z "$base4" ] || [ "$base4" = "null" ]; then
    echo "❌ 网络 $net_name 没有 IPv4 Subnet/IPRange"
    return 1
  fi

  local ip="${base4%.*}.${last_octet}"

  # 3) IPv6：仅当 EnableIPv6=true 且存在 IPv6 Subnet 才生成 ip6（避免 RA-only 网关坑）
  local enable_ipv6 subnet6 gateway6 ip6_prefix ip6
  enable_ipv6=$(echo "$network_info" | jq -r '.[0].EnableIPv6 // false')
  subnet6=$(echo "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Subnet | test(":")) | .Subnet' | head -n1)
  gateway6=$(echo "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Subnet | test(":")) | (.Gateway // empty)' | head -n1)

  ip6=""
  if [ "$enable_ipv6" = "true" ] && [ -n "$subnet6" ] && [ "$subnet6" != "null" ]; then
    ip6_prefix=$(echo "$subnet6" | cut -d'/' -f1)
    local v4_3 v4_4
    v4_3=$(echo "$ip" | cut -d'.' -f3)
    v4_4=$(echo "$ip" | cut -d'.' -f4)

    if [[ "$ip6_prefix" == *"::" ]]; then
      ip6="${ip6_prefix}${v4_3}:${v4_4}"
    else
      ip6="${ip6_prefix}::${v4_3}:${v4_4}"
    fi
  else
    gateway6=""
  fi

  # 4) MAC
  local mac
  mac=$(ip_to_mac "$ip")

  # 5) 输出/回填
  echo "Network: $net_name"
  echo "IPv4: $ip"
  echo "IPv6: $ip6"
  echo "MAC: $mac"
  echo "Gateway: $gateway"
  echo "Gateway6: $gateway6"

  calculated_ip=$ip
  calculated_ip6=$ip6
  calculated_mac=$mac
  calculated_gateway=$gateway
  calculated_gateway6=$gateway6
}

# ---- 自动探测 mihomo 下一跳 IP（返回一个 IPv4 或空串）----
# 参数1: route4_cidr（如 10.0.1.0/24）
# 参数2: network_info（docker network inspect 的 JSON 字符串）
detect_mihomo_ip() {
  local _route4="$1" _netinfo="$2"

  # 1) 环境变量优先（大写/小写都支持）
  if [ -n "$MIHOMO" ]; then echo "$MIHOMO"; return; fi
  if [ -n "$mihomo" ]; then echo "$mihomo"; return; fi

  # 2) systemd 环境文件（可选）
  if [ -f /etc/default/macvlan_env ]; then
    # shellcheck source=/dev/null
    . /etc/default/macvlan_env
    if [ -n "$MIHOMO" ]; then echo "$MIHOMO"; return; fi
    if [ -n "$mihomo" ]; then echo "$mihomo"; return; fi
  fi

  # 3) Docker 容器：名称含 mihomo/clash/clash-meta 的容器；优先选与 _route4 同网段的 IP
  local ids iplist ip best=""
  ids=$(docker ps --format '{{.ID}} {{.Names}}' | grep -Ei '(^|[ _-])(mihomo|clash-meta|clash)($|[ _-])' | awk '{print $1}')
  for id in $ids; do
    iplist=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$id")
    for ip in $iplist; do
      if [ -n "$ip" ] && [ -n "$_route4" ] && cidr_contains_ip "$ip" "$_route4"; then
        echo "$ip"; return
      fi
      [ -z "$best" ] && best="$ip"
    done
  done
  [ -n "$best" ] && { echo "$best"; return; }

  # 4) 回退到 macvlan 的 IPv4 网关
  local gw4
  gw4=$(echo "$_netinfo" | jq -r '.[0].IPAM.Config[] | select(.Subnet | test(":") | not) | .Gateway // empty' | head -n1)
  [ -n "$gw4" ] && { echo "$gw4"; return; }

  # 5) 无可用
  echo ""
}

# 校验参数
env_require_vars() {
    local env_file="$1"; shift
    local missing=0

    for v in "$@"; do
        if ! grep -q "^${v}=" "$env_file"; then
            echo "❌ $env_file 缺少必要变量：$v"
            missing=1
        fi
    done

    [ "$missing" -eq 0 ]
}

prompt_ipv4_last_octet() {
  # 用法：prompt_ipv4_last_octet "提示语" 默认值
  local prompt="$1"
  local def="$2"
  local v

  read -r -p "$prompt" v
  v="${v:-$def}"

  if [[ ! "$v" =~ ^[0-9]+$ ]] || [ "$v" -lt 1 ] || [ "$v" -gt 254 ]; then
    echo "❌ 无效的 IPv4 最后一段：$v"
    return 1
  fi

 echo "📌 使用 IPv4 最后一段：$v" >&2
 echo "$v"
}

# 仓库更新
repo_stage_update() {
  # 用法同原来：
  # repo_stage_update "项目名" "/data/dockerapps" "repo_url" "dir_name"
  #
  # 输出全局变量：
  #   TARGET_DIR WORK_DIR NEED_SWITCH NEXT_DIR BAK_DIR

  local name="$1"
  local base="$2"
  local repo_url="$3"
  local dir_name="$4"

  local ts; ts="$(date +%Y%m%d-%H%M%S)"

  TARGET_DIR="${base%/}/${dir_name}"
  WORK_DIR=""
  NEED_SWITCH=0
  NEXT_DIR=""
  BAK_DIR=""

  # ✅ 关键改动：只要正式目录存在（无论是否 git），都不 pull，直接走 next clone
  if [ -d "$TARGET_DIR" ]; then
    echo "🔄 [$name] 检测到现有目录：$TARGET_DIR（不做 git pull，直接走 next 部署）"

    local tmp="${base%/}/${dir_name}.tmp-${ts}"
    NEXT_DIR="${base%/}/${dir_name}.next-${ts}"
    BAK_DIR="${base%/}/${dir_name}.bak-${ts}"

    rm -rf "$tmp" "$NEXT_DIR" 2>/dev/null || true

    if git clone "$repo_url" "$tmp" && mv "$tmp" "$NEXT_DIR"; then
      WORK_DIR="$NEXT_DIR"
      NEED_SWITCH=1
      echo "✅ [$name] next 目录已准备：$NEXT_DIR"
      return 0
    fi

    echo "❌ [$name] next clone 失败：保持现有目录不变（避免断网/断服务）"
    rm -rf "$tmp" "$NEXT_DIR" 2>/dev/null || true
    return 1
  fi

  # 不存在则首次 clone 到正式目录（NEED_SWITCH=0）
  echo "⬇️ [$name] 未检测到目录，直接 clone 到正式目录：$TARGET_DIR"
  if git clone "$repo_url" "$TARGET_DIR"; then
    WORK_DIR="$TARGET_DIR"
    NEED_SWITCH=0
    return 0
  fi

  return 1
}

# 容器层（停旧 → 起新 → 更新/回滚）
compose_deploy_with_repo_switch() {
  # 用法（推荐）：
  #   compose_deploy_with_repo_switch "mihomo" "mihomo" docker-compose.yml docker-compose.ipv6.yml
  #
  # 依赖 repo_stage_update 已经被调用过，且设置了全局变量：
  #   WORK_DIR NEED_SWITCH TARGET_DIR BAK_DIR

  local name="$1"; shift
  local svc="$1"; shift
  local -a files=("$@")

  local -a COMPOSE
  if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    echo "❌ 未找到 docker compose / docker-compose"
    return 1
  fi

  [ ${#files[@]} -eq 0 ] && files=("docker-compose.yml")

  local -a fargs=()
  for f in "${files[@]}"; do fargs+=("-f" "$f"); done

  # ✅ 固定 project name：确保 next/正式 两次 up 属于同一个项目
  local PROJECT
  PROJECT="$name"         # 或者你想用 "$svc" / dir_name，都行，但要稳定
  local -a pargs=(-p "$PROJECT")

  # A) 先在 WORK_DIR 做 config 校验（不碰容器）
  cd "$WORK_DIR" || { echo "❌ 进入目录失败：$WORK_DIR"; return 1; }

  echo "🔎 [$name] docker compose config 校验..."
  if ! "${COMPOSE[@]}" "${pargs[@]}" "${fargs[@]}" config >/tmp/"$name".compose.check 2>/tmp/"$name".compose.err; then
    echo "❌ [$name] compose 校验失败："
    sed 's/^/  /' /tmp/"$name".compose.err
    return 1
  fi

  # B) 备份旧容器（stop + rename）用于回滚
  local ts backup_cname old_running=""
  ts="$(date +%Y%m%d-%H%M%S)"
  backup_cname=""

  if docker ps -a --format '{{.Names}}' | grep -qx "$svc"; then
    backup_cname="${svc}.bak-${ts}"
    old_running="$(docker inspect -f '{{.State.Running}}' "$svc" 2>/dev/null || echo "")"

    echo "🧩 [$name] 发现旧容器 $svc，先停止并重命名为备份：$backup_cname"
    docker stop "$svc" >/dev/null 2>&1 || true

    if docker ps -a --format '{{.Names}}' | grep -qx "$backup_cname"; then
      echo "❌ [$name] 备份容器名已存在：$backup_cname（请手动处理后重试）"
      return 1
    fi

    docker rename "$svc" "$backup_cname" || {
      echo "❌ [$name] 旧容器重命名失败（无法避免 container_name 冲突）"
      return 1
    }
  fi

  rollback_container() {
    # 删除新容器（如果占名）
    if docker ps -a --format '{{.Names}}' | grep -qx "$svc"; then
      docker rm -f "$svc" >/dev/null 2>&1 || true
    fi
    # 还原旧容器
    if [ -n "$backup_cname" ] && docker ps -a --format '{{.Names}}' | grep -qx "$backup_cname"; then
      docker rename "$backup_cname" "$svc" >/dev/null 2>&1 || true
      [ "$old_running" = "true" ] && docker start "$svc" >/dev/null 2>&1 || true
      echo "🔁 [$name] 已回滚恢复旧容器：$svc"
    fi
  }

  rollback_dir() {
    # 仅当我们真的把正式目录备份走了，才尝试回滚目录
    if [ -n "${BAK_DIR:-}" ] && [ -d "$BAK_DIR" ]; then
      rm -rf "$TARGET_DIR" 2>/dev/null || true
      mv "$BAK_DIR" "$TARGET_DIR" 2>/dev/null || true
      WORK_DIR="$TARGET_DIR"
      NEED_SWITCH=0
      echo "🔁 [$name] 已回滚恢复旧目录：$TARGET_DIR"
    fi
  }

  # C) 在 WORK_DIR 启动新容器（next 或正式都一样）
  echo "🚀 [$name] 启动新容器（WORK_DIR=$WORK_DIR）..."
  if ! "${COMPOSE[@]}" "${pargs[@]}" "${fargs[@]}" up -d --force-recreate; then
    echo "❌ [$name] 新容器启动失败，开始回滚..."
    rollback_container
    return 1
  fi

  # D) 如果 NEED_SWITCH=1：切 next -> 正式，并在正式目录再 up 一次（挂载稳定）
  if [ "${NEED_SWITCH:-0}" -eq 1 ]; then
    echo "🔁 [$name] 新容器运行成功，开始切换目录：next -> 正式"

    # 备份旧目录（如果存在）
    if [ -d "$TARGET_DIR" ]; then
      [ -z "${BAK_DIR:-}" ] && BAK_DIR="${TARGET_DIR}.bak-${ts}"
      mv "$TARGET_DIR" "$BAK_DIR" || {
        echo "❌ [$name] 备份旧目录失败：$TARGET_DIR"
        rollback_container
        return 1
      }
    fi

    # next -> 正式
    if ! mv "$WORK_DIR" "$TARGET_DIR"; then
      echo "❌ [$name] next -> 正式目录切换失败，开始回滚..."
      rollback_dir
      rollback_container
      return 1
    fi

    WORK_DIR="$TARGET_DIR"
    NEED_SWITCH=0

    # 在正式目录再强制重建一次，确保挂载源稳定到正式路径
    cd "$WORK_DIR" || { echo "❌ 进入目录失败：$WORK_DIR"; rollback_dir; rollback_container; return 1; }
    echo "🚀 [$name] 在正式目录再次重建（确保挂载路径稳定）..."
    if ! "${COMPOSE[@]}" "${pargs[@]}" "${fargs[@]}" up -d --force-recreate; then
      echo "❌ [$name] 正式目录重建失败，开始回滚..."
      rollback_dir
      rollback_container
      return 1
    fi
  fi

  # E) 最终 running 检查
  sleep 1
  if ! docker inspect -f '{{.State.Running}}' "$svc" 2>/dev/null | grep -q true; then
    echo "❌ [$name] 容器未处于 running：$svc"
    docker logs --tail=80 "$svc" 2>/dev/null || true
    echo "❌ [$name] running 检查失败，开始回滚..."
    rollback_dir
    rollback_container
    return 1
  fi

  DEPLOY_BACKUP_CONTAINER="$backup_cname"
  [ -n "$backup_cname" ] && echo "✅ [$name] 新容器启动成功，旧容器已备份：$backup_cname" && echo "🧩 确认稳定后可手动 docker rm -f ${DEPLOY_BACKUP_CONTAINER}删除"

  return 0
}

# 删除备份+检查
repo_offer_delete_backup() {
  # 用法：
  # repo_offer_delete_backup "项目名" "$BAK_DIR" "container_name"

  local name="$1"
  local bak="$2"
  local container="$3"

  [ -z "$bak" ] && return 0
  [ ! -d "$bak" ] && return 0

  # 检查容器是否还在挂载 bak
  if [ -n "$container" ]; then
    local m
    m="$(docker inspect -f '{{range .Mounts}}{{println .Source}}{{end}}' "$container" 2>/dev/null | grep -F "$bak" || true)"
    if [ -n "$m" ]; then
      echo "⚠️ [$name] 检测到容器仍挂载备份目录：$bak"
      echo "   为安全起见不允许删除。请确认已在正式目录 --force-recreate 重建后再删。"
      return 0
    fi
  fi

  read -r -p "是否删除旧的 [$name] 目录备份？($bak) [y/N]: " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    rm -rf "$bak"
    echo "🗑️ 已删除：$bak"
  else
    echo "ℹ️ 已保留：$bak"
  fi
}

# ========== 功能函数 ==========

function os_info() { cat /etc/os-release; }

function nic_info() { ip addr; }

function disk_info() { lsblk -o NAME,SIZE,FSTYPE,UUID,MOUNTPOINT; }

function format_disk() {
  echo "📝 当前磁盘列表："
  lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT

  read -p "请输入需要格式化的磁盘名称（例如 sda，不含 /dev/）: " disk_name
  disk_path="/dev/$disk_name"

  # 检查磁盘是否存在
  if [ ! -b "$disk_path" ]; then
    echo "❌ 磁盘 $disk_path 不存在，退出"
    return 1
  fi

  echo "🔍 选择的磁盘信息："
  lsblk $disk_path

  read -p "⚠️ 警告：磁盘 $disk_path 数据将被清除，确认格式化？(y/n): " confirm
  if [ "$confirm" != "y" ]; then
    echo "❌ 操作取消"
    return 1
  fi

  # 检查磁盘上是否有分区
  partitions=$(lsblk -n -o NAME $disk_path | grep -v "^$disk_name$")
  if [ -n "$partitions" ]; then
    echo "🔧 删除磁盘上已有分区..."
    for part in $partitions; do
      sudo wipefs -a /dev/$part
      sudo parted /dev/$disk_name rm $(echo $part | grep -o "[0-9]*$")
    done
  fi

  echo "💽 创建新分区并格式化 ext4"
  sudo parted -s $disk_path mklabel gpt
  sudo parted -s $disk_path mkpart primary ext4 0% 100%
  sudo mkfs.ext4 -F ${disk_path}1

  # 检查是否已挂载
  mountpoint=$(lsblk -no MOUNTPOINT ${disk_path}1)
  if [ -n "$mountpoint" ]; then
    echo "✅ 分区已挂载到：$mountpoint"
  else
    read -p "📁 请输入挂载目录（例如 /data）： " mount_dir
    if [ ! -d "$mount_dir" ]; then
      sudo mkdir -p $mount_dir
    fi
    echo "🔗 挂载分区到 $mount_dir"
    sudo mount ${disk_path}1 $mount_dir

    # 自动写入 /etc/fstab
    uuid=$(sudo blkid -s UUID -o value ${disk_path}1)
    echo "UUID=$uuid $mount_dir ext4 defaults,nofail 0 2" | sudo tee -a /etc/fstab

    echo "✅ 格式化并挂载完成：$disk_path -> $mount_dir"
    echo "🔒 永久挂载已添加到 /etc/fstab，重启后自动挂载"
  fi
}

function docker_info() { docker info; }

function install_docker() {
    . /etc/os-release

    sudo apt-get update
    sudo apt-get install -y ca-certificates curl gnupg lsb-release

    sudo install -m 0755 -d /etc/apt/keyrings

    if [[ "$ID" == "debian" ]]; then
        sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
        sudo chmod a+r /etc/apt/keyrings/docker.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    elif [[ "$ID" == "ubuntu" ]]; then
        sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
        sudo chmod a+r /etc/apt/keyrings/docker.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME:-$VERSION_CODENAME} stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    else
        echo "当前系统 $ID 不在支持范围内，请手动安装 Docker。"
        return 1
    fi

    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    sudo systemctl enable docker
    sudo systemctl start docker

    echo "✅ Docker 安装完成，版本信息："
    docker --version
}

# ========== 1. 创建 macvlan 网络 ==========
create_macvlan_network() {
  echo "🔧 开始创建 macvlan 网络"

  # 1) 列出所有可能作为 parent 的接口（不过滤 ovs/bridge；只排除明显不可用的）
  local interfaces=()
  while IFS= read -r iface; do
    case "$iface" in
      # 明确排除：容器/隧道/虚拟/内核专用
      lo|docker0|docker*|br-*|virbr*|veth*|mvbr*|tun*|tap*|wg*|tailscale*|zt*|ifb*|dummy*|gre*|gretap*|ip6gre*|sit*|macvtap*|kube*|cni*|flannel*|calico*|ovs-system* )
        continue
        ;;
      *)
        # 放宽：允许 eth/ens/enp/eno/wlan/bond/team/br/ovs 等以及 VLAN 子接口 (xxx.88)
        # 你飞牛/OVS 场景需要把 br0/ovs* 放进来
        if [[ "$iface" =~ ^(e(n|th|np|ns|no|ni)|ens|enp|eno|eth|wlan|wl|bond|team|br|ovs)([0-9a-zA-Z\.\-:_]+)?$ ]]; then
          interfaces+=("$iface")
        fi
        ;;
    esac
  done < <(ls /sys/class/net)

  if [ ${#interfaces[@]} -eq 0 ]; then
    echo "❌ 未找到可用的网卡/接口。"
    return 1
  fi

  echo "请选择 parent 接口（可选物理口 / VLAN 子接口 / OVS bridge 口）："
  local i ip4 ip6
  for i in "${!interfaces[@]}"; do
    ip4="$(ip -4 addr show "${interfaces[$i]}" 2>/dev/null | awk '/ inet /{print $2}' | head -n1)"
    ip6="$(ip -6 addr show "${interfaces[$i]}" 2>/dev/null | awk '/ inet6 / && $2 ~ /^fd/{print $2}' | head -n1)"
    echo "$i) ${interfaces[$i]}  IPv4: ${ip4:-无}  ULA: ${ip6:-无}"
  done

  local netcard_index networkcard
  read -r -p "输入网卡序号: " netcard_index
  if ! [[ "$netcard_index" =~ ^[0-9]+$ ]] || [ "$netcard_index" -lt 0 ] || [ "$netcard_index" -ge "${#interfaces[@]}" ]; then
    echo "❌ 无效的网卡序号：$netcard_index"
    return 1
  fi
  networkcard="${interfaces[$netcard_index]}"
  [ -n "$networkcard" ] || { echo "❌ 未能获取网卡名称"; return 1; }
  echo "选择的 parent 接口: $networkcard"

  # ========= VLAN 处理 =========
  local vlan_id="" vlan_iface="" vlan_suffix="" parent_iface=""
  if [[ "$networkcard" != *.* ]]; then
    read -r -p "是否为 macvlan 使用 VLAN ID？直接回车表示不使用，输入 VLAN ID（例如 88）: " vlan_id
    if [ -n "$vlan_id" ]; then
      if ! [[ "$vlan_id" =~ ^[0-9]+$ ]] || [ "$vlan_id" -lt 1 ] || [ "$vlan_id" -gt 4094 ]; then
        echo "❌ VLAN ID 无效：$vlan_id"
        return 1
      fi

      vlan_iface="${networkcard}.${vlan_id}"
      echo "🔧 将使用 VLAN 子接口: $vlan_iface (parent: $networkcard, VLAN ID: $vlan_id)"

      if ! ip link show "$vlan_iface" >/dev/null 2>&1; then
        sudo ip link add link "$networkcard" name "$vlan_iface" type vlan id "$vlan_id" || {
          echo "❌ 创建 VLAN 接口失败：$vlan_iface"
          return 1
        }
      fi
      sudo ip link set "$vlan_iface" up || true
      networkcard="$vlan_iface"
    fi
  else
    vlan_suffix="${networkcard#*.}"
    if [[ "$vlan_suffix" =~ ^[0-9]+$ ]]; then
      vlan_id="$vlan_suffix"
    fi
    echo "ℹ️ 检测到带 VLAN 的接口: $networkcard (推测 VLAN ID: ${vlan_id:-未知})"
  fi
  # ========= VLAN 处理结束 =========

  # ========= IPv4：先网关，再算 CIDR & range =========
  local ip="" gateway="" cidr="" iprange="" subnet4="" iprangev4="" suggest_gateway="" suggest_prefixlen="" prefixlen="" auto_cidr=""
  ip="$(ip -4 addr show "$networkcard" 2>/dev/null | awk '/ inet /{print $2}' | head -n1 | cut -d'/' -f1)"

  if [ -n "$ip" ]; then
    # 接口本身有 IP：建议用该接口的前缀长度；网关优先取该接口路由到默认的下一跳
    local cidr_from_iface gw_from_iface
    cidr_from_iface="$(get_subnet_v4 "$ip" "$networkcard")"
    gw_from_iface="$(ip -4 route show default 2>/dev/null | awk -v dev="$networkcard" '$0 ~ (" dev "dev" ") {print $3; exit}')"
    [ -z "$gw_from_iface" ] && gw_from_iface="$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')"
    suggest_gateway="$gw_from_iface"
    suggest_prefixlen="${cidr_from_iface#*/}"
  else
    echo "⚠️ 未在接口 $networkcard 上检测到 IPv4 地址（VLAN/bridge 接口通常没有 IP）"

    parent_iface="${networkcard%%.*}"
    local parent_ip parent_cidr parent_mask p1 p2 p3 p4 third_octet
    parent_ip="$(ip -4 addr show "$parent_iface" 2>/dev/null | awk '/ inet /{print $2}' | head -n1 | cut -d'/' -f1)"

    if [ -n "$parent_ip" ]; then
      parent_cidr="$(get_subnet_v4 "$parent_ip" "$parent_iface")"
      parent_mask="${parent_cidr#*/}"
      IFS='.' read -r p1 p2 p3 p4 <<< "${parent_cidr%/*}"

      if [ -n "$vlan_id" ]; then
        third_octet="$vlan_id"
        suggest_prefixlen="24"
      else
        third_octet="$p3"
        suggest_prefixlen="$parent_mask"
      fi

      suggest_gateway="${p1}.${p2}.${third_octet}.1"
      echo "👉 已根据 trunk 接口 $parent_iface 推算推荐 IPv4 网关：$suggest_gateway"
      echo "👉 推荐前缀长度：/$suggest_prefixlen"
    else
      echo "❌ trunk 接口 $parent_iface 也没有 IPv4，无法推算，需要手动输入网关和网段。"
    fi
  fi

  if [ -n "$suggest_gateway" ]; then
    read -r -p "请输入 IPv4 网关 (回车使用推荐 $suggest_gateway): " gateway
    [ -z "$gateway" ] && gateway="$suggest_gateway"
  else
    read -r -p "请输入 IPv4 网关 (例如 10.88.0.1): " gateway
  fi

  [ -n "$gateway" ] || { echo "❌ IPv4 网关不能为空。"; return 1; }

  prefixlen="${suggest_prefixlen:-24}"
  auto_cidr="${gateway%.*}.0/${prefixlen}"

  echo "👉 已根据网关 $gateway 推算 IPv4 子网：$auto_cidr"
  echo "⚠️ 提示：IPRange 应为 macvlan 专用网段（建议 /24 或更小），不要与 DHCP/静态地址重叠。"
  read -r -p "请输入 macvlan IPv4 子网CIDR (回车使用推荐 $auto_cidr): " cidr
  [ -z "$cidr" ] && cidr="$auto_cidr"

  read -r -p "请输入 macvlan IPv4 range, 回车使用 $cidr: " iprange
  [ -z "$iprange" ] && iprange="$cidr"

  iprangev4="$(echo "$iprange" | cut -d'/' -f1)"
  subnet4="$(echo "$iprange" | cut -d'/' -f2)"

  # ========= IPv6：更稳的收敛逻辑 =========
  local gateway6="" cidr6="" iprange6="" subnet6="" iprangev6_prefix="" suggest_gateway6="" suggest_cidr6="" auto_cidr6=""
  # 优先：从接口/父接口拿到 ULA 前缀（fdxx）
  local ip6_cidr ip6_addr prefix_len6 ula_prefix

  ip6_cidr="$(ip -6 addr show "$networkcard" 2>/dev/null | awk '/ inet6 / && $2 ~ /^fd/{print $2; exit}')"
  if [ -z "$ip6_cidr" ]; then
    parent_iface="${networkcard%%.*}"
    ip6_cidr="$(ip -6 addr show "$parent_iface" 2>/dev/null | awk '/ inet6 / && $2 ~ /^fd/{print $2; exit}')"
  fi

  if [ -n "$ip6_cidr" ]; then
    ip6_addr="${ip6_cidr%/*}"
    prefix_len6="${ip6_cidr#*/}"
    # 取前 4 段作为稳定 ULA /64 前缀（fd10:0:1:xx）
    ula_prefix="$(echo "$ip6_addr" | awk -F: '{print $1":"$2":"$3":"$4}')"
    suggest_cidr6="${ula_prefix}::/64"
    suggest_gateway6="${ula_prefix}::1"
  else
    # 没有现成 ULA：退回你原来的“IPv4->ULA 前缀”方案（但只作为建议）
    if [ -n "$gateway" ]; then
      local prefix6
      prefix6="$(ipv4_to_ipv6_prefix "$gateway")"
      suggest_cidr6="${prefix6}::/64"
      suggest_gateway6="${prefix6}::1"
    fi
  fi

  if [ -n "$suggest_gateway6" ]; then
    echo "检测到/推算 IPv6 Gateway: $suggest_gateway6"
    read -r -p "请输入 IPv6 网关 (回车使用推荐 $suggest_gateway6，留空表示不启用IPv6): " gateway6
    [ -z "$gateway6" ] && gateway6="$suggest_gateway6"
  else
    read -r -p "请输入 IPv6 网关 (例如 fd10:0:1:0::1，留空表示不启用IPv6): " gateway6
  fi

  if [ -z "$gateway6" ]; then
    cidr6=""; iprange6=""; subnet6=""; iprangev6_prefix=""
  else
    auto_cidr6="${suggest_cidr6:-$(ipv4_to_ipv6_prefix "$gateway")::/64}"
    echo "👉 已根据 IPv6 网关 $gateway6 推算 IPv6 子网：$auto_cidr6"
    echo "⚠️ 提示：IPv6 IPRange 建议 /64（不要与现网 RA/DHCPv6 冲突）。"
    read -r -p "请输入 IPv6 子网CIDR (回车使用推荐 $auto_cidr6): " cidr6
    [ -z "$cidr6" ] && cidr6="$auto_cidr6"

    read -r -p "请输入 macvlan IPv6 range, 回车使用 $cidr6: " iprange6
    [ -z "$iprange6" ] && iprange6="$cidr6"

    subnet6="$(echo "$iprange6" | cut -d'/' -f2)"
    iprangev6_prefix="$(echo "$iprange6" | cut -d'/' -f1)"
  fi

  # ========== 根据物理网卡 + VLAN ID 生成 macvlan 网络名称 ==========
  local raw_phys safe_phys network_name
  raw_phys="${networkcard%%.*}"
  safe_phys="$(echo "$raw_phys" | sed 's/[^a-zA-Z0-9_-]/_/g')"

  if [ -n "$vlan_id" ]; then
    network_name="macvlan_${safe_phys}_${vlan_id}"
  else
    network_name="macvlan_${safe_phys}"
  fi

  # ========= 最终确认 =========
  echo "macvlan 参数确认："
  [ -n "$vlan_id" ] && echo "VLAN ID     : $vlan_id"
  echo "Parent 接口 : $networkcard"
  echo "IPv4 gateway: $gateway"
  echo "IPv4 subnet : $cidr"
  echo "IPv4 range  : $iprange"
  if [ -n "$gateway6" ]; then
    echo "IPv6 gateway: $gateway6"
    echo "IPv6 subnet : $cidr6"
    echo "IPv6 range  : $iprange6"
  else
    echo "IPv6        : 不启用"
  fi
  echo "网络名称：$network_name"

  local confirm
  read -r -p "是否正确？(y/n): " confirm
  if [ "$confirm" != "y" ]; then
    echo "退出 macvlan 创建。"
    return 1
  fi

  # 启用 promiscuous mode
  sudo ip link set "$networkcard" promisc on || true

  # 创建 docker macvlan 网络
  echo "🔨 正在创建 docker macvlan 网络：$network_name ..."
  if [ -n "$gateway6" ] && [ -n "$cidr6" ]; then
    docker network create -d macvlan \
      --subnet="$cidr"  --ip-range="$iprange"  --gateway="$gateway" \
      --ipv6 --subnet="$cidr6" --ip-range="$iprange6" --gateway="$gateway6" \
      -o parent="$networkcard" "$network_name"
  else
    docker network create -d macvlan \
      --subnet="$cidr" --ip-range="$iprange" --gateway="$gateway" \
      -o parent="$networkcard" "$network_name"
  fi

  echo "✅ macvlan 网络创建完成：$network_name"
}

# ========== 2. 配置 macvlan bridge 与 systemd ==========
create_macvlan_bridge() {
    echo "🔧 开始创建/更新 macvlan bridge（宿主机 <-> macvlan 网络互通）"

    # 1. 列出所有 macvlan 开头的 docker 网络
    mapfile -t macvlan_networks < <(docker network ls --format '{{.Name}}' | grep '^macvlan' || true)
    if [ ${#macvlan_networks[@]} -eq 0 ]; then
        echo "❌ 未发现任何以 macvlan 开头的 Docker 网络，请先创建 macvlan 网络。"
        return 1
    fi

    echo "可用的 macvlan 网络："
    for i in "${!macvlan_networks[@]}"; do
        echo "  $i) ${macvlan_networks[$i]}"
    done

    read -p "请输入要配置 bridge 的 macvlan 序号(默认 0): " idx
    idx=${idx:-0}
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [ "$idx" -lt 0 ] || [ "$idx" -ge "${#macvlan_networks[@]}" ]; then
        echo "❌ 输入序号无效。"
        return 1
    fi

    macvlan_name="${macvlan_networks[$idx]}"
    echo "📡 选中的 macvlan 网络: $macvlan_name"

    # 2. 获取网络配置
    network_info=$(docker network inspect "$macvlan_name" 2>/dev/null)
    if [ -z "$network_info" ]; then
        echo "❌ 无法 inspect Docker 网络：$macvlan_name"
        return 1
    fi

    # parent 接口（例如 eth0.8）
    parent_if=$(echo "$network_info" | jq -r '.[0].Options.parent // empty')
    if [ -z "$parent_if" ] || [ "$parent_if" = "null" ]; then
        echo "❌ 在 $macvlan_name 中未找到 parent 接口(Options.parent)，请检查该网络是否为 macvlan 类型。"
        return 1
    fi
    echo "🔗 发现 parent 接口: $parent_if"

    # === IPv4 部分：Subnet + IPRange 组合使用 ===
    subnet4_cidr=$(echo "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Subnet | test(":") | not) | .Subnet // empty' | head -n1)
    if [ -z "$subnet4_cidr" ] || [ "$subnet4_cidr" = "null" ]; then
        echo "❌ 无法从 $macvlan_name 中解析 IPv4 Subnet，请确认该网络配置了 IPv4。"
        return 1
    fi
    echo "🌐 IPv4 子网(Subnet): $subnet4_cidr"

    iprange4_cidr=$(echo "$network_info" | jq -r --arg s "$subnet4_cidr" '
      .[0].IPAM.Config[]
      | select((.Subnet // "") == $s)
      | (.IPRange // empty)
    ' | head -n1)
    if [ -n "$iprange4_cidr" ] && [ "$iprange4_cidr" != "null" ]; then
        echo "🌐 IPv4 IPRange: $iprange4_cidr"
        base4="${iprange4_cidr%/*}"   # 例如 10.0.2.0
    else
        base4="${subnet4_cidr%/*}"    # 例如 10.0.2.0
    fi
    # ⭐ 路由/掩码：优先 IPRange，缺省退回 Subnet
    route4_cidr="${iprange4_cidr:-$subnet4_cidr}"
    prefix4="${route4_cidr#*/}"

    # 用 base 前 3 段 + .254 作为 bridge IP
    bridge4="${base4%.*}.254"
    bridge4_cidr="${bridge4}/${prefix4}"
    echo "📍 计划 bridge IPv4: $bridge4_cidr"

    # === 新增：基于 bridge IPv4 生成稳定 MAC（使用已有函数） ===
    bridge_mac="$(ip_to_mac "$bridge4")"
    if [ -z "$bridge_mac" ]; then
      echo "❌ ip_to_mac 计算失败：bridge4=$bridge4"
      return 1
    fi
    echo "🧷 计划固定 bridge MAC: $bridge_mac"

    # === IPv6 部分：IPRange 优先，没有则用 Subnet；统一收敛到 /64，bridge 用 ::eeee ===
    subnet6_cidr=$(echo "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Subnet | test(":")) | .Subnet // empty' | head -n1)
    bridge6_cidr=""
    route6_pref=""

    if [ -n "$subnet6_cidr" ] && [ "$subnet6_cidr" != "null" ]; then
        echo "🌐 IPv6 子网(Subnet): $subnet6_cidr"

        iprange6_cidr=$(echo "$network_info" | jq -r --arg s "$subnet6_cidr" '
          .[0].IPAM.Config[]
          | select((.Subnet // "") == $s)
          | (.IPRange // empty)
        ' | head -n1)
        if [ -n "$iprange6_cidr" ] && [ "$iprange6_cidr" != "null" ]; then
            echo "🌐 IPv6 IPRange: $iprange6_cidr"
            base6="${iprange6_cidr%/*}"    # 比如 fd10:0:20:: 或 fd10:0:20::100
        else
            base6="${subnet6_cidr%/*}"     # 比如 fd10:0:20::
        fi

        # 归一：提纯前缀主体，统一 /64，bridge 固定 ::eeee
        base6_addr="${subnet6_cidr%/*}"   # fd10:0:20::  或 fd10:0:20:1::
        base6_prefix="${base6_addr%%::*}" # fd10:0:20    或 fd10:0:20:1

        bridge6_cidr="${base6_prefix}::eeee/64"
        route6_pref="${base6_prefix}::/64"
        echo "  计划 bridge IPv6: $bridge6_cidr"
    fi

    # 3. 生成接口名 / 脚本名 / service 名（mvb 前缀，尽量保留下划线）

    # VLAN判断：来自 macvlan 名或 parent_if
    vlan_id=""
    if [[ "$macvlan_name" =~ ^macvlan_([0-9]+)$ || "$macvlan_name" =~ ^macvlan-([0-9]+)$ ]]; then
        vlan_id="${BASH_REMATCH[1]}"
    elif [[ "$parent_if" =~ \.([0-9]+)$ ]]; then
        vlan_id="${BASH_REMATCH[1]}"
    fi

    # 物理网卡名（不缩写）
    raw_phys="${parent_if%%.*}"

    # 网络名（无长度限制）
    if [ -n "$vlan_id" ]; then
        safe_name="macvlan_${raw_phys}_${vlan_id}"
    else
        safe_name="macvlan_${raw_phys}"
    fi

    # 目标形式（优先保持）
    if [ -n "$vlan_id" ]; then
        bridge_try="mvb_${raw_phys}_${vlan_id}"
    else
        bridge_try="mvb_${raw_phys}"
    fi

    max_len=15

    # 如果长度 ≤ 15，直接使用
    if [ ${#bridge_try} -le $max_len ]; then
        bridge_if="$bridge_try"
    else
        # 1) 裁剪 phys（保留下划线）
        if [ -n "$vlan_id" ]; then
            prefix="mvb_"
            mid="${raw_phys}"
            suffix="_${vlan_id}"
        else
            prefix="mvb_"
            mid="${raw_phys}"
            suffix=""
        fi

        # 可用空间（保留 prefix 和 suffix）
        keep_len=$(( max_len - ${#prefix} - ${#suffix} ))
        [ $keep_len -lt 0 ] && keep_len=0

        # 裁剪物理网卡名（尾部裁剪）
        mid_cut="${mid: -$keep_len}"

        bridge_if="${prefix}${mid_cut}${suffix}"

        # 2) 若仍超长，移除下划线再重试
        if [ ${#bridge_if} -gt $max_len ]; then
            prefix="mvb"
            if [ -n "$vlan_id" ]; then
                core="${raw_phys}${vlan_id}"    # no underscores
            else
                core="${raw_phys}"
            fi
            keep_len=$(( max_len - ${#prefix} ))
            core_cut="${core: -$keep_len}"
            bridge_if="${prefix}${core_cut}"
        fi

        # 3) 最终保险 — 保留前缀 mvb，裁掉右边
        if [ ${#bridge_if} -gt $max_len ]; then
            bridge_if="mvb${bridge_if: -$((max_len-3))}"
        fi
    fi

    setup_script="/usr/local/bin/${safe_name}.sh"
    service_name="${safe_name}.service"

    echo "🧩 bridge 接口: $bridge_if"
    echo "🧩 配置脚本: $setup_script"
    echo "🧩 systemd 服务: $service_name"

    # —— 在写脚本之前：检测是否安装了 mihomo；若有则询问，否则询问是否指向其他 IP ——
    mihomo_ip=""
    FAKE_IP_GW=""

    # 1. 尝试探测 Mihomo IP
    if docker ps -a --format '{{.Names}}' | grep -qi 'mihomo'; then
      mihomo_ip="$(detect_mihomo_ip "$route4_cidr" "$network_info")"
      if [ -n "$mihomo_ip" ]; then
        echo "🔎 检测到 mihomo 相关容器，探测到 IP: $mihomo_ip"
        read -r -p "是否将 198.18.0.0/15 路由指向 mihomo ($mihomo_ip)？(y/n，默认 n): " yn_mihomo
        if [[ "$yn_mihomo" =~ ^[Yy]$ ]]; then
          FAKE_IP_GW="$mihomo_ip"
        fi
      fi
    fi

    if [ -n "$FAKE_IP_GW" ]; then
      echo "✅ 将写入路由规则: 198.18.0.0/15 via $FAKE_IP_GW"
    else
      echo "ℹ️ 不写入 198.18.0.0/15 的静态路由。"
    fi

    read -p "确认创建/更新以上 bridge？(y/n): " yn
    if [[ ! "$yn" =~ ^[Yy]$ ]]; then
        echo "⚠️ 已取消。"
        return 0
    fi

    # 4. 写入桥接脚本
    sudo mkdir -p /usr/local/bin

    cat <<EOF | sudo tee "$setup_script" >/dev/null
#!/bin/bash
set -e

SUBNET4_CIDR="$subnet4_cidr"
IPRANGE4_CIDR="$iprange4_cidr"
ROUTE6_PREF="$route6_pref"
BRIDGE6_CIDR="$bridge6_cidr"
FAKE_IP_GW="$FAKE_IP_GW"
MIHOMO_IP="$mihomo_ip"

# 1. 物理层清理与创建
ip link del "$bridge_if" 2>/dev/null || true
ip link add "$bridge_if" link "$parent_if" address "$bridge_mac" type macvlan mode bridge

# 🔒 MAC 校验（关键）
ip link show "$bridge_if" | grep -qi "$bridge_mac" || { echo "❌ MAC not set to $bridge_mac"; exit 1; }

# 2. IPv4 地址分配
ip addr replace "$bridge4_cidr" dev "$bridge_if"

# 3. IPv6 地址（有才配置）
if [ -n "\$BRIDGE6_CIDR" ]; then
  sysctl -w "net.ipv6.conf.${bridge_if}.accept_dad=0" >/dev/null || true
  ip -6 addr replace "\$BRIDGE6_CIDR" dev "$bridge_if"
fi
EOF

      cat <<EOF | sudo tee -a "$setup_script" >/dev/null

# 4. 接口启动与混杂模式
ip link set "$bridge_if" up
ip link set "$bridge_if" promisc on
ip link set "$parent_if" up 2>/dev/null || true
ip link set "$parent_if" promisc on

# 5. IPv4 路由：有 IPRange 才拦 IPRange + metric；否则拦 Subnet 不抢 metric
if [ -n "\$IPRANGE4_CIDR" ]; then
  ip route replace "\$IPRANGE4_CIDR" dev "$bridge_if" metric 10
else
  ip route replace "\$SUBNET4_CIDR" dev "$bridge_if"
fi

# 5.1 198.18.0.0/15（Fake-IP / 代理入口）说明 & 防踩坑
#
# ⚠️ 如果 198.18.x.x 由 Mac mini + surge 承载，Mac mini网卡上dns设为自动，不能指定为路由器网关
#
if [ -n "\$FAKE_IP_GW" ]; then
  ip route replace 198.18.0.0/15 via "\$FAKE_IP_GW" dev "$bridge_if" onlink 2>/dev/null || true
fi

# 6. IPv6 路由：不建议用 metric
if [ -n "\$ROUTE6_PREF" ]; then
  ip -6 route replace "\$ROUTE6_PREF" dev "$bridge_if"
fi

# 7. 内核参数调优
sysctl -w "net.ipv4.conf.${bridge_if}.rp_filter=0" >/dev/null || true
sysctl -w "net.ipv4.conf.${parent_if}.rp_filter=0" >/dev/null || true
sysctl -w "net.ipv4.conf.all.rp_filter=0" >/dev/null || true
sysctl -w "net.ipv4.conf.default.rp_filter=0" >/dev/null || true
EOF

    sudo chmod +x "$setup_script"

    # 5. 写入 systemd 服务
    sudo bash -c "cat > /etc/systemd/system/$service_name" <<EOF
[Unit]
Description=macvlan bridge for $macvlan_name ($bridge_if)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$setup_script
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    # 6. 启用并立即执行
    sudo systemctl daemon-reload 2>/dev/null || true
    sudo systemctl enable "$service_name" 2>/dev/null || true

    # 群晖 systemctl 可能无法 start，兜底直接执行一次脚本
    if ! sudo systemctl start "$service_name" 2>/dev/null; then
        echo "⚠️ systemctl start 不可用，直接执行 bridge 脚本"
        sudo "$setup_script" || return 1
    fi

    echo "✅ 已为 macvlan 网络 $macvlan_name 创建/更新 bridge 接口: $bridge_if"
    echo "   IPv4: $bridge4_cidr"
    if [ -n "$bridge6_cidr" ]; then
        echo "   IPv6: $bridge6_cidr"
    fi
}

install_librespeed() {

    echo "🔧 安装 LibreSpeed（需要选择 macvlan 网络）"

    # 1) 选择 macvlan（回车退出）
    select_macvlan_or_exit
    case $? in
      0) ;;
      2) return 0 ;;
      *) return 1 ;;
    esac

    # 2) 选择 IPv4 最后一段（回车默认 111）
    local last_octet
    last_octet="$(prompt_ipv4_last_octet \
      "请输入 LibreSpeed IPv4 最后一段（1-254，回车默认 111）: " 111)" || return 1

    # 3) 计算 IP / IPv6 / MAC（基于 SELECTED_MACVLAN）
    calculate_ip_mac "$last_octet"
    librespeed="$calculated_ip"
    librespeed6="$calculated_ip6"
    librespeedmac="$calculated_mac"

    # 4) 输入目录（回车退出）
    read -r -p "即将安装 LibreSpeed，请输入存储目录(例如 /data/dockerapps)，回车退出: " dockerapps
    if [ -z "$dockerapps" ]; then
        echo "✅ 已退出 LibreSpeed 安装。"
        return 0
    fi

    mkdir -p "$dockerapps" || return 1
    cd "$dockerapps" || return 1

    # 5) 清理旧目录（重装就清掉）
    if [ -d "${dockerapps}/librespeed" ]; then
        echo "⚠️ 检测到 ${dockerapps}/librespeed 已存在，正在删除..."
        rm -rf "${dockerapps}/librespeed"
    fi

    # 6) clone 仓库（仓库内自带 docker-compose.yml）
    git clone https://github.com/perryyeh/librespeed.git "${dockerapps}/librespeed" || return 1
    cd "${dockerapps}/librespeed" || return 1

    # 7) 写 .env（compose 读取）
    cat > .env <<EOF
MACVLAN_NET=${SELECTED_MACVLAN}
librespeed4=${librespeed}
librespeed6=${librespeed6}
librespeedmac=${librespeedmac}
EOF

    echo "✅ 已生成 .env："
    cat .env
    echo

    # 8) 启动（无 IPv6 就只用基础 compose；有 IPv6 再叠加 override）
    docker rm -f librespeed >/dev/null 2>&1 || true

    if [ -n "$librespeed6" ]; then
        docker compose -f docker-compose.yml -f docker-compose.ipv6.yml up -d
    else
        docker compose -f docker-compose.yml up -d
    fi

    echo "✅ LibreSpeed 已启动"
    echo "访问地址：http://${librespeed}"
    if [ -n "$librespeed6" ]; then
        echo "IPv6 地址：${librespeed6}"
    else
        echo "IPv6：未启用（所选 macvlan 未开启 IPv6 或无 IPv6 子网）"
    fi
}

install_adguardhome() {

    echo "🔧 安装 AdGuardHome（需要选择 macvlan 网络）"

    # 0) 选择 macvlan（回车退出）
    select_macvlan_or_exit
    case $? in
      0) ;;
      2) return 0 ;;
      *) return 1 ;;
    esac

    # 1) 输入 mosdns IPv4 最后一段（默认 119）-> 计算 mosdns/mosdns6
    local mosdns_last mosdns mosdns6
    mosdns_last="$(prompt_ipv4_last_octet \
      "请输入 mosdns IPv4 最后一段（1-254，回车默认 119）: " \
      119
    )" || return 1
    calculate_ip_mac "$mosdns_last"
    mosdns="$calculated_ip"
    mosdns6="$calculated_ip6"

    # 2) 输入 AdGuardHome IPv4 最后一段（默认 114）-> 计算 adguard/adguard6/adguardmac/gateway
    local adg_last adguard adguard6 adguardmac gateway
    adg_last="$(prompt_ipv4_last_octet \
      "请输入 adguard IPv4 最后一段（1-254，回车默认 114）: " \
      114
    )" || return 1
    calculate_ip_mac "$adg_last"
    adguard="$calculated_ip"
    adguard6="$calculated_ip6"
    adguardmac="$calculated_mac"
    gateway="$calculated_gateway"

    # 3) 输入目录（回车退出）
    local dockerapps
    read -r -p "即将安装 AdGuardHome，请输入存储目录(例如 /data/dockerapps)，回车退出: " dockerapps
    if [ -z "$dockerapps" ]; then
        echo "✅ 已退出 AdGuardHome 安装。"
        return 0
    fi

    mkdir -p "${dockerapps}/adguardwork" "${dockerapps}" || return 1

    # 4) 更新/获取仓库（stage：设置 WORK_DIR / NEED_SWITCH / TARGET_DIR / BAK_DIR）
    local REPO_URL="https://github.com/perryyeh/adguardhome.git"
    repo_stage_update "adguardhome" "$dockerapps" "$REPO_URL" "adguardhome" || return 1
    cd "$WORK_DIR" || { echo "❌ 进入目录失败：$WORK_DIR"; return 1; }

    # 5) 是否启用 IPv6：按你原判定（macvlan 支持 + 有 IPv6 子网）
    local USE_IPV6=0
    if macvlan_ipv6_enabled "$SELECTED_MACVLAN"; then
      USE_IPV6=1
    fi

    # 6) 写 .env（字段不变；但 confdir 用 WORK_DIR，避免 next 启动还挂旧目录）
    write_env_file "$WORK_DIR/.env" \
      "MACVLAN_NET=${SELECTED_MACVLAN}" \
      "adguard4=${adguard}" \
      "adguard6=${adguard6}" \
      "adguardmac=${adguardmac}"

    echo "✅ 已生成 .env："
    cat .env
    echo

    # 7) 替换逻辑（必须保留：mosdns / mosdns6 / gateway）
    if [ -f "${WORK_DIR}/AdGuardHome.yaml" ]; then
        sed -i "s/10.0.1.119/${mosdns}/g" "${WORK_DIR}/AdGuardHome.yaml"
        if [ -n "$mosdns6" ]; then
            sed -i "s/#\[fd10::1:119\]/[${mosdns6}]/g" "${WORK_DIR}/AdGuardHome.yaml"
        fi
        if [ -n "$gateway" ] && [ "$gateway" != "null" ]; then
            sed -i "s/10.0.0.1/${gateway}/g" "${WORK_DIR}/AdGuardHome.yaml"
        fi
    else
        echo "ℹ️ 未找到 AdGuardHome.yaml：首次启动后可在 WebUI 配置上游 DNS（或你之后再替换）。"
    fi

    # 8) .env 基本校验（统一用抽象函数）
    local required_vars=(MACVLAN_NET adguard4 adguardmac)
    [ "$USE_IPV6" -eq 1 ] && required_vars+=(adguard6)

    env_require_vars ".env" "${required_vars[@]}" || {
        echo "⚠️ .env 校验失败，取消启动，避免影响现有 adguardhome"
        return 1
    }

    # 9) 选择 compose 文件列表
    local compose_files=(docker-compose.yml)
    if [ "$USE_IPV6" -eq 1 ] && [ -f "$WORK_DIR/docker-compose.ipv6.yml" ]; then
        compose_files+=(docker-compose.ipv6.yml)
    fi

    # 10) 停旧备份 → 起新 → 回滚（失败） → next->正式目录切换（若需要） → 正式目录再重建
    #     （注意：第二个参数是容器名，必须和 compose 里的 container_name 一致）
    compose_deploy_with_repo_switch "adguardhome" "adguardhome" "${compose_files[@]}" || return 1

    echo "✅ AdGuardHome 已启动：${adguard}"
    echo "  macvlan 网络: ${SELECTED_MACVLAN}"
    echo "  MAC        : ${adguardmac}"
    echo "  上游 mosdns : ${mosdns}"
    if [ "$USE_IPV6" -eq 1 ]; then
        echo "  IPv6       : ${adguard6}"
    else
        echo "  IPv6       : 未启用（所选 macvlan 未开启 IPv6 或无 IPv6 子网）"
    fi

    # 11) 可选删除目录备份（带挂载检查）
    repo_offer_delete_backup "adguardhome" "$BAK_DIR" "adguardhome"
}

install_mosdns() {

    echo "🔧 安装 mosdns（需要选择 macvlan 网络）"

    # 0) 选择 macvlan（回车退出）
    select_macvlan_or_exit
    case $? in
      0) ;;
      2) return 0 ;;
      *) return 1 ;;
    esac

    # 仅用于写 mosdns 上游：只需要 mihomo IPv4
    local mihomo_input mihomo

    read -r -p "surge请输入198.18.0.2, mihomo请输入输完整IP或最后一段（回车默认 120）: " mihomo_input

    # ✅ 关键修复
    if [ -z "$mihomo_input" ]; then
        calculate_ip_mac 120
        mihomo="$calculated_ip"
    elif [[ "$mihomo_input" =~ ^[0-9]+$ ]]; then
        if [ "$mihomo_input" -lt 1 ] || [ "$mihomo_input" -gt 254 ]; then
            echo "❌ 无效的最后一段：$mihomo_input"
            return 1
        fi
        calculate_ip_mac "$mihomo_input"
        mihomo="$calculated_ip"
    else
        mihomo="$(echo "$mihomo_input" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)"
        [ -n "$mihomo" ] || { echo "❌ 无法解析 IPv4：$mihomo_input"; return 1; }
    fi

    echo "📌 上游 mihomo / surge IPv4：$mihomo"

    # 2) 选择 mosdns IPv4 最后一段（回车默认 119）
    local mosdns_last
    mosdns_last="$(prompt_ipv4_last_octet \
      "请输入 mosdns IPv4 最后一段（1-254，回车默认 119）: " 119)" || return 1

    # 3) 计算 mosdns IP / IPv6 / MAC / 网关（基于 SELECTED_MACVLAN）
    calculate_ip_mac "$mosdns_last"
    local mosdns mosdns6 mosdnsmac gateway
    mosdns="$calculated_ip"
    mosdns6="$calculated_ip6"
    mosdnsmac="$calculated_mac"
    gateway="$calculated_gateway"

    # 是否启用 IPv6（逻辑跟 mihomo 一致：EnableIPv6=true 且存在 IPv6 Subnet）
    local USE_IPV6=0
    if docker network inspect "$SELECTED_MACVLAN" | jq -e '.[0].EnableIPv6==true and (.[0].IPAM.Config[]?.Subnet|test(":"))' >/dev/null 2>&1; then
        USE_IPV6=1
    fi

    # 4) 输入目录（回车退出）
    local dockerapps
    read -r -p "即将安装 mosdns，请输入存储目录(例如 /data/dockerapps)，回车退出: " dockerapps
    if [ -z "$dockerapps" ]; then
        echo "✅ 已退出 mosdns 安装。"
        return 0
    fi
    mkdir -p "$dockerapps" || return 1

    # 5) 仓库更新：
    local REPO_URL="https://github.com/perryyeh/mosdns.git"
    repo_stage_update "mosdns" "$dockerapps" "$REPO_URL" "mosdns" || return 1

    # repo_stage_update 会设置：WORK_DIR / NEED_SWITCH / NEXT_DIR / BAK_DIR（全局变量）
    cd "$WORK_DIR" || { echo "❌ 进入目录失败：$WORK_DIR"; return 1; }

    # 6) 替换 dns.yaml 里上游 mihomo / gateway
    if [ -f "dns.yaml" ]; then
        # 用 # 作为分隔符更稳（避免 / 等字符导致 sed 崩）
        sed -i "s#198.18.0.2#${mihomo}#g" dns.yaml
        if [ -n "$gateway" ] && [ "$gateway" != "null" ]; then
            sed -i "s#10.0.0.1#${gateway}#g" dns.yaml
        fi
    else
        echo "❌ 未找到 ${WORK_DIR}/dns.yaml"
        return 1
    fi

    # 7) 写 .env（compose 读取）
    cat > .env <<EOF
MACVLAN_NET=${SELECTED_MACVLAN}
mosdns4=${mosdns}
mosdns6=${mosdns6}
mosdnsmac=${mosdnsmac}
EOF

    echo "✅ 已生成 .env："
    cat .env
    echo

    if [ "$USE_IPV6" -eq 1 ] && [ -z "$mosdns6" ]; then
        echo "❌ 该 macvlan 网络启用了 IPv6，但未能计算出 mosdns6（可能 IPv6 子网解析失败）"
        return 1
    fi


    # 8) .env 基本校验
    local required_vars=(MACVLAN_NET mosdns4 mosdnsmac)
    [ "$USE_IPV6" -eq 1 ] && required_vars+=(mosdns6)

    env_require_vars ".env" "${required_vars[@]}" || {
        echo "⚠️ .env 校验失败，取消启动，避免影响现有 mosdns"
        return 1
    }

    # 9) 选择 compose 文件列表
    local compose_files=(docker-compose.yml)
    if [ "$USE_IPV6" -eq 1 ] && [ -f docker-compose.ipv6.yml ]; then
        compose_files+=(docker-compose.ipv6.yml)
    fi

    # 10）一步部署：校验 -> 停旧备份 -> 起新 -> next->正式 -> 正式再up -> 失败回滚
    compose_deploy_with_repo_switch "mosdns" "mosdns" "${compose_files[@]}" || return 1

    # 11）
    echo "✅ mosdns 已启动：${mosdns}"
    echo "  上游 mihomo / surge : ${mihomo}"
    echo "  macvlan 网络: ${SELECTED_MACVLAN}"
    echo "  MAC        : ${mosdnsmac}"
    if [ "$USE_IPV6" -eq 1 ]; then
        echo "  IPv6       : ${mosdns6}"
    else
        echo "  IPv6       : 未启用（所选 macvlan 未开启 IPv6 或无 IPv6 子网）"
    fi

    # 12) 可选删除备份（带挂载检查）
    repo_offer_delete_backup "mosdns" "$BAK_DIR" "mosdns"
}

install_mihomo() {

    echo "🔧 安装 mihomo（需要选择 macvlan 网络）"

    # 1) 选择 macvlan（回车退出）
    select_macvlan_or_exit
    case $? in
      0) ;;
      2) return 0 ;;
      *) return 1 ;;
    esac

    # 2) 选择 mihomo IPv4 最后一段（回车默认 120）
    local mihomo_last
    mihomo_last="$(prompt_ipv4_last_octet \
      "请输入 mihomo IPv4 最后一段（1-254，回车默认 120）: " 120)" || return 1

    # 3) 计算 IP / IPv6 / MAC / Gateway（基于 SELECTED_MACVLAN）
    calculate_ip_mac "$mihomo_last"
    mihomo=$calculated_ip
    mihomo6=$calculated_ip6
    mihomomac=$calculated_mac
    gateway=$calculated_gateway

    USE_IPV6=0
    if docker network inspect "$SELECTED_MACVLAN" | jq -e '.[0].EnableIPv6==true and (.[0].IPAM.Config[]?.Subnet|test(":"))' >/dev/null 2>&1; then
      USE_IPV6=1
    fi

    # 4) 输入目录（回车退出）
    read -r -p "即将安装 mihomo，请输入存储目录(例如 /data/dockerapps)，回车退出: " dockerapps
    if [ -z "$dockerapps" ]; then
        echo "✅ 已退出 mihomo 安装。"
        return 0
    fi

    mkdir -p "$dockerapps" || return 1
    cd "$dockerapps" || return 1

    # 5) repo 分阶段更新（内部会设置 WORK_DIR / NEED_SWITCH / BAK_DIR 等全局变量）
    REPO_URL="https://github.com/perryyeh/mihomo.git"
    repo_stage_update "mihomo" "$dockerapps" "$REPO_URL" "mihomo" || return 1
    cd "$WORK_DIR" || { echo "❌ 进入目录失败：$WORK_DIR"; return 1; }

    # 6) 替换 config.yaml 里的网关
    if [ -f "config.yaml" ] && [ -n "$gateway" ] && [ "$gateway" != "null" ]; then
        sed -i "s/10.0.0.1/${gateway}/g" config.yaml
    fi

    # 7) 生成 .env（compose 会用到）
    cat > .env <<EOF
MACVLAN_NET=${SELECTED_MACVLAN}
mihomo4=${mihomo}
mihomo6=${mihomo6}
mihomomac=${mihomomac}
EOF

    echo "✅ 已生成 .env 文件："
    cat .env
    echo

    if [ "$USE_IPV6" -eq 1 ] && [ -z "$mihomo6" ]; then
        echo "❌ 该 macvlan 网络启用了 IPv6，但未能计算出 mihomo6（可能 IPv6 子网解析失败）"
        return 1
    fi

    # === 8 .env 基本校验 ===
    required_vars=(MACVLAN_NET mihomo4 mihomomac)
    [ "$USE_IPV6" -eq 1 ] && required_vars+=(mihomo6)

    env_require_vars ".env" "${required_vars[@]}" || {
        echo "⚠️ .env 校验失败，取消启动，避免断网"
        return 1
    }

    # 9) 选择 compose 文件列表
    compose_files=(docker-compose.yml)
    if [ "$USE_IPV6" -eq 1 ] && [ -f docker-compose.ipv6.yml ]; then
        compose_files+=(docker-compose.ipv6.yml)
    fi

    # 10) 一步部署：校验 -> 停旧备份 -> 起新 -> next->正式 -> 正式再up -> 失败回滚
    compose_deploy_with_repo_switch "mihomo" "mihomo" "${compose_files[@]}" || return 1

    echo "✅ mihomo 已启动！访问地址：http://${mihomo}:9090/ui/  密码：admin"
    if [ "$USE_IPV6" -eq 1 ]; then
        echo "IPv6：${mihomo6}"
    else
        echo "IPv6：未启用（所选 macvlan 未开启 IPv6 或无 IPv6 子网）"
    fi

    # 11) 可选删除备份（带挂载检查）
    repo_offer_delete_backup "mihomo" "$BAK_DIR" "mihomo"
}

install_ddnsgo() {
    echo "🔧 安装 ddns-go（依赖 mihomo 已安装并运行）"

    local mihomo_container="mihomo"

    # 0) 检查 mihomo 是否在运行（network_mode=container:mihomo 需要它是 running 状态）
    if ! docker ps --format '{{.Names}}' | grep -qx "$mihomo_container"; then
        echo "❌ 未检测到正在运行的 mihomo 容器（容器名：$mihomo_container）。"
        echo "   ddns-go 计划与 mihomo 共用网络（例如 network_mode=container:mihomo），"
        echo "   请先运行 install_mihomo 安装并启动 mihomo 再继续。"
        return 1
    fi

    # 1) 输入目录（回车退出）
    read -r -p "即将安装 ddns-go，请输入存储目录(例如 /data/dockerapps)，回车退出: " dockerapps
    if [ -z "$dockerapps" ]; then
        echo "✅ 已退出 ddns-go 安装。"
        return 0
    fi

    mkdir -p "$dockerapps" || return 1
    cd "$dockerapps" || return 1

    # 2) repo 分阶段更新
    REPO_URL="https://github.com/perryyeh/ddnsgo.git"
    repo_stage_update "ddnsgo" "$dockerapps" "$REPO_URL" "ddnsgo" || return 1
    cd "$WORK_DIR" || { echo "❌ 进入目录失败：$WORK_DIR"; return 1; }

    # 3) 选择 compose 文件列表（默认只用 docker-compose.yml）
    local compose_files=(docker-compose.yml)

    # 4) 一步部署：校验 -> 停旧备份 -> 起新 -> next->正式 -> 正式再up -> 失败回滚
    compose_deploy_with_repo_switch "ddnsgo" "ddnsgo" "${compose_files[@]}" || return 1

    echo "✅ ddns-go 已启动！正在检测 mihomo IP 以生成管理地址..."

    # 5) 读取 mihomo 容器的 IPv4 / IPv6
    local mihomo4 mihomo6
    mihomo4="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$mihomo_container" 2>/dev/null || true)"
    mihomo6="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' "$mihomo_container" 2>/dev/null || true)"

    echo
    echo "📡 检测到的 mihomo 容器网络信息："
    if [ -n "$mihomo4" ]; then
        echo "  - IPv4: $mihomo4"
    else
        echo "  - IPv4: 未检测到（可能使用纯 IPv6 或网络未就绪）"
    fi

    if [ -n "$mihomo6" ]; then
        echo "  - IPv6: $mihomo6"
    else
        echo "  - IPv6: 未检测到或未启用"
    fi
    echo

    # 6) 给出 ddns-go 管理界面地址（默认监听 9876）
    local ddns_port=9876

    echo "👉 ddns-go 管理界面地址（请在浏览器中打开）："
    if [ -n "$mihomo4" ]; then
        echo "  - IPv4：  http://${mihomo4}:${ddns_port}/"
    fi
    if [ -n "$mihomo6" ]; then
        echo "  - IPv6：  http://[${mihomo6}]:${ddns_port}/"
    fi

    if [ -z "$mihomo4" ] && [ -n "$mihomo6" ]; then
        echo "ℹ️  当前仅检测到 IPv6，可在支持 IPv6 的环境中访问上方 IPv6 地址。"
    elif [ -z "$mihomo4" ] && [ -z "$mihomo6" ]; then
        echo "⚠️  未能自动检测 mihomo 的 IP，请手动确认网络配置和 ddns-go 监听端口。"
    fi

    # 7) 可选删除备份（带挂载检查）
    repo_offer_delete_backup "ddnsgo" "$BAK_DIR" "ddnsgo"
}

install_portainer() {
    read -p "即将安装watchtower，请输入存储目录(例如 /data/dockerapps): " dockerapps
    docker run -d -p 8000:8000 -p 9443:9443 --network=host --name=portainer --restart=always \
    -v /var/run/docker.sock:/var/run/docker.sock -v ${dockerapps}/portainer:/data portainer/portainer-ce:lts
}

# 安装samba
install_samba() {
    echo "🔧 开始安装 Samba（基于 macvlan 独立 IP）"

    # 0. 选择要使用的 macvlan 网络（数字选择）
    echo "🔧 检测可用的 macvlan 网络："
    mapfile -t macvlan_list < <(docker network ls --format '{{.Name}}' | grep '^macvlan' || true)

    if [ ${#macvlan_list[@]} -eq 0 ]; then
        echo "❌ 未检测到任何 macvlan 网络，请先创建（菜单 8）。"
        return 1
    fi

    echo "可用网络："
    for i in "${!macvlan_list[@]}"; do
        idx=$((i + 1))
        echo "  ${idx}) ${macvlan_list[$i]}"
    done

    read -p "请选择要使用的 macvlan 网络编号（默认 1）: " net_index
    net_index=${net_index:-1}

    if ! [[ "$net_index" =~ ^[0-9]+$ ]] || [ "$net_index" -lt 1 ] || [ "$net_index" -gt "${#macvlan_list[@]}" ]; then
        echo "❌ 无效输入。"
        return 1
    fi

    macvlan_name="${macvlan_list[$((net_index - 1))]}"
    echo "✅ 已选择 macvlan 网络: ${macvlan_name}"

    # 读取该 macvlan 网络配置
    network_info=$(docker network inspect "$macvlan_name" 2>/dev/null)
    if [ -z "$network_info" ] || [ "$network_info" = "[]" ]; then
        echo "❌ 未检测到 docker 网络 $macvlan_name，请确认名称是否正确。"
        return 1
    fi

    # ---- 解析 IPv4 subnet ----
    subnet4=$(echo "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Subnet | test(":") | not) | .Subnet // empty')

    if [ -z "$subnet4" ] || [ "$subnet4" = "null" ]; then
        echo "❌ 网络 $macvlan_name 未配置 IPv4 子网，无法为 Samba 分配地址。"
        return 1
    fi

    subnet4_ip=$(echo "$subnet4" | cut -d'/' -f1)
    subnet4_mask=$(echo "$subnet4" | cut -d'/' -f2)
    base_v4_prefix="${subnet4_ip%.*}"   # 例如 10.0.8
    last_octet=145
    samba4="${base_v4_prefix}.${last_octet}"

    # ---- 解析 IPv6 subnet（如有）----
    subnet6=$(echo "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Subnet | test(":")) | .Subnet // empty')

    samba6=""
    subnet6_mask=""
    if [ -n "$subnet6" ] && [ "$subnet6" != "null" ]; then
        subnet6_ip=$(echo "$subnet6" | cut -d'/' -f1)
        subnet6_mask=$(echo "$subnet6" | cut -d'/' -f2)

        # 用 IPv6 子网地址的前缀 + host-id 145 生成地址
        prefix6=$(echo "$subnet6_ip" | rev | cut -d':' -f2- | rev):
        samba6="${prefix6}${last_octet}"
    fi

    # MAC 用工具函数 ip_to_mac 由 IPv4 生成（该函数在脚本其他位置已存在）
    sambamac=$(ip_to_mac "$samba4")

    echo "📡 选用的 macvlan 网络: $macvlan_name"
    echo "📍 规划的 Samba 地址:"
    echo "  IPv4 : $samba4/$subnet4_mask"
    [ -n "$samba6" ] && echo "  IPv6 : $samba6/${subnet6_mask}"
    echo "  MAC  : $sambamac"

    # 2. 收集用户参数
    read -p "请输入 Docker 应用存储目录(例如 /data/dockerapps): " dockerapps
    read -p "请输入要共享的实际路径(例如 /data/nvr/samba): " smb_storage
    read -p "请输入 Samba 用户名: " smb_user
    read -s -p "请输入 Samba 密码: " smb_pass
    echo

    appdir="${dockerapps}/samba"

    # 3. 如果目录已存在，先删掉再 clone
    if [ -d "${appdir}" ]; then
        echo "⚠️ 检测到 ${appdir} 已存在，正在删除..."
        rm -rf "${appdir}"
    fi

    mkdir -p "${dockerapps}"

    # 4. 克隆仓库（你的仓库）
    git clone https://github.com/perryyeh/samba.git "${appdir}"

    cd "${appdir}" || return 1

    # 5. 确认 docker-compose.yml 存在
    if [ ! -f docker-compose.yml ]; then
        echo "❌ 未找到 ${appdir}/docker-compose.yml，请确认仓库中已包含该文件"
        return 1
    fi

    # 6. 生成 .env 文件（包含 appdir / MACVLAN_NET 等参数）
    cat > .env <<EOF
# 使用的 macvlan 网络名（compose 中 networks.macvlan.name 使用）
MACVLAN_NET=${macvlan_name}

# 固定 IP / MAC
samba4=${samba4}
samba6=${samba6}
sambamac=${sambamac}

# Samba 配置
SMB_USER=${smb_user}
SMB_PASS=${smb_pass}
SMB_STORAGE=${smb_storage}
SMB_PORT=445

# 应用目录（用于挂载 smb.conf / users.conf）
appdir=${appdir}
EOF

    echo "✅ 已生成 ${appdir}/.env："
    cat .env
    echo

    # 7. 启动容器
    docker compose up -d

    echo "✅ Samba 容器已启动："
    echo "  使用 macvlan 网络 : ${macvlan_name}"
    echo "  IPv4 地址        : ${samba4}"
    [ -n "$samba6" ] && echo "  IPv6 地址        : ${samba6}"
    echo "  MAC 地址         : ${sambamac}"
    echo "  用户名           : ${smb_user}"
    echo "  密码             : ${smb_pass}"
    echo "  宿主路径         : ${smb_storage}"
    echo "  配置路径         : ${appdir}/smb.conf"
    echo "  端口             : 445"
}

# ========== 删除 docker macvlan 网络 ==========
clean_macvlan_network() {
    echo "🧹 清理 Docker macvlan 网络"

    # 找出所有以 macvlan 开头的 Docker 网络
    mapfile -t macvlan_networks < <(docker network ls --format '{{.Name}}' | grep '^macvlan' || true)

    if [ ${#macvlan_networks[@]} -eq 0 ]; then
        echo "ℹ️ 当前没有任何以 macvlan 开头的 Docker 网络。"
        return 0
    fi

    # 列表展示（含是否使用中）
    echo "检测到以下 macvlan 网络："
    for i in "${!macvlan_networks[@]}"; do
        net="${macvlan_networks[$i]}"
        containers=$(docker network inspect -f '{{range $id,$c := .Containers}}{{printf "%s " $c.Name}}{{end}}' "$net" 2>/dev/null)
        if [ -n "$containers" ]; then
            echo "  $i) $net    (使用中的容器: $containers)"
        else
            echo "  $i) $net"
        fi
    done

    echo
    echo "请输入要删除的网络序号，或输入 a 表示删除全部，回车取消："
    read -p "你的选择: " choice

    if [ -z "$choice" ]; then
        echo "⚠️ 已取消删除 macvlan 网络。"
        return 0
    fi

    local to_delete=()

    if [[ "$choice" =~ ^[0-9]+$ ]]; then
        if [ "$choice" -lt 0 ] || [ "$choice" -ge "${#macvlan_networks[@]}" ]; then
            echo "❌ 无效的序号。"
            return 1
        fi
        to_delete=("${macvlan_networks[$choice]}")
    elif [[ "$choice" =~ ^[Aa]$ ]]; then
        to_delete=("${macvlan_networks[@]}")
    else
        echo "❌ 无效输入。"
        return 1
    fi

    # 先构建剩余网络的 <phys>_<vlan> 索引，用于判断 VLAN 是否仍被其他 macvlan 使用
    declare -A remain_key_count
    for net in "${macvlan_networks[@]}"; do
        skip=false
        for del in "${to_delete[@]}"; do
            [[ "$net" == "$del" ]] && { skip=true; break; }
        done
        $skip && continue
        # 解析 macvlan_<phys> 或 macvlan_<phys>_<vid>
        if [[ "$net" =~ ^macvlan_([A-Za-z0-9_-]+)_([0-9]+)$ ]]; then
            phys="${BASH_REMATCH[1]}"
            vid="${BASH_REMATCH[2]}"
            key="${phys}_${vid}"
            remain_key_count["$key"]=$(( ${remain_key_count["$key"]:-0} + 1 ))
        elif [[ "$net" =~ ^macvlan_([A-Za-z0-9_-]+)$ ]]; then
            phys="${BASH_REMATCH[1]}"
            # 无 VLAN 的网络，不涉及删除子接口
        fi
    done

    for net in "${to_delete[@]}"; do
        echo
        echo "🧻 准备删除 macvlan 网络: $net"

        containers=$(docker network inspect -f '{{range $id,$c := .Containers}}{{printf "%s " $c.Name}}{{end}}' "$net" 2>/dev/null)
        if [ -n "$containers" ]; then
            echo "⚠️ 该网络仍有容器在使用：$containers"
            read -p "是否强制删除该网络？相关容器将失去该网络连接。(y/N): " yn
            if [[ ! "$yn" =~ ^[Yy]$ ]]; then
                echo "⏭ 已跳过 $net"
                continue
            fi
        fi

        if docker network rm "$net"; then
            echo "✅ 已删除 macvlan 网络: $net"
        else
            echo "❌ 删除 macvlan 网络失败: $net"
            continue
        fi

        # —— 尝试同步清理当初创建的 VLAN 子接口（如 eth0.88）——
        # 仅当网络名为 macvlan_<phys>_<vid> 时尝试推断；phys 假定与系统实际接口同名（之前已做过安全化）
        if [[ "$net" =~ ^macvlan_([A-Za-z0-9_-]+)_([0-9]+)$ ]]; then
            phys_safe="${BASH_REMATCH[1]}"
            vid="${BASH_REMATCH[2]}"

            # 如果其它 macvlan 仍在用相同 <phys>_<vid>，则不清理该 VLAN 子接口
            key="${phys_safe}_${vid}"
            if [ "${remain_key_count[$key]:-0}" -gt 0 ]; then
                echo "ℹ️ 仍有其它 macvlan 使用 ${phys_safe}.${vid}，跳过删除该 VLAN 子接口。"
                continue
            fi

            # 推断真实物理口名（之前创建时仅做过“安全字符替换”，常见 eth0/eno1/enpXsY 均一致）
            phys="$phys_safe"
            vlan_if="${phys}.${vid}"

            # 仅当 VLAN 子接口存在时才考虑删除
            if ip link show "$vlan_if" >/dev/null 2>&1; then
                echo "🔎 检测到同名 VLAN 子接口：$vlan_if"
                # 再保险：确认该 VLAN 接口当前没有地址或不在使用中（不强制，但给出提示）
                has_addr4=$(ip -4 addr show "$vlan_if" | awk '/ inet /{print $2}' | wc -l)
                has_addr6=$(ip -6 addr show "$vlan_if" | awk '/ inet6 /{print $2}' | wc -l)

                if [ "$has_addr4" -gt 0 ] || [ "$has_addr6" -gt 0 ]; then
                    echo "⚠️ 注意：$vlan_if 当前仍有 IP 地址：IPv4=$has_addr4, IPv6=$has_addr6"
                fi

                read -p "是否一并删除 VLAN 子接口 $vlan_if ？(y/N): " delv
                if [[ "$delv" =~ ^[Yy]$ ]]; then
                    sudo ip link set "$vlan_if" down 2>/dev/null || true
                    if sudo ip link delete "$vlan_if"; then
                        echo "✅ 已删除 VLAN 子接口：$vlan_if"
                    else
                        echo "❌ 删除 VLAN 子接口失败：$vlan_if"
                    fi
                else
                    echo "⏭ 已保留 VLAN 子接口：$vlan_if"
                fi
            fi
        fi
    done
}

# ========== 删除 docker macvlan bridge ==========
clean_macvlan_bridge() {
    echo "🧹 清理 macvlan bridge（支持多个）"

    # 找 macvlan_* 的 systemd 服务
    local svc_files=()
    if compgen -G "/etc/systemd/system/macvlan*.service" > /dev/null; then
        for f in /etc/systemd/system/macvlan*.service; do
            svc_files+=("$f")
        done
    fi

    if [ ${#svc_files[@]} -eq 0 ]; then
        echo "ℹ️ 未发现 macvlan bridge service。"
        return 0
    fi

    echo "检测到以下 macvlan bridge 服务："
    local i
    for i in "${!svc_files[@]}"; do
        local svc_path="${svc_files[$i]}"
        local svc_name=$(basename "$svc_path")
        local safe_name="${svc_name%.service}"
        local setup_script="/usr/local/bin/${safe_name}.sh"

        # ⭐直接从脚本中提取 bridge_if（最可靠）
        local bridge_if=""
        if [ -f "$setup_script" ]; then
            bridge_if=$(grep -E 'ip link add "[^"]+"' "$setup_script" | \
                        head -n1 | sed -E 's/.*add "([^"]+)".*/\1/')
        fi

        echo "  $i) 服务: $svc_name   接口: ${bridge_if:-未知}   脚本: $setup_script"
    done

    echo
    read -p "请输入要清理的序号，或输入 a 表示清理全部，回车取消: " choice
    [ -z "$choice" ] && { echo "⚠️ 已取消"; return 0; }

    local to_clean=()
    if [[ "$choice" =~ ^[0-9]+$ ]]; then
        to_clean=("${svc_files[$choice]}")
    elif [[ "$choice" =~ ^[Aa]$ ]]; then
        to_clean=("${svc_files[@]}")
    else
        echo "❌ 无效输入"
        return 1
    fi

    for svc_path in "${to_clean[@]}"; do
        local svc_name=$(basename "$svc_path")
        local safe_name="${svc_name%.service}"
        local setup_script="/usr/local/bin/${safe_name}.sh"

        # ⭐再从脚本中提取一次 bridge_if
        local bridge_if=""
        if [ -f "$setup_script" ]; then
            bridge_if=$(grep -E 'ip link add "[^"]+"' "$setup_script" | \
                        head -n1 | sed -E 's/.*add "([^"]+)".*/\1/')
        fi

        echo "🧻 清理: $svc_name"
        echo "   bridge_if: ${bridge_if:-未知}"
        echo "   脚本: $setup_script"

        # 停止服务
        systemctl disable --now "$svc_name" 2>/dev/null || true

        # 删除网卡
        [ -n "$bridge_if" ] && ip link del "$bridge_if" 2>/dev/null || true

        # 删除脚本
        [ -f "$setup_script" ] && rm -f "$setup_script"

        # 删除 service
        rm -f "$svc_path"
    done

    systemctl daemon-reload
    echo "✅ 清理完成。"
}

install_watchtower() {
    echo "🔧 安装并启动常驻 watchtower..."

    API=$(docker version --format '{{.Server.APIVersion}}')

    docker run -d \
      --name watchtower \
      --restart=always \
      -e DOCKER_API_VERSION="$API" \
      -e TZ="Asia/Shanghai" \
      -v /var/run/docker.sock:/var/run/docker.sock \
      containrrr/watchtower:latest \
      --cleanup \
      --include-restarting \
      --revive-stopped

    echo "✅ watchtower 已常驻运行"
}

run_watchtower_once() {
    echo "🔧 正在执行 watchtower --run-once 更新所有容器（排除 watchtower 自身）..."
    API=$(docker version --format '{{.Server.APIVersion}}')   # 预期=1.52
    docker run --rm \
        -e DOCKER_API_VERSION="$API" \
        -v /var/run/docker.sock:/var/run/docker.sock \
        containrrr/watchtower:latest \
        --run-once \
        --cleanup \
        --rolling-restart \
        --include-stopped \
        --disable-containers watchtower
    echo "✅ watchtower run-once 更新完成"
}

# =====================
#  功能 70：迁移 Docker 目录
# =====================
migrate_docker_datadir() {
    # 前置校验
    if [ -z "${BASH_VERSION:-}" ]; then exec /usr/bin/env bash "$0" "$@"; fi
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then echo "请以 root 权限运行（sudo bash $0）"; return 1; fi
    if ! command -v docker >/dev/null 2>&1; then
        echo "未检测到 Docker，请先安装 Docker 后再迁移。"
        return 1
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "未检测到 systemctl，无法停止/启动 docker 服务。"
        return 1
    fi

    local DEFAULT_ROOT="/var/lib/docker"
    local CURRENT_ROOT=""
    local NEW_ROOT=""
    local DAEMON_JSON="/etc/docker/daemon.json"
    local BACKUP_SUFFIX
    BACKUP_SUFFIX="$(date +%Y%m%d-%H%M%S)"

    # 读取当前 Docker Root Dir（优先 docker info）
    CURRENT_ROOT="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
    if [[ -z "$CURRENT_ROOT" ]]; then
        # docker daemon 可能没起，兜底从 daemon.json 读
        if [[ -f "$DAEMON_JSON" ]]; then
            CURRENT_ROOT="$(sed -n 's/.*"data-root"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$DAEMON_JSON" | head -n1)"
        fi
        [[ -z "$CURRENT_ROOT" ]] && CURRENT_ROOT="$DEFAULT_ROOT"
    fi

    echo "📌 Docker 默认目录：$DEFAULT_ROOT"
    echo "📌 Docker 当前目录：$CURRENT_ROOT"
    echo

    # 如果已经不是默认目录，询问是否继续迁移
    if [[ "$CURRENT_ROOT" != "$DEFAULT_ROOT" ]]; then
        echo "⚠️ 检测到 Docker 已不在默认目录（已迁移过）。"
        read -r -p "是否要再次迁移到新的目录？(y/N，回车默认不迁移): " again
        if [[ ! "$again" =~ ^[Yy]$ ]]; then
            echo "✅ 已取消迁移。"
            return 0
        fi
    fi

    # 读取用户输入的新目录（回车退出不迁移）
    read -r -p "请输入迁移目标目录（例如 /data/docker；回车退出不迁移）: " NEW_ROOT
    if [[ -z "$NEW_ROOT" ]]; then
        echo "✅ 未输入路径，已退出迁移。"
        return 0
    fi

    # 规范化路径：去掉末尾 /
    NEW_ROOT="${NEW_ROOT%/}"

    # 目标目录必须存在（按你原逻辑）
    if [[ ! -d "$NEW_ROOT" ]]; then
        echo "❌ 目录不存在：$NEW_ROOT  —— 已取消迁移。"
        return 1
    fi

    if [[ "$NEW_ROOT" == "$CURRENT_ROOT" ]]; then
        echo "✅ 目标目录与当前目录相同，无需迁移。"
        return 0
    fi

    # 停止 docker + socket（避免 socket 抢跑旧参数）
    systemctl stop docker docker.socket >/dev/null 2>&1 || true

    # 依赖：rsync
    if ! command -v rsync >/dev/null 2>&1; then
        echo "安装 rsync ..."
        apt-get update -y && apt-get install -y rsync
    fi

    # 同步数据（从 CURRENT_ROOT -> NEW_ROOT）
    mkdir -p "$NEW_ROOT"
    if [[ -d "$CURRENT_ROOT" && -n "$(ls -A "$CURRENT_ROOT" 2>/dev/null || true)" ]]; then
        rsync -aHAX --delete --numeric-ids "$CURRENT_ROOT"/ "$NEW_ROOT"/
        echo "✅ 数据已同步到 $NEW_ROOT"
    else
        echo "ℹ️ $CURRENT_ROOT 为空或不存在，将创建全新 Docker 根目录"
    fi

    # 备份旧目录以便回滚（备份 CURRENT_ROOT）
    local OLD_BAK=""
    if [[ -d "$CURRENT_ROOT" ]]; then
        OLD_BAK="${CURRENT_ROOT}.bak-${BACKUP_SUFFIX}"
        mv "$CURRENT_ROOT" "$OLD_BAK"
        echo "🧩 已备份旧目录到 $OLD_BAK"
    fi
    mkdir -p "$CURRENT_ROOT"  # 占位，防止某些脚本依赖路径存在

    # 目录链权限：父目录至少 755；data-root 目录 711；所有权 root:root
    chmod 755 "$(dirname "$NEW_ROOT")" 2>/dev/null || true
    chmod 711 "$NEW_ROOT" 2>/dev/null || true
    chown -R root:root "$NEW_ROOT" 2>/dev/null || true

    # 备份并写回 daemon.json（显式设置 data-root + 日志轮转）
    mkdir -p "$(dirname "$DAEMON_JSON")"
    if [[ -f "$DAEMON_JSON" ]]; then
        cp -a "$DAEMON_JSON" "${DAEMON_JSON}.bak-${BACKUP_SUFFIX}"
        echo "🧩 已备份 $DAEMON_JSON 为 ${DAEMON_JSON}.bak-${BACKUP_SUFFIX}"
    fi
    tee "$DAEMON_JSON" >/dev/null <<EOF
{
  "data-root": "$NEW_ROOT",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "20m",
    "max-file": "3"
  }
}
EOF

    # 如果 systemd 里写死了 --data-root，则覆写为不带该参数（使用 daemon.json）
    if systemctl cat docker 2>/dev/null | grep -q -- "--data-root="; then
        mkdir -p /etc/systemd/system/docker.service.d
        tee /etc/systemd/system/docker.service.d/override.conf >/dev/null <<'OVR'
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd -H fd://
OVR
        echo "🧩 已写入 systemd override，移除 --data-root 覆盖"
    fi

    systemctl daemon-reload

    # 启动 docker（不启动 socket，直接启 service）
    systemctl start docker || { echo "❌ 启动 docker 失败，请查看：journalctl -u docker --no-pager -n 200"; goto_rollback=1; }

    # 校验根目录是否生效
    local ROOT_DIR
    ROOT_DIR="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
    if [[ "$ROOT_DIR" == "$NEW_ROOT" ]]; then
        echo "✅ 迁移成功：Docker Root Dir = $ROOT_DIR"
        if [[ -n "$OLD_BAK" ]]; then
            echo "🧹 如确认正常，可删除备份释放空间：rm -rf $OLD_BAK"
        fi
        return 0
    fi

    # 未生效则回滚
    echo "❌ 迁移校验失败：当前 Docker Root Dir = ${ROOT_DIR:-未知}"
    echo "↩️ 回滚到迁移前……"

    systemctl stop docker docker.socket >/dev/null 2>&1 || true

    # 恢复 daemon.json：回滚到 CURRENT_ROOT（迁移前）
    tee "$DAEMON_JSON" >/dev/null <<EOF
{
  "data-root": "$CURRENT_ROOT",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "20m",
    "max-file": "3"
  }
}
EOF

    # 恢复目录：移除占位，恢复备份
    rm -rf "$CURRENT_ROOT"
    if [[ -n "$OLD_BAK" && -d "$OLD_BAK" ]]; then
        mv "$OLD_BAK" "$CURRENT_ROOT"
        echo "🧩 已恢复旧目录：$CURRENT_ROOT"
    else
        echo "⚠️ 未找到旧目录备份（$OLD_BAK），请手动检查。"
    fi

    systemctl daemon-reload
    systemctl start docker >/dev/null 2>&1 || true
    echo "已回滚至迁移前状态。"
    return 1
}

# =====================
#  功能 71：优化 Docker 日志（设置轮转）
# =====================
optimize_docker_logs() {
    # 前置校验
    if [ -z "${BASH_VERSION:-}" ]; then exec /usr/bin/env bash "$0" "$@"; fi
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then echo "请以 root 权限运行（sudo bash $0）"; return 1; fi
    if ! command -v docker >/dev/null 2>&1; then
        echo "未检测到 Docker，请先安装 Docker。"
        return 1
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "未检测到 systemctl，无法重启 docker 服务。"
        return 1
    fi

    local DAEMON_JSON="/etc/docker/daemon.json"
    local BACKUP_SUFFIX; BACKUP_SUFFIX="$(date +%Y%m%d-%H%M%S)"
    local TMP="/tmp/daemon.json.$$"

    mkdir -p "$(dirname "$DAEMON_JSON")"

    # 备份
    if [[ -f "$DAEMON_JSON" ]]; then
        cp -a "$DAEMON_JSON" "${DAEMON_JSON}.bak-${BACKUP_SUFFIX}"
        echo "🧩 已备份 $DAEMON_JSON 为 ${DAEMON_JSON}.bak-${BACKUP_SUFFIX}"
    fi

    # 写入/合并配置：只保证 json-file + 轮转参数，不破坏 data-root 和其它键
    if command -v jq >/dev/null 2>&1; then
        if [[ -s "$DAEMON_JSON" ]] && jq '.' "$DAEMON_JSON" >/dev/null 2>&1; then
            # 文件存在且 JSON 正常 → 合并（保留其它键与现有 log-opts 其它字段）
            jq '
              .["log-driver"] = "json-file"
              | .["log-opts"] = (.["log-opts"] // {})
              | .["log-opts"]["max-size"] = "20m"
              | .["log-opts"]["max-file"] = "3"
            ' "$DAEMON_JSON" > "$TMP"
        else
            # 文件不存在/空/损坏 → 重写（尽力保留 data-root）
            local CURRENT_ROOT=""
            if [[ -s "$DAEMON_JSON" ]]; then
                CURRENT_ROOT="$(sed -n 's/.*"data-root"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$DAEMON_JSON" | head -n1)"
            fi
            if [[ -z "$CURRENT_ROOT" ]]; then
                CURRENT_ROOT="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
            fi
            if [[ -n "$CURRENT_ROOT" ]]; then
                cat > "$TMP" <<EOF
{
  "data-root": "$CURRENT_ROOT",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "20m",
    "max-file": "3"
  }
}
EOF
            else
                cat > "$TMP" <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "20m",
    "max-file": "3"
  }
}
EOF
            fi
        fi
        mv -f "$TMP" "$DAEMON_JSON"
    else
        # 没有 jq：尽力保留现有 data-root，再重写日志配置
        local CURRENT_ROOT=""
        if [[ -f "$DAEMON_JSON" ]]; then
            CURRENT_ROOT="$(sed -n 's/.*"data-root"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$DAEMON_JSON" | head -n1)"
        fi
        if [[ -z "$CURRENT_ROOT" ]]; then
            CURRENT_ROOT="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
        fi

        if [[ -n "$CURRENT_ROOT" ]]; then
            cat > "$DAEMON_JSON" <<EOF
{
  "data-root": "$CURRENT_ROOT",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "20m",
    "max-file": "3"
  }
}
EOF
        else
            cat > "$DAEMON_JSON" <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "20m",
    "max-file": "3"
  }
}
EOF
        fi
    fi

    # 使配置生效
    systemctl restart docker || { echo "❌ docker 重启失败，请查看：journalctl -u docker --no-pager -n 200"; return 1; }

    # 回显确认
    local ROOT_DIR LOG_DRIVER
    ROOT_DIR="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
    LOG_DRIVER="$(docker info --format '{{.LoggingDriver}}' 2>/dev/null || true)"
    echo "✅ Docker 日志轮转已启用（20m x 3），RootDir：${ROOT_DIR:-未知}，LogDriver：${LOG_DRIVER:-未知}"

    # 提示：Docker 轮转不等于 gzip 压缩（避免误判）
    local CID
    CID="$(docker ps -q 2>/dev/null | head -n1 || true)"
    if [[ -n "$CID" && -n "$ROOT_DIR" ]]; then
        echo "🔎 示例容器日志路径：$ROOT_DIR/containers/$CID/$CID-json.log（Docker 只轮转 .log/.log.1，不会自动生成 .gz）"
    fi
}

# ========== 主循环 ==========

install_dependencies
show_menu

while true; do
    read -p "请输入选项: " choice
    case $choice in
        0) show_menu ;;
        1) os_info ;;
        2) nic_info ;;
        3) disk_info ;;
        4) docker_info ;;
        5) format_disk ;;
        7) install_docker ;;
        8) create_macvlan_network ;;
        9) clean_macvlan_network ;;
        10) install_portainer ;;
        11) install_librespeed ;;
        14) install_adguardhome ;;
        19) install_mosdns ;;
        20) install_mihomo ;;
        21) install_ddnsgo ;;
        45) install_samba ;;
        70) migrate_docker_datadir ;;
        71) optimize_docker_logs ;;
        90) create_macvlan_bridge ;;
        91) clean_macvlan_bridge ;;
        97) install_watchtower ;;
        98) run_watchtower_once ;;
        99) echo "退出脚本。"; exit 0 ;;
        *) echo "无效选项，请重新输入。" ;;
    esac
done