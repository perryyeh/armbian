#!/bin/bash

# ========== 环境准备 ==========

function install_dependencies() {
    echo "🔧 检查并安装依赖..."

    # 定义依赖列表
    dependencies=(ipcalc curl jq git)

    for dep in "${dependencies[@]}"; do
        if ! dpkg -s $dep >/dev/null 2>&1; then
            echo "🔍 依赖 $dep 未安装，开始安装..."
            sudo apt-get update
            sudo apt-get install -y $dep
        else
            echo "✅ 依赖 $dep 已安装，跳过"
        fi
    done
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
    echo "10）安装portainer面板和watchtower自动更新"
    echo "11）安装librespeed测速"
    echo "14）安装adguardhome"
    echo "19）安装mosdns"
    echo "20）安装mihomo"
    echo "45）安装samba"
    echo "80）创建macvlan bridge"
    echo "88）强制使用watchtower更新一次镜像"
    echo "90）清理macvlan bridge"
    echo "91）清理macvlan"
    echo "99）退出"
    echo "============================"
}

# ========== 功能函数 ==========

function os_info() { cat /etc/os-release; }

function nic_info() { ip addr; }

function disk_info() { lsblk -o NAME,SIZE,FSTYPE,UUID,MOUNTPOINT; }

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


function install_portainer_watchtower() {
    read -p "即将安装watchtower，请输入存储目录(例如 /data/dockerapps): " dockerapps
    docker run -d -p 8000:8000 -p 9443:9443 --network=host --name=portainer --restart=always \
    -v /var/run/docker.sock:/var/run/docker.sock -v ${dockerapps}/portainer:/data portainer/portainer-ce:lts

    docker run -d --name=watchtower --restart=always -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower --cleanup
}

# ========== 工具函数 ==========
# 计算IP地址对应MAC地址
ip_to_mac() {
  IFS='.' read -r ip1 ip2 ip3 ip4 <<< "$1"
  printf '86:88:%02x:%02x:%02x:%02x\n' $ip1 $ip2 $ip3 $ip4
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
    local netmask=$(ip -4 addr show $iface | grep inet | awk '{print $2}' | cut -d'/' -f2)
    cidr=$(ipcalc -n $ip/$netmask | grep Network | awk '{print $2}')
  fi
  echo $cidr
}

# ========== 1. 创建 macvlan 网络 ==========
function create_macvlan_network() {
  echo "🔧 开始创建 macvlan 网络"

  # 列出所有网卡供用户选择（尽量选择物理口）
  interfaces=($(ls /sys/class/net))
  echo "请选择【物理】网卡："
  for i in "${!interfaces[@]}"; do
    ip4=$(ip -4 addr show ${interfaces[$i]} | grep -w inet | awk '{print $2}')
    ip6=$(ip -6 addr show ${interfaces[$i]} | grep -w inet6 | grep fd | awk '{print $2}')
    echo "$i) ${interfaces[$i]}  IPv4: ${ip4:-无}  IPv6: ${ip6:-无}"
  done

  read -p "输入网卡序号: " netcard_index
  networkcard=${interfaces[$netcard_index]}
  echo "选择的网卡: $networkcard"

  # ========= VLAN 处理 =========
  vlan_id=""
  if [[ "$networkcard" != *.* ]]; then
    read -p "是否为 macvlan 使用 VLAN ID？直接回车表示不使用，输入 VLAN ID（例如 88）: " vlan_id
    if [ -n "$vlan_id" ]; then
      vlan_iface="${networkcard}.${vlan_id}"
      echo "🔧 将使用带 VLAN 的接口: $vlan_iface (parent: $networkcard, VLAN ID: $vlan_id)"

      if ! ip link show "$vlan_iface" >/dev/null 2>&1; then
        sudo ip link add link "$networkcard" name "$vlan_iface" type vlan id "$vlan_id"
      fi
      sudo ip link set "$vlan_iface" up

      networkcard="$vlan_iface"
    fi
  else
    # 用户直接选的是 eth0.8 这种
    vlan_suffix="${networkcard#*.}"
    if [[ "$vlan_suffix" =~ ^[0-9]+$ ]]; then
      vlan_id="$vlan_suffix"
    fi
    echo "ℹ️ 检测到带 VLAN 的接口: $networkcard (推测 VLAN ID: ${vlan_id:-未知})"
  fi
  # ========= VLAN 处理结束 =========

  # ========= IPv4：先网关，再算 CIDR & range =========
  ip=$(ip -4 addr show "$networkcard" | grep -w inet | head -n1 | awk '{print $2}' | cut -d'/' -f1)

  suggest_gateway=""
  suggest_prefixlen=""

  if [ -n "$ip" ]; then
    # 接口本身有 IP，直接用它的网关/前缀
    cidr_from_iface=$(get_subnet_v4 "$ip" "$networkcard")
    gw_from_iface=$(ip route | grep "^default" | grep "dev $networkcard" | awk '{print $3}')
    suggest_gateway="$gw_from_iface"
    suggest_prefixlen="${cidr_from_iface#*/}"  # 例如 23 / 24
  else
    echo "⚠️ 未在接口 $networkcard 上检测到 IPv4 地址（VLAN 接口通常没有 IP）"

    parent_iface=${networkcard%%.*}
    parent_ip=$(ip -4 addr show "$parent_iface" | grep -w inet | head -n1 | awk '{print $2}' | cut -d'/' -f1)

    if [ -n "$parent_ip" ]; then
      parent_cidr=$(get_subnet_v4 "$parent_ip" "$parent_iface")
      parent_net=${parent_cidr%/*}
      parent_mask=${parent_cidr#*/}

      IFS='.' read -r p1 p2 p3 p4 <<< "$parent_net"

      # 策略：沿用前两段，第三段用 VLAN ID（没有 VLAN 就用原来的）
      if [ -n "$vlan_id" ]; then
        third_octet=$vlan_id
      else
        third_octet=$p3
      fi

      suggest_gateway="${p1}.${p2}.${third_octet}.1"
      # VLAN 场景默认 /24；无 VLAN 就沿用原掩码
      if [ -n "$vlan_id" ]; then
        suggest_prefixlen="24"
      else
        suggest_prefixlen="$parent_mask"
      fi

      echo "👉 已根据 trunk 接口 $parent_iface 推算推荐 IPv4 网关：$suggest_gateway"
      echo "👉 推荐前缀长度：/$suggest_prefixlen"
    else
      echo "❌ trunk 接口 $parent_iface 也没有 IPv4，无法推算，需要手动输入网关和网段。"
    fi
  fi

  # 先确认 / 覆盖 IPv4 网关
  if [ -n "$suggest_gateway" ]; then
    read -p "请输入 IPv4 网关 (回车使用推荐 $suggest_gateway): " input_gateway
    if [ -n "$input_gateway" ]; then
      gateway="$input_gateway"
    else
      gateway="$suggest_gateway"
    fi
  else
    read -p "请输入 IPv4 网关 (例如 10.88.0.1): " gateway
  fi

  if [ -z "$gateway" ]; then
    echo "❌ IPv4 网关不能为空。"
    return 1
  fi

  # 根据网关自动推算子网 CIDR（默认网关所在网段 .0/前缀）
  gw_net_ip="${gateway%.*}.0"
  prefixlen="${suggest_prefixlen:-24}"
  auto_cidr="${gw_net_ip}/${prefixlen}"

  echo "👉 已根据网关 $gateway 自动推算 IPv4 子网：$auto_cidr"

  # 用户可再覆盖 IPv4 子网
  read -p "请输入 macvlan IPv4 子网CIDR (回车使用推荐 $auto_cidr): " input_cidr
  if [ -n "$input_cidr" ]; then
    cidr="$input_cidr"
  else
    cidr="$auto_cidr"
  fi

  # IPv4 range 默认等于子网
  read -p "请输入 macvlan IPv4 range, 回车使用 $cidr: " iprange
  [ -z "$iprange" ] && iprange=$cidr
  iprangev4=$(echo "$iprange" | cut -d'/' -f1)
  subnet4=$(echo "$iprange" | cut -d'/' -f2)

  # ========= IPv6：同样先网关，再算 CIDR & range =========
  suggest_gateway6=""
  suggest_cidr6=""

  # 优先从接口现有 IPv6 计算
  ip6_info=$(ip -6 addr show "$networkcard" | grep -w inet6 | grep fd | head -n1 || true)
  if [ -n "$ip6_info" ]; then
    ip6_cidr=$(echo "$ip6_info" | awk '{print $2}')
    ip6=$(echo "$ip6_cidr" | cut -d'/' -f1)
    prefix_len6=$(echo "$ip6_cidr" | cut -d'/' -f2)
    ip6_prefix=$(echo "$ip6" | cut -d':' -f1-4)
    suggest_cidr6="${ip6_prefix}::/${prefix_len6}"
    suggest_gateway6="${ip6_prefix}::1"
  else
    # 没有现成 IPv6，就按你的原逻辑，用 IPv4 网关推一个 ULA 前缀（fdxx:...）
    if [ -n "$gateway" ]; then
      prefix6=$(ipv4_to_ipv6_prefix "$gateway")
      suggest_cidr6="${prefix6}::/64"
      suggest_gateway6="${prefix6}::1"
    fi
  fi

  # 先让用户确认 / 覆盖 IPv6 网关
  if [ -n "$suggest_gateway6" ]; then
    echo "检测到/推算 IPv6 Gateway: $suggest_gateway6"
    read -p "请输入 IPv6 网关 (回车使用推荐 $suggest_gateway6，留空表示不启用IPv6): " input_gateway6
    if [ -n "$input_gateway6" ]; then
      gateway6="$input_gateway6"
    else
      gateway6="$suggest_gateway6"
    fi
  else
    read -p "请输入 IPv6 网关 (例如 fd10:86:28::1，留空表示不启用IPv6): " gateway6
  fi

  # 如果用户留空 IPv6 网关，则不配置 IPv6
  if [ -z "$gateway6" ]; then
    cidr6=""
    iprange6=""
    subnet6=""
    iprangev6_prefix=""
  else
    # 基于当前网关6和已有前缀建议，推一个 CIDR
    if [ -n "$suggest_cidr6" ]; then
      auto_cidr6="$suggest_cidr6"
    else
      # 没有任何前缀建议时，简单取 IPv4 对应前缀 + /64
      prefix6=$(ipv4_to_ipv6_prefix "$gateway")
      auto_cidr6="${prefix6}::/64"
    fi

    echo "👉 已根据 IPv6 网关 $gateway6 自动/推算 IPv6 子网：$auto_cidr6"
    read -p "请输入 IPv6 子网CIDR (回车使用推荐 $auto_cidr6): " input_cidr6
    if [ -n "$input_cidr6" ]; then
      cidr6="$input_cidr6"
    else
      cidr6="$auto_cidr6"
    fi

    read -p "请输入 macvlan IPv6 range, 回车使用 $cidr6: " iprange6
    [ -z "$iprange6" ] && iprange6=$cidr6
    subnet6=$(echo "$iprange6" | cut -d'/' -f2)
    iprangev6_prefix=$(echo "$iprange6" | cut -d'/' -f1)
    iprangev6_prefix=$(echo "$iprangev6_prefix" | rev | cut -d':' -f2- | rev):
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

  read -p "是否正确？(y/n): " confirm
  if [ "$confirm" != "y" ]; then
    echo "退出 macvlan 创建。"
    return 1
  fi

  # 根据 VLAN 决定 docker network 名称
  if [ -n "$vlan_id" ]; then
    network_name="macvlan_${vlan_id}"
  else
    network_name="macvlan"
  fi

  # 启用 promiscuous mode
  sudo ip link set "$networkcard" promisc on

  # 创建 docker macvlan 网络
  echo "🔨 正在创建 docker macvlan 网络：$network_name ..."
  if [ -n "$gateway6" ] && [ -n "$cidr6" ]; then
    docker network create -d macvlan \
      --subnet="$cidr" --ip-range="$iprange" --gateway="$gateway" \
      --ipv6 --subnet="$cidr6" --gateway="$gateway6" \
      -o parent="$networkcard" "$network_name"
  else
    docker network create -d macvlan \
      --subnet="$cidr" --ip-range="$iprange" --gateway="$gateway" \
      -o parent="$networkcard" "$network_name"
  fi

  echo "✅ macvlan 网络创建完成：$network_name"
}

# ========== 2. 配置 macvlan bridge 与 systemd ==========
function create_macvlan_bridge() {

  echo "🔧 配置 macvlan bridge 互通（支持多网段多 bridge 共存）"

  echo "可用的 macvlan 网络："
  docker network ls --format '{{.Name}}' | grep '^macvlan' || echo "  （当前没有名称包含 macvlan 的网络，请先创建）"

  read -p "请输入要配置 bridge 的 macvlan 网络名 (默认 macvlan): " macvlan_name
  macvlan_name=${macvlan_name:-macvlan}

  # 读取 docker network 配置
  network_info=$(docker network inspect "$macvlan_name" 2>/dev/null)
  if [ -z "$network_info" ] || [ "$network_info" = "[]" ]; then
    echo "❌ 未检测到 docker 网络 $macvlan_name，请确认名称是否正确。"
    return 1
  fi

  # 从 docker network 中解析 parent 接口（可能是 eth0 或 eth0.88 等）
  parent_from_docker=$(echo "$network_info" | jq -r '.[0].Options.parent // empty')
  if [ -n "$parent_from_docker" ] && [ "$parent_from_docker" != "null" ]; then
    networkcard="$parent_from_docker"
    echo "✅ 从 docker 网络中检测到 parent 接口: $networkcard"
  else
    # 兜底：让用户手动选择
    echo "🔍 未在 docker 配置中找到 parent，请手动选择网卡："
    interfaces=($(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo\|docker\|veth'))
    for i in "${!interfaces[@]}"; do
      echo "$i) ${interfaces[$i]}"
    done
    read -p "请输入网卡编号: " choice
    networkcard=${interfaces[$choice]}
    echo "✅ 已选择网卡: $networkcard"
  fi

  # 解析 IPv4 网段（优先 IPRange，其次 Subnet）
  iprange=$(echo "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Subnet | test(":") | not) | .IPRange // empty')
  if [ -z "$iprange" ] || [ "$iprange" = "null" ]; then
    iprange=$(echo "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Subnet | test(":") | not) | .Subnet')
  fi

  # 解析 IPv6 网段
  iprange6=$(echo "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Subnet | test(":")) | .Subnet')

  iprangev4=$(echo "$iprange" | cut -d'/' -f1)
  subnet4=$(echo "$iprange" | cut -d'/' -f2)

  iprangev6_prefix=$(echo "$iprange6" | cut -d'/' -f1)
  subnet6=$(echo "$iprange6" | cut -d'/' -f2)
  iprangev6_prefix=$(echo "$iprangev6_prefix" | rev | cut -d':' -f2- | rev):

  if [ -z "$iprangev4" ] || [ -z "$iprangev6_prefix" ]; then
    echo "❌ 无法从 $macvlan_name 中解析到 IPv4/IPv6 网段，请确认网络配置。"
    return 1
  fi

  echo "使用 macvlan 网络: $macvlan_name"
  echo " Parent 接口 : $networkcard"
  echo " IPv4 range  : $iprangev4/$subnet4"
  echo " IPv6 prefix : $iprangev6_prefix/$subnet6"

  # 计算 mihomo IP（保持你原来的 120 号规则，用于 198.18/15 的路由）
  calculate_ip_mac 120
  mihomo=$calculated_ip

  echo "🔧 正在为 $macvlan_name 配置独立的 macvlan bridge"

  # 每个 macvlan 网络有自己独立的 bridge / 脚本 / service
  # 1) 生成安全的名字（把非字母数字变成下划线）
  safe_name=$(echo "$macvlan_name" | sed 's/[^0-9A-Za-z]/_/g')

  # 2) bridge 接口名（注意 Linux 接口名 <=15 字符，这里简单截断一下）
  bridge_if_raw="mvbr_${safe_name}"
  bridge_if=${bridge_if_raw:0:15}

  # 3) 脚本和 service 名称
  setup_script="/usr/local/bin/macvlan-${safe_name}.sh"
  service_name="macvlan-${safe_name}.service"

  echo " Bridge 接口 : $bridge_if"
  echo " Setup 脚本  : $setup_script"
  echo " Systemd 服务: $service_name"

  # 计算 bridge IPv4 / IPv6 地址
  bridge="${iprangev4%.*}.254"
  ipv4_fourth=$(echo "$bridge" | cut -d'.' -f4)
  bridge6="${iprangev6_prefix}${ipv4_fourth}"
  bridge_mac=$(ip_to_mac "$bridge")

  echo " Bridge IPv4 : $bridge/$subnet4"
  echo " Bridge IPv6 : $bridge6/$subnet6"

  # 生成针对当前 macvlan 网络的专属 setup 脚本
  cat <<EOF | sudo tee "$setup_script"
#!/bin/bash
ip link del $bridge_if 2>/dev/null
ip link add $bridge_if link $networkcard type macvlan mode bridge
ip addr add $bridge/$subnet4 dev $bridge_if
ip -6 addr add $bridge6/$subnet6 dev $bridge_if
ip link set $bridge_if up
ip link set $bridge_if promisc on
ip route replace $iprange dev $bridge_if
ip -6 route replace $iprange6 dev $bridge_if
ip route add 198.18.0.0/15 via $mihomo dev $bridge_if
EOF

  sudo chmod +x "$setup_script"

  # 为当前 macvlan 网络生成独立的 systemd 服务
  cat <<EOF | sudo tee "/etc/systemd/system/${service_name}"
[Unit]
Description=Setup macvlan bridge for ${macvlan_name}
After=network.target

[Service]
Type=oneshot
ExecStart=${setup_script}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable "${service_name}"
  sudo systemctl start "${service_name}"

  echo "✅ 已为 $macvlan_name 创建/启动独立的 bridge：$bridge_if"
  echo "   - 脚本 : $setup_script"
  echo "   - 服务 : $service_name"
  echo "   - IPv4 : $bridge/$subnet4"
  echo "   - IPv6 : $bridge6/$subnet6"
}

install_mihomo() {
    calculate_ip_mac 120
    mihomo=$calculated_ip
    mihomo6=$calculated_ip6
    mihomomac=$calculated_mac
    gateway=$calculated_gateway

    read -p "即将安装mihomo，请输入存储目录(例如 /data/dockerapps): " dockerapps
    cd ${dockerapps}

    # 删除旧目录
    if [ -d "${dockerapps}/mihomo" ]; then
      echo "⚠️ 检测到 ${dockerapps}/mihomo 已存在，正在删除..."
      rm -rf ${dockerapps}/mihomo
    fi

    # 拉取配置仓库
    git clone https://github.com/perryyeh/mihomo.git

    cd ${dockerapps}/mihomo

    # 替换 config.yaml 里的网关
    sed -i "s/10.0.0.1/$gateway/g" config.yaml

    # 生成 .env 文件供 docker compose 使用
    cat > .env <<EOF
mihomo4=${mihomo}
mihomo6=${mihomo6}
mihomomac=${mihomomac}
dockerapps=${dockerapps}
EOF

    echo "✅ 已生成 .env 文件："
    cat .env
    echo

    # 检查 docker-compose.yml
    if [ ! -f docker-compose.yml ]; then
      echo "❌ 未找到 docker-compose.yml，请确认仓库中已包含该文件"
      return 1
    fi

    # 启动容器
    docker compose up -d

    echo "mihomo 已启动！访问地址：http://$mihomo:9090/ui/  密码：admin"
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
    base_v4_prefix="${subnet4_ip%.*}"   # 例如 10.86.28
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

function install_mosdns() {

    calculate_ip_mac 120
    mihomo=$calculated_ip

    calculate_ip_mac 119
    mosdns=$calculated_ip
    mosdns6=$calculated_ip6
    mosdnsmac=$calculated_mac
    gateway=$calculated_gateway

    read -p "即将安装mosdns，请输入存储目录(例如 /data/dockerapps): " dockerapps
    cd ${dockerapps}

    # 如果 mihomo 目录已存在则先删除
    if [ -d "${dockerapps}/mosdns" ]; then
      echo "⚠️ 检测到 ${dockerapps}/mosdns 已存在，正在删除..."
      rm -rf ${dockerapps}/mosdns
    fi

    git clone https://github.com/perryyeh/mosdns.git
    sed -i "s/198.18.0.2/$mihomo/g" ${dockerapps}/mosdns/config.yaml
    sed -i "s/10.0.0.1/$gateway/g" ${dockerapps}/mosdns/config.yaml

    docker run -d --name=mosdns --hostname=mosdns --restart=always --network=macvlan \
    --ip=${mosdns} --ip6=${mosdns6} --mac-address=${mosdnsmac} \
    -v ${dockerapps}/mosdns:/etc/mosdns irinesistiana/mosdns
}

function install_adguardhome() {

    calculate_ip_mac 119
    mosdns=$calculated_ip
    mosdns6=$calculated_ip6

    calculate_ip_mac 114
    adguard=$calculated_ip
    adguard6=$calculated_ip6
    adguardmac=$calculated_mac
    gateway=$calculated_gateway

    read -p "即将安装adguardhome，请输入存储目录(例如 /data/dockerapps): " dockerapps
    cd ${dockerapps}


    # 如果 mihomo 目录已存在则先删除
    if [ -d "${dockerapps}/adguardhome" ]; then
      echo "⚠️ 检测到 ${dockerapps}/adguardhome 已存在，正在删除..."
      rm -rf ${dockerapps}/adguardhome
    fi

    # 生成adguard work目录
    mkdir -p adguardwork

    git clone https://github.com/perryyeh/adguardhome.git


    # 等待文件生成，最多等 10 秒
    for i in {1..30}; do
        if [ -f "${dockerapps}/adguardhome/AdGuardHome.yaml" ]; then
            echo "✅ 配置文件已生成，开始修改..."
            break
        else
            echo "⏳ 等待配置文件生成中 ($i/10)..."
            sleep 1
        fi
    done

    # 再次检查并 sed
    if [ -f "${dockerapps}/adguardhome/AdGuardHome.yaml" ]; then
        sed -i "s/10.0.1.119/$mosdns/g;" ${dockerapps}/adguardhome/AdGuardHome.yaml
        sed -i "s/fd10:00:00::1:119/$mosdns6/g;" ${dockerapps}/adguardhome/AdGuardHome.yaml
        sed -i "s/10.0.0.1/$gateway/g" ${dockerapps}/adguardhome/AdGuardHome.yaml
    else
        echo "❌ 配置文件跳过sed替换，请自行更改AdGuardHome.yaml中mosdns和gateway配置"
    fi

    docker run -d --name=adguardhome --hostname=adguardhome --restart=always --network=macvlan \
    --ip=${adguard} --ip6=${adguard6} --mac-address=${adguardmac} \
    -v ${dockerapps}/adguardwork:/opt/adguardhome/work \
    -v ${dockerapps}/adguardhome:/opt/adguardhome/conf \
    adguard/adguardhome

    echo "adguardhome 访问地址：http://$adguard  用户名admin 密码admin"
}


function install_librespeed() {
    calculate_ip_mac 111
    librespeed=$calculated_ip
    librespeed6=$calculated_ip6
    librespeedmac=$calculated_mac

    docker run -d --name=librespeed --hostname=librespeed --restart=always --network=macvlan \
    --ip=${librespeed} --ip6=${librespeed6} --mac-address=${librespeedmac} \
    linuxserver/librespeed:latest

    echo "librespeed 访问地址：http://$librespeed"
}

function calculate_ip_mac() {

  local last_octet=$1

  if [[ ! "$last_octet" =~ ^[0-9]+$ ]]; then
    echo "❌ calculate_ip_mac 输入无效: $last_octet"
    return 1
  fi


  # 1. 获取 docker macvlan 网络配置
  network_info=$(docker network inspect macvlan)

  iprange=$(echo "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Subnet | test(":") | not) | .IPRange')
  iprange6=$(echo "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Subnet | test(":")) | .Subnet')

  gateway=$(echo "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Gateway | test(":") | not) | .Gateway')
  gateway6=$(echo "$network_info" | jq -r '.[0].IPAM.Config[] | select(.Gateway | test(":")) | .Gateway')

  iprangev4=$(echo $iprange | cut -d'/' -f1)
  iprangev6_prefix=$(echo $iprange6 | cut -d'/' -f1)

  # 2. 计算 IPv4
  ip="${iprangev4%.*}.$last_octet"

  # 3. 计算 IPv6
  if [ -n "$iprangev6_prefix" ]; then
    ipv4_third=$(echo $ip | cut -d'.' -f3)
    ipv4_fourth=$(echo $ip | cut -d'.' -f4)
    if [[ "$iprangev6_prefix" == *"::" ]]; then
      ip6="${iprangev6_prefix}${ipv4_third}:${ipv4_fourth}"
    else
      ip6="${iprangev6_prefix}::${ipv4_third}:${ipv4_fourth}"
    fi
  else
    ip6=""
  fi

  # 4. MAC 生成
  mac=$(ip_to_mac $ip)

  # 5. 输出
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


# ========== 删除 docker macvlan 网络 ==========
function clean_macvlan_network() {
  echo "🧹 正在删除 docker macvlan 网络配置..."

  # 删除 docker macvlan 网络
  docker network rm macvlan 2>/dev/null

  # 删除 docker daemon ipv6 配置（如存在）
  if [ -f /etc/docker/daemon.json ]; then
    sudo rm /etc/docker/daemon.json
    sudo systemctl restart docker
    echo "✅ 已删除 /etc/docker/daemon.json 并重启 docker"
  fi

  # 清理 IPv6 路由中 fd10 / fd17 / fd19 前缀
  for prefix in fd10 fd17 fd19; do
    ip -6 route | grep "^$prefix" | awk '{print $1}' | while read route; do
      sudo ip -6 route del $route
      echo "🗑️ 已删除 IPv6 路由: $route"
    done
  done

  echo "✅ docker macvlan 网络清理完成"
}

# ========== 删除 macvlan bridge 配置 ==========
function clean_macvlan_bridge() {
  echo "🧹 正在删除 macvlan bridge 配置..."

  # 删除 macvlan bridge 网络接口
  sudo ip link del macvlan-bridge 2>/dev/null

  # 停止并禁用 systemd 服务
  sudo systemctl stop macvlan.service
  sudo systemctl disable macvlan.service

  # 删除 systemd 服务文件
  sudo rm /etc/systemd/system/macvlan.service

  # 删除 macvlan-setup.sh 脚本
  sudo rm /usr/local/bin/macvlan-setup.sh

  # 重载 systemd
  sudo systemctl daemon-reload

  echo "✅ macvlan bridge 配置已删除"
}

function run_watchtower_once() {
    echo "🔧 正在执行 watchtower --run-once 更新所有容器..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower --run-once
    echo "✅ watchtower 更新完成"
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
        10) install_portainer_watchtower ;;
        11) install_librespeed ;;
        14) install_adguardhome ;;
        19) install_mosdns ;;
        20) install_mihomo ;;
        45) install_samba ;;
        80) create_macvlan_bridge ;;
        88) run_watchtower_once ;;
        90) clean_macvlan_bridge ;;
        91) clean_macvlan_network ;;
        99) echo "退出脚本。"; exit 0 ;;
        *) echo "无效选项，请重新输入。" ;;
    esac
done
