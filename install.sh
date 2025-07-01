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
    echo "8）开启ipv6并创建macvlan"
    echo "9）清理macvlan和macvlan bridge"
    echo "10）安装portainer面板和watchtower自动更新"
    echo "11）安装librespeed测速"
    echo "14）安装adguardhome"
    echo "19）安装mosdns"
    echo "20）安装mihomo"
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
    if [[ "$ID" == "debian" ]]; then
        sudo apt-get update
        sudo apt-get install -y ca-certificates curl
        sudo install -m 0755 -d /etc/apt/keyrings
        sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
        sudo chmod a+r /etc/apt/keyrings/docker.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        sudo apt-get update
    elif [[ "$ID" == "ubuntu" ]]; then
        sudo apt-get update
        sudo apt-get install -y ca-certificates curl
        sudo install -m 0755 -d /etc/apt/keyrings
        sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
        sudo chmod a+r /etc/apt/keyrings/docker.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME:-$VERSION_CODENAME} stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        sudo apt-get update
    fi
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

function create_macvlan() {
  echo "开启ipv6并创建macvlan"

  # ========== 工具函数 ==========
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

  ip_to_mac() {
    IFS='.' read -r ip1 ip2 ip3 ip4 <<< "$1"
    printf '86:88:%02x:%02x:%02x:%02x\n' $ip1 $ip2 $ip3 $ip4
  }

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

  # ========== 1. 显示网卡列表 ==========
  interfaces=($(ls /sys/class/net))
  echo "请选择网卡："
  for i in "${!interfaces[@]}"; do
    ip4=$(ip -4 addr show ${interfaces[$i]} | grep -w inet | awk '{print $2}')
    ip6=$(ip -6 addr show ${interfaces[$i]} | grep -w inet6 | grep fd | awk '{print $2}')
    echo "$i) ${interfaces[$i]}  IPv4: ${ip4:-无}  IPv6: ${ip6:-无}"
  done

  # ========== 2. 用户选择 ==========
  read -p "输入网卡序号: " netcard_index
  networkcard=${interfaces[$netcard_index]}
  echo "选择的网卡: $networkcard"

  # ========== 3. 获取 IPv4 ==========
  ip=$(ip -4 addr show $networkcard | grep -w inet | head -n1 | awk '{print $2}' | cut -d'/' -f1)
  cidr=$(get_subnet_v4 $ip $networkcard)
  gateway=$(ip route | grep "^default" | grep "dev $networkcard" | awk '{print $3}')

  echo "下面开始配置macvlan的gateway/subnet/iprange，例子："
  echo "          ipv4             ipv6"
  echo "gateway   10.88.100.1      fd10:88:100::1"
  echo "subnet    10.88.100.0/23   fd10:88:100::/64"
  echo "iprange   10.88.101.0/24   fd10:88:100::11:0/112"

  echo "检测到 IPv4 Gateway: $gateway"
  read -p "按回车确认，输入其他以修改: " input_gateway
  [ -n "$input_gateway" ] && gateway=$input_gateway

  echo "检测到 IPv4 Subnet: $cidr"
  read -p "按回车确认，输入其他以修改: " input_cidr
  [ -n "$input_cidr" ] && cidr=$input_cidr

  read -p "请输入 macvlan IPv4 range, 回车使用 $cidr: " iprange
  [ -z "$iprange" ] && iprange=$cidr
  iprangev4=$(echo $iprange | cut -d'/' -f1)
  subnet4=$(echo $iprange | cut -d'/' -f2)

  # ========== 4. 获取 IPv6 ==========
  ip6_info=$(ip -6 addr show $networkcard | grep -w inet6 | grep fd | head -n1)
  if [ -n "$ip6_info" ]; then
    ip6_cidr=$(echo $ip6_info | awk '{print $2}')
    ip6=$(echo $ip6_cidr | cut -d'/' -f1)
    subnet_prefix=$(echo $ip6_cidr | cut -d'/' -f2)
    cidr6=$(echo $ip6 | cut -d':' -f1-4)::/$subnet_prefix
    gateway6=$(echo $ip6 | cut -d':' -f1-4)::1
  else
    ip6=""
    gateway6=$(ipv4_to_ipv6_prefix $gateway)::1
    cidr6=$(ipv4_to_ipv6_prefix $gateway)::/64
  fi

  echo "检测到 IPv6 Gateway: $gateway6"
  read -p "按回车确认，输入其他以修改: " input_gateway6
  [ -n "$input_gateway6" ] && gateway6=$input_gateway6

  echo "检测到 IPv6 Subnet: $cidr6"
  read -p "按回车确认，输入其他以修改: " input_cidr6
  [ -n "$input_cidr6" ] && cidr6=$input_cidr6

  read -p "请输入 macvlan IPv6 range: " iprange6
  subnet6=$(echo $iprange6 | cut -d'/' -f2)
  iprangev6_prefix=$(echo $iprange6 | cut -d'/' -f1)
  iprangev6_prefix=$(echo $iprangev6_prefix | rev | cut -d':' -f2- | rev):

  # ========== 5. 计算 bridge 和 mihomo ==========
  bridge="${iprangev4%.*}.254"
  mihomo="${iprangev4%.*}.120"

  ipv4_fourth=$(echo $bridge | cut -d'.' -f4)
  bridge6="${iprangev6_prefix}${ipv4_fourth}"

  bridgemac=$(ip_to_mac $bridge)

  # ========== 6. 输出变量 ==========
  echo "macvlan参数确认："
  echo "host ip：$ip $ip6"
  echo "gateway：$gateway $gateway6"
  echo "subnet：$cidr $cidr6"
  echo "subnet4：$subnet4"
  echo "subnet6：$subnet6"
  echo "iprange：$iprange $iprange6"
  echo "bridge：$bridge $bridge6    MAC: $bridgemac"

  read -p "是否正确？(y/n): " confirm
  if [ "$confirm" != "y" ]; then
    echo "退出macvlan创建。"
    return 1
  fi

  # ========== 7. daemon.json ========== 此段不能用，有冲突
  # if [ ! -s /etc/docker/daemon.json ]; then
  #   echo "{\"ipv6\": true, \"fixed-cidr-v6\": \"$iprange6\"}" | sudo tee /etc/docker/daemon.json
  # else
  #   sudo jq '. + {"ipv6":true,"fixed-cidr-v6":"'"$iprange6"'"}' /etc/docker/daemon.json > tmp.json && sudo mv tmp.json /etc/docker/daemon.json
  # fi
  # sudo systemctl restart docker

  # ========== 8. 创建 macvlan ==========
  echo "docker network create -d macvlan --subnet=\"$cidr\" --ip-range=\"$iprange\" --gateway=\"$gateway\" --ipv6 --subnet=\"$cidr6\" --gateway=\"$gateway6\" -o parent=\"$networkcard\" macvlan"
  docker network create -d macvlan --subnet=$cidr --ip-range=$iprange --gateway=$gateway --ipv6 --subnet=$cidr6 --gateway=$gateway6 -o parent=$networkcard macvlan

  # ========== 9. macvlan 互通 ==========
  cat <<EOF | sudo tee /usr/local/bin/macvlan-setup.sh
#!/bin/bash
ip link del macvlan-bridge 2>/dev/null
ip link add macvlan-bridge link $networkcard type macvlan mode bridge
ip addr add $bridge/$subnet4 dev macvlan-bridge
ip -6 addr add $bridge6/$subnet6 dev macvlan-bridge
ip link set macvlan-bridge up
ip link set macvlan-bridge promisc on
ip route replace $iprange dev macvlan-bridge
ip -6 route replace $iprange6 dev macvlan-bridge
ip route add 198.18.0.0/15 via $mihomo dev macvlan-bridge
EOF

  chmod +x /usr/local/bin/macvlan-setup.sh

  # ========== 10. systemd ==========
  cat <<EOF | sudo tee /etc/systemd/system/macvlan.service
[Unit]
Description=Setup macvlan interface
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/macvlan-setup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable macvlan.service
  sudo systemctl start macvlan.service
  sudo systemctl status macvlan.service
}

function install_mihomo() {
    calculate_ip_mac 120
    mihomo=$calculated_ip
    mihomo6=$calculated_ip6
    mihomomac=$calculated_mac
    gateway=$calculated_gateway

    read -p "即将安装mihomo，请输入存储目录(例如 /data/dockerapps): " dockerapps
    cd ${dockerapps}

    # 如果 mihomo 目录已存在则先删除
    if [ -d "${dockerapps}/mihomo" ]; then
      echo "⚠️ 检测到 ${dockerapps}/mihomo 已存在，正在删除..."
      rm -rf ${dockerapps}/mihomo
    fi

    git clone https://github.com/perryyeh/mihomo.git
    sed -i "s/10.0.0.1/$gateway/g" ${dockerapps}/mihomo/config.yaml

    docker run -d --name=mihomo --hostname=mihomo --restart=always --network=macvlan \
    --ip=${mihomo} --ip6=${mihomo6} --mac-address=${mihomomac} \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.default.disable_ipv6=0 \
    --device=/dev/net/tun --cap-add=NET_ADMIN \
    -v ${dockerapps}/mihomo:/root/.config/mihomo metacubex/mihomo

    echo "mihomo 访问地址：http://$mihomo:9090/ui/"
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

    echo "adguardhome 访问地址：http://$adguard"
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
  ip_to_mac() {
    IFS='.' read -r ip1 ip2 ip3 ip4 <<< "$1"
    printf '86:88:%02x:%02x:%02x:%02x\n' $ip1 $ip2 $ip3 $ip4
  }
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


function clean_macvlan() {
    echo "正在清理macvlan bridge 和 docker macvlan网络..."
    sudo ip link del macvlan-bridge 2>/dev/null
    sudo systemctl stop macvlan.service
    sudo systemctl disable macvlan.service
    sudo rm /etc/systemd/system/macvlan.service
    docker network rm macvlan
    sudo rm /usr/local/bin/macvlan-setup.sh
    sudo systemctl daemon-reload
    sudo rm /etc/docker/daemon.json
    sudo systemctl restart docker
    # 清理路由
    for prefix in fd10 fd17 fd19; do
        ip -6 route | grep "^$prefix" | awk '{print $1}' | while read route; do
            sudo ip -6 route del $route
        done
    done

    echo "macvlan 和 macvlan bridge 已清理完成。"
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
        8) create_macvlan ;;
        9) clean_macvlan ;;
        10) install_portainer_watchtower ;;
        11) install_librespeed ;;
        14) install_adguardhome ;;
        19) install_mosdns ;;
        20) install_mihomo ;;
        99) echo "退出脚本。"; exit 0 ;;
        *) echo "无效选项，请重新输入。" ;;
    esac
done
