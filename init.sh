#!/bin/bash

set -e

while true; do
    echo "=== 获取宿主机网卡及 IPv4 信息 ==="
    interfaces=()
    mapfile -t raw < <(ip -4 -o addr show | grep -v ' lo ')

    i=1
    for line in "${raw[@]}"; do
        iface=$(echo "$line" | awk '{print $2}')
        ipaddr=$(echo "$line" | awk '{print $4}')
        mask=$(ip -o -f inet addr show "$iface" | awk '{print $4}' | cut -d/ -f2)
        interfaces+=("$iface|$ipaddr|$mask")
        echo "$i) 接口: $iface, IP: ${ipaddr%%/*}, 子网掩码: $mask"
        ((i++))
    done

    read -p "请输入要使用的网卡编号: " choice
    selected_line=${interfaces[$((choice-1))]}

    if [[ -n "$selected_line" ]]; then
        networkcard=$(echo "$selected_line" | cut -d'|' -f1)
        ip=$(echo "$selected_line" | cut -d'|' -f2 | cut -d/ -f1)
        mask=$(echo "$selected_line" | cut -d'|' -f3)

        gateway=$(ip route | grep default | grep "$networkcard" | awk '{print $3}')
        subnet=$(ipcalc -n "$ip"/"$mask" | grep Network | awk '{print $2}')

        echo "检测到："
        echo "IP地址：$ip"
        echo "网关：$gateway"
        echo "子网掩码：$subnet"
        read -p "是否正确？(y/n): " confirm

        if [[ "$confirm" == "y" ]]; then
            break
        fi
    else
        echo "无效的选择，请重试。"
    fi
done

echo "=== 第4步：创建 macvlan 网络 ==="
docker network rm macvlan >/dev/null 2>&1 || true
docker network create -d macvlan \
  --subnet="$subnet" \
  --ip-range="$subnet" \
  --gateway="$gateway" \
  --ipv6 --subnet=fd88:88::/60 --gateway=fd88:88::1 \
  -o parent="$networkcard" \
  macvlan

# 第5步，生成几个固定 IP
ip_prefix=$(echo "$ip" | cut -d. -f1-3)
bridge="${ip_prefix}.254"
adguard="${ip_prefix}.114"
mosdns="${ip_prefix}.119"
mihomo="${ip_prefix}.120"

echo "=== 第6步：创建 macvlan-setup.sh 脚本 ==="
sudo tee /usr/local/bin/macvlan-setup.sh >/dev/null <<EOF
#!/bin/bash
ip link add macvlan-bridge link $networkcard type macvlan mode bridge
ip addr add $bridge dev macvlan-bridge
ip link set macvlan-bridge up
ip route add $subnet dev macvlan-bridge
ip route add $adguard dev macvlan-bridge
EOF

echo "=== 第7步：设置脚本权限 ==="
sudo chmod +x /usr/local/bin/macvlan-setup.sh

echo "=== 第8步：创建 systemd 服务文件 ==="
sudo tee /etc/systemd/system/macvlan.service >/dev/null <<EOF
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

echo "=== 启用并启动服务 ==="
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable macvlan.service
sudo systemctl start macvlan.service

echo "=== 第9步：查看服务状态 ==="
sudo systemctl status macvlan.service --no-pager
