# Armbian Macvlan 网络自动初始化工具

此项目提供一个自动化脚本 `init.sh`，用于在 Armbian 或其他基于 Debian 的系统中自动创建 Docker macvlan 网络，并配置宿主机与容器之间的互通。

---

## ✨ 功能特性

- 自动列出宿主网卡及对应 IPv4 地址和子网掩码
- 交互式选择网卡并确认 IP / 网关 / 子网配置
- 自动创建 Docker macvlan 网络
- 自动创建宿主机 `macvlan-bridge` 接口用于互通
- 自动写入并启用 Systemd 服务，确保开机自启
- 支持预定义多个容器 IP：AdGuard（.114）、MosDNS（.119）、Mihomo（.120）

---

## 🧱 脚本结构说明

脚本名：`init.sh`

主要步骤如下：

1. 列出宿主机网卡列表和对应 IP / 子网掩码
2. 用户选择网卡并确认 IP 配置
3. 解析出网关与子网信息
4. 自动创建 macvlan 网络（IPv4 + IPv6 支持）
5. 自动计算以下容器 IP：
    - 宿主桥接接口（Bridge）：`.254`
    - AdGuard Home：`.114`
    - MosDNS：`.119`
    - Mihomo：`.120`
6. 生成 `/usr/local/bin/macvlan-setup.sh` 配置脚本
7. 创建 Systemd 服务 `/etc/systemd/system/macvlan.service`
8. 启用并启动服务
9. 展示服务运行状态

---

## 🚀 使用方法

### 1. 直接运行脚本

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/perryyeh/armbian/main/init.sh)
```

### 2. 或克隆项目运行

```bash
git clone https://github.com/perryyeh/armbian.git
cd armbian
chmod +x init.sh
./init.sh
```

按照交互提示操作即可。

## 📦 依赖项
脚本依赖以下工具，请确保已安装：
- ipcalc （用于解析子网）
- docker
- systemd（Armbian 默认已包含）

安装方式（如未安装）：
```bash
sudo apt update
sudo apt install ipcalc docker.io -y
```

## 📌 注意事项
- 脚本默认使用 fd88:88::/60 作为 IPv6 网段
- 已存在的 macvlan 网络会被删除并重新创建
- 如果需要为更多容器分配固定 IP，可根据桥接 IP 模板自行添加

## 🛠 示例生成内容
- macvlan 网络（Docker）
- /usr/local/bin/macvlan-setup.sh 配置脚本
- /etc/systemd/system/macvlan.service Systemd 服务

## 📜 License
MIT License © 2025