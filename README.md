# Armbian 旁路由脚本 

此项目提供一个自动化脚本，用于在Armbian系统中自动创建 Docker macvlan 网络，并配置宿主机与容器之间的互通，安装librespeed测速，mihomo，mosdns，adguard等基础容器。

---
## ✨ 功能特性
- 交互式选择网卡并确认 IP / 网关 / 子网配置
- 创建 Docker macvlan 网络
- 创建宿主机 `macvlan-bridge` 接口用于互通
- 写入并启用 Systemd 服务，确保开机自启
- 预定义多个容器 IP：librespeed（.111） AdGuardhome（.114）、MosDNS（.119）、Mihomo（.120）
- 此代码多数由openai和gemimi生成
---

## 🧱 脚本菜单说明

- 0）显示菜单
- 1）显示操作系统信息
- 2）显示网卡信息
- 3）显示磁盘信息
- 4）显示docker信息
- 5）安装docker
- 6）安装portainer面板和watchtower自动更新
- 7）开启ipv6并创建macvlan
- 9）清理macvlan和macvlan bridge
- 11）安装librespeed测速
- 14）安装adguardhome
- 19）安装mosdns
- 20）安装mihomo
- 99）退出

---

## 🚀 使用方法

### 1. 直接运行脚本

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/perryyeh/armbian/main/install.sh)
```

### 2. 或克隆项目运行

```bash
git clone https://github.com/perryyeh/armbian.git
cd armbian
chmod +x install.sh
./install.sh
```

按照交互提示操作即可。

## 📦 依赖项
脚本依赖以下工具，会自动安装：
ipcalc 
curl 
jq 
git


## 📌 注意事项
- 脚本默认使用ipv4计算出ula ipv6地址，生成类似fd10:: fd19:: fd17:: 作为 IPv6 网段，如不用默认获取请一定要输入
- 安装错误请12回滚操作，以免流量死循环导致无法进入而重新刷机
- 因为自用路由器不支持ula，所以ula自动生成可能有bug，请提pr
- 本代码目前只在armbian下测试通过，其他linux请谨慎尝试
- 已存在的 macvlan 网络会被删除并重新创建

## 📜 License
MIT License © 2025