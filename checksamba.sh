#!/bin/bash
# check_smb_version.sh
# 一键检测 Samba 版本 & 协议支持情况（含自动安装 smbclient）

CONTAINER_NAME=${1:-samba}

echo "🔍 正在检测 Samba 容器: $CONTAINER_NAME"
echo "------------------------------------------"

# 检查容器是否存在
if ! docker ps --format '{{.Names}}' | grep -qw "$CONTAINER_NAME"; then
    echo "❌ 找不到容器 $CONTAINER_NAME，请确认容器名是否正确。"
    exit 1
fi

# 自动安装 smbclient（Debian / Ubuntu / Armbian / Alpine 通用）
if ! command -v smbclient >/dev/null 2>&1; then
    echo "📦 检测到未安装 smbclient，正在尝试自动安装..."
    if [ -f /etc/debian_version ]; then
        sudo apt update && sudo apt install smbclient
    elif [ -f /etc/alpine-release ]; then
        sudo apk add --no-cache samba-client
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y samba-client
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y samba-client
    else
        echo "⚠️ 未识别的系统，请手动安装 smbclient。"
    fi
fi

if ! command -v smbclient >/dev/null 2>&1; then
    echo "❌ smbclient 安装失败，无法执行协议测试。"
else
    echo "✅ smbclient 已安装：$(smbclient -V)"
fi

# 1️⃣ 检查 smbd 版本
echo "------------------------------------------"
SMBD_VER=$(docker exec "$CONTAINER_NAME" smbd -V 2>/dev/null)
if [ -n "$SMBD_VER" ]; then
    echo "✅ Samba 服务版本: $SMBD_VER"
else
    echo "⚠️ 无法获取 smbd 版本（可能镜像中未包含 smbd 二进制）"
fi

# 2️⃣ 检查 smb.conf 中的协议配置
echo "------------------------------------------"
echo "📜 smb.conf 中的协议配置:"
docker exec "$CONTAINER_NAME" grep -E 'server (min|max) protocol' /etc/samba/smb.conf 2>/dev/null || \
    echo "（未找到 server min/max protocol 配置，使用默认）"

# 3️⃣ 检查 testparm 输出
echo "------------------------------------------"
echo "🧪 Samba 实际运行配置摘要："
docker exec "$CONTAINER_NAME" testparm -s | grep "Server min protocol\|Server max protocol"

# 4️⃣ 自动检测 smbclient 协议支持
echo "------------------------------------------"
if command -v smbclient >/dev/null 2>&1; then
    SMB_IPv4=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_NAME")
    SMB_IPv6=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' "$CONTAINER_NAME")

    echo "📡 自动检测 smbclient 协议支持："
    if [ -n "$SMB_IPv4" ]; then
        echo "  🔸 IPv4 地址: $SMB_IPv4"
        for ver in NT1 SMB2 SMB3; do
            echo -n "    协议测试 $ver → "
            smbclient -L "//$SMB_IPv4" -m "$ver" -N -g >/dev/null 2>&1 && echo "✅ 支持" || echo "❌ 不支持"
        done
    fi

    if [ -n "$SMB_IPv6" ]; then
        echo "  🔸 IPv6 地址: [$SMB_IPv6]"
        for ver in NT1 SMB2 SMB3; do
            echo -n "    协议测试 $ver → "
            smbclient -L "://[$SMB_IPv6]" -m "$ver" -N -g >/dev/null 2>&1 && echo "✅ 支持" || echo "❌ 不支持"
        done
    fi
else
    echo "⚠️ 本机未安装 smbclient，跳过协议测试。"
fi

echo "------------------------------------------"
echo "✅ 检测完成。"