#for Vr4.0.0
# 下载并安装 cloudflared
!wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
!dpkg -i cloudflared-linux-amd64.deb > /dev/null 2>&1

# 后台启动 Tunnel，将本地 5000 端口暴露到公网
!nohup cloudflared tunnel --url http://localhost:5000 > cloudflared.log 2>&1 &
!sleep 8

# 提取生成的公网 URL
!echo "========================================="
!echo "🌐 Your Public URL (Copy this):"
!grep -o 'https://[^ ]*\.trycloudflare\.com' cloudflared.log | head -n 1
!echo "========================================="
