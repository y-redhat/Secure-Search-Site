#for Vr4.0.0
# 安装 Python 依赖
!pip install flask flask-sock flask-limiter requests bcrypt cryptography pysocks -q

# 安装并启动 Tor 代理
!apt-get install -y tor > /dev/null
!nohup tor > /dev/null 2>&1 &
!sleep 3
!echo "✅ Tor and dependencies installed."
