import os
os.system("pkill cloudflared 2>/dev/null; echo 'cloudflared stopped'")
os.system("fuser -k 5000/tcp 2>/dev/null || echo 'No process on port 5000'")
print(kill)
