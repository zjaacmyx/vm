#!/bin/bash

# ====================== v2.3 FINAL ========================
# VMess + WS + TLS 部署脚本
# 修复点：
# 1. Debian pip 受限修复
# 2. DNS 配置错误修复
# 3. 证书签发失败即终止
# 4. Telegram 推送格式正确
# 5. 新增第二条消息 → 代码块显示 vmess 链接（支持一键复制）
# ==========================================================

clear

# --- 基本配置 ---
CLOUDFLARE_EMAIL="zjaacg@gmail.com"
GLOBAL_KEY="4a2cbf42292cb56d6b3e3828a0c4c03fe3a48"
DOMAIN="aack.eu.org"
TG_BOT_TOKEN="6373113358:AAEFSlUzIc_PBJLamGS4enmejWidYiHnlO8"
TG_CHAT_ID="5270368345"

echo "================================================="
echo " v2.3 终极版（Telegram一键复制）已启动"
echo " 域名: $DOMAIN"
echo " 邮箱: $CLOUDFLARE_EMAIL"
echo "================================================="
echo

# --- 依赖安装 ---
apt update -y >/dev/null 2>&1
apt install -y python3 python3-pip python3-requests curl socat >/dev/null 2>&1
pip3 install requests --break-system-packages --quiet || true
apt install -y pipx >/dev/null 2>&1 && pipx install requests >/dev/null 2>&1 || true

python3 - << 'EOF'
try:
    import requests
except:
    exit("[x] requests 模块安装失败，停止。")
EOF

# --- 安装 acme.sh ---
if [ ! -f "/root/.acme.sh/acme.sh" ]; then
    curl -s https://get.acme.sh | sh >/dev/null 2>&1
fi

export CF_Key="$GLOBAL_KEY"
export CF_Email="$CLOUDFLARE_EMAIL"
echo "[√] 依赖准备完成"

# --- Python 核心逻辑 ---
python3 - "$CLOUDFLARE_EMAIL" "$GLOBAL_KEY" "$DOMAIN" "$TG_BOT_TOKEN" "$TG_CHAT_ID" << 'EOF'
import random, string, requests, subprocess, json, uuid, sys, os, socket, time, base64, re

CLOUDFLARE_EMAIL, GLOBAL_KEY, DOMAIN, TG_BOT_TOKEN, TG_CHAT_ID = sys.argv[1:6]

TEMP_KEY = "/root/private.key"
TEMP_CERT = "/root/cert.crt"
FINAL_KEY = "/usr/local/etc/xray/private.key"
FINAL_CERT = "/usr/local/etc/xray/cert.crt"

def escape_md(text):
    chars = r'_*[]()~`>#+-=|{}.!'
    return re.sub(f'([{re.escape(chars)}])', r'\\\1', text)

def send_tg(msg):
    esc_msg = escape_md(msg)
    try:
        requests.post(
            f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
            json={"chat_id": TG_CHAT_ID, "text": esc_msg, "parse_mode": "MarkdownV2"},
            timeout=10
        )
    except Exception as e:
        print(f"[!] TG失败: {e}")

def get(zone):
    h={"X-Auth-Email":CLOUDFLARE_EMAIL,"X-Auth-Key":GLOBAL_KEY}
    r=requests.get(f"https://api.cloudflare.com/client/v4/zones?name={DOMAIN}",headers=h).json()
    if r.get("success"):
        return r["result"][0]["id"]
    sys.exit("[x] Zone ID error")

def ip():
    return requests.get("https://api.ipify.org").text.strip()

def inf():
    r=requests.get("http://ip-api.com/json/?fields=org,country,countryCode,status").json()
    if r.get("status")=="success":
        return r["org"],r["country"],r["countryCode"]
    return "VPS","Unknown","xx"

def dns(z,s,i):
    d={"type":"A","name":f"{s}.{DOMAIN}","content":i,"ttl":60,"proxied":False}
    h={"X-Auth-Email":CLOUDFLARE_EMAIL,"X-Auth-Key":GLOBAL_KEY,"Content-Type":"application/json"}
    r=requests.post(f"https://api.cloudflare.com/client/v4/zones/{z}/dns_records",json=d,headers=h)
    if r.status_code == 200:
        return f"{s}.{DOMAIN}"
    sys.exit("[x] DNS失败")

def cert(fd):
    print(f"[*] SSL for {fd}")
    p=subprocess.run(["/root/.acme.sh/acme.sh","--issue","--server","letsencrypt","--dns","dns_cf",
                      "-d",fd,"--key-file",TEMP_KEY,"--fullchain-file",TEMP_CERT,"--force"], text=True)
    if p.returncode!=0:
        sys.exit("[x] ACME失败")

def port():
    while True:
        p=random.randint(20001,65535)
        if socket.socket().connect_ex(("127.0.0.1",p)): return p

def gen(fd, pr, co):
    c={"ps":f"{pr}-{co}","add":fd,"port":str(port()),"id":str(uuid.uuid4()),
       "aid":0,"net":"ws","type":"none","host":fd,"path":"/v2","tls":"tls"}
    return c,"vmess://"+base64.b64encode(json.dumps(c).encode()).decode()

def write(c):
    cfg={
      "dns":{"servers":["https://doh.pub/dns-query"]},
      "log":{"loglevel":"warning"},
      "inbounds":[{
        "port":int(c["port"]),"protocol":"vmess",
        "settings":{"clients":[{"id":c["id"],"alterId":0}]},
        "streamSettings":{
          "network":"ws","security":"tls",
          "tlsSettings":{"certificates":[{"certificateFile":FINAL_CERT,"keyFile":FINAL_KEY}]},
          "wsSettings":{"path":c["path"]}
        }}],
      "outbounds":[{"protocol":"freedom"}]
    }
    os.makedirs("/usr/local/etc/xray",exist_ok=True)
    open("/usr/local/etc/xray/config.json","w").write(json.dumps(cfg,indent=2))

prov, cou, code = inf()
zid = get(DOMAIN)
ipnow = ip()
sub = f"{prov[:3].lower()}-{code.lower()}-{''.join(random.choices(string.ascii_lowercase+string.digits,k=3))}"
fd = dns(zid, sub, ipnow)

time.sleep(15)
cert(fd)
cfg, link = gen(fd, prov[:3], cou)
write(cfg)

msg = (
    f"✅ 新节点部署成功\n\n"
    f"节点备注: {cfg['ps']}\n"
    f"地址 (Address): {cfg['add']}\n"
    f"端口 (Port): {cfg['port']}\n"
    f"UUID: {cfg['id']}\n\n"
    f"一键导入链接:\n{link}"
)
send_tg(msg)

# 🔥第二条消息 → 可直接复制
send_tg(f"```text\n{link}\n```")

print("节点部署完成，已推送 Telegram。")
EOF

# --- 安装 Xray ---
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1

# --- 证书移动 ---
if [ -f /root/cert.crt ] && [ -f /root/private.key ]; then
    XRAY_USER=$(grep -oP '^User=\K.*' /etc/systemd/system/xray.service 2>/dev/null || echo nobody)
    XRAY_GROUP=$(id -gn "$XRAY_USER" 2>/dev/null || echo nogroup)
    mkdir -p /usr/local/etc/xray
    mv /root/cert.crt /usr/local/etc/xray/cert.crt
    mv /root/private.key /usr/local/etc/xray/private.key
    chown "$XRAY_USER:$XRAY_GROUP" /usr/local/etc/xray/*
else
    echo "[x] 证书未生成，中止！"
    exit 1
fi

systemctl restart xray
sleep 2

if systemctl is-active --quiet xray; then
    echo "================================================="
    echo " 🎉 v2.3 部署完成，节点已可用！"
    echo "================================================="
else
    echo "[x] Xray 启动失败，请执行：journalctl -u xray -f"
fi
