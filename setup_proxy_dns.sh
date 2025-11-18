#!/bin/bash

# ====================== v2.4 FINAL ========================
# VMess + WS + TLS 部署脚本
# ⛑ 修复Telegram推送为Markdown V1 → 支持点击复制链接
# 🛠 保留v2.3全部稳定优化（pip修复/DNS修复/证书失败保护）
# ==========================================================

clear

# --- 基础配置 ---
CLOUDFLARE_EMAIL="zjaacg@gmail.com"
GLOBAL_KEY="4a2cb42292cb56d6b3e3828a0c4c03fe3a48"
DOMAIN="aack.eu.org"
TG_BOT_TOKEN="6373113358:AAEFSlUzIc_PBJLamGS4enmejWidYiHnlO8"
TG_CHAT_ID="5270368345"

echo "================================================="
echo " v2.4 最终稳定版本（Telegram点击复制）启动"
echo " 域名: $DOMAIN"
echo " 邮箱: $CLOUDFLARE_EMAIL"
echo "================================================="
echo

# --- 安装依赖（支持Debian12） ---
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

# ==================== 核心逻辑 ====================
python3 - "$CLOUDFLARE_EMAIL" "$GLOBAL_KEY" "$DOMAIN" "$TG_BOT_TOKEN" "$TG_CHAT_ID" << 'EOF'
import random, string, requests, subprocess, json, uuid, sys, os, socket, time, base64

CLOUDFLARE_EMAIL, GLOBAL_KEY, DOMAIN, TG_BOT_TOKEN, TG_CHAT_ID = sys.argv[1:6]
TEMP_KEY, TEMP_CERT = "/root/private.key", "/root/cert.crt"
FINAL_KEY, FINAL_CERT = "/usr/local/etc/xray/private.key", "/usr/local/etc/xray/cert.crt"

# ---- Telegram MarkdownV1 发送函数（允许点击复制） ----
def send_tg_v1(msg):
    try:
        requests.post(
            f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
            json={"chat_id": TG_CHAT_ID, "text": msg, "parse_mode": "Markdown"},
            timeout=10
        )
    except Exception as e:
        print(f"[!] Telegram 推送失败: {e}")

def get_public_ip():
    return requests.get("https://api.ipify.org").text.strip()

def get_ip_info():
    try:
        r = requests.get("http://ip-api.com/json/?fields=org,country,countryCode,status").json()
        if r.get("status") == "success":
            return r["org"], r["country"], r["countryCode"]
    except:
        pass
    return "VPS", "Unknown", "xx"

def get_zone_id():
    h = {"X-Auth-Email": CLOUDFLARE_EMAIL, "X-Auth-Key": GLOBAL_KEY}
    r = requests.get(f"https://api.cloudflare.com/client/v4/zones?name={DOMAIN}", headers=h).json()
    if r.get("success") and r.get("result"):
        return r["result"][0]["id"]
    sys.exit("[x] Zone ID 获取失败")

def create_dns(zone, sub, ip):
    data = {"type":"A","name":f"{sub}.{DOMAIN}","content":ip,"ttl":60,"proxied":False}
    h = {"X-Auth-Email":CLOUDFLARE_EMAIL,"X-Auth-Key":GLOBAL_KEY,"Content-Type":"application/json"}
    r = requests.post(f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records", json=data, headers=h)
    if r.status_code == 200:
        return f"{sub}.{DOMAIN}"
    sys.exit("[x] DNS 记录创建失败")

def install_cert(fd):
    p = subprocess.run(
        ["/root/.acme.sh/acme.sh","--issue","--server","letsencrypt","--dns","dns_cf",
         "-d",fd,"--key-file",TEMP_KEY,"--fullchain-file",TEMP_CERT,"--force"],
        text=True
    )
    if p.returncode != 0:
        sys.exit("[x] SSL 证书申请失败")

def find_port():
    while True:
        p = random.randint(20001,65535)
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1",p)) != 0:
                return p

def gen_vmess(fd, prov, country):
    cfg = {"ps":f"{prov}-{country}","add":fd,"port":str(find_port()),"id":str(uuid.uuid4()),
           "aid":0,"net":"ws","type":"none","host":fd,"path":"/v2","tls":"tls"}
    link = "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()
    return cfg, link

def write_xray(cfg):
    config = {
        "dns": {"servers":["https://doh.pub/dns-query"]},
        "log": {"loglevel":"warning"},
        "inbounds": [{
            "port": int(cfg["port"]),
            "protocol":"vmess",
            "settings":{"clients":[{"id":cfg["id"],"alterId":0}]},
            "streamSettings":{
                "network":"ws","security":"tls",
                "tlsSettings":{"certificates":[{"certificateFile":FINAL_CERT,"keyFile":FINAL_KEY}]},
                "wsSettings":{"path":cfg["path"]}
            }
        }],
        "outbounds":[{"protocol":"freedom"}]
    }
    os.makedirs("/usr/local/etc/xray", exist_ok=True)
    with open("/usr/local/etc/xray/config.json","w") as f:
        json.dump(config, f, indent=2)

# ---- 执行流程 ----
prov, country, code = get_ip_info()
zone_id = get_zone_id()
ipnow = get_public_ip()
sub = f"{prov[:3].lower()}-{code.lower()}-{''.join(random.choices(string.ascii_lowercase+string.digits, k=3))}"
fd = create_dns(zone_id, sub, ipnow)
time.sleep(15)
install_cert(fd)
cfg, link = gen_vmess(fd, prov[:3], country)
write_xray(cfg)

# ---- 推送主消息（MarkdownV1，可点击复制） ----
msg = (
    f"✅ *新节点部署成功*\n\n"
    f"*节点备注:* `{cfg['ps']}`\n"
    f"*地址 (Address):* `{cfg['add']}`\n"
    f"*端口 (Port):* `{cfg['port']}`\n"
    f"*UUID:* `{cfg['id']}`\n\n"
    f"*一键导入链接 (点击复制):*\n`{link}`"
)
send_tg_v1(msg)

print(f"节点部署成功 → {link}")
EOF

# --- 安装 Xray ---
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1

# --- 证书移动 ---
if [ ! -f /root/cert.crt ] || [ ! -f /root/private.key ]; then
    echo "[x] 证书未生成，停止"
    exit 1
fi

XRAY_USER=$(grep -oP '^User=\K.*' /etc/systemd/system/xray.service 2>/dev/null || echo nobody)
XRAY_GROUP=$(id -gn "$XRAY_USER" 2>/dev/null || echo nogroup)
mkdir -p /usr/local/etc/xray
mv /root/cert.crt /usr/local/etc/xray/cert.crt
mv /root/private.key /usr/local/etc/xray/private.key
chown "$XRAY_USER:$XRAY_GROUP" /usr/local/etc/xray/*

systemctl restart xray
sleep 2

if systemctl is-active --quiet xray; then
    echo "================================================="
    echo " 🎉 v2.4 部署完成，Telegram 点击复制已恢复！"
    echo "================================================="
else
    echo "[x] Xray 启动失败，请执行: journalctl -u xray -f"
fi
