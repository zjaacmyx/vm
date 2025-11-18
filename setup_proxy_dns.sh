#!/bin/bash

# ====================== v2.2 最终修复增强版 ========================
# 自动 VMess+WS+TLS 部署脚本
# - Debian 12 pip 限制处理
# - 修复 DNS JSON 错误
# - 证书失败自动终止
# - Telegram 推送使用 MarkdownV2 并全转义
# ===============================================================

clear

# --- 步骤1: 配置信息 ---
CLOUDFLARE_EMAIL="zjaacg@gmail.com"
GLOBAL_KEY="4a2cbf42292cb56d6b3e3828a0c4c03fe3a48"
DOMAIN="aack.eu.org"

TG_BOT_TOKEN="6373113358:AAEFSlUzIc_PBJLamGS4enmejWidYiHnlO8"
TG_CHAT_ID="5270368345"

echo "================================================="
echo " v2.2 最终修复版配置加载完毕"
echo " 邮箱: $CLOUDFLARE_EMAIL"
echo " 域名: $DOMAIN"
echo " Telegram: $( [[ -n "$TG_BOT_TOKEN" ]] && echo '已配置' || echo '未配置' )"
echo "================================================="
echo

# --- 步骤2: 依赖安装 ---
echo "[*] 正在安装依赖..."
apt update -y >/dev/null 2>&1
apt install -y python3 python3-pip python3-requests curl socat >/dev/null 2>&1

pip3 install requests --quiet --disable-pip-version-check --no-python-version-warning --break-system-packages 2>/dev/null || true

if ! python3 - <<EOF >/dev/null 2>&1
import requests
EOF
then
    apt install -y pipx >/dev/null 2>&1
    pipx install requests >/dev/null 2>&1 || true
fi

if ! python3 - <<EOF >/dev/null 2>&1
import requests
EOF
then
    apt install -y python3-requests >/dev/null 2>&1
fi

if ! python3 - <<EOF
import requests
EOF
then
    echo "[x] requests 模块安装失败，中止执行！"
    exit 1
fi
echo "[√] 依赖安装完成"
echo

# --- 步骤3: 安装 acme.sh ---
echo "[*] 检查 acme.sh..."
if [ ! -f "/root/.acme.sh/acme.sh" ]; then
    curl -s https://get.acme.sh | sh >/dev/null 2>&1
    echo "[√] acme.sh 安装完成"
else
    echo "[*] acme.sh 已存在"
fi

export CF_Key="$GLOBAL_KEY"
export CF_Email="$CLOUDFLARE_EMAIL"
echo

# --- 步骤4: 核心部署逻辑 ---
echo "[*] 执行域名申请、证书生成和配置写入..."

python3 - "$CLOUDFLARE_EMAIL" "$GLOBAL_KEY" "$DOMAIN" "$TG_BOT_TOKEN" "$TG_CHAT_ID" <<'EOF'
import random, string, requests, json, subprocess, uuid, sys, os, socket, time, base64, re

if len(sys.argv) < 6:
    print("[x] 参数不足")
    sys.exit(1)

CLOUDFLARE_EMAIL, GLOBAL_KEY, DOMAIN, TG_BOT_TOKEN, TG_CHAT_ID = sys.argv[1:6]

TEMP_KEY_PATH = "/root/private.key"
TEMP_FULLCHAIN_PATH = "/root/cert.crt"
FINAL_KEY_PATH = "/usr/local/etc/xray/private.key"
FINAL_FULLCHAIN_PATH = "/usr/local/etc/xray/cert.crt"

def safe_print(msg):
    print(msg, flush=True)

def escape_markdown(text: str) -> str:
    escape_chars = r'_*[]()~`>#+-=|{}.!'
    return re.sub(f'([{re.escape(escape_chars)}])', r'\\\1', text)

def send_tg(msg):
    if not TG_BOT_TOKEN:
        return
    esc_msg = escape_markdown(msg)
    try:
        requests.post(
            f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
            json={"chat_id": TG_CHAT_ID, "text": esc_msg, "parse_mode": "MarkdownV2"},
            timeout=10
        )
    except Exception as e:
        print(f"[!] Telegram 推送失败: {e}")

def get_public_ip():
    return requests.get("https://api.ipify.org", timeout=5).text.strip()

def get_ip_info():
    try:
        data = requests.get("http://ip-api.com/json/?fields=country,countryCode,org,status", timeout=5).json()
        if data.get("status") == "success":
            return data.get("org", "VPS"), data.get("country", "Unknown"), data.get("countryCode", "xx")
    except: pass
    return "VPS", "Unknown", "xx"

def get_zone_id():
    headers = {"X-Auth-Email": CLOUDFLARE_EMAIL, "X-Auth-Key": GLOBAL_KEY}
    r = requests.get(f"https://api.cloudflare.com/client/v4/zones?name={DOMAIN}", headers=headers).json()
    if r.get("success") and r.get("result"):
        return r["result"][0]["id"]
    sys.exit("[x] 无法获取 Zone ID")

def create_dns(zone_id, subdomain, ip):
    safe_print(f"[*] 创建 DNS: {subdomain}.{DOMAIN} → {ip}")
    data = {"type":"A","name":f"{subdomain}.{DOMAIN}","content":ip,"ttl":60,"proxied":False}
    headers = {"X-Auth-Email":CLOUDFLARE_EMAIL,"X-Auth-Key":GLOBAL_KEY,"Content-Type":"application/json"}
    r = requests.post(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", json=data, headers=headers)
    if r.status_code == 200:
        return f"{subdomain}.{DOMAIN}"
    sys.exit(f"[x] DNS 创建失败: {r.text}")

def install_cert(full_domain):
    safe_print(f"[*] 正在申请证书: {full_domain}")
    cmd = ["/root/.acme.sh/acme.sh","--issue","--server","letsencrypt","--dns","dns_cf","-d", full_domain,"--key-file",TEMP_KEY_PATH,"--fullchain-file",TEMP_FULLCHAIN_PATH,"--force"]
    p = subprocess.run(cmd, text=True)
    if p.returncode != 0:
        sys.exit("[x] ACME 证书签发失败")

def find_port():
    while True:
        port = random.randint(20001, 65535)
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port

def gen_vmess(full_domain, provider, country):
    cfg = {"ps":f"{provider}-{country}","add":full_domain,"port":str(find_port()),"id":str(uuid.uuid4()),
           "aid":0,"net":"ws","type":"none","host":full_domain,"path":"/v2","tls":"tls"}
    vmess = "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()
    return cfg, vmess

def write_xray(cfg):
    config = {
        "dns": {"servers":["https://doh.pub/dns-query"]},
        "log": {"loglevel":"warning"},
        "inbounds": [{
            "port": int(cfg["port"]),
            "protocol":"vmess",
            "settings":{"clients":[{"id":cfg["id"],"alterId":0}]},
            "streamSettings":{
                "network":"ws",
                "security":"tls",
                "tlsSettings":{"certificates":[{"certificateFile":FINAL_FULLCHAIN_PATH,"keyFile":FINAL_KEY_PATH}]},
                "wsSettings":{"path":cfg["path"]}
            }
        }],
        "outbounds":[{"protocol":"freedom"}]
    }
    os.makedirs("/usr/local/etc/xray", exist_ok=True)
    with open("/usr/local/etc/xray/config.json", "w") as f:
        json.dump(config, f, indent=2)

provider, country, code = get_ip_info()
zone_id = get_zone_id()
ip = get_public_ip()
subdomain = f"{provider[:3].lower()}-{code.lower()}-{''.join(random.choices(string.ascii_lowercase+string.digits, k=3))}"
full_domain = create_dns(zone_id, subdomain, ip)

time.sleep(15)
install_cert(full_domain)
cfg, vmess_link = gen_vmess(full_domain, provider[:3], country)
write_xray(cfg)

message = (
    f"✅ 新节点部署成功\n\n"
    f"节点备注: {cfg['ps']}\n"
    f"地址 (Address): {cfg['add']}\n"
    f"端口 (Port): {cfg['port']}\n"
    f"UUID: {cfg['id']}\n\n"
    f"一键导入链接:\n{vmess_link}"
)
send_tg(message)

print("\n---------------- 客户端配置 ----------------")
print(f" 节点备注: {cfg['ps']}")
print(f" 地址: {cfg['add']}")
print(f" 端口: {cfg['port']}")
print(f" UUID: {cfg['id']}")
print(f"\n导入链接:\n{vmess_link}")
print("------------------------------------------------")
EOF

# --- 步骤5: 安装 Xray ---
echo "[*] 安装 Xray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
echo "[√] Xray 安装完成"

# --- 步骤6: 证书处理 ---
if [ -f /root/cert.crt ] && [ -f /root/private.key ]; then
    XRAY_USER=$(grep -oP '^User=\K.*' /etc/systemd/system/xray.service || echo nobody)
    XRAY_GROUP=$(id -gn "$XRAY_USER" 2>/dev/null || echo nogroup)
    mkdir -p /usr/local/etc/xray
    mv /root/cert.crt /usr/local/etc/xray/cert.crt
    mv /root/private.key /usr/local/etc/xray/private.key
    chown "$XRAY_USER:$XRAY_GROUP" /usr/local/etc/xray/*
    echo "[√] 证书配置完成"
else
    echo "[x] 证书未生成，安装终止"
    exit 1
fi

systemctl restart xray
sleep 2

if systemctl is-active --quiet xray; then
    echo "================================================="
    echo " 🎉 v2.2 部署完成，节点可用！！！"
    echo "================================================="
else
    echo "[x] Xray 启动失败，请检查: journalctl -u xray -f"
fi
