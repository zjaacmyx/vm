#!/bin/bash

# ====================== v2 最终修复增强版 ========================
# 自动 VMess+WS+TLS 部署脚本
# ⚙ 修复 pip 限制、DNS JSON 错误、证书未生成继续执行问题
# 🎯 Telegram 推送恢复原版完整格式（地址+端口+UUID+链接）
# ===============================================================

clear

# --- 步骤1: 配置信息 ---
CLOUDFLARE_EMAIL="zjaacg@gmail.com"
GLOBAL_KEY="4a2cbf42292cb56d6b3e3828a0c4c03fe3a48"
DOMAIN="aack.eu.org"

TG_BOT_TOKEN="6373113358:AAEFSlUzIc_PBJLamGS4enmejWidYiHnlO8"
TG_CHAT_ID="5270368345"

echo "================================================="
echo " v2 最终修复版配置加载完毕"
echo " 邮箱: $CLOUDFLARE_EMAIL"
echo " 域名: $DOMAIN"
echo " Telegram: $( [[ -n "$TG_BOT_TOKEN" ]] && echo '已配置' || echo '未配置' )"
echo "================================================="
echo

# --- 步骤2: 安装系统依赖 ---
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
echo "[*] 正在检测 acme.sh..."
if [ ! -f "/root/.acme.sh/acme.sh" ]; then
    curl -s https://get.acme.sh | sh >/dev/null 2>&1
    echo "[√] acme.sh 安装完成"
else
    echo "[*] acme.sh 已存在"
fi

export CF_Key="$GLOBAL_KEY"
export CF_Email="$CLOUDFLARE_EMAIL"
echo

# --- 步骤4: 核心操作 Python ---
echo "[*] 执行证书申请 & 配置生成逻辑..."

python3 - "$CLOUDFLARE_EMAIL" "$GLOBAL_KEY" "$DOMAIN" "$TG_BOT_TOKEN" "$TG_CHAT_ID" <<'EOF'
import random, string, requests, json, subprocess, uuid, sys, os, socket, time, base64

if len(sys.argv) < 6:
    print("[x] 参数不足")
    sys.exit(1)

CLOUDFLARE_EMAIL, GLOBAL_KEY, DOMAIN, TG_BOT_TOKEN, TG_CHAT_ID = sys.argv[1:6]

TEMP_KEY_PATH = "/root/private.key"
TEMP_FULLCHAIN_PATH = "/root/cert.crt"
FINAL_KEY_PATH = "/usr/local/etc/xray/private.key"
FINAL_FULLCHAIN_PATH = "/usr/local/etc/xray/cert.crt"

def safe_print(s):
    print(s, flush=True)

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org", timeout=5).text.strip()
    except:
        sys.exit("[x] 无法获取公网 IP")

def get_ip_info():
    try:
        r = requests.get("http://ip-api.com/json/?fields=country,countryCode,org,status", timeout=5).json()
        if r.get("status") == "success":
            return r.get("org", "VPS"), r.get("country", "Unknown"), r.get("countryCode", "xx")
    except:
        pass
    return "VPS", "Unknown", "xx"

def get_zone_id():
    h = {"X-Auth-Email": CLOUDFLARE_EMAIL, "X-Auth-Key": GLOBAL_KEY}
    r = requests.get(f"https://api.cloudflare.com/client/v4/zones?name={DOMAIN}", headers=h).json()
    if r.get("success") and r.get("result"):
        return r["result"][0]["id"]
    sys.exit("[x] 获取 Cloudflare Zone ID 失败")

def create_dns(zone, sub, ip):
    safe_print(f"[*] 创建DNS记录: {sub}.{DOMAIN} → {ip}")
    url = f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records"
    h = {"X-Auth-Email": CLOUDFLARE_EMAIL, "X-Auth-Key": GLOBAL_KEY, "Content-Type": "application/json"}
    d = {"type": "A", "name": f"{sub}.{DOMAIN}", "content": ip, "ttl": 60, "proxied": False}
    r = requests.post(url, headers=h, json=d)
    if r.status_code == 200:
        return f"{sub}.{DOMAIN}"
    sys.exit(f"[x] DNS 记录创建失败: {r.text}")

def install_cert(fd):
    safe_print(f"[*] 申请证书: {fd}")
    cmd = ["/root/.acme.sh/acme.sh","--issue","--server","letsencrypt","--dns","dns_cf","-d",fd,"--key-file",TEMP_KEY_PATH,"--fullchain-file",TEMP_FULLCHAIN_PATH,"--force"]
    p = subprocess.run(cmd, text=True)
    if p.returncode != 0:
        sys.exit("[x] 证书申请失败")

def find_port():
    while True:
        p = random.randint(20001, 65535)
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", p)) != 0:
                return p

def gen_cfg(fd, provider, country):
    cfg = {"ps":f"{provider}-{country}", "add":fd, "port":str(find_port()), "id":str(uuid.uuid4()), 
           "aid":0, "net":"ws", "type":"none", "host":fd, "path":"/v2", "tls":"tls"}
    vmess = "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()
    return cfg, vmess

def write_xray(c):
    server = {
      "dns": {"servers": ["https://doh.pub/dns-query"]},
      "log": {"loglevel": "warning"},
      "inbounds": [{
        "port": int(c["port"]),
        "protocol": "vmess",
        "settings": {"clients":[{"id":c["id"],"alterId":0}]},
        "streamSettings": {
          "network":"ws",
          "security":"tls",
          "tlsSettings":{"certificates":[{"certificateFile": FINAL_FULLCHAIN_PATH, "keyFile": FINAL_KEY_PATH}]},
          "wsSettings":{"path": c["path"]}
        }
      }],
      "outbounds":[{"protocol":"freedom"}]
    }
    os.makedirs("/usr/local/etc/xray", exist_ok=True)
    with open("/usr/local/etc/xray/config.json", "w") as f:
        json.dump(server, f, indent=2)

def send_tg(msg):
    if not TG_BOT_TOKEN: return
    try:
        requests.post(f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage", json={"chat_id": TG_CHAT_ID, "text": msg, "parse_mode": "Markdown"})
    except:
        pass

org, country, cc = get_ip_info()
zone = get_zone_id()
ip = get_public_ip()
sub = f"{org[:3].lower()}-{cc.lower()}-{''.join(random.choices(string.ascii_lowercase+string.digits, k=3))}"
fd = create_dns(zone, sub, ip)
time.sleep(15)
install_cert(fd)
cfg, link = gen_cfg(fd, org[:3], country)
write_xray(cfg)

# Telegram 推送恢复原格式
notification = (
    f"✅ *新节点部署成功*\n\n"
    f"*节点备注:* `{cfg['ps']}`\n"
    f"*地址 (Address):* `{cfg['add']}`\n"
    f"*端口 (Port):* `{cfg['port']}`\n"
    f"*UUID:* `{cfg['id']}`\n\n"
    f"*一键导入链接 (点击复制):*\n`{link}`"
)
send_tg(notification)

print("\n----------------- 客户端配置 -----------------")
print(f" 节点备注: {cfg['ps']}")
print(f" 地址: {cfg['add']}")
print(f" 端口: {cfg['port']}")
print(f" UUID: {cfg['id']}")
print(f"\n VMess 导入链接:\n{link}\n")
print("-------------------------------------------------")
EOF

# --- 步骤5: Xray 安装 ---
echo "[*] 正在安装 Xray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
echo "[√] Xray 安装完成"

# --- 步骤6: 证书移动 ---
if [ -f /root/cert.crt ] && [ -f /root/private.key ]; then
    XRAY_USER=$(grep -oP '^User=\K.*' /etc/systemd/system/xray.service || echo nobody)
    XRAY_GROUP=$(id -gn "$XRAY_USER" 2>/dev/null || echo nogroup)
    mkdir -p /usr/local/etc/xray
    mv /root/cert.crt /usr/local/etc/xray/cert.crt
    mv /root/private.key /usr/local/etc/xray/private.key
    chown "$XRAY_USER:$XRAY_GROUP" /usr/local/etc/xray/*
    echo "[√] 证书配置完成"
else
    echo "[x] 证书未生成，中止"
    exit 1
fi

# --- 重启 Xray ---
systemctl restart xray
sleep 2

# --- 验证 ---
if systemctl is-active --quiet xray; then
    echo "================================================="
    echo " 🎉 v2 最终修复版部署完成，节点已可用！"
    echo "================================================="
else
    echo "[x] Xray 启动失败，查看日志: journalctl -u xray -f"
fi
