#!/bin/bash

# ====================== v2 完整增强版 ========================
# 自动 VMess+WS+TLS 部署脚本（修复DNS语法+pip限制）
# - 修复 pip Debian PEP668 问题
# - 自动安装 requests 模块（pip → pipx → apt 三种方式保障）
# - 修复 Xray DNS 语法错误
# - 证书生成失败则终止安装
# - 默认使用单节点 DoH (https://doh.pub/dns-query)
# ===============================================================

clear

# --- 步骤1: 配置信息 ---
CLOUDFLARE_EMAIL="zjaacg@gmail.com"
GLOBAL_KEY="4a2cbf42292cb56d6b3e3828a0c4c03fe3a48"
DOMAIN="aack.eu.org"

TG_BOT_TOKEN="6373113358:AAEFSlUzIc_PBJLamGS4enmejWidYiHnlO8"
TG_CHAT_ID="5270368345"

echo "================================================="
echo " v2版配置加载中..."
echo " 邮箱: $CLOUDFLARE_EMAIL"
echo " 域名: $DOMAIN"
echo " Telegram 推送: $( [[ -n "$TG_BOT_TOKEN" ]] && echo '已配置' || echo '未配置' )"
echo "================================================="
echo

# --- 步骤2: 安装依赖 ---
echo "[*] 安装软件包和Python依赖..."
apt update -y >/dev/null 2>&1
apt install -y python3 python3-pip python3-requests curl socat >/dev/null 2>&1

# pip 尝试安装 requests
pip3 install requests --break-system-packages --quiet 2>/dev/null || true

# 如果依旧失败，尝试安装 pipx 并安装
if ! python3 - <<EOF >/dev/null 2>&1
import requests
EOF
then
    echo "[!] pip安装失败，尝试pipx安装..."
    apt install -y pipx >/dev/null 2>&1
    pipx install requests >/dev/null 2>&1 || true
fi

# 最后尝试 apt
if ! python3 - <<EOF >/dev/null 2>&1
import requests
EOF
then
    echo "[!] pipx失败，使用 apt 安装 python3-requests"
    apt install -y python3-requests >/dev/null 2>&1
fi

# 最后检测
if ! python3 - <<EOF
import requests
EOF
then
    echo "[x] 依赖 requests 安装失败，请手动修复后再执行！"
    exit 1
fi

echo "[√] 依赖安装完成！"
echo


# --- 步骤3: 安装 acme.sh ---
echo "[*] 检查 acme.sh ..."
if [ ! -f "/root/.acme.sh/acme.sh" ]; then
    curl -s https://get.acme.sh | sh >/dev/null 2>&1
    echo "[√] acme.sh 已安装"
else
    echo "[*] acme.sh 已存在"
fi

export CF_Key="$GLOBAL_KEY"
export CF_Email="$CLOUDFLARE_EMAIL"

echo

# --- 步骤4: 核心 Python 执行 ---
echo "[*] 执行核心域名/证书/配置生成逻辑..."

python3 - "$CLOUDFLARE_EMAIL" "$GLOBAL_KEY" "$DOMAIN" "$TG_BOT_TOKEN" "$TG_CHAT_ID" <<'EOF'
import random, string, requests, json, subprocess, uuid, sys, os, socket, time

if len(sys.argv) < 6:
    print("[x] 参数不足")
    sys.exit(1)

CLOUDFLARE_EMAIL = sys.argv[1]
GLOBAL_KEY = sys.argv[2]
DOMAIN = sys.argv[3]
TG_BOT_TOKEN = sys.argv[4]
TG_CHAT_ID = sys.argv[5]

TEMP_KEY_PATH = "/root/private.key"
TEMP_FULLCHAIN_PATH = "/root/cert.crt"
FINAL_KEY_PATH = "/usr/local/etc/xray/private.key"
FINAL_FULLCHAIN_PATH = "/usr/local/etc/xray/cert.crt"

def safe_print(msg):
    print(msg, flush=True)

def get_public_ip():
    return requests.get("https://api.ipify.org").text.strip()

def get_ip_info():
    safe_print("[*] 获取IP信息")
    try:
        r = requests.get("http://ip-api.com/json/?fields=country,countryCode,org,status").json()
        if r["status"] == "success":
            return r["org"], r["country"], r["countryCode"]
    except: pass
    return "VPS", "Unknown", "xx"

def get_zone_id():
    h = {"X-Auth-Email": CLOUDFLARE_EMAIL,"X-Auth-Key": GLOBAL_KEY}
    r = requests.get(f"https://api.cloudflare.com/client/v4/zones?name={DOMAIN}",headers=h).json()
    if r.get("success"):
        return r["result"][0]["id"]
    sys.exit(1)

def create_dns(zone, sub, ip):
    safe_print(f"[*] 创建DNS记录 {sub}.{DOMAIN} → {ip}")
    data = {"type":"A","name":f"{sub}.{DOMAIN}","content":ip,"ttl":60,"proxied":False}
    h = {"X-Auth-Email":CLOUDFLARE_EMAIL,"X-Auth-Key":GLOBAL_KEY,"Content-Type":"application/json"}
    r = requests.post(f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records",json=data,headers=h)
    if r.status_code == 200:
        return f"{sub}.{DOMAIN}"
    sys.exit(1)

def install_cert(full_domain):
    safe_print(f"[*] ACME申请证书 for {full_domain}")
    cmd = ["/root/.acme.sh/acme.sh","--issue","--server","letsencrypt","--dns","dns_cf","-d",full_domain,"--key-file",TEMP_KEY_PATH,"--fullchain-file",TEMP_FULLCHAIN_PATH,"--force"]
    p = subprocess.run(cmd, text=True, stdout=sys.stdout, stderr=subprocess.STDOUT)
    if p.returncode != 0:
        safe_print("[x] 证书申请失败")
        sys.exit(1)

def find_port():
    while True:
        port = random.randint(20001, 65535)
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port

def generate_config(full, provider, country):
    uid = str(uuid.uuid4())
    port = find_port()
    path = "/v2"
    cfg = {"ps":f"{provider}-{country}","add":full,"port":str(port),"id":uid,"aid":0,"net":"ws","type":"none","host":full,"path":path,"tls":"tls"}
    import base64
    vmess = "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()
    return cfg, vmess

def write_xray(cfg):
    server_cfg = {
      "dns": {"servers": ["https://doh.pub/dns-query"]},
      "log": {"loglevel": "warning"},
      "inbounds": [{
        "port": int(cfg["port"]),
        "protocol": "vmess",
        "settings": {"clients":[{"id":cfg["id"],"alterId":0}]},
        "streamSettings": {
          "network":"ws",
          "security":"tls",
          "tlsSettings":{"certificates":[{"certificateFile": FINAL_FULLCHAIN_PATH, "keyFile": FINAL_KEY_PATH}]},
          "wsSettings":{"path": cfg["path"]}
        }
      }],
      "outbounds":[{"protocol":"freedom"}]
    }
    os.makedirs("/usr/local/etc/xray", exist_ok=True)
    with open("/usr/local/etc/xray/config.json","w") as f:
        json.dump(server_cfg,f,indent=2)

def send_tg(msg):
    if not TG_BOT_TOKEN: return
    try:
        requests.post(f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",json={"chat_id":TG_CHAT_ID,"text":msg})
    except: pass

org, country, cc = get_ip_info()
zone = get_zone_id()
ip = get_public_ip()
sub = f"{org[:3].lower()}-{cc.lower()}-{''.join(random.choices(string.ascii_lowercase+string.digits, k=3))}"
full_domain = create_dns(zone, sub, ip)

time.sleep(15)
install_cert(full_domain)
cfg, link = generate_config(full_domain, org[:3], country)
write_xray(cfg)

print("\n节点生成成功:")
print(f"名称: {cfg['ps']}")
print(f"链接: {link}\n")

send_tg(f"新节点部署成功:\n{link}")
EOF

# --- 步骤5: 安装/更新 Xray ---
echo "[*] 安装/更新 Xray..."
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

    echo "[√] 证书设置完成"
else
    echo "[x] 未找到证书，请检查 ACME 执行日志"
    exit 1
fi

# --- 重启 Xray ---
systemctl restart xray
sleep 2

# --- 验证 ---
if systemctl is-active --quiet xray; then
    echo "================================================="
    echo "  🎉 v2 部署完成，节点可用！"
    echo "================================================="
else
    echo "[x] Xray 启动失败，请查看日志: journalctl -u xray -f"
fi
