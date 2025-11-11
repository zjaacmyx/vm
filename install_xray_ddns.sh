#!/bin/bash
set -e

# ==============================================================================
# 一键部署 Xray + 智能 Cloudflare DDNS (含 systemd 定时自动更新)
# ==============================================================================

# -------------------[ 用户配置区 ]-------------------
CLOUDFLARE_EMAIL="zjaacg@gmail.com"
GLOBAL_KEY="4a2cbf42292cb56d6b3e3828a0c4c03fe3a48"
DOMAIN="aack.eu.org"

TG_BOT_TOKEN="6373113358:AAEFSlUzIc_PBJLamGS4enmejWidYiHnlO8"
TG_CHAT_ID="5270368345"

DOH_SERVER="https://anycast.dns.nextdns.io/dns-query"
DDNS_ZONE_ID="5bcd4f03195a971cebd370e70161ed7d"

DDNS_RECORD_FILE="/root/ddns_domain.txt"
# ----------------------------------------------------

clear
echo "================================================="
echo " 🚀 Xray + 智能 DDNS 一键部署启动"
echo "================================================="

# -------------------[ 系统依赖 ]-------------------
echo "[1/11] 安装依赖..."
apt update -y >/dev/null
apt install -y python3 python3-pip curl wget socat dos2unix >/dev/null
pip3 install -U requests >/dev/null
echo "[√] 系统依赖安装完成"
echo

# -------------------[ acme.sh ]-------------------
if [ ! -f "/root/.acme.sh/acme.sh" ]; then
  echo "[2/11] 安装 acme.sh..."
  curl -s https://get.acme.sh | sh >/dev/null
else
  echo "[2/11] acme.sh 已存在，跳过"
fi
export CF_Key="$GLOBAL_KEY"
export CF_Email="$CLOUDFLARE_EMAIL"

# -------------------[ 安装 Xray ]-------------------
echo "[3/11] 安装或更新 Xray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null
echo "[√] Xray 安装完成"
echo

# -------------------[ Python 主逻辑 ]-------------------
echo "[4/11] 执行主配置逻辑..."
python3 - <<EOF
import requests, json, subprocess, time, uuid, random, string, os

EMAIL = "$CLOUDFLARE_EMAIL"
KEY = "$GLOBAL_KEY"
DOMAIN = "$DOMAIN"
ZONE = "$DDNS_ZONE_ID"
TG_TOKEN = "$TG_BOT_TOKEN"
TG_CHAT = "$TG_CHAT_ID"
DOH = "$DOH_SERVER"
RECORD_FILE = "$DDNS_RECORD_FILE"

def safe_print(x): print(x, flush=True)

def get_ip():
    try: return requests.get("https://api.ipify.org").text.strip()
    except: return "0.0.0.0"

def list_records(sub):
    url=f"https://api.cloudflare.com/client/v4/zones/{ZONE}/dns_records?type=A&name={sub}"
    h={"X-Auth-Email":EMAIL,"X-Auth-Key":KEY}
    return requests.get(url,headers=h).json().get("result",[])

def create_record(sub,ip):
    data={"type":"A","name":sub,"content":ip,"ttl":120,"proxied":False}
    h={"X-Auth-Email":EMAIL,"X-Auth-Key":KEY,"Content-Type":"application/json"}
    requests.post(f"https://api.cloudflare.com/client/v4/zones/{ZONE}/dns_records",headers=h,json=data)

def ensure_subdomain():
    if os.path.exists(RECORD_FILE):
        sub = open(RECORD_FILE).read().strip()
        if sub: return sub
    rand = ''.join(random.choices(string.ascii_lowercase+string.digits,k=5))
    sub = f"auto-{rand}.{DOMAIN}"
    open(RECORD_FILE,"w").write(sub)
    return sub

def issue_cert(sub):
    subprocess.run(["/root/.acme.sh/acme.sh","--issue","--dns","dns_cf","-d",sub,
                    "--key-file","/root/private.key","--fullchain-file","/root/cert.crt","--force"],
                    check=True)

def write_xray(sub,port,uuidv4):
    cfg={
      "log":{"loglevel":"warning"},
      "dns":{"servers":[DOH]},
      "inbounds":[{
        "port":port,"protocol":"vmess",
        "settings":{"clients":[{"id":uuidv4,"alterId":0}]},
        "streamSettings":{
          "network":"ws","security":"tls",
          "tlsSettings":{"certificates":[{"certificateFile":"/usr/local/etc/xray/cert.crt","keyFile":"/usr/local/etc/xray/private.key"}]},
          "wsSettings":{"path":"/v2"}
        }}],
      "outbounds":[{"protocol":"freedom"}]
    }
    os.makedirs("/usr/local/etc/xray",exist_ok=True)
    with open("/usr/local/etc/xray/config.json","w") as f: json.dump(cfg,f,indent=2)

def notify(msg):
    if not TG_TOKEN: return
    try:
        requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                      json={"chat_id":TG_CHAT,"text":msg,"parse_mode":"Markdown"})
    except: pass

def main():
    sub = ensure_subdomain()
    ip = get_ip()
    safe_print(f"[*] 当前公网IP: {ip}")
    if not list_records(sub):
        safe_print(f"[*] Cloudflare 无记录，正在创建 {sub}...")
        create_record(sub,ip)
    else:
        safe_print(f"[√] 记录已存在: {sub}")
    time.sleep(10)
    safe_print("[*] 申请证书...")
    issue_cert(sub)
    port=random.randint(20000,60000)
    uid=str(uuid.uuid4())
    write_xray(sub,port,uid)
    msg=f"✅ 新节点部署成功\\nDomain: `{sub}`\\nPort: `{port}`\\nUUID: `{uid}`"
    notify(msg)
    safe_print(msg)

main()
EOF

# -------------------[ 权限 & 服务启动 ]-------------------
echo "[5/11] 设置证书权限..."
XRAY_USER=$(systemctl show -p User xray | cut -d= -f2)
[ -z "$XRAY_USER" ] && XRAY_USER="nobody"
XRAY_GROUP=$(id -gn "$XRAY_USER" 2>/dev/null || echo nogroup)
mkdir -p /usr/local/etc/xray
mv -f /root/cert.crt /usr/local/etc/xray/cert.crt 2>/dev/null || true
mv -f /root/private.key /usr/local/etc/xray/private.key 2>/dev/null || true
chown "$XRAY_USER:$XRAY_GROUP" /usr/local/etc/xray/*.crt /usr/local/etc/xray/*.key 2>/dev/null || true
echo "[√] 权限设置完成"
echo

# -------------------[ 重启 Xray ]-------------------
echo "[6/11] 重启 Xray..."
systemctl restart xray
sleep 2
systemctl is-active --quiet xray && echo "[√] Xray 正常运行" || echo "[x] Xray 启动失败"
echo

# -------------------[ 智能 DDNS 脚本 ]-------------------
echo "[7/11] 写入智能 DDNS 脚本..."
cat >/root/cf_ddns.py <<'EOF'
import requests, json, time, os
EMAIL="'"$CLOUDFLARE_EMAIL"'"
KEY="'"$GLOBAL_KEY"'"
ZONE="'"$DDNS_ZONE_ID"'"
FILE="'"$DDNS_RECORD_FILE"'"

def get_ip(): return requests.get("https://api.ipify.org").text.strip()
def get_sub():
    if os.path.exists(FILE): return open(FILE).read().strip()
    return None
def get_record_id(sub):
    u=f"https://api.cloudflare.com/client/v4/zones/{ZONE}/dns_records?type=A&name={sub}"
    h={"X-Auth-Email":EMAIL,"X-Auth-Key":KEY}
    r=requests.get(u,headers=h).json()
    if r.get("result"): return r["result"][0]["id"]
def update_dns(sub,ip,rec):
    u=f"https://api.cloudflare.com/client/v4/zones/{ZONE}/dns_records/{rec}"
    h={"X-Auth-Email":EMAIL,"X-Auth-Key":KEY,"Content-Type":"application/json"}
    d={"type":"A","name":sub,"content":ip,"ttl":120,"proxied":False}
    return requests.put(u,headers=h,json=d).json()

if __name__=="__main__":
    print(f"\n==== Cloudflare DDNS 检查启动 {time.ctime()} ====")
    sub=get_sub()
    if not sub:
        print("[x] 未找到本地子域配置，跳过。")
        exit(0)
    rid=get_record_id(sub)
    ip=get_ip()
    if rid:
        res=update_dns(sub,ip,rid)
        print("[√] 更新成功" if res.get("success") else "[x] 更新失败", res)
    else:
        print("[!] 找不到记录，请重新部署。")
EOF

# -------------------[ systemd 服务 + timer ]-------------------
echo "[8/11] 创建 systemd 服务 + 定时任务..."
cat >/etc/systemd/system/cf-ddns-check.service <<'EOF'
[Unit]
Description=Cloudflare DDNS 定时更新服务
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /root/cf_ddns.py
StandardOutput=append:/root/cf_ddns.log
StandardError=append:/root/cf_ddns.log
EOF

cat >/etc/systemd/system/cf-ddns-check.timer <<'EOF'
[Unit]
Description=每 30 分钟检查并更新 Cloudflare DDNS

[Timer]
OnBootSec=15s
OnUnitActiveSec=30min
Unit=cf-ddns-check.service

[Install]
WantedBy=multi-user.target
EOF

dos2unix /root/cf_ddns.py /etc/systemd/system/cf-ddns-check.service /etc/systemd/system/cf-ddns-check.timer >/dev/null || true
systemctl daemon-reload
systemctl enable cf-ddns-check.timer
systemctl start cf-ddns-check.timer
echo "[√] DDNS 定时器已启用"
echo

# -------------------[ 立即执行一次 ]-------------------
echo "[9/11] 立即执行 DDNS 更新..."
python3 /root/cf_ddns.py | tee -a /root/cf_ddns.log

# -------------------[ 状态展示 ]-------------------
echo "[10/11] 查看定时任务状态:"
systemctl list-timers | grep cf-ddns-check
echo

echo "[11/11] ✅ 部署完成！"
echo "-------------------------------------------------"
echo "📄 子域文件: $DDNS_RECORD_FILE"
echo "📄 DDNS 日志: /root/cf_ddns.log"
echo "⏱️ 定时更新: 每 30 分钟自动执行"
echo "-------------------------------------------------"
