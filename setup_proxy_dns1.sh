#!/bin/bash

# ==============================================================================
# 全自动 VMess + WS + TLS 节点部署脚本 (集成指定DNS最终版)
#
# 更新: 1. 在Xray配置中加入您指定的单一DNS-over-HTTPS服务器。
#       2. 智能检测Xray服务的运行用户(User)和对应的用户组(Group)。
#
# 安全警告: 此脚本包含敏感信息，请勿泄露。
# ==============================================================================

# 清屏
clear

# --- 步骤 1: 预先配置您的所有信息 ---
CLOUDFLARE_EMAIL="zjaacg@gmail.com"
GLOBAL_KEY="4a2cbf42292cb56d6b3e3828a0c4c03fe3a48"
DOMAIN="aack.eu.org"

# --- 预填您的 Telegram Bot 信息 ---
TG_BOT_TOKEN="6373113358:AAEFSlUzIc_PBJLamGS4enmejWidYiHnlO8"
TG_CHAT_ID="5270368345"


# --- 检查Cloudflare信息是否已填写 ---
if [[ -z "$CLOUDFLARE_EMAIL" || -z "$GLOBAL_KEY" || -z "$DOMAIN" ]]; then
    echo "错误: 脚本顶部的 CLOUDFLARE_EMAIL, GLOBAL_KEY, 和 DOMAIN 变量不能为空！"
    exit 1
fi
echo "================================================="
echo " 配置信息已加载，准备开始执行..."
echo " 邮箱: $CLOUDFLARE_EMAIL"
echo " 域名: $DOMAIN"
if [[ -n "$TG_BOT_TOKEN" && -n "$TG_CHAT_ID" ]]; then
    echo " TG推送: 已配置"
fi
echo "================================================="
echo

# --- 步骤 2: 安装系统依赖 ---
echo "[*] 正在更新软件包列表并安装必要的系统依赖..."
apt update -y > /dev/null 2>&1
apt install -y python3 python3-pip curl socat > /dev/null 2>&1
pip3 install requests --quiet --disable-pip-version-check --no-python-version-warning
echo "[√] 系统依赖安装完成。"
echo

# --- 步骤 3: 检测并安装 acme.sh ---
if [ ! -f "/root/.acme.sh/acme.sh" ]; then
    echo "[*] acme.sh 未安装，正在为您自动安装..."
    curl -s https://get.acme.sh | sh > /dev/null 2>&1
    echo "[√] acme.sh 安装完成。"
else
    echo "[*] acme.sh 已安装，跳过安装步骤。"
fi
echo

# --- 步骤 4: 设置 acme.sh 所需的环境变量 ---
export CF_Key="$GLOBAL_KEY"
export CF_Email="$CLOUDFLARE_EMAIL"

# --- 步骤 5: 运行核心配置的 Python 脚本 ---
echo "[*] 正在执行核心配置脚本 (域名申请、证书生成)..."
python3 - "$CLOUDFLARE_EMAIL" "$GLOBAL_KEY" "$DOMAIN" "$TG_BOT_TOKEN" "$TG_CHAT_ID" <<'EOF'
import random
import string
import requests
import json
import subprocess
import uuid
import sys
import os
import socket

# 从命令行参数读取变量
if len(sys.argv) < 6:
    print("[x] 错误: 脚本参数不足。")
    sys.exit(1)

CLOUDFLARE_EMAIL = sys.argv[1]
GLOBAL_KEY = sys.argv[2]
DOMAIN = sys.argv[3]
TG_BOT_TOKEN = sys.argv[4]
TG_CHAT_ID = sys.argv[5]

# 定义临时路径和最终路径
TEMP_KEY_PATH = "/root/private.key"
TEMP_FULLCHAIN_PATH = "/root/cert.crt"
FINAL_KEY_PATH = "/usr/local/etc/xray/private.key"
FINAL_FULLCHAIN_PATH = "/usr/local/etc/xray/cert.crt"


def safe_print(message):
    print(message, flush=True)

def get_ip_info():
    """通过API获取IP的服务商和国家信息"""
    try:
        safe_print("[*] 正在检测IP归属地和服务商...")
        response = requests.get("http://ip-api.com/json/?fields=status,country,countryCode,isp,org", timeout=5).json()
        if response.get("status") == "success":
            org_name = response.get("org", "").lower()
            country_name_en = response.get("country", "Unknown")
            country_code = response.get("countryCode", "xx").lower()
            provider = "VPS"
            if "microsoft" in org_name: provider = "AZ"
            elif "amazon" in org_name: provider = "AWS"
            elif "google" in org_name: provider = "GCP"
            elif "oracle" in org_name: provider = "OCI"
            elif "vultr" in org_name: provider = "Vultr"
            elif "digitalocean" in org_name: provider = "DO"
            country_map = {"South Korea": "韩国", "Japan": "日本", "Hong Kong": "香港", "Taiwan": "台湾", "Singapore": "新加坡", "United States": "美国", "United Kingdom": "英国", "Germany": "德国", "France": "法国", "Netherlands": "荷兰", "Russia": "俄罗斯", "Canada": "加拿大", "Australia": "澳大利亚", "Malaysia": "马来西亚", "Thailand": "泰国"}
            country_name_cn = country_map.get(country_name_en, country_name_en)
            safe_print(f"[√] IP信息识别成功: {provider} - {country_name_cn} ({country_code})")
            return provider, country_name_cn, country_code
        else:
            safe_print("[!] IP信息检测失败，将使用默认值。")
            return "VPS", "Unknown", "xx"
    except Exception as e:
        safe_print(f"[!] 获取IP信息时发生错误: {e}")
        return "VPS", "Unknown", "xx"

def get_zone_id():
    url = f"https://api.cloudflare.com/client/v4/zones?name={DOMAIN}"
    headers = {"X-Auth-Email": CLOUDFLARE_EMAIL, "X-Auth-Key": GLOBAL_KEY, "Content-Type": "application/json"}
    try:
        response = requests.get(url, headers=headers, timeout=10).json()
        if response.get("success") and len(response.get("result", [])) > 0:
            return response["result"][0]["id"]
        else:
            safe_print(f"[x] 错误: 无法通过域名 '{DOMAIN}' 获取 Zone ID。")
            sys.exit(1)
    except Exception as e:
        safe_print(f"[x] 获取 Zone ID 时发生网络错误: {e}")
        sys.exit(1)

def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org", timeout=5)
        response.raise_for_status()
        return response.text.strip()
    except Exception as e:
        safe_print(f"[x] 错误: 获取公网 IP 失败: {e}")
        sys.exit(1)

def generate_subdomain(provider, country_code):
    random_chars = ''.join(random.choices(string.ascii_lowercase + string.digits, k=3))
    return f"{provider.lower()}-{country_code}-{random_chars}"

def create_dns_record(zone_id, subdomain, ip):
    full_domain = f"{subdomain}.{DOMAIN}"
    safe_print(f"[*] 正在为 {full_domain} 创建 DNS A 记录...")
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    headers = {"X-Auth-Email": CLOUDFLARE_EMAIL, "X-Auth-Key": GLOBAL_KEY, "Content-Type": "application/json"}
    data = {"type": "A", "name": full_domain, "content": ip, "ttl": 60, "proxied": False}
    response = requests.post(url, headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        safe_print(f"[√] DNS 记录创建成功: {full_domain} -> {ip} (代理已关闭, TTL=1分钟)")
        return full_domain
    else:
        safe_print(f"[x] 错误: 创建 DNS 记录失败: {response.text}")
        sys.exit(1)

def install_certificate(full_domain):
    safe_print(f"[*] 正在为 {full_domain} 申请 SSL 证书 (这可能需要1-2分钟)...")
    command = ["/root/.acme.sh/acme.sh", "--issue", "--server", "letsencrypt", "--dns", "dns_cf", "-d", full_domain, "--key-file", TEMP_KEY_PATH, "--fullchain-file", TEMP_FULLCHAIN_PATH, "--force"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in iter(process.stdout.readline, ''):
        sys.stdout.write(f"    {line}")
        sys.stdout.flush()
    process.wait()
    if process.returncode != 0:
        safe_print(f"[x] 错误: 证书申请失败。")
        sys.exit(1)
    safe_print(f"[√] 证书已成功申请并安装!")

def find_available_port(start=20001, end=65535):
    """查找一个可用的随机端口"""
    while True:
        port = random.randint(start, end)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('127.0.0.1', port)) != 0:
                safe_print(f"[*] 已生成可用随机端口: {port}")
                return port

def generate_vmess_config(full_domain, provider, country_name_cn, port):
    """生成 VMess 客户端配置"""
    profile_name = f"{provider}-{country_name_cn}"
    vmess_config = {"v": "2", "ps": profile_name, "add": full_domain, "port": str(port), "id": str(uuid.uuid4()), "aid": 0, "net": "ws", "type": "none", "host": full_domain, "path": "/v2", "tls": "tls"}
    import base64
    vmess_link = "vmess://" + base64.b64encode(json.dumps(vmess_config, separators=(',', ':')).encode('utf-8')).decode('utf-8')
    return vmess_config, vmess_link

def write_xray_config(vmess_config):
    safe_print("[*] 正在生成并写入 Xray 服务端配置文件...")
    server_config = {
      "dns": {
        "servers": [
          "https://dns.yuguan.xyz/dns-query",
          "https://doh.360.cn/dns-query",
          "https://cloudflare-dns.com/dns-query",
          "https://dns.adguard-dns.com/dns-query",
          "https://dns0.eu/dns-query"
        ]
      },
      "log": {"loglevel": "warning"},
      "inbounds": [{
        "port": int(vmess_config['port']),
        "protocol": "vmess",
        "settings": {
          "clients": [
            {"id": vmess_config['id'], "alterId": 0}
          ]
        },
        "streamSettings": {
          "network": "ws",
          "security": "tls",
          "tlsSettings": {
            "certificates": [
              {
                "certificateFile": FINAL_FULLCHAIN_PATH,
                "keyFile": FINAL_KEY_PATH
              }
            ]
          },
          "wsSettings": {
            "path": vmess_config['path']
          }
        }
      }],
      "outbounds": [
        {"protocol": "freedom"}
      ]
    }
    try:
        os.makedirs("/usr/local/etc/xray", exist_ok=True)
        with open("/usr/local/etc/xray/config.json", "w") as f:
            json.dump(server_config, f, indent=2)
        safe_print("[√] 服务端配置文件写入成功: /usr/local/etc/xray/config.json")
    except Exception as e:
        safe_print(f"[x] 错误: 写入服务端配置文件失败: {e}")
        sys.exit(1)


def send_telegram_notification(token, chat_id, message):
    if not token or not chat_id: return
    safe_print("[*] 正在向 Telegram 推送节点信息...")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {'chat_id': chat_id, 'text': message, 'parse_mode': 'Markdown'}
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            safe_print("[√] Telegram 推送成功！")
        else:
            safe_print(f"[x] 错误: Telegram 推送失败: {response.text}")
    except Exception as e:
        safe_print(f"[x] 错误: 推送到 Telegram 时发生网络错误: {e}")

def main():
    provider, country_name_cn, country_code = get_ip_info()
    zone_id = get_zone_id()
    vps_ip = get_public_ip()
    subdomain = generate_subdomain(provider, country_code)
    full_domain = create_dns_record(zone_id, subdomain, vps_ip)
    
    safe_print("[*] 等待 15 秒，以确保 DNS 全局生效...")
    import time
    time.sleep(15)

    install_certificate(full_domain)
    
    random_port = find_available_port()
    vmess_config, vmess_link = generate_vmess_config(full_domain, provider, country_name_cn, random_port)
    
    write_xray_config(vmess_config)
    
    print("\n----------------- 客户端配置 -----------------")
    print(f" 节点名称: {vmess_config['ps']}")
    print(f" 端口: {vmess_config['port']}")
    print(f" V2Ray / Xray 客户端导入链接 (VMess Link):")
    print(f"\n{vmess_link}\n")
    print("-------------------------------------------------")
    
    notification_message = (
        f"✅ *新节点部署成功*\n\n"
        f"*节点备注:* `{vmess_config['ps']}`\n"
        f"*地址 (Address):* `{vmess_config['add']}`\n"
        f"*端口 (Port):* `{vmess_config['port']}`\n"
        f"*UUID:* `{vmess_config['id']}`\n\n"
        f"*一键导入链接 (点击即可复制):*\n`{vmess_link}`"
    )
    send_telegram_notification(TG_BOT_TOKEN, TG_CHAT_ID, notification_message)

if __name__ == "__main__":
    main()
EOF

# --- 步骤 6: 安装并配置 Xray 服务端 ---
echo "[*] 正在执行/更新 Xray 安装，以确保用户和环境正确..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install > /dev/null 2>&1
echo "[√] Xray 安装/更新完成。"
echo


# --- 步骤 7: 移动证书并设置权限 (智能检测用户和用户组) ---
echo "[*] 正在移动证书到 Xray 可访问的目录并设置权限..."

# 智能检测Xray服务的运行用户
XRAY_USER=$(grep -oP '^User=\K.*' /etc/systemd/system/xray.service)

if [ -z "$XRAY_USER" ]; then
    echo "[!] 未能自动检测到Xray用户，将尝试使用 'nobody' 作为备用。"
    XRAY_USER="nobody"
fi
echo "[*] 检测到Xray服务运行用户为: $XRAY_USER"

# 智能检测该用户的用户组
XRAY_GROUP=$(id -gn "$XRAY_USER")
if [ $? -ne 0 ] || [ -z "$XRAY_GROUP" ]; then
    echo "[!] 未能自动检测到用户 '$XRAY_USER' 的用户组，将尝试使用 'nogroup' 作为备用。"
    XRAY_GROUP="nogroup"
fi
echo "[*] 检测到对应的用户组为: $XRAY_GROUP"


if [ -f /root/cert.crt ] && [ -f /root/private.key ]; then
    mkdir -p /usr/local/etc/xray
    mv /root/cert.crt /usr/local/etc/xray/cert.crt
    mv /root/private.key /usr/local/etc/xray/private.key
    
    # 使用检测到的用户和用户组来设置所有权
    chown "$XRAY_USER:$XRAY_GROUP" /usr/local/etc/xray/cert.crt
    chown "$XRAY_USER:$XRAY_GROUP" /usr/local/etc/xray/private.key
    
    echo "[√] 证书移动和权限设置完成。"
else
    echo "[!] 未找到生成的证书文件，跳过移动步骤。Xray可能会启动失败。"
fi
echo


# --- 步骤 8: 重启 Xray 服务 ---
echo "[*] 正在重启 Xray 服务以应用新配置..."
systemctl restart xray
echo "[*] 等待2秒让服务启动..."
sleep 2

# --- 步骤 9: 检查最终状态 ---
echo "[*] 检查 Xray 服务状态..."
if systemctl is-active --quiet xray; then
    echo "[√] Xray 服务正在运行！"
    echo
    echo "================================================="
    echo " ✅  部署完成！节点已可用！ "
    echo "================================================="
else
    echo "[x] 错误: Xray 服务启动失败！请手动检查配置和日志。"
    echo "   - 检查日志: journalctl -u xray -f"
    echo "   - 检查配置: cat /usr/local/etc/xray/config.json"
fi
