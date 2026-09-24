var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.js
var index_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const domain = url.origin;
    const WEB_USER = env.WEB_USER || "admin";
    const WEB_PASS = env.WEB_PASS || "admin888";
    const PROXY_USER = env.PROXY_USER || "proxy";
    const PROXY_PASS = env.PROXY_PASS || "888888";
    const authenticate = /* @__PURE__ */ __name((request2) => {
      const authHeader = request2.headers.get("Authorization");
      if (!authHeader) return false;
      const [scheme, encoded] = authHeader.split(" ");
      if (scheme !== "Basic") return false;
      try {
        const decoded = atob(encoded);
        const [username, password] = decoded.split(":");
        return username === WEB_USER && password === WEB_PASS;
      } catch (e) {
        return false;
      }
    }, "authenticate");
    const unauthorizedResponse = /* @__PURE__ */ __name(() => {
      return new Response("Unauthorized Access. Scanner Blocked.", {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Basic realm="Proxy System Security Control"',
          "Content-Type": "text/plain;charset=UTF-8"
        }
      });
    }, "unauthorizedResponse");
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS servers (
        ip TEXT PRIMARY KEY,
        details TEXT,
        last_seen INTEGER,
        stats TEXT
      )
    `).run();
    await env.DB.prepare(`ALTER TABLE servers ADD COLUMN stats TEXT`).run().catch(() => {
    });
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS server_logs (
        ip TEXT PRIMARY KEY,
        logs TEXT,
        updated_at INTEGER
      )
    `).run();
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS global_config (
        key TEXT PRIMARY KEY,
        value TEXT
      )
    `).run();
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS instance_config (
        ip TEXT PRIMARY KEY,
        country TEXT,
        port INTEGER,
        switch_trigger INTEGER DEFAULT 0,
        enabled INTEGER DEFAULT 1,
        updated_at INTEGER
      )
    `).run();
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS agent_instances (
        instance_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        ip TEXT NOT NULL,
        country TEXT NOT NULL DEFAULT 'JP',
        port INTEGER NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        switch_trigger INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `).run();
    await env.DB.prepare(`ALTER TABLE agent_instances ADD COLUMN remark TEXT NOT NULL DEFAULT ''`).run().catch(() => {
    });
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS agent_reports (
        instance_id TEXT PRIMARY KEY,
        ip TEXT NOT NULL, details TEXT NOT NULL DEFAULT '[]',
        stats TEXT NOT NULL DEFAULT '{}', logs TEXT, last_seen INTEGER NOT NULL
      )
    `).run();
    if (url.pathname === "/scripts/proxy_server.py") {
      const PROXY_CODE = `#!/usr/bin/env python3
from __future__ import annotations
import select, socket, threading, urllib.parse, time, base64
from typing import Any

PROXY_USER = b"${PROXY_USER}"
PROXY_PASS = b"${PROXY_PASS}"

# \u5168\u5C40\u8F6F\u5F00\u5173\uFF1A\u7531 lite_manager \u52A8\u6001\u66F4\u65B0\uFF0C\u5B9E\u73B0\u79D2\u5207
ACTIVE_BIND = "tun_main"

def parse_int(value: Any) -> int:
    try: return int(value)
    except: return 0

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk: raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data

def create_connection(address: tuple[str, int], timeout: float = 20) -> socket.socket:
    global ACTIVE_BIND
    bind_interface = ACTIVE_BIND
    host, port = address
    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            if bind_interface:
                sock.setsockopt(socket.SOL_SOCKET, 25, bind_interface.encode('utf-8'))
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            if sock: sock.close()
    raise err or OSError("getaddrinfo empty")

def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored: return
        for source in readable:
            target = right if source is left else left
            data = source.recv(65536)
            if not data: return
            target.sendall(data)

def socks5_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)
        
        if b"\\x02" not in methods:
            client.sendall(b"\\x05\\xFF") 
            return
        client.sendall(b"\\x05\\x02")
        
        auth_req = recv_exact(client, 2)
        if auth_req[0] != 1: return
        ulen = auth_req[1]
        uname = recv_exact(client, ulen)
        plen = recv_exact(client, 1)[0]
        upass = recv_exact(client, plen)
        
        if uname != PROXY_USER or upass != PROXY_PASS:
            client.sendall(b"\\x01\\x01") 
            return
        client.sendall(b"\\x01\\x00") 

        version, command, _, address_type = recv_exact(client, 4)
        if version != 5 or command != 1: return
        if address_type == 1: host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3: host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4: host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else: return
        port = int.from_bytes(recv_exact(client, 2), "big")
        
        upstream = create_connection((host, port), timeout=20)
        client.sendall(b"\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00")
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def http_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
        data = first_byte
        while b"\\r\\n\\r\\n" not in data and len(data) < 65536:
            chunk = client.recv(4096)
            if not chunk: break
            data += chunk
        head, rest = data.split(b"\\r\\n\\r\\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\\r\\n")
        
        expected_auth = "Basic " + base64.b64encode(PROXY_USER + b":" + PROXY_PASS).decode("ascii")
        auth_passed = False
        for line in lines[1:]:
            if line.lower().startswith("proxy-authorization:"):
                if line.split(":", 1)[1].strip() == expected_auth:
                    auth_passed = True
                    break
                    
        if not auth_passed:
            client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\\r\\nProxy-Authenticate: Basic realm=\\"Proxy\\"\\r\\n\\r\\n")
            return

        method, target, version = lines[0].split(" ", 2)
        if method.upper() == "CONNECT":
            host, _, port_text = target.partition(":")
            upstream = create_connection((host, parse_int(port_text) or 443), timeout=20)
            client.sendall(b"HTTP/1.1 200 Connection Established\\r\\n\\r\\n")
            if rest: upstream.sendall(rest)
            relay(client, upstream)
            return
        parsed = urllib.parse.urlsplit(target)
        if not parsed.hostname: return
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = [line for line in lines[1:] if not line.lower().startswith(("proxy-connection:", "connection:", "proxy-authorization:"))]
        request = f"{method} {path} {version}\\r\\n" + "\\r\\n".join(headers) + "\\r\\nConnection: close\\r\\n\\r\\n"
        upstream = create_connection((parsed.hostname, port), timeout=20)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def proxy_client(client: socket.socket, address: tuple[str, int]) -> None:
    try:
        client.settimeout(30)
        first = recv_exact(client, 1)
        if first == b"\\x05": socks5_client(client, first)
        else: http_client(client, first)
    except:
        try: client.close()
        except: pass

def start_proxy_server(host: str, port: int) -> None:
    try:
        # \u652F\u6301\u53CC\u6808\uFF1A\u5224\u65AD\u5730\u5740\u4E2D\u662F\u5426\u5305\u542B\u5192\u53F7\u4EE5\u542F\u7528 AF_INET6
        af = socket.AF_INET6 if ":" in host else socket.AF_INET
        server = socket.socket(af, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # \u5F3A\u5236\u89E3\u9664 V6ONLY\uFF0C\u5141\u8BB8\u4E00\u4E2A IPv6 Socket \u540C\u65F6\u63A5\u6536 IPv4 \u548C IPv6 \u8FDE\u63A5
        if af == socket.AF_INET6:
            try:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except:
                pass
        server.bind((host, port))
        server.listen(256)
    except Exception as e: return
    while True:
        try:
            client, address = server.accept()
            threading.Thread(target=proxy_client, args=(client, address), daemon=True).start()
        except: time.sleep(0.5)
`;
      return new Response(PROXY_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }
    if (url.pathname === "/scripts/lite_manager.py") {
      const MANAGER_CODE = `#!/usr/bin/env python3
import base64, csv, os, subprocess, threading, time, urllib.request, urllib.parse, json
from pathlib import Path
import proxy_server

API_URL = "https://www.vpngate.net/api/iphone/"
C2_URL = "${domain}"

WORKSPACE = Path(os.getenv("INSTALL_DIR", "/opt/proxy_lite"))
CONFIG_DIR = WORKSPACE / "configs"
AUTH_FILE = WORKSPACE / "auth.txt"
INSTANCE_ID = os.getenv("INSTANCE_ID", "legacy-" + os.getenv("PROXY_PORT", "7920"))
SERVICE_NAME = os.getenv("SERVICE_NAME", "proxy-lite.service")
TUN_MAIN_NAME = os.getenv("TUN_MAIN", "tun_main")
TUN_BACKUP_NAME = os.getenv("TUN_BACKUP", "tun_backup")

WEB_USER = "${WEB_USER}"
WEB_PASS = "${WEB_PASS}"

PROXY_PORT_ENV = os.getenv("PROXY_PORT")
PROXY_PORT = int(PROXY_PORT_ENV or "7920")
target_country = os.getenv("COUNTRY", "JP").upper()
last_switch_trigger = 0
switch_trigger_initialized = False

state_lock = threading.Lock()
dead_ips = set()
last_blacklist_clear = time.time()
public_ip = ""

global_node_reservoir = {}
node_attempts = {}
node_successes = {}
reservoir_lock = threading.Lock()

class Tunnel:
    def __init__(self, name: str, table_id: int):
        self.name = name
        self.table_id = table_id
        self.process = None
        self.node = None
        self.entry_ip = ""
        self.egress_ip = ""
        self.country = ""
        self.ready = False
        self.connected_at = 0
        self.is_connecting = False

tun_main = Tunnel(TUN_MAIN_NAME, int(os.getenv("TUN_MAIN_TABLE", "101")))
tun_backup = Tunnel(TUN_BACKUP_NAME, int(os.getenv("TUN_BACKUP_TABLE", "102")))

def penalize_node(ip: str, penalty: int):
    """
    \u8282\u70B9\u4FE1\u8A89\u52A8\u6001\u964D\u7EA7\u673A\u5236\uFF1A
    \u7ED9\u4E0D\u53EF\u7528\u6216\u4F4E\u8D28\u7684\u8282\u70B9\u52A0\u4E0A\u9AD8\u989D\u7684\u865A\u62DF ping \u503C\u60E9\u7F5A\uFF0C
    \u786E\u4FDD\u4E0B\u4E00\u6B21\u8C03\u5EA6\u6392\u5E8F\u65F6\uFF0C\u8BE5\u8282\u70B9\u88AB\u6C38\u4E45\u538B\u5165\u84C4\u6C34\u6C60\u5E95\u90E8\uFF0C\u4ECE\u800C\u907F\u514D"\u6B7B\u5FAA\u73AF\u5047\u6027\u67AF\u7AED"\u3002
    """
    with reservoir_lock:
        if ip in global_node_reservoir:
            global_node_reservoir[ip]["ping"] += penalty

def get_public_ip():
    global public_ip
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=5) as res:
            public_ip = res.read().decode("utf-8").strip()
    except: public_ip = "Unknown_IP"

def get_c2_headers():
    auth_ptr = base64.b64encode(f"{WEB_USER}:{WEB_PASS}".encode()).decode()
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Authorization": f"Basic {auth_ptr}"
    }

def get_recent_logs():
    try:
        res = subprocess.run(["journalctl", "-u", SERVICE_NAME, "-n", "30", "--no-pager", "--output=cat"], capture_output=True, text=True, errors="replace")
        return res.stdout
    except: return "暂无日志，等待上报..."

def update_config_loop():
    global target_country, last_switch_trigger, switch_trigger_initialized, PROXY_PORT, tun_main, tun_backup
    while True:
        try:
            req = urllib.request.Request(f"{C2_URL}/api/config", headers=get_c2_headers())
            with urllib.request.urlopen(req, timeout=10) as res:
                data = json.loads(res.read().decode("utf-8"))
                instance_data = {}
                try:
                    instance_url = f"{C2_URL}/api/instance-config?ip={urllib.parse.quote(public_ip)}&instance_id={urllib.parse.quote(INSTANCE_ID)}"
                    with urllib.request.urlopen(urllib.request.Request(instance_url, headers=get_c2_headers()), timeout=10) as instance_res:
                        instance_data = json.loads(instance_res.read().decode("utf-8"))
                except Exception:
                    pass
                desired_country = str(instance_data.get("country") or data.get("0", "JP")).upper()
                switch_trigger = max(int(data.get("switch_trigger", 0)), int(instance_data.get("switch_trigger", 0)))
                # Per-instance environment port is authoritative; never fall back to another Agent's global port.
                new_port = int(instance_data.get("port") or PROXY_PORT)
                
                if new_port != PROXY_PORT:
                    print(f"[*] \u6536\u5230\u7AEF\u53E3\u53D8\u66F4\u6307\u4EE4 ({PROXY_PORT} -> {new_port})\uFF0C\u91CD\u542F\u5B88\u62A4\u8FDB\u7A0B...", flush=True)
                    os._exit(0)
                
                with state_lock:
                    # The first controller response establishes the baseline. A
                    # switch_trigger already present before this Agent process
                    # started is historical and must not be replayed on restart.
                    if not switch_trigger_initialized:
                        last_switch_trigger = switch_trigger
                        switch_trigger_initialized = True
                        force_switch = False
                    else:
                        force_switch = (switch_trigger > last_switch_trigger)
                    if target_country != desired_country or force_switch:
                        target_country = desired_country
                        if force_switch: print(f"[*] \u6536\u5230\u5F3A\u5236\u66F4\u6362\u6307\u4EE4\uFF0C\u6B63\u5728\u6E05\u9000\u901A\u9053\u5E76\u62C9\u9ED1\u5F53\u524D IP...", flush=True)
                        else: print(f"[*] \u7B56\u7565\u70ED\u5207\u6362: \u76EE\u6807\u91CD\u5B9A\u5411\u5230 {desired_country}...", flush=True)
                        
                        if tun_main.entry_ip: dead_ips.add(tun_main.entry_ip)
                        if tun_main.process:
                            try: tun_main.process.terminate(); tun_main.process.wait(2)
                            except: tun_main.process.kill()
                        tun_main.ready = False; tun_main.process = None; tun_main.entry_ip = ""; tun_main.egress_ip = ""; tun_main.is_connecting = False
                        
                        if tun_backup.process:
                            try: tun_backup.process.terminate(); tun_backup.process.wait(2)
                            except: tun_backup.process.kill()
                        tun_backup.ready = False; tun_backup.process = None; tun_backup.entry_ip = ""; tun_backup.egress_ip = ""; tun_backup.is_connecting = False
                        
                        last_switch_trigger = switch_trigger
        except Exception as e: pass
        time.sleep(15)

def c2_heartbeat_loop():
    global public_ip, PROXY_PORT, tun_main, tun_backup
    while True:
        if not public_ip or public_ip == "Unknown_IP": get_public_ip()
        details = []
        with state_lock:
            for tun in [tun_main, tun_backup]:
                if tun.ready and tun.process and tun.process.poll() is None:
                    uptime = time.time() - tun.connected_at
                    details.append({
                        "tunnel": tun.name,
                        "active": proxy_server.ACTIVE_BIND == tun.name,
                        "country": tun.country, 
                        "port": PROXY_PORT, 
                        "connected_time": int(uptime), 
                        "node_ip": tun.egress_ip if tun.egress_ip else tun.entry_ip
                    })
        
        with reservoir_lock:
            country_stats = {}
            for node in global_node_reservoir.values():
                country = node.get("country", "??")
                item = country_stats.setdefault(country, {"total": 0, "available": 0, "attempts": 0, "successes": 0, "nodes": []})
                item["total"] += 1
                node_available = node.get("ip") not in dead_ips
                item["nodes"].append({"ip": node.get("ip"), "available": node_available})
                if node_available:
                    item["available"] += 1
                item["attempts"] += node_attempts.get(node.get("ip"), 0)
                item["successes"] += node_successes.get(node.get("ip"), 0)
            for item in country_stats.values():
                item["success_rate"] = round(item["successes"] * 100 / item["attempts"], 1) if item["attempts"] else None
        payload = json.dumps({"instance_id": INSTANCE_ID, "ip": public_ip, "details": details, "stats": country_stats, "logs": get_recent_logs()}).encode('utf-8')
        try:
            req = urllib.request.Request(f"{C2_URL}/api/report", data=payload, headers=get_c2_headers(), method='POST')
            urllib.request.urlopen(req, timeout=10)
        except Exception as e: pass
        time.sleep(8)

def setup_env():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text("vpn\\nvpn\\n", encoding="utf-8")
        AUTH_FILE.chmod(0o600)
    # \u5F3A\u5236\u7CFB\u7EDF\u89E3\u9664\u53CD\u5411\u8DEF\u5F84\u8FC7\u6EE4\uFF0C\u9632\u6B62\u7B56\u7565\u8DEF\u7531\u53CC\u62E8\u65F6\u6570\u636E\u5305\u88AB\u5185\u6838\u4E22\u5F03
    subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"], capture_output=True)
    subprocess.run(["sysctl", "-w", "net.ipv4.conf.default.rp_filter=2"], capture_output=True)

def harvest_snapshot_nodes() -> list:
    try:
        req = urllib.request.Request(API_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as res: text = res.read().decode("utf-8", errors="replace")
        lines = [line for line in text.splitlines() if line and not line.startswith("*")]
        if lines and lines[0].startswith("#"): lines[0] = lines[0][1:]
        nodes = []
        for row in csv.DictReader(lines):
            ip = row.get("IP")
            if not ip or not row.get("OpenVPN_ConfigData_Base64"): continue
            raw_ping = row.get("Ping", "")
            nodes.append({
                "ip": ip, 
                "ping": int(raw_ping) if raw_ping.isdigit() else 9999, 
                "country": row.get("CountryShort", "").upper(), 
                "config": base64.b64decode(row["OpenVPN_ConfigData_Base64"]).decode("utf-8", errors="replace"),
                "harvested_at": time.time()
            })
        return nodes
    except Exception as e: return []

def vpngate_fetch_loop():
    global global_node_reservoir, dead_ips
    while True:
        snapshot = harvest_snapshot_nodes()
        if snapshot:
            with reservoir_lock:
                for n in snapshot:
                    # \u4FDD\u7559\u539F\u6709\u7684\u60E9\u7F5A\u6027 ping \u503C\uFF0C\u9632\u6B62\u574F\u8282\u70B9\u88AB\u65B0\u6293\u53D6\u7684\u5FEB\u7167\u5237\u65B0\u540E\u53C8\u8DD1\u5230\u524D\u5217\u53BB
                    if n["ip"] in global_node_reservoir:
                        n["ping"] = max(n["ping"], global_node_reservoir[n["ip"]]["ping"])
                    global_node_reservoir[n["ip"]] = n
            print(f"[*] \u26A1 \u8282\u70B9\u5E93\u66F4\u65B0\uFF0C\u5F53\u524D\u56E4\u79EF\u6709\u6548\u8282\u70B9 -> {len(global_node_reservoir)} \u4E2A", flush=True)
        else:
            # FIX 3: \u5982\u679C VPNGate \u63A5\u53E3\u88AB\u9650\u6D41\u6216\u4E0D\u901A\uFF0C\u5EF6\u957F\u73B0\u6709\u8282\u70B9\u7684\u751F\u547D\u5468\u671F\uFF0C\u9632\u6B62\u5E93\u5E72\u6DB8
            with reservoir_lock:
                now = time.time()
                for n in global_node_reservoir.values():
                    n["harvested_at"] = now
        time.sleep(300)

def setup_routing(tun_name: str, table_id: int):
    subprocess.run(["ip", "rule", "del", "pref", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "del", "pref", str(table_id + 1000)], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "route", "add", "default", "dev", tun_name, "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "add", "oif", tun_name, "lookup", str(table_id), "pref", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "add", "iif", tun_name, "lookup", str(table_id), "pref", str(table_id + 1000)], capture_output=True)

def connect_node(tun: Tunnel, node: dict):
    global dead_ips, node_attempts, node_successes
    with reservoir_lock:
        node_attempts[node["ip"]] = node_attempts.get(node["ip"], 0) + 1
    try:
        cfg_path = CONFIG_DIR / f"{tun.name}.ovpn"
        log_file = WORKSPACE / f"{tun.name}_err.log"
        cfg_path.write_text(node["config"], encoding="utf-8")
        
        ovpn_version = subprocess.run(["openvpn", "--version"], capture_output=True, text=True).stdout
        cipher_args = ["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"] if "2.4" in ovpn_version else ["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "--data-ciphers-fallback", "AES-128-CBC"]
        
        # \u5F3A\u5236\u6DFB\u52A0 --nobind \u89E3\u9664\u7AEF\u53E3\u51B2\u7A81\uFF0C--route-nopull \u5265\u593A\u8DEF\u7531\u4FEE\u6539\u6743
        cmd = ["openvpn", "--config", str(cfg_path), "--dev", tun.name, "--dev-type", "tun", 
               "--nobind", "--route-nopull",
               "--pull-filter", "ignore", "route-ipv6", "--pull-filter", "ignore", "ifconfig-ipv6", 
               "--auth-user-pass", str(AUTH_FILE), "--auth-nocache", 
               "--connect-timeout", "5", "--connect-retry-max", "1", "--verb", "3"] + cipher_args
               
        with open(log_file, "w") as f: process = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
        
        success = False
        for _ in range(15):
            time.sleep(1)
            if process.poll() is not None: break
            try:
                if "Initialization Sequence Completed" in log_file.read_text():
                    success = True; break
            except: pass
                
        if success and process.poll() is None:
            setup_routing(tun.name, tun.table_id)
            time.sleep(1) 
            
            # --- \u7A7F\u900F\u83B7\u53D6\u901A\u9053\u771F\u5B9E\u51FA\u53E3 IP ---
            true_ip = ""
            try:
                true_ip_res = subprocess.run(["curl", "-s", "-m", "10", "--interface", tun.name, "https://api.ipify.org"], capture_output=True, text=True)
                candidate_ip = true_ip_res.stdout.strip()
                if candidate_ip and candidate_ip.count('.') == 3:
                    true_ip = candidate_ip
            except: pass
            
            egress_ip = true_ip if true_ip else node['ip']
            
            if true_ip and true_ip != node['ip']:
                print(f"[*] {tun.name} \u63A2\u6D4B\u5230\u771F\u5B9E\u51FA\u53E3 IP \u4E0E\u5165\u53E3\u4E0D\u4E00\u81F4: \u5165\u53E3 {node['ip']} -> \u51FA\u53E3 {true_ip}", flush=True)

            is_residential = True
            try:
                # \u517C\u5BB9 testisp.info/api/check \u7684\u65B0\u89E3\u6790\u903B\u8F91
                req_url = f"https://testisp.info/api/check?ip={egress_ip}"
                check_req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}, method="GET")
                with urllib.request.urlopen(check_req, timeout=10) as check_res:
                    data = json.loads(check_res.read().decode("utf-8"))
                    isp_flag = str(data.get("isp", {}).get("flag", "")).lower()
                    
                    if isp_flag == "hosting":
                        is_residential = False
            except Exception as e: pass
            
            if not is_residential:
                print(f"[-] {tun.name} \u8282\u70B9\u51FA\u53E3 ({egress_ip}) \u68C0\u6D4B\u4E3A\u673A\u623F IP\uFF0C\u6B8B\u5FCD\u629B\u5F03\uFF01", flush=True)
                penalize_node(node["ip"], 50000)  # \u673A\u623F IP \u6781\u91CD\u60E9\u7F5A\uFF0C\u51E0\u4E4E\u4E0D\u518D\u542F\u7528
                dead_ips.add(node["ip"])
                try: process.terminate(); process.wait(2)
                except: process.kill()
                return

            print(f"[*] {tun.name} \u8FDB\u884C\u6D41\u5A92\u4F53\u8D28\u68C0（网络连通性探测）...", flush=True)
            probe_endpoints = ["https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204", "https://1.1.1.1"]
            probe_ok = any(subprocess.run(["curl", "-I", "-L", "-s", "-A", "Mozilla/5.0", "-m", "5", "--interface", tun.name, endpoint], capture_output=True).returncode == 0 for endpoint in probe_endpoints)
            if not probe_ok:
                print("[!] \\u5916\\u7F51\\u63A2\\u9488\\u6682\\u672A\\u901A\\u8FC7\\uFF0C\\u4FDD\\u7559\\u5DF2\\u5EFA\\u7ACB\\u96A7\\u9053\\u5E76\\u7EE7\\u7EED\\u4E0A\\u62A5", flush=True)
            if False:
                print(f"[-] {tun.name} \u8282\u70B9\u51FA\u53E3\u65E0\u6CD5\u8FDE\u901A YouTube\uFF0C\u62C9\u9ED1\u66F4\u6362: {node['ip']}", flush=True)
                penalize_node(node["ip"], 10000)  # YT \u8FDE\u4E0D\u901A\u91CD\u7F5A
                dead_ips.add(node["ip"])
                try: process.terminate(); process.wait(2)
                except: process.kill()
                return

            with state_lock:
                tun.process = process
                tun.node = node
                # \u6B64\u65F6\u4E0D\u518D\u9700\u8981\u8D4B entry_ip\uFF0C\u56E0\u4E3A\u5728 maintain_pool \u91CC\u5DF2\u63D0\u524D\u9501\u4F4F\u5751\u4F4D
                tun.egress_ip = egress_ip
                tun.country = node["country"]
                tun.connected_at = time.time()
                tun.ready = True
                with reservoir_lock:
                    node_successes[node["ip"]] = node_successes.get(node["ip"], 0) + 1
            role = "\u4E3B\u7F51\u5361" if proxy_server.ACTIVE_BIND == tun.name else "\u5907\u7528\u7F51\u5361"
            print(f"[+] {tun.name} ({role}) \u5B8C\u5168\u5C31\u7EEA: \u5165\u53E3 {node['ip']} -> \u51FA\u53E3 {egress_ip}", flush=True)
        else:
            penalize_node(node["ip"], 5000)  # \u5EFA\u8FDE\u8D85\u65F6\u4E2D\u5EA6\u60E9\u7F5A
            try: process.terminate(); process.wait(2)
            except: process.kill()
            dead_ips.add(node["ip"])
    finally:
        with state_lock:
            tun.is_connecting = False
            # A failed candidate must release its reservation immediately;
            # otherwise the stale entry_ip can block the next replacement
            # and leave the Agent with only one reported tunnel.
            if not tun.ready:
                tun.process = None
                tun.node = None
                tun.entry_ip = ""
                tun.egress_ip = ""

def health_check_loop():
    global tun_main, tun_backup, dead_ips
    fail_counts = {}
    while True:
        time.sleep(15)
        with state_lock:
            targets = [(tun_main, tun_main.name), (tun_backup, tun_backup.name)]
        for tun, target_tun in targets:
            with state_lock:
                if not tun.ready or not tun.process or tun.process.poll() is not None or time.time() - tun.connected_at <= 20:
                    continue
                target_entry_ip = tun.entry_ip
                proc_ref = tun.process
            endpoints = ["http://www.gstatic.com/generate_204", "http://cp.cloudflare.com/generate_204", "http://1.1.1.1", "http://8.8.8.8"]
            is_alive = any(subprocess.run(["curl", "-I", "-s", "-m", "5", "--interface", target_tun, ep], capture_output=True).returncode == 0 for ep in endpoints)
            if not is_alive:
                is_alive = subprocess.run(["ping", "-c", "2", "-W", "3", "-I", target_tun, "8.8.8.8"], capture_output=True).returncode == 0
            if is_alive:
                fail_counts[target_tun] = 0
                continue
            fail_counts[target_tun] = fail_counts.get(target_tun, 0) + 1
            if fail_counts[target_tun] < 3:
                print(f"[*] {target_tun} 探针无响应，独立复核 ({fail_counts[target_tun]}/3)...", flush=True)
                continue
            print(f"[!] {target_tun} 连续多维探针失败，重新拨号: {target_entry_ip}", flush=True)
            if target_entry_ip:
                penalize_node(target_entry_ip, 3000)
                dead_ips.add(target_entry_ip)
            try: proc_ref.terminate(); proc_ref.wait(timeout=2)
            except Exception:
                try: proc_ref.kill()
                except Exception: pass
            with state_lock:
                if tun.process == proc_ref:
                    tun.process = None; tun.ready = False; tun.node = None; tun.entry_ip = ""; tun.egress_ip = ""; tun.is_connecting = False
            fail_counts[target_tun] = 0

def get_best_candidate():
    global global_node_reservoir, dead_ips, target_country, tun_main, tun_backup
    with reservoir_lock:
        all_pool_nodes = sorted(list(global_node_reservoir.values()), key=lambda x: x["ping"])
        candidates = [n for n in all_pool_nodes if n["country"] == target_country and n["ip"] not in dead_ips]
        
        active_ips = []
        if tun_main.entry_ip: active_ips.append(tun_main.entry_ip)
        if tun_backup.entry_ip: active_ips.append(tun_backup.entry_ip)
        candidates = [n for n in candidates if n["ip"] not in active_ips]

        if not candidates:
            has_blacklisted = any(n["country"] == target_country for n in all_pool_nodes)
            if has_blacklisted:
                dead_ips.clear()
                print(f"[!] \u26A1 \u7D27\u6025\u7194\u65AD\uFF1A[{target_country}] \u8282\u70B9\u9ED1\u540D\u5355\u91CA\u653E\u6551\u573A\uFF08\u7531\u4E8E\u52A8\u6001\u4FE1\u8A89\u7CFB\u7EDF\u5B58\u5728\uFF0C\u5386\u53F2\u574F\u8282\u70B9\u5C06\u88AB\u6C89\u5E95\uFF09", flush=True)
                candidates = [n for n in all_pool_nodes if n["country"] == target_country and n["ip"] not in active_ips]

        if candidates: return candidates.pop(0)
    return None

def maintain_pool():
    global dead_ips, last_blacklist_clear, tun_main, tun_backup
    while True:
        if time.time() - last_blacklist_clear > 600:
            dead_ips.clear()
            last_blacklist_clear = time.time()

        with reservoir_lock:
            now = time.time()
            stale_ips = [ip for ip, node in global_node_reservoir.items() if now - node["harvested_at"] > 10800]
            for ip in stale_ips: global_node_reservoir.pop(ip, None)

        with state_lock:
            # Reap either slot when its OpenVPN process exits. Previously only
            # the backup slot was reaped, leaving stale main-slot state behind.
            for tun in (tun_main, tun_backup):
                if not tun.is_connecting and (tun.process is None or tun.process.poll() is not None):
                    if tun.process is not None or tun.ready:
                        tun.process = None
                        tun.node = None
                        tun.entry_ip = ""
                        tun.egress_ip = ""
                        tun.ready = False
                        print(f"[*] {tun.name} 进程已退出，释放槽位并重新选节点", flush=True)
            # Keep traffic bound to a live tunnel after failover and reconnect.
            if proxy_server.ACTIVE_BIND == tun_backup.name and (not tun_backup.ready or not tun_backup.process or tun_backup.process.poll() is not None) and tun_main.ready and tun_main.process and tun_main.process.poll() is None:
                proxy_server.ACTIVE_BIND = tun_main.name
                print(f"[*] \u4E3B\u901A\u9053\u5DF2\u6062\u590D\uFF0C\u4E1A\u52A1\u7ED1\u5B9A\u5207\u56DE: {tun_main.name}", flush=True)
            elif proxy_server.ACTIVE_BIND == tun_main.name and (not tun_main.ready or not tun_main.process or tun_main.process.poll() is not None) and tun_backup.ready and tun_backup.process and tun_backup.process.poll() is None:
                proxy_server.ACTIVE_BIND = tun_backup.name
                print(f"[*] \u4E3B\u901A\u9053\u4E0D\u53EF\u7528\uFF0C\u4E1A\u52A1\u7ED1\u5B9A\u5207\u81F3: {tun_backup.name}", flush=True)
            # FIX 2: \u4E25\u683C\u68C0\u6D4B\u901A\u9053\u662F\u5426\u6B63\u5728\u8FDE\u63A5\uFF0C\u9632\u6B62\u7531\u4E8E\u5C1A\u672A\u5C31\u7EEA\u5BFC\u81F4\u7684\u9519\u8BEF\u5224\u6B7B\u548C\u79D2\u5207\u6DF7\u4E71
            main_dead = False
            if not tun_main.is_connecting:
                if tun_main.process is None or tun_main.process.poll() is not None or not tun_main.ready:
                    main_dead = True

            if main_dead:
                if tun_backup.ready and tun_backup.process and tun_backup.process.poll() is None and not tun_backup.is_connecting:
                    print(f"[*] \u26A1 \u4E3B\u901A\u9053\u66B4\u6BD9\uFF0C\u8F6F\u5F00\u5173\u79D2\u5207\uFF01\u65E0\u7F1D\u63A5\u7BA1\u4E1A\u52A1\u81F3\u5907\u7528\u901A\u9053: \u51FA\u53E3 {tun_backup.egress_ip or tun_backup.entry_ip}", flush=True)
                    # \u4FDD\u6301 main/backup \u8EAB\u4EFD\u56FA\u5B9A\uFF0C\u53EA\u5207\u6362\u4E1A\u52A1\u7ED1\u5B9A
                    proxy_server.ACTIVE_BIND = tun_backup.name
                    
                    # \u5F02\u6B65\u6E05\u7406\u6B7B\u6389\u7684\u65E7\u4E3B\u5361 (\u73B0\u5728\u7684 tun_backup)
                    if tun_main.process:
                        try: tun_main.process.terminate(); tun_main.process.wait(2)
                        except: tun_main.process.kill()
                    tun_main.process = None; tun_main.node = None; tun_main.entry_ip = ""; tun_main.egress_ip = ""
                    tun_main.ready = False; tun_main.is_connecting = False
                else:
                    if tun_main.process:
                        try: tun_main.process.terminate(); tun_main.process.wait(2)
                        except: tun_main.process.kill()
                    tun_main.process = None; tun_main.ready = False; tun_main.is_connecting = False
                    tun_main.entry_ip = ""; tun_main.egress_ip = ""

        with state_lock:
            needs_main = not tun_main.ready and not tun_main.is_connecting
            needs_backup = not tun_backup.ready and not tun_backup.is_connecting

        # Fill both slots independently. The former if/elif made one slot
        # depend on the other and could leave the Agent reporting one IP.
        if needs_main:
            node = get_best_candidate()
            if node:
                with state_lock:
                    tun_main.is_connecting = True
                    tun_main.entry_ip = node["ip"]
                threading.Thread(target=connect_node, args=(tun_main, node,), daemon=True).start()

        if needs_backup:
            # The main candidate is reserved before this lookup, so select a
            # different node whenever the country pool has at least two nodes.
            node = get_best_candidate()
            if node:
                with state_lock:
                    tun_backup.is_connecting = True
                    tun_backup.entry_ip = node["ip"]
                threading.Thread(target=connect_node, args=(tun_backup, node,), daemon=True).start()

        time.sleep(2)

def main():
    global PROXY_PORT, tun_main
    if os.geteuid() != 0: return
    get_public_ip()
    setup_env()
    subprocess.run(["pkill", "-f", f"openvpn.*{tun_main.name}|{tun_backup.name}"], capture_output=True)
    
    proxy_server.ACTIVE_BIND = tun_main.name
    
    # Environment-file values are authoritative for multi-agent services.
    # Only the legacy service without PROXY_PORT falls back to global_config.
    if not PROXY_PORT_ENV:
        try:
            req = urllib.request.Request(f"{C2_URL}/api/config", headers=get_c2_headers())
            with urllib.request.urlopen(req, timeout=10) as res:
                data = json.loads(res.read().decode("utf-8"))
                PROXY_PORT = int(data.get("port", 7920))
        except: pass

    print("========================================", flush=True)
    print(f"  Proxy Controller (\u4E3B\u5907\u53CC\u6D3B\u5F15\u64CE) \u542F\u52A8\uFF01\u7AEF\u53E3: {PROXY_PORT}", flush=True)
    print("========================================", flush=True)

    threading.Thread(target=vpngate_fetch_loop, daemon=True).start()
    threading.Thread(target=update_config_loop, daemon=True).start()
    # \u542F\u7528\u5168\u5C40 IPv6 ANY \u76D1\u542C
    threading.Thread(target=proxy_server.start_proxy_server, args=("::", PROXY_PORT), daemon=True).start()
    threading.Thread(target=health_check_loop, daemon=True).start()
    threading.Thread(target=c2_heartbeat_loop, daemon=True).start()
    maintain_pool()

if __name__ == "__main__":
    main()
`;
      return new Response(MANAGER_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }
    if (url.pathname === "/agent") {
      const requestedPort = Number(url.searchParams.get("port") || 7920);
      const agentPort = Number.isInteger(requestedPort) && requestedPort >= 1024 && requestedPort <= 65535 ? requestedPort : 7920;
      const requestedIp = url.searchParams.get("ip") || "54.65.193.234";
      const agentIp = /^[0-9a-fA-F:.]+$/.test(requestedIp) ? requestedIp : "54.65.193.234";
      const safeAgentId = agentIp.replace(/[^A-Za-z0-9_-]/g, "_");
      const agentScript = `#!/usr/bin/env bash
set -euo pipefail
BASE=/opt/proxy_lite
CONFIG=/etc/proxy-lite/instances.json
CONTROLLER_ENV=/etc/proxy-lite/controller.env
mkdir -p "$BASE/configs" /etc/proxy-lite
cat > "$CONTROLLER_ENV" <<'ENV'
C2_URL=${domain}
WEB_USER=${WEB_USER}
WEB_PASS=${WEB_PASS}
ENV
chmod 600 "$CONTROLLER_ENV"

echo "net.ipv4.conf.all.rp_filter=2" > /etc/sysctl.d/99-proxy-lite.conf
echo "net.ipv4.conf.default.rp_filter=2" >> /etc/sysctl.d/99-proxy-lite.conf
sysctl --system >/dev/null 2>&1 || true
apt-get update -q
apt-get install -y openvpn python3 curl iproute2 iptables cron psmisc
mkdir -p "$BASE/.latest"
curl -fsSL -u '${WEB_USER}:${WEB_PASS}' ${domain}/scripts/lite_manager.py -o "$BASE/.latest/lite_manager.py"
curl -fsSL -u '${WEB_USER}:${WEB_PASS}' ${domain}/scripts/proxy_server.py -o "$BASE/.latest/proxy_server.py"
chmod 700 "$BASE/.latest"/*.py
MANAGE_SCRIPT=/opt/proxy_lite_${agentPort}/proxy-lite-${agentPort}.sh
mkdir -p "$(dirname "$MANAGE_SCRIPT")"
cat > "$MANAGE_SCRIPT" <<'SH'
#!/usr/bin/env bash
set -u
PORT="${agentPort}"
INSTANCE_ID="${agentIp}-${agentPort}"
SERVICE="proxy-lite-${safeAgentId}-${agentPort}"
INSTALL_DIR="/opt/proxy_lite_${agentPort}"
CONFIG="/etc/proxy-lite/instances.json"
REMOVED="/etc/proxy-lite/removed.json"
CONTROLLER_ENV="/etc/proxy-lite/controller.env"

as_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "请使用 root 或 sudo 运行此脚本" >&2
    exit 1
  fi
}

service_file() { echo "/etc/systemd/system/\${SERVICE}.service"; }
ensure_unit() {
  if [ ! -f "$(service_file)" ] && [ -x /usr/local/sbin/proxy-lite-multi ]; then
    systemctl daemon-reload
    systemctl restart proxy-lite-multi.service >/dev/null 2>&1 || true
    sleep 1
  fi
}
print_status() {
  echo "Agent ${agentPort} · \${INSTANCE_ID}"
  echo "服务： \${SERVICE}.service"
  printf '开机自启： '; systemctl is-enabled "\${SERVICE}.service" 2>/dev/null || echo 未知
  printf '运行状态：  '; systemctl is-active "\${SERVICE}.service" 2>/dev/null || echo 未运行
  echo
  systemctl --no-pager --full status "\${SERVICE}.service" 2>&1 | sed -n '1,24p'
  echo
  echo "最近日志（最多 20 行）"
  journalctl -u "\${SERVICE}.service" -n 20 --no-pager --output=cat 2>/dev/null || true
}

remove_local_config() {
  python3 - "$PORT" "$CONFIG" "$REMOVED" <<'PYREMOVE'
import json, sys
from pathlib import Path
port, config_name, removed_name = str(int(sys.argv[1])), sys.argv[2], sys.argv[3]
config = Path(config_name)
removed = Path(removed_name)
try: data = json.load(open(config))
except Exception: data = []
config.parent.mkdir(parents=True, exist_ok=True)
config.write_text(json.dumps([x for x in data if str(x.get('port')) != port], indent=2))
try: tomb = set(str(x) for x in json.load(open(removed)))
except Exception: tomb = set()
tomb.add(port)
removed.write_text(json.dumps(sorted(tomb)))
PYREMOVE
}

case "\${1:-help}" in
  start)
    as_root
    ensure_unit
    systemctl enable --now "\${SERVICE}.service"
    echo "已启动 Agent ${agentPort}（\${SERVICE}.service）"
    ;;
  stop)
    as_root
    systemctl disable --now "\${SERVICE}.service"
    echo "已停止 Agent ${agentPort}"
    ;;
  restart)
    as_root
    ensure_unit
    systemctl restart "\${SERVICE}.service"
    echo "已重启 Agent ${agentPort}"
    ;;
  status)
    as_root
    ensure_unit
    print_status
    ;;
  logs)
    as_root
    journalctl -u "\${SERVICE}.service" -n 80 --no-pager --output=cat
    ;;
  uninstall)
    as_root
    systemctl disable --now "\${SERVICE}.service" 2>/dev/null || true
    remove_local_config
    rm -f "/etc/systemd/system/\${SERVICE}.service"
    systemctl daemon-reload
    if [ -r "\${CONTROLLER_ENV}" ]; then
      . "\${CONTROLLER_ENV}"
      if [ -n "\${C2_URL:-}" ] && [ -n "\${WEB_USER:-}" ] && [ -n "\${WEB_PASS:-}" ]; then
        curl -fsS --get -u "\${WEB_USER}:\${WEB_PASS}" \\
          --data-urlencode "instance_id=\${INSTANCE_ID}" \\
          -X DELETE "\${C2_URL}/api/instances" >/dev/null || \\
          echo "警告：本地已卸载，但控制端登记删除失败" >&2
      fi
    fi
    rm -rf "\${INSTALL_DIR}"
    rm -f "\${0}" "/usr/local/sbin/proxy-lite-${agentPort}.sh"
    echo "已卸载 Agent ${agentPort}"
    ;;
  help|*)
    echo "用法: \${0} {start|stop|restart|status|logs|uninstall}"
    echo "  start      启动并设置开机自启"
    echo "  stop       停止并取消开机自启"
    echo "  restart    重启 Agent"
    echo "  status     显示服务状态和最近日志"
    echo "  logs       显示最近 80 行完整日志"
    echo "  uninstall  停止服务并清理本机与控制端登记"
    ;;
esac
SH
chmod 700 "$MANAGE_SCRIPT"
ln -sfn "$MANAGE_SCRIPT" "/usr/local/sbin/proxy-lite-${agentPort}.sh"

python3 - "$CONFIG" "${agentIp}" "${agentPort}" <<'PYCFG'
import json, sys
path, ip, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
try: data = json.load(open(path)); data = data if isinstance(data, list) else []
except Exception: data = []
data = [x for x in data if str(x.get('port')) != str(port)]
data.append({'instance_id': f'{ip}-{port}', 'name': f'Agent {port}', 'ip': ip, 'country': 'JP', 'port': port, 'enabled': True, 'install_dir': f'/opt/proxy_lite_{port}'})
json.dump(data, open(path, 'w'), indent=2)
PYCFG
mkdir -p /etc/proxy-lite
python3 - <<'PYREM'
import json
p='/etc/proxy-lite/removed.json'
try: data=json.load(open(p))
except Exception: data=[]
data=[x for x in data if str(x) != '${agentPort}']
json.dump(data, open(p, 'w'))
PYREM
curl -fsSL -u '${WEB_USER}:${WEB_PASS}' -H 'Content-Type: application/json' -X POST ${domain}/api/instances \
  --data '{"instance_id":"${agentIp}-${agentPort}","name":"Agent ${agentPort}","remark":"由安装命令自动登记","ip":"${agentIp}","country":"JP","port":${agentPort},"enabled":true}' >/dev/null
cat > /usr/local/sbin/proxy-lite-multi <<'PY2'
#!/usr/bin/env python3
import json, os, subprocess
from pathlib import Path
CONFIG=Path(os.environ.get('PROXY_LITE_CONFIG','/etc/proxy-lite/instances.json'))
BASE=Path('/opt/proxy_lite')
LATEST=BASE/'.latest'
ENV=Path('/etc/proxy-lite/controller.env')
def sync_from_controller():
    values={}
    for line in ENV.read_text().splitlines():
        if '=' in line:
            k,v=line.split('=',1); values[k]=v
    import urllib.request, base64
    req=urllib.request.Request(values['C2_URL']+'/api/instances', headers={'Authorization':'Basic '+base64.b64encode((values['WEB_USER']+':'+values['WEB_PASS']).encode()).decode()})
    with urllib.request.urlopen(req, timeout=15) as r:
        remote=json.loads(r.read().decode())
    if not isinstance(remote, list): return
    try: removed = {str(x) for x in json.load(open('/etc/proxy-lite/removed.json'))}
    except Exception: removed = set()
    try: local = json.load(open(CONFIG))
    except Exception: local = []
    merged = {}
    for x in local + remote:
        key = str(x.get('port') or x.get('instance_id'))
        if key and key not in removed: merged[key] = x
    CONFIG.write_text(json.dumps(list(merged.values()), indent=2))
def main():
    try: sync_from_controller()
    except Exception as e: print('控制端同步跳过：', e)
    data=json.loads(CONFIG.read_text())
    if not isinstance(data,list): raise SystemExit('config must be a JSON array')
    ids=set(); ports=set(); desired=set()
    for x in data:
        if not x.get('enabled',True): continue
        iid=str(x.get('instance_id','')); port=int(x.get('port',0))
        if not iid or port in ports or iid in ids or not 1024 <= port <= 65535: raise SystemExit('invalid or duplicate instance')
        ids.add(iid); ports.add(port)
        safe=''.join(c if c.isalnum() or c in '_-' else '_' for c in iid)
        service='proxy-lite-'+safe; desired.add(service); d=Path(x.get('install_dir') or '/opt/proxy_lite_'+str(port)); d.mkdir(parents=True,exist_ok=True)
        source=LATEST if (LATEST/'lite_manager.py').exists() and (LATEST/'proxy_server.py').exists() else BASE
        for f in ('lite_manager.py','proxy_server.py'):
            dst=d/f
            if not dst.exists():
                dst.write_bytes((source/f).read_bytes()); dst.chmod(0o700)
        (d/'.env').write_text('\\n'.join([f'INSTANCE_ID={iid}',f'PROXY_PORT={port}',f'INSTALL_DIR={d}',f'SERVICE_NAME={service}.service',f'TUN_MAIN=tun_{port}_main',f'TUN_BACKUP=tun_{port}_backup',f'TUN_MAIN_TABLE={100+port%1000}',f'TUN_BACKUP_TABLE={1100+port%1000}',f'COUNTRY={str(x.get("country","JP")).upper()}', '']))
        unit='''[Unit]
Description=Proxy Lite INSTANCE
After=network.target
[Service]
Type=simple
EnvironmentFile=DIRECTORY/.env
WorkingDirectory=DIRECTORY
ExecStart=/usr/bin/python3 -u DIRECTORY/lite_manager.py
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
'''.replace('INSTANCE',iid).replace('DIRECTORY',str(d))
        Path('/etc/systemd/system',service+'.service').write_text(unit)
        subprocess.run(['systemctl','enable','--now',service+'.service'],check=False)
    # Reconcile removals/disabled entries so delete and disable are real operations.
    unit_dir=Path('/etc/systemd/system')
    for unit in unit_dir.glob('proxy-lite-*.service'):
        name=unit.name[:-8]
        if name not in desired and name != 'proxy-lite-multi':
            subprocess.run(['systemctl','disable','--now',unit.name],check=False)
            try: unit.unlink()
            except FileNotFoundError: pass
    subprocess.run(['systemctl','daemon-reload'],check=False)
if __name__=='__main__': main()
PY2
chmod 700 /usr/local/sbin/proxy-lite-multi
cat > /usr/local/sbin/proxy-lite-remove <<'PYREMOVE'
#!/usr/bin/env python3
import json, shutil, subprocess, sys
from pathlib import Path
if len(sys.argv) != 2 or not sys.argv[1].isdigit(): raise SystemExit('usage: proxy-lite-remove PORT')
port = str(int(sys.argv[1])); config = Path('/etc/proxy-lite/instances.json'); removed = Path('/etc/proxy-lite/removed.json')
try: data = json.load(open(config))
except Exception: data = []
targets = [x for x in data if str(x.get('port')) == port]
config.write_text(json.dumps([x for x in data if str(x.get('port')) != port], indent=2))
try: tomb = set(str(x) for x in json.load(open(removed)))
except Exception: tomb = set()
tomb.add(port); removed.write_text(json.dumps(sorted(tomb)))
for item in targets:
    safe = ''.join(c if c.isalnum() or c in '_-' else '_' for c in str(item.get('instance_id', '')))
    if safe: subprocess.run(['systemctl', 'disable', '--now', 'proxy-lite-' + safe + '.service'], check=False)
    install_dir = Path(str(item.get('install_dir') or '/opt/proxy_lite_' + port))
    if install_dir != Path('/') and str(install_dir).startswith('/opt/'):
        shutil.rmtree(install_dir, ignore_errors=True)
fallback_dir = Path('/opt/proxy_lite_' + port)
if fallback_dir.exists(): shutil.rmtree(fallback_dir, ignore_errors=True)
subprocess.run(['systemctl', 'daemon-reload'], check=False)
subprocess.run(['systemctl', 'restart', 'proxy-lite-multi.service'], check=False)
print('removed agent port', port)
PYREMOVE
chmod 700 /usr/local/sbin/proxy-lite-remove
cat > /etc/systemd/system/proxy-lite-multi.service <<'UNIT'
[Unit]
Description=Proxy Lite file-driven multi-agent launcher
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/proxy-lite-multi
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable proxy-lite-multi.service
systemctl restart proxy-lite-multi.service
echo "[+] Multi-agent installation complete. Edit $CONFIG, then run systemctl restart proxy-lite-multi.service"
`;
      return new Response(agentScript, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }
    if (url.pathname === "/remove-agent") {
      const removePort = Number(url.searchParams.get("port") || 0);
      const removeIp = url.searchParams.get("ip") || "";
      const removeInstanceId = removeIp ? `${removeIp}-${removePort}` : "";
      const removeScript = `#!/usr/bin/env bash
set -euo pipefail
PORT="\${1:-${removePort}}"
IP="\${2:-${removeIp}}"
if ! [[ "\$PORT" =~ ^[0-9]+$ ]] || [ "\$PORT" -lt 1024 ] || [ "\$PORT" -gt 65535 ]; then echo "invalid port" >&2; exit 2; fi
sudo systemctl list-unit-files --no-legend 'proxy-lite-*.service' | awk -v p="\$PORT" '\$1 ~ "-" p "\\\\.service$" {print \$1}' | while read -r unit; do sudo systemctl disable --now "\$unit" || true; done
sudo python3 - "\$PORT" <<'PYREMOVE'
import json, sys
from pathlib import Path
port = str(int(sys.argv[1]))
config = Path('/etc/proxy-lite/instances.json')
removed = Path('/etc/proxy-lite/removed.json')
try: data = json.load(open(config))
except Exception: data = []
config.write_text(json.dumps([x for x in data if str(x.get('port')) != port], indent=2))
try: tomb = set(str(x) for x in json.load(open(removed)))
except Exception: tomb = set()
tomb.add(port)
removed.write_text(json.dumps(sorted(tomb)))
PYREMOVE
sudo rm -rf "/opt/proxy_lite_\${PORT}"
sudo systemctl daemon-reload
sudo systemctl restart proxy-lite-multi.service 2>/dev/null || true
if [ -n "\$IP" ]; then
  curl -fsS -u '${WEB_USER}:${WEB_PASS}' -X DELETE "${domain}/api/instances?instance_id=\${IP}-\${PORT}" >/dev/null || echo "warning: local cleanup succeeded but controller record removal failed" >&2
fi
echo "removed agent port \$PORT"
`;
      return new Response(removeScript, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }
    if (url.pathname.startsWith("/api/testisp-lookup/")) {
      if (!authenticate(request)) return unauthorizedResponse();
      const targetIp = url.pathname.replace("/api/testisp-lookup/", "");
      try {
        const reqUrl = `https://testisp.info/api/check?ip=${targetIp}`;
        const resp = await fetch(reqUrl, {
          headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Referer": "https://testisp.info/"
          }
        });
        const data = await resp.text();
        return new Response(data, {
          status: resp.status,
          headers: {
            "Content-Type": resp.headers.get("content-type") || "application/json",
            "Access-Control-Allow-Origin": "*"
          }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }
    if (url.pathname === "/api/countries") {
      try {
        const response = await fetch("https://www.vpngate.net/api/iphone/");
        const text = await response.text();
        const lines = text.split("\n");
        const dynamicCountries = /* @__PURE__ */ new Set();
        for (let i = 2; i < lines.length; i++) {
          const parts = lines[i].split(",");
          if (parts.length > 6) {
            const country = parts[6];
            if (country && country.length === 2 && country !== "xx" && country !== "--") {
              dynamicCountries.add(country.toUpperCase());
            }
          }
        }
        const predefinedCountries = ["US", "JP", "KR", "SG", "HK", "TW", "GB", "DE", "FR", "NL", "CA", "AU", "IN", "VN", "BR", "AE", "MY", "TH", "PH", "ID", "TR", "ZA", "IT", "ES", "RU", "CH", "SE", "PL", "NO", "DK", "FI", "IE", "AT", "NZ", "BE", "PT", "CZ", "GR", "HU", "RO", "BG", "HR", "SK", "SI", "LT", "LV", "EE", "UA", "RS", "BA", "CY", "MT", "IS", "LU"];
        const allCountries = /* @__PURE__ */ new Set([...predefinedCountries, ...Array.from(dynamicCountries)]);
        return new Response(JSON.stringify(Array.from(allCountries).sort()), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
      } catch (err) {
        return new Response(JSON.stringify(["US", "JP", "KR", "SG", "HK", "TW"]), { headers: { "Content-Type": "application/json" } });
      }
    }
    if (url.pathname === "/" || url.pathname === "/api/config" || url.pathname === "/api/nodes" || url.pathname === "/api/proxies" || url.pathname === "/api/report" || url.pathname === "/api/instance-config" || url.pathname === "/api/instances") {
      if (!authenticate(request)) return unauthorizedResponse();
    }
    if (url.pathname === "/api/config" && request.method === "GET") {
      const { results } = await env.DB.prepare(`SELECT value FROM global_config WHERE key = 'slot_map'`).all();
      if (results && results.length > 0) return new Response(results[0].value, { headers: { "Content-Type": "application/json" } });
      return new Response(JSON.stringify({ "0": "JP", "port": 7920 }), { headers: { "Content-Type": "application/json" } });
    }
    if (url.pathname === "/api/config" && request.method === "POST") {
      const data = await request.json();
      const sanitizedMap = {
        "0": data["0"] || "JP",
        "port": parseInt(data.port) || 7920
      };
      if (data.switch_trigger) sanitizedMap.switch_trigger = data.switch_trigger;
      await env.DB.prepare(`INSERT INTO global_config (key, value) VALUES ('slot_map', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).bind(JSON.stringify(sanitizedMap)).run();
      return new Response("OK");
    }
    if (url.pathname === "/api/instance-config" && request.method === "GET") {
      const ip = url.searchParams.get("ip") || "";
      const instanceId = url.searchParams.get("instance_id") || "";
      let row = null;
      if (instanceId) row = await env.DB.prepare(`SELECT instance_id, ip, country, port, switch_trigger, enabled FROM agent_instances WHERE instance_id = ?1`).bind(instanceId).first();
      if (!row && ip && !instanceId) row = await env.DB.prepare(`SELECT ip, country, port, switch_trigger, enabled FROM instance_config WHERE ip = ?1`).bind(ip).first();
      return new Response(JSON.stringify(row || {}), { headers: { "Content-Type": "application/json" } });
    }
    if (url.pathname === "/api/instance-config" && request.method === "POST") {
      const data = await request.json();
      const ip = String(data.ip || "").trim();
      const country = String(data.country || "").trim().toUpperCase();
      const port = parseInt(data.port) || 7920;
      if (!ip || !/^[A-Z]{2}$/.test(country)) return new Response("实例配置无效", { status: 400 });
      const trigger = parseInt(data.switch_trigger) || Date.now();
      await env.DB.prepare(`INSERT INTO instance_config (ip, country, port, switch_trigger, enabled, updated_at) VALUES (?1, ?2, ?3, ?4, 1, ?5) ON CONFLICT(ip) DO UPDATE SET country=excluded.country, port=excluded.port, switch_trigger=excluded.switch_trigger, enabled=1, updated_at=excluded.updated_at`).bind(ip, country, port, trigger, Date.now()).run();
      return new Response("OK");
    }
    if (url.pathname === "/api/instances" && request.method === "GET") {
      const { results } = await env.DB.prepare(`SELECT * FROM agent_instances ORDER BY port ASC`).all();
      return new Response(JSON.stringify(results || []), { headers: { "Content-Type": "application/json" } });
    }
    if (url.pathname === "/api/instances" && (request.method === "POST" || request.method === "PUT")) {
      const data = await request.json();
      const id = String(data.instance_id || "").trim();
      const name = String(data.name || id).trim();
      const remark = String(data.remark || "").trim().slice(0, 200);
      const ip = String(data.ip || "").trim();
      const country = String(data.country || "JP").trim().toUpperCase();
      const port = Number(data.port);
      const enabled = data.enabled === false || data.enabled === 0 ? 0 : 1;
      if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{1,95}$/.test(id) || !name || !ip || !/^[A-Z]{2}$/.test(country) || !Number.isInteger(port) || port < 1024 || port > 65535) return new Response(实例参数无效, { status: 400 });
      const conflict = await env.DB.prepare(`SELECT instance_id FROM agent_instances WHERE ip = ?1 AND port = ?2 AND instance_id <> ?3`).bind(ip, port, id).first();
      if (conflict) return new Response("Port already used", { status: 409 });
      const now = Date.now();
      const old = await env.DB.prepare(`SELECT created_at FROM agent_instances WHERE instance_id = ?1`).bind(id).first();
      const trigger = Number(data.switch_trigger) || now;
      await env.DB.prepare(`INSERT INTO agent_instances (instance_id,name,remark,ip,country,port,enabled,switch_trigger,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9) ON CONFLICT(instance_id) DO UPDATE SET name=excluded.name,remark=excluded.remark,ip=excluded.ip,country=excluded.country,port=excluded.port,enabled=excluded.enabled,switch_trigger=excluded.switch_trigger,updated_at=excluded.updated_at`).bind(id, name, remark, ip, country, port, enabled, trigger, old?.created_at || now).run();
      await env.DB.prepare(`INSERT INTO instance_config (ip,country,port,switch_trigger,enabled,updated_at) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(ip) DO UPDATE SET country=excluded.country,port=excluded.port,switch_trigger=excluded.switch_trigger,enabled=excluded.enabled,updated_at=excluded.updated_at`).bind(ip, country, port, trigger, enabled, now).run();
      return new Response(JSON.stringify({ ok: true, instance_id: id }), { headers: { "Content-Type": "application/json" } });
    }
    if (url.pathname === "/api/instances" && request.method === "DELETE") {
      const id = String(url.searchParams.get("instance_id") || "").trim();
      if (!id) return new Response("instance_id required", { status: 400 });
      const removed = await env.DB.prepare(`SELECT ip FROM agent_instances WHERE instance_id = ?1`).bind(id).first();
      await env.DB.prepare(`DELETE FROM agent_instances WHERE instance_id = ?1`).bind(id).run();
      await env.DB.prepare(`DELETE FROM agent_reports WHERE instance_id = ?1`).bind(id).run();
      if (removed?.ip) await env.DB.prepare(`UPDATE instance_config SET enabled = 0, updated_at = ?1 WHERE ip = ?2`).bind(Date.now(), removed.ip).run();
      return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
    }
    if (url.pathname === "/api/report" && request.method === "POST") {
      try {
        const data = await request.json();
        const instanceId = String(data.instance_id || "legacy-" + data.ip).trim();
        const now = Date.now();
        await env.DB.prepare(`INSERT INTO agent_reports (instance_id,ip,details,stats,logs,last_seen) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(instance_id) DO UPDATE SET ip=excluded.ip,details=excluded.details,stats=excluded.stats,logs=excluded.logs,last_seen=excluded.last_seen`).bind(instanceId, data.ip, JSON.stringify(data.details || []), JSON.stringify(data.stats || {}), data.logs || null, now).run();
        await env.DB.prepare(`INSERT INTO servers (ip, details, last_seen, stats) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(ip) DO UPDATE SET details = excluded.details, last_seen = excluded.last_seen, stats = excluded.stats`).bind(data.ip, JSON.stringify(data.details || []), now, JSON.stringify(data.stats || {})).run();
        if (data.logs) {
          await env.DB.prepare(`INSERT INTO server_logs (ip, logs, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(ip) DO UPDATE SET logs = excluded.logs, updated_at = excluded.updated_at`).bind(data.ip, data.logs, Date.now()).run();
        }
        return new Response("OK", { status: 200 });
      } catch (err) {
        return new Response("Error", { status: 500 });
      }
    }
    if (url.pathname === "/api/proxies") {
      const cutoff = Date.now() - 12e4;
      await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
      const { results } = await env.DB.prepare(`SELECT ip, details FROM servers`).all();
      let proxyList = [];
      if (results) {
        for (let server of results) {
          const details = JSON.parse(server.details || "[]");
          const activeNode = details.find((d) => d.active) || details[0];
          if (activeNode) {
            proxyList.push(`socks5://${PROXY_USER}:${PROXY_PASS}@${server.ip}:${activeNode.port}#${activeNode.country}_ActiveNode_${activeNode.node_ip || "IP"}`);
          }
        }
      }
      return new Response(proxyList.join("\n"), { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }
    if (url.pathname === "/api/nodes") {
      const cutoff = Date.now() - 12e4;
      await env.DB.prepare(`DELETE FROM agent_reports WHERE last_seen < ?1`).bind(cutoff).run();
      const { results } = await env.DB.prepare(`
        SELECT i.instance_id, i.name, i.ip, i.country AS configured_country, i.port AS configured_port,
               i.enabled, r.details, r.stats, r.logs, r.last_seen
        FROM agent_instances i
        LEFT JOIN agent_reports r ON r.instance_id = i.instance_id
        WHERE i.enabled = 1 OR r.last_seen >= ?1
        ORDER BY i.port ASC
      `).bind(cutoff).all();
      return new Response(JSON.stringify(results || []), { headers: { "Content-Type": "application/json" } });
    }
    if (url.pathname === "/") {
      return new Response(DASHBOARD_HTML(domain, WEB_USER, WEB_PASS, PROXY_USER, PROXY_PASS), { headers: { "Content-Type": "text/html;charset=UTF-8", "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0" } });
    }
    return new Response("Not Found", { status: 404 });
  }
};
var DASHBOARD_HTML = /* @__PURE__ */ __name((domain, webUser, webPass, proxyUser, proxyPass) => `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Controller - \u53CC\u6D3B\u5F15\u64CE\u603B\u63A7</title>
    <script src="https://cdn.tailwindcss.com"><\/script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: rgba(15, 23, 42, 0.5); }
        ::-webkit-scrollbar-thumb { background: rgba(51, 65, 85, 0.8); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(71, 85, 105, 1); }
        input[type=number]::-webkit-inner-spin-button, 
        input[type=number]::-webkit-outer-spin-button { -webkit-appearance: none; margin: 0; }
    </style>
</head>
<body class="min-h-screen bg-[#090E17] text-slate-300 relative overflow-x-hidden selection:bg-indigo-500/30">
    <div class="fixed top-[-20%] left-[-10%] w-[50%] h-[50%] bg-indigo-600/20 blur-[120px] rounded-full pointer-events-none z-0"></div>
    <div class="fixed bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-blue-600/10 blur-[120px] rounded-full pointer-events-none z-0"></div>

    <div class="max-w-7xl mx-auto p-6 relative z-10">
        <div class="flex flex-col md:flex-row justify-between items-start md:items-end mb-10 gap-6">
            <div>
                <h1 class="text-4xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 via-indigo-400 to-purple-400 tracking-tight drop-shadow-sm">Proxy Controller</h1>
                <p class="text-slate-400 mt-2 text-sm flex items-center gap-2">
                    <svg class="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
                    \u76F4\u94FE\u63D0\u53D6 API: <a href="/api/proxies" target="_blank" class="text-indigo-400 hover:text-indigo-300 border-b border-indigo-400/30 hover:border-indigo-300 transition-colors">${domain}/api/proxies</a>
                </p>
            </div>
            
            <div class="flex flex-col gap-3 w-full md:w-auto">
                <div class="bg-slate-900/80 backdrop-blur-md border border-slate-700/50 rounded-xl overflow-hidden shadow-lg">
                    <div class="bg-slate-800/50 px-4 py-2 border-b border-slate-700/50 flex items-center gap-2">
                        <div class="flex gap-1.5">
                            <div class="w-3 h-3 rounded-full bg-rose-500/80"></div>
                            <div class="w-3 h-3 rounded-full bg-amber-500/80"></div>
                            <div class="w-3 h-3 rounded-full bg-emerald-500/80"></div>
                        </div>
                        <span class="text-xs text-slate-400 font-mono ml-2">VPS Agent \u7BA1\u7406 (Root)</span>
                    </div>
                    <div class="flex flex-wrap items-center gap-2 p-3 bg-[#0D1117]">
                        <input id="agent-ip-input" value="54.65.193.234" placeholder="服务器 IP" class="w-36 rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs text-slate-200">
                        <input id="agent-port-input" value="7920" inputmode="numeric" placeholder="端口" class="w-20 rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs text-slate-200">
                        <code id="install-command" class="hidden"></code>
                        <code id="uninstall-command" class="hidden"></code>
                        <button onclick="copyText(document.getElementById('install-command').textContent, '\u5B89\u88C5\u547D\u4EE4\u5DF2\u590D\u5236')" class="shrink-0 px-3 py-1.5 rounded-md bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs hover:bg-emerald-500/25">\u590D\u5236\u5B89\u88C5\u547D\u4EE4</button>
                        <button onclick="copyText(document.getElementById('uninstall-command').textContent, '\u5378\u8F7D\u547D\u4EE4\u5DF2\u590D\u5236')" class="shrink-0 px-3 py-1.5 rounded-md bg-rose-500/15 border border-rose-500/30 text-rose-300 text-xs hover:bg-rose-500/25">\u590D\u5236\u5378\u8F7D\u547D\u4EE4</button>
                    </div>
                </div>

                <div class="flex gap-4 text-xs font-mono">
                    <div class="bg-slate-900/50 border border-slate-800 rounded-lg px-3 py-2 flex-1 flex justify-between items-center shadow-sm">
                        <span class="text-slate-500">\u9762\u677F\u51ED\u8BC1</span>
                        <span class="text-indigo-300 font-bold ml-4">${webUser} <span class="text-slate-600">/</span> ${webPass}</span>
                    </div>
                    <div class="bg-slate-900/50 border border-slate-800 rounded-lg px-3 py-2 flex-1 flex justify-between items-center shadow-sm">
                        <span class="text-slate-500">\u4EE3\u7406\u51ED\u8BC1</span>
                        <span class="text-amber-300 font-bold ml-4">${proxyUser} <span class="text-slate-600">/</span> ${proxyPass}</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-8">
            <div class="lg:col-span-1 bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl p-6 shadow-xl shadow-black/20">
                <div class="flex items-center gap-2 mb-4">
                    <svg class="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <h2 class="text-lg font-bold text-slate-200">\u5168\u91CF\u56FD\u5BB6\u4EE3\u7801\u5E93</h2>
                </div>
                <p class="text-xs text-slate-500 mb-4 leading-relaxed">\u7CFB\u7EDF\u5DF2\u5408\u5E76\u9884\u8BBE\u4EE3\u7801\u53CA\u5B9E\u65F6\u7684\u7F51\u7EDC\u63A2\u6D4B\u4EE3\u7801\uFF0C\u63D0\u4F9B\u6700\u5168\u9762\u7684\u76EE\u6807\u9501\u5B9A\u9009\u62E9\u3002</p>
                <div id="countries-list" class="flex flex-wrap gap-2 max-h-[160px] overflow-y-auto pr-1">
                    <span class="text-slate-600 text-sm animate-pulse">\u6B63\u5728\u540C\u6B65\u6570\u636E\u5E93...</span>
                </div>
            </div>

            <div class="lg:col-span-3 bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl p-6 shadow-xl shadow-black/20 flex flex-col justify-center relative overflow-hidden">
                <div class="absolute top-0 right-0 p-6 opacity-5 pointer-events-none">
                    <svg class="w-32 h-32" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
                </div>
                
                <div class="mb-6 relative z-10">
                    <h2 class="text-2xl font-bold text-slate-100 tracking-wide mb-1 flex items-center gap-2">\u4E3B\u5907\u53CC\u6D3B\u8C03\u5EA6\u5F15\u64CE <span class="bg-indigo-500/20 text-indigo-400 text-[10px] uppercase font-bold px-2 py-0.5 rounded-full border border-indigo-500/30">主备模式</span></h2>
                    <p class="text-sm text-slate-400">\u5355\u8DEF\u7AEF\u53E3\u9501\u5B9A\uFF0C\u5185\u7F6E\u4E3B\u5907\u53CC\u8DEF\u96A7\u9053 (tun_main / tun_backup)\uFF0C\u901A\u9053\u6B7B\u6D3B\u5C06\u7531\u8F6F\u5F00\u5173\u77AC\u95F4\u63A5\u7BA1\u3002</p>
                </div>
                
                <div class="flex flex-wrap items-center bg-slate-950/50 border border-slate-800/80 rounded-xl p-5 relative z-10 gap-y-4">
                    <div class="flex items-center gap-3 mr-3 border-r border-slate-700/50 pr-4">
                        <span class="text-slate-400 text-sm font-medium whitespace-nowrap">\u76EE\u6807\u5730\u533A:</span>
                        <input type="text" id="slot-cfg-0" value="JP" maxlength="2" class="bg-slate-900 border border-slate-700 rounded-lg py-2 w-16 text-white font-bold text-lg uppercase text-center focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 outline-none transition-all shadow-inner" placeholder="US" />
                    </div>
                    
                    <div class="flex items-center gap-3 mr-4">
                        <span class="text-slate-400 text-sm font-medium whitespace-nowrap">\u670D\u52A1\u7AEF\u53E3:</span>
                        <input type="number" id="slot-port" value="7920" min="1024" max="65535" class="bg-slate-900 border border-slate-700 rounded-lg py-2 w-24 text-white font-bold text-lg text-center focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 outline-none transition-all shadow-inner" placeholder="7920" />
                    </div>
                    
                    <button onclick="saveConfig()" class="group relative px-6 py-2.5 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 text-white text-sm font-bold shadow-lg shadow-blue-900/20 hover:shadow-indigo-900/40 hover:-translate-y-0.5 transition-all duration-200 overflow-hidden ml-auto">
                        <div class="absolute inset-0 bg-white/20 group-hover:translate-x-full -translate-x-full transform transition-transform duration-300 ease-in-out skew-x-12"></div>
                        <span class="flex items-center gap-2">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"></path></svg>
                            \u4E0B\u53D1\u7B56\u7565
                        </span>
                    </button>
                    
                    <div class="h-8 w-px bg-slate-800 mx-2 hidden sm:block"></div>

                    <button onclick="switchIP()" class="group relative px-6 py-2.5 rounded-lg bg-gradient-to-r from-purple-600 to-pink-600 text-white text-sm font-bold shadow-lg shadow-purple-900/20 hover:shadow-pink-900/40 hover:-translate-y-0.5 transition-all duration-200 overflow-hidden">
                         <div class="absolute inset-0 bg-white/20 group-hover:translate-x-full -translate-x-full transform transition-transform duration-300 ease-in-out skew-x-12"></div>
                         <span class="flex items-center gap-2">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                            \u5F3A\u5236\u66F4\u6362 IP
                         </span>
                    </button>
                </div>
            </div>
        </div>
        
        <div class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 mb-8">
            <div class="px-6 py-4 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
                <h3 class="font-semibold text-slate-200">\u591A Agent \u5B9E\u4F8B\u914D\u7F6E</h3>
                <button onclick="addInstance()" class="px-3 py-1.5 rounded-md bg-indigo-500/20 border border-indigo-500/30 text-indigo-300 text-xs">\uFF0B\u65B0\u589E\u5B9E\u4F8B</button>
            </div>
            <div id="instances-table" class="space-y-4 p-4 sm:p-6"><div class="py-6 text-center text-slate-500">\u6B63\u5728\u52A0\u8F7D\u5B9E\u4F8B\u914D\u7F6E...</div></div>
        </div>

        <div class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 mb-8">
            <div class="px-6 py-4 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
                <h3 class="font-semibold text-slate-200">\u5730\u533A\u8282\u70B9\u7EDF\u8BA1</h3>
                <span class="text-xs text-slate-500">\u53EF\u7528\u8282\u70B9 / \u6210\u529F\u7387</span>
            </div>
            <div class="max-h-96 overflow-y-auto overflow-x-auto"><table class="w-full text-left"><thead class="sticky top-0 z-10"><tr class="bg-slate-900/95 text-slate-400 text-xs"><th class="py-3 px-6">\u5730\u533A</th><th class="py-3 px-6">\u53EF\u7528\u8282\u70B9\u6570\u91CF</th><th class="py-3 px-6">\u8282\u70B9\u6210\u529F\u7387</th></tr></thead><tbody id="country-stats-table"><tr><td colspan="3" class="py-6 px-6 text-slate-500">\u7B49\u5F85 Agent \u4E0A\u62A5\u7EDF\u8BA1...</td></tr></tbody></table></div>
        </div>

        <div id="ip-score-section" style="display: none;" class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 mb-8">
            <div class="px-6 py-4 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
                <h3 class="font-semibold text-slate-200 flex items-center gap-2">
                    <svg class="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                    \u539F\u751F\u6DF1\u5EA6\u8D28\u68C0\u62A5\u544A (testisp.info)
                </h3>
                <a id="ip-score-link" href="#" class="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 transition-colors">
                    \u539F\u7248\u9875\u9762 <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
                </a>
            </div>
            
            <div id="native-score-container" class="p-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 bg-[#090E17]">
                <div class="col-span-full py-16 flex flex-col items-center justify-center text-slate-500">
                    <svg class="animate-spin h-8 w-8 text-indigo-500 mb-4" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    <span>\u7A7F\u900F\u8BF7\u6C42\u4E2D\uFF0C\u6B63\u5728\u6784\u5EFA\u539F\u751F\u8D28\u68C0\u62A5\u544A...</span>
                </div>
            </div>
        </div>

        <div class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 pb-8">
            <div class="px-4 py-3 border-b border-slate-800 bg-slate-900/80 flex justify-between items-center">
                <span class="text-xs text-slate-400 font-mono flex items-center gap-2">
                    <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M4 17h16a2 2 0 002-2V5a2 2 0 00-2-2H4a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
                    VPS \u5B9E\u65F6\u8FD0\u884C\u65E5\u5FD7 (自动同步)
                </span>
                <span class="flex gap-1.5">
                    <div class="w-3 h-3 rounded-full bg-rose-500/80 shadow-[0_0_5px_rgba(244,63,94,0.5)]"></div>
                    <div class="w-3 h-3 rounded-full bg-amber-500/80 shadow-[0_0_5px_rgba(245,158,11,0.5)]"></div>
                    <div class="w-3 h-3 rounded-full bg-emerald-500/80 shadow-[0_0_5px_rgba(16,185,129,0.5)]"></div>
                </span>
            </div>
            <div class="p-4 h-64 overflow-y-auto bg-[#0D1117] font-mono text-[13px] leading-relaxed text-slate-300" id="terminal-output">
                <div class="text-slate-500 animate-pulse">\u7B49\u5F85 VPS \u5FC3\u8DF3\u56DE\u4F20\u65E5\u5FD7\u6570\u636E...</div>
            </div>
        </div>
    </div>

    <div id="instance-modal" class="fixed inset-0 z-50 hidden items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4" role="dialog" aria-modal="true" aria-labelledby="instance-modal-title">
        <div class="w-full max-w-2xl rounded-2xl border border-slate-700 bg-[#111827] shadow-2xl shadow-black/50">
            <div class="flex items-center justify-between border-b border-slate-700 px-6 py-4">
                <div><p class="text-xs font-mono uppercase tracking-widest text-indigo-400">Agent 实例</p><h3 id="instance-modal-title" class="mt-1 text-xl font-bold text-white">\u7F16\u8F91\u5B9E\u4F8B</h3></div>
                <button type="button" onclick="closeInstanceModal()" class="rounded-lg px-3 py-1 text-2xl text-slate-400 hover:bg-slate-800 hover:text-white" aria-label="\u5173\u95ED">\xD7</button>
            </div>
            <form id="instance-form" class="grid grid-cols-1 gap-4 p-6 sm:grid-cols-2">
                <label class="text-sm text-slate-400">\u5B9E\u4F8B ID<input id="form-instance-id" required pattern="[A-Za-z0-9][A-Za-z0-9._:-]{1,95}" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none focus:border-indigo-500"></label>
                <label class="text-sm text-slate-400">\u5907\u6CE8<input id="form-instance-remark" maxlength="200" placeholder="\u4F8B\u5982\uFF1A\u7F8E\u56FD\u670D\u52A1\u5668 / \u65E5\u672C VPS" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none focus:border-indigo-500"></label>
                <label class="text-sm text-slate-400">\u5B9E\u4F8B\u540D\u79F0<input id="form-instance-name" required class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none focus:border-indigo-500"></label>
                <label class="text-sm text-slate-400">\u6BCD\u673A IP<input id="form-instance-ip" required class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-white outline-none focus:border-indigo-500"></label>
                <label class="text-sm text-slate-400">\u76EE\u6807\u5730\u533A<input id="form-instance-country" required maxlength="2" pattern="[A-Za-z]{2}" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono uppercase text-white outline-none focus:border-indigo-500"></label>
                <label class="text-sm text-slate-400">\u670D\u52A1\u7AEF\u53E3<input id="form-instance-port" required type="number" min="1024" max="65535" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-white outline-none focus:border-indigo-500"></label>
                <label class="flex items-end gap-3 pb-2 text-sm text-slate-300"><input id="form-instance-enabled" type="checkbox" class="h-4 w-4 accent-indigo-500">\u542F\u7528\u6B64\u5B9E\u4F8B</label>
                <div class="flex justify-end gap-3 border-t border-slate-700 pt-5 sm:col-span-2"><button type="button" onclick="closeInstanceModal()" class="rounded-lg border border-slate-600 px-5 py-2 text-sm text-slate-300 hover:bg-slate-800">\u53D6\u6D88</button><button type="submit" class="rounded-lg bg-indigo-600 px-5 py-2 text-sm font-bold text-white hover:bg-indigo-500">\u4FDD\u5B58\u5E76\u4E0B\u53D1</button></div>
            </form>
        </div>
    </div>

    <script>
        const PANEL_AUTH = 'Basic ' + btoa('${webUser}:${webPass}');
        const apiFetch = (path, options = {}) => {
            const headers = Object.assign({}, options.headers || {}, { Authorization: PANEL_AUTH });
            return fetch(path, Object.assign({}, options, { headers }));
        };
        let currentScoreIp = "";

        let instanceRows = [];
        let editingInstanceId = null;
        const modal = document.getElementById('instance-modal');
        function openInstanceModal(x) {
            editingInstanceId = x && x.instance_id ? x.instance_id : null;
            document.getElementById('instance-modal-title').textContent = editingInstanceId ? '\u7F16\u8F91\u5B9E\u4F8B' : '\u65B0\u589E\u5B9E\u4F8B';
            document.getElementById('form-instance-id').value = x?.instance_id || '54.65.193.234-7925';
            document.getElementById('form-instance-id').readOnly = !!editingInstanceId;
            document.getElementById('form-instance-name').value = x?.name || 'Agent 7925';
            document.getElementById('form-instance-remark').value = x?.remark || '';
            document.getElementById('form-instance-ip').value = x?.ip || '54.65.193.234';
            document.getElementById('form-instance-country').value = x?.country || 'US';
            document.getElementById('form-instance-port').value = x?.port || 7925;
            document.getElementById('form-instance-enabled').checked = x ? !!x.enabled : true;
            modal.classList.remove('hidden'); modal.classList.add('flex');
            setTimeout(() => document.getElementById('form-instance-name').focus(), 0);
        }
        function closeInstanceModal(){ modal.classList.add('hidden'); modal.classList.remove('flex'); editingInstanceId=null; }
        document.getElementById('instance-form').addEventListener('submit', async (event) => {
            event.preventDefault();
            const data = {instance_id:document.getElementById('form-instance-id').value.trim(), remark:document.getElementById('form-instance-remark').value.trim(), name:document.getElementById('form-instance-name').value.trim(), ip:document.getElementById('form-instance-ip').value.trim(), country:document.getElementById('form-instance-country').value.trim().toUpperCase(), port:Number(document.getElementById('form-instance-port').value), enabled:document.getElementById('form-instance-enabled').checked};
            const res = await apiFetch('/api/instances',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
            if(!res.ok){alert('\u4FDD\u5B58\u5931\u8D25\uFF1A'+await res.text());return;} closeInstanceModal(); await loadInstances(); alert('\u5B9E\u4F8B\u914D\u7F6E\u5DF2\u4FDD\u5B58\uFF1B\u8FD0\u884C\u4E2D\u7684 launcher \u4F1A\u5728\u4E0B\u6B21\u540C\u6B65\u65F6\u5E94\u7528');
        });
        function toggleInstanceGroup(key) {
            const box = document.querySelector('[data-instance-group="'+key+'"]');
            const button = document.querySelector('[data-group-toggle="'+key+'"]');
            if (!box || !button) return;
            const hidden = box.classList.toggle('hidden');
            const arrow = button.querySelector('[data-group-arrow]');
            if (arrow) arrow.textContent = hidden ? '\u25B8' : '\u25BE';
            button.setAttribute('aria-expanded', hidden ? 'false' : 'true');
        }
        function toggleAgentCard(id) {
            const detail = document.querySelector('[data-agent-detail="'+id+'"]');
            const card = document.querySelector('[data-agent-card="'+id+'"]');
            if (!detail || !card) return;
            const hidden = detail.classList.toggle('hidden');
            card.classList.toggle('border-indigo-500/50', !hidden);
            const arrow = card.querySelector('[data-agent-arrow]');
            if (arrow) arrow.textContent = hidden ? '\u25B8' : '\u25BE';
        }
        async function setGroupRemark(ip) {
            const current = (instanceRows.find(x => x.ip === ip) || {}).remark || '';
            const remark = prompt('\u8BBE\u7F6E\u670D\u52A1\u5668\u5206\u7EC4\u5907\u6CE8\uFF08\u4F1A\u540C\u6B65\u5230\u8BE5\u670D\u52A1\u5668\u4E0B\u6240\u6709 Agent\uFF09', current);
            if (remark === null) return;
            for (const x of instanceRows.filter(x => x.ip === ip)) {
                const res = await apiFetch('/api/instances', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({...x, remark:remark.trim()})});
                if (!res.ok) { alert('\u7EC4\u5907\u6CE8\u4FDD\u5B58\u5931\u8D25\uFF1A' + await res.text()); return; }
            }
            await loadInstances();
        }
        function renderInstanceGroups(nodes) {
            const body = document.getElementById('instances-table');
            const nodeMap = Object.fromEntries((nodes || []).map(n => [n.instance_id || ('legacy-' + n.ip), n]));

            const groups = (instanceRows || []).reduce((all, x) => { (all[x.ip] ||= []).push(x); return all; }, {});
            const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
            const html = Object.entries(groups).sort(([a],[b]) => a.localeCompare(b, undefined, {numeric:true})).map(([ip, rows]) => {
                const key = 'group-' + ip.replace(/[^A-Za-z0-9]/g, '_');
                const groupRemark = rows.find(x => x.remark)?.remark || '\u672A\u8BBE\u7F6E\u5907\u6CE8';
                const cards = rows.sort((a,b) => a.port-b.port).map(x => {
                    const n = nodeMap[x.instance_id] || {};
                    let details = []; try { details = JSON.parse(n.details || '[]'); } catch(e) {}
                    const active = details.find(d => d.active) || details[0] || {};
                    const age = n.last_seen ? Math.floor((Date.now()-n.last_seen)/1000) : null;
                    const routes = details.length ? details.map(d => '<span class="inline-flex items-center gap-2 rounded-lg border '+(d.active?'border-emerald-500/30 bg-emerald-500/10 text-emerald-300':'border-sky-500/30 bg-sky-500/10 text-sky-300')+' px-2.5 py-1.5 text-xs"><b>'+esc(d.tunnel || 'tun')+'</b><span>'+esc(d.country || '')+' '+esc(d.node_ip || '---')+':'+esc(d.port || '')+'</span><span class="font-semibold">'+(d.active?'主用':'备用')+'</span></span>').join('') : (n.last_seen && age !== null && age < 20 ? '<span class="text-sky-300 text-xs">Agent 已连接，隧道重连中</span>' : '<span class="text-amber-400 text-xs">\u7B49\u5F85 Agent \u4E0A\u62A5</span>');
                    const heartbeat = age === null ? '<span class="text-slate-500">\u65E0\u5FC3\u8DF3</span>' : '<span class="'+(age < 20 ? 'text-emerald-400':'text-rose-400')+' font-mono">'+age+'s \u524D</span>';
                    const id = esc(x.instance_id);
                    return '<div data-agent-card="'+id+'" class="overflow-hidden rounded-xl border border-slate-700/70 bg-slate-950/50 transition-colors"><button type="button" onclick="toggleAgentCard(this.dataset.agentId)" data-agent-id="'+id+'" class="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-slate-800/50"><span data-agent-arrow class="text-indigo-400">\u25B8</span><span class="min-w-0 flex-1"><span class="block truncate font-mono text-sm text-indigo-200">'+id+'</span><span class="block truncate text-xs text-slate-400">'+esc(x.remark || '\u672A\u8BBE\u7F6E\u5B9E\u4F8B\u5907\u6CE8')+'</span></span><span class="hidden sm:inline text-xs text-slate-500">'+esc(x.country)+' \xB7 '+esc(x.port)+'</span><span class="rounded-full px-2 py-1 text-xs '+(x.enabled?'bg-emerald-500/10 text-emerald-300':'bg-slate-700 text-slate-400')+'">'+(x.enabled?'\u542F\u7528':'\u505C\u7528')+'</span><span class="text-xs text-slate-500">\u8BE6\u60C5</span></button><div data-agent-detail="'+id+'" class="hidden border-t border-slate-800/80 px-4 py-4"><div class="grid gap-4 lg:grid-cols-[1fr_auto] lg:items-start"><div><div class="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500">\u4E3B\u5907\u53CC\u8DEF\u51FA\u53E3</div><div class="flex flex-wrap gap-2">'+routes+'</div><div class="mt-3 flex flex-wrap gap-4 text-xs"><span class="text-slate-400">\u5FC3\u8DF3\uFF1A'+heartbeat+'</span><span class="text-slate-400">\u6BCD\u673A\uFF1A<b class="font-mono text-slate-300">'+esc(x.ip)+'</b></span><span class="text-slate-400">\u914D\u7F6E\uFF1A<b class="font-mono text-indigo-300">'+esc(x.country)+' : '+esc(x.port)+'</b></span></div></div><div class="flex flex-wrap justify-end gap-2"><button data-id="'+id+'" onclick="editInstance(this.dataset.id)" class="rounded-lg bg-sky-500/15 px-3 py-1.5 text-xs text-sky-300">\u7F16\u8F91</button><button data-id="'+id+'" onclick="forceInstanceSwitch(this.dataset.id)" class="rounded-lg bg-amber-500/15 px-3 py-1.5 text-xs text-amber-300">\u6362 IP</button><button data-ip="'+esc(x.ip)+'" data-port="'+esc(active.port || x.port)+'" data-node-ip="'+esc(active.node_ip || '')+'" data-country="'+esc(active.country || x.country)+'" onclick="copyInstanceProxy(this.dataset.ip,Number(this.dataset.port),this.dataset.nodeIp,this.dataset.country)" class="rounded-lg bg-emerald-500/15 px-3 py-1.5 text-xs text-emerald-300">\u590D\u5236\u4EE3\u7406</button><button data-id="'+id+'" onclick="deleteInstance(this.dataset.id)" class="rounded-lg bg-rose-500/15 px-3 py-1.5 text-xs text-rose-300">\u5220\u9664</button></div></div></div></div>';
                }).join('');
                return '<section class="overflow-hidden rounded-2xl border border-indigo-500/20 bg-slate-900/50"><div class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 bg-slate-800/60 px-4 py-3 sm:px-5"><button type="button" data-group-toggle="'+key+'" aria-expanded="false" onclick="toggleInstanceGroup(this.dataset.groupToggle)" class="flex min-w-0 items-center gap-3 text-left"><span data-group-arrow class="text-indigo-400">\u25B8</span><span class="min-w-0"><span class="block truncate font-semibold text-indigo-200">'+esc(groupRemark)+'</span><span class="block text-xs text-slate-500">'+esc(ip)+' \xB7 '+rows.length+' \u4E2A Agent</span></span></button><button data-group-ip="'+esc(ip)+'" onclick="setGroupRemark(this.dataset.groupIp)" class="rounded-lg bg-indigo-500/15 px-3 py-1.5 text-xs text-indigo-300 hover:bg-indigo-500/25">\u8BBE\u7F6E\u7EC4\u5907\u6CE8</button></div><div data-instance-group="'+key+'" class="hidden space-y-3 p-3 sm:p-4">'+cards+'</div></section>';
            }).join('');
            body.innerHTML = html || '<div class="py-6 text-center text-slate-500">\u6682\u65E0\u5B9E\u4F8B</div>';
        }
        async function loadInstances() {
            const [instancesRes, nodesRes] = await Promise.all([apiFetch('/api/instances'), apiFetch('/api/nodes')]);
            instanceRows = await instancesRes.json();
            renderInstanceGroups(await nodesRes.json());
        }
        function editInstance(id){ const x=instanceRows.find(v=>v.instance_id===id); if(x) openInstanceModal(x); }
        function addInstance(){ openInstanceModal(null); }
        async function deleteInstance(id){ if(!confirm('\u786E\u8BA4\u5220\u9664\u5B9E\u4F8B '+id+'\uFF1F')) return; const r=await apiFetch('/api/instances?instance_id='+encodeURIComponent(id),{method:'DELETE'}); if(!r.ok) alert('\u5220\u9664\u5931\u8D25\uFF1A'+await r.text()); else { await loadInstances(); await fetchNodes(); } }

        async function fetchCountries() {
            try {
                const res = await fetch('/api/countries');
                const list = await res.json();
                const container = document.getElementById('countries-list');
                container.innerHTML = list.map(c => \`<button type="button" data-country="\${c}" onclick="selectCountry('\${c}')" class="bg-slate-800/80 hover:bg-indigo-500/20 text-slate-300 hover:text-indigo-300 transition-colors border border-slate-700/50 px-2.5 py-1 rounded-md text-xs font-mono font-bold cursor-pointer">\${c}</button>\`).join('');
            } catch(e) {}
        }

        function selectCountry(country) {
            const input = document.getElementById('slot-cfg-0');
            input.value = String(country || '').toUpperCase();
            document.querySelectorAll('[data-country]').forEach(button => {
                const active = button.dataset.country === input.value;
                button.classList.toggle('bg-indigo-500/30', active);
                button.classList.toggle('text-indigo-300', active);
                button.classList.toggle('border-indigo-500/60', active);
            });
            input.focus();
        }
        async function loadConfig() {
            try {
                const res = await apiFetch('/api/config');
                const map = await res.json();
                document.getElementById('slot-cfg-0').value = map["0"] || 'JP';
                document.getElementById('slot-port').value = map["port"] || 7920;
                selectCountry(map["0"] || 'JP');
            } catch(e) {}
        }

        async function saveConfig() {
            const val = document.getElementById(\`slot-cfg-0\`).value.toUpperCase().trim() || 'JP';
            const port = parseInt(document.getElementById(\`slot-port\`).value) || 7920;
            await apiFetch('/api/config', {
                method: 'POST',
                body: JSON.stringify({ "0": val, "port": port })
            });
            alert('\u{1F680} \u7B56\u7565\u53CA\u7AEF\u53E3\u5DF2\u4E91\u7AEF\u540C\u6B65\uFF01Agent \u5C06\u5728\u4E0B\u4E00\u5FC3\u8DF3\u5468\u671F\u5E94\u7528\u3002');
        }

        async function switchIP() {
            const val = document.getElementById(\`slot-cfg-0\`).value.toUpperCase().trim() || 'JP';
            const port = parseInt(document.getElementById(\`slot-port\`).value) || 7920;
            await apiFetch('/api/config', {
                method: 'POST',
                body: JSON.stringify({ "0": val, "port": port, "switch_trigger": Date.now() })
            });
            alert('\u{1F504} \u91CD\u62E8\u6307\u4EE4\u5DF2\u4E0B\u53D1\uFF01VPS \u5C06\u6E05\u9000\u5F53\u524D\u901A\u9053\u6C60\u91CD\u65B0\u5E76\u53D1\u5EFA\u8FDE...');
        }

        async function copyInstanceProxy(ip, port, nodeIp, country) {
            const proxy = 'socks5://${proxyUser}:${proxyPass}@' + ip + ':' + port + '#' + (country || 'NODE') + '_ActiveNode_' + (nodeIp || 'IP');
            try {
                await navigator.clipboard.writeText(proxy);
                alert('\u5DF2\u590D\u5236\u8BE5\u5B9E\u4F8B\u4EE3\u7406\u5730\u5740');
            } catch (e) {
                const area = document.createElement('textarea'); area.value = proxy; document.body.appendChild(area); area.select(); document.execCommand('copy'); area.remove(); alert('\u5DF2\u590D\u5236\u8BE5\u5B9E\u4F8B\u4EE3\u7406\u5730\u5740');
            }
        }

        async function copyText(text, message) {
            try { await navigator.clipboard.writeText(text); }
            catch (e) { const area=document.createElement('textarea'); area.value=text; document.body.appendChild(area); area.select(); document.execCommand('copy'); area.remove(); }
            if (message) alert(message);
        }

        function updateAgentCommands() {
            const ip = document.getElementById('agent-ip-input')?.value.trim() || '54.65.193.234';
            const port = document.getElementById('agent-port-input')?.value.trim() || '7920';
            document.getElementById('install-command').textContent = 'curl -fsSL -u sysadmin "' + '${domain}' + '/agent?ip=' + encodeURIComponent(ip) + '&port=' + encodeURIComponent(port) + '" | bash';
            document.getElementById('uninstall-command').textContent = 'curl -fsSL -u sysadmin "' + '${domain}' + '/remove-agent?ip=' + encodeURIComponent(ip) + '&port=' + encodeURIComponent(port) + '" | bash';
        }

        async function setInstanceCountry(ip) {
            const input = document.getElementById('instance-country-' + ip.replace(/./g, '-'));
            const country = (input ? input.value : '').toUpperCase().trim();
            if (!/^[A-Z]{2}$/.test(country)) { alert('\u8BF7\u8F93\u5165\u4E24\u4F4D\u56FD\u5BB6\u4EE3\u7801\uFF0C\u4F8B\u5982 US\u3001JP\u3001KR'); return; }
            const configured = instanceRows.find(x => x.ip === ip);
            const port = Number(configured?.port) || 7920;
            const res = await apiFetch('/api/instance-config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ip, country, port, switch_trigger: Date.now()}) });
            if (!res.ok) { alert('\u5B9E\u4F8B\u7B56\u7565\u4FDD\u5B58\u5931\u8D25\uFF1AHTTP ' + res.status); return; }
            if (input) { input.dataset.saved = country; input.blur(); }
            alert('\u5DF2\u4FDD\u5B58\u5E76\u4E0B\u53D1 ' + ip + ' \u2192 ' + country + '\uFF1BAgent \u5C06\u5728\u7EA6 15 \u79D2\u5185\u5E94\u7528');
        }
        async function forceInstanceSwitch(instanceId) {
            const x = instanceRows.find(v => v.instance_id === instanceId); if (!x) return;
            const res = await apiFetch('/api/instances', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({...x, switch_trigger:Date.now()}) });
            if (!res.ok) { alert('\u5F3A\u5236\u6362 IP \u4E0B\u53D1\u5931\u8D25'); return; }
            alert('\u5DF2\u8981\u6C42 '+instanceId+' \u5F3A\u5236\u66F4\u6362\u51FA\u53E3'); fetchNodes();
        }

        async function loadNativeIpScore(ip) {
            const container = document.getElementById('native-score-container');
            container.innerHTML = '<div class="col-span-full py-16 flex flex-col items-center justify-center text-slate-500"><svg class="animate-spin h-8 w-8 text-indigo-500 mb-4" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg><span>\u7A7F\u900F\u8BF7\u6C42\u4E2D\uFF0C\u6B63\u5728\u6784\u5EFA\u539F\u751F\u8D28\u68C0\u62A5\u544A...</span></div>';
            
            try {
                const res = await apiFetch('/api/testisp-lookup/' + encodeURIComponent(ip));
                const rawText = await res.text();
                
                let d;
                try {
                    d = JSON.parse(rawText);
                } catch (e) {
                    const safeText = rawText.substring(0, 500).replace(/</g, '&lt;').replace(/>/g, '&gt;');
                    throw new Error(\`\u76EE\u6807\u63A5\u53E3\u8FD4\u56DE\u4E86\u975E JSON \u683C\u5F0F\u6570\u636E(\u53EF\u80FD API \u8DEF\u5F84\u9519\u8BEF\u6216\u88AB\u4E91\u7AEF\u76FE\u62E6\u622A)\u3002<br>HTTP \u72B6\u6001\u7801: \${res.status}<br><div class="mt-3 text-left bg-slate-900 p-3 rounded text-xs text-rose-300 font-mono break-all overflow-y-auto max-h-32 border border-rose-500/30">\${safeText}</div>\`);
                }
                
                if (!d || !d.geo || !d.isp) {
                    container.innerHTML = \`<div class="col-span-full text-center py-8 text-rose-400 bg-rose-500/10 rounded-xl border border-rose-500/20">\u65E0\u6CD5\u83B7\u53D6\u62A5\u544A: \u63A5\u53E3\u8FD4\u56DE\u6570\u636E\u7ED3\u6784\u5F02\u5E38 \${d.error || ''}</div>\`;
                    return;
                }

                const isHosting = d.isp.flag === 'hosting';
                const threat = d.risk.threat_listed;
                const isNative = d.geo.is_native;
                
                const tags = isHosting 
                    ? '<span class="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/20 text-xs font-bold">\u673A\u623FIP</span>' 
                    : '<span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 text-xs font-bold">\u5BB6\u5EAD\u5BBD\u5E26</span>';
                
                const locStr = [d.geo.country, d.geo.city].filter(Boolean).join(" ");
                const orgStr = d.isp.org || '-';

                container.innerHTML = \`
                    <div class="col-span-full bg-slate-800/60 border border-slate-700/80 p-5 rounded-2xl flex flex-wrap gap-4 justify-between items-center mb-2 shadow-lg">
                        <div class="flex items-center gap-4">
                            <span class="text-3xl font-extrabold font-mono text-white tracking-tight drop-shadow-sm">\${ip}</span>
                            <span class="text-slate-400 text-sm hidden sm:flex items-center border-l border-slate-700 pl-4 h-6">
                                <span class="uppercase tracking-widest text-indigo-400 mr-2 text-xs font-bold">\${d.geo.country_code || 'N/A'}</span> 
                                \${locStr} \xB7 \${orgStr}
                            </span>
                        </div>
                    </div>

                    <div class="bg-slate-800/40 border border-slate-700/60 p-6 rounded-2xl flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow hover:bg-slate-800/60">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest pb-3 border-b border-slate-700/50">\u57FA\u7840\u7269\u7406\u753B\u50CF</h4>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">IP \u539F\u751F\u6027</span> <span class="font-medium text-sm">\${isNative ? '<span class="px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-bold">\u539F\u751F IP (Native)</span>' : \`<span class="px-2.5 py-1 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30 text-xs font-bold">\${d.geo.native_type || '\u5E7F\u64AD IP'}</span>\`}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">\u4E1A\u52A1\u6807\u8BB0</span> <div class="flex gap-1">\${tags}</div></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">\u8FD0\u8425\u7C7B\u578B</span> <span class="font-medium \${isHosting ? 'text-rose-400' : 'text-emerald-400'} text-sm">\${d.isp.type || '-'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">\u5F52\u5C5E\u673A\u6784</span> <span class="font-medium text-slate-300 text-sm truncate max-w-[150px]" title="\${orgStr}">\${orgStr}</span></div>
                    </div>

                    <div class="bg-slate-800/40 border border-slate-700/60 p-6 rounded-2xl flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow hover:bg-slate-800/60">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest pb-3 border-b border-slate-700/50">ISP \u7F51\u7EDC\u5E95\u5C42</h4>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">ASN</span> <span class="font-medium text-indigo-300 text-sm font-mono">\${d.isp.asn || '-'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">\u89E3\u6790\u65F6\u533A</span> <span class="font-medium text-slate-300 text-sm font-mono">\${d.geo.timezone || '-'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">\u504F\u79FB\u91CF (Drift)</span> <span class="font-medium \${d.geo.has_drift ? 'text-rose-400' : 'text-emerald-400'} text-sm">\${d.geo.drift_km || 0} km</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">\u53CD\u5411 DNS (rDNS)</span> <span class="font-medium text-slate-400 text-xs font-mono truncate max-w-[150px]" title="\${d.isp.rdns || '-'}">\${d.isp.rdns || '-'}</span></div>
                    </div>

                    <div class="bg-slate-800/40 border border-slate-700/60 p-6 rounded-2xl flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow hover:bg-slate-800/60">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest pb-3 border-b border-slate-700/50">\u98CE\u9669\u6DF1\u5EA6\u68C0\u6D4B</h4>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">Spamhaus \u60C5\u62A5</span> <span class="\${threat ? 'px-2.5 py-1 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 text-xs font-bold' : 'px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-bold'}">\${threat ? '\u{1F6A8} \u5DF2\u5728\u9ED1\u540D\u5355' : '\u2705 \u7EAF\u51C0\u65E0\u5F02\u5E38'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">\u4EE3\u7406/\u673A\u623F\u7279\u5F81</span> <span class="font-medium text-xs font-bold \${d.isp.warning ? 'text-amber-400' : 'text-emerald-400'} truncate max-w-[150px]" title="\${d.isp.warning || ''}">\${d.isp.warning || '\u672A\u68C0\u6D4B\u5230\u660E\u663E\u5F02\u5E38'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">\u6570\u636E\u6E90</span> <span class="font-medium text-slate-400 text-xs">\${d.data_source || 'Unknown'}</span></div>
                    </div>
                \`;
            } catch (e) {
                container.innerHTML = \`<div class="col-span-full text-left p-6 text-rose-400 bg-rose-500/10 rounded-xl border border-rose-500/20">\${e.message}</div>\`;
            }
        }

        async function fetchNodes() {
            try {
                const res = await apiFetch('/api/nodes');
                const servers = await res.json();
                renderInstanceGroups(servers);
                const stats = {};
                const uniqueNodes = new Map();
                const fallbackStats = {};
                (servers || []).forEach(server => {
                    try { Object.entries(JSON.parse(server.stats || '{}')).forEach(([country, value]) => {
                        const attempts = value.attempts || 0;
                        const successes = value.successes || 0;
                        const current = stats[country] || {total: 0, available: 0, attempts: 0, successes: 0};
                        current.attempts = Math.max(current.attempts, attempts);
                        current.successes = Math.max(current.successes, successes);
                        const fallback = fallbackStats[country] || {total: 0, available: 0};
                        fallback.total = Math.max(fallback.total, value.total || 0);
                        fallback.available = Math.max(fallback.available, value.available || 0);
                        fallbackStats[country] = fallback;
                        if (Array.isArray(value.nodes)) value.nodes.forEach(node => {
                            const ip = String(node.ip || '').trim();
                            if (!ip) return;
                            const key = country + ':' + ip;
                            const existing = uniqueNodes.get(key);
                            uniqueNodes.set(key, {country, available: Boolean(node.available) || Boolean(existing?.available)});
                        });
                        stats[country] = current;
                    }); } catch (e) {}
                });
                uniqueNodes.forEach(node => {
                    const current = stats[node.country] || {total: 0, available: 0, attempts: 0, successes: 0};
                    current.total += 1;
                    if (node.available) current.available += 1;
                    stats[node.country] = current;
                });
                Object.entries(fallbackStats).forEach(([country, fallback]) => {
                    if (uniqueNodes.size && [...uniqueNodes.values()].some(node => node.country === country)) return;
                    const current = stats[country] || {total: 0, available: 0, attempts: 0, successes: 0};
                    current.total = fallback.total;
                    current.available = fallback.available;
                    stats[country] = current;
                });
                const statsBody = document.getElementById('country-stats-table');
                if (statsBody) {
                    try {
                        const statRows = Object.entries(stats).sort((a,b) => b[1].available - a[1].available || b[1].total - a[1].total).map(([country, value]) => {
                            const rate = value.attempts ? ((value.successes * 100) / value.attempts).toFixed(1) + '%' : '\u6682\u65E0';
                            return '<tr class="border-t border-slate-800/50"><td class="py-3 px-6 font-mono font-bold text-indigo-300">' + country + '</td><td class="py-3 px-6 text-emerald-400">' + value.available + '</td><td class="py-3 px-6 text-slate-300">' + rate + '</td></tr>';
                        }).join('');
                        statsBody.innerHTML = statRows || '<tr><td colspan="4" class="py-6 px-6 text-slate-500">\u6682\u65E0\u8282\u70B9\u7EDF\u8BA1</td></tr>';
                    } catch (statsError) {
                        statsBody.innerHTML = '<tr><td colspan="4" class="py-6 px-6 text-amber-400">\u7EDF\u8BA1\u6682\u65F6\u4E0D\u53EF\u7528\uFF0C\u8282\u70B9\u77E9\u9635\u4ECD\u6B63\u5E38\u52A0\u8F7D</td></tr>';
                    }
                }
                const terminal = document.getElementById('terminal-output');
                if (!terminal) return;

                if (servers.length > 0 && servers[0].details) {
                    const details = JSON.parse(servers[0].details);
                    // \u6DF1\u5EA6\u8D28\u68C0\u62A5\u544A\uFF1A\u6C38\u8FDC\u63D0\u53D6\u6B63\u5728\u627F\u8F7D\u4E1A\u52A1\u7684 ACTIVE \u7F51\u5361 IP \u8FDB\u884C\u8BC4\u5206
                    const activeNode = details.find(d => d.active) || details[0];
                    if (activeNode && activeNode.node_ip) {
                        const newIp = activeNode.node_ip;
                        if (newIp !== currentScoreIp) {
                            currentScoreIp = newIp;
                            document.getElementById('ip-score-section').style.display = 'block';
                            
                            // \u9488\u5BF9 testisp.info \u524D\u7AEF\u9ED8\u8BA4\u4EC5\u67E5\u672C\u673A\u7684\u9632\u5446\u673A\u5236\uFF1A\u81EA\u52A8\u590D\u5236 IP \u5230\u526A\u8D34\u677F\uFF0C\u8DF3\u8F6C\u540E\u7531\u7528\u6237\u7C98\u8D34
                            const scoreLink = document.getElementById('ip-score-link');
                            scoreLink.href = \`https://testisp.info/?ip=\${newIp}\`;
                            scoreLink.onclick = (e) => {
                                e.preventDefault();
                                navigator.clipboard.writeText(newIp).then(() => {
                                    alert('\u{1F7E2} \u5DF2\u81EA\u52A8\u590D\u5236\u96A7\u9053\u8282\u70B9 IP: ' + newIp + '\\n\\n\u7531\u4E8E testisp.info \u5B98\u7F51\u9ED8\u8BA4\u4EC5\u68C0\u6D4B\u672C\u673A\uFF0C\u8BF7\u5728\u968F\u540E\u6253\u5F00\u7684\u7F51\u9875\u3010\u8F93\u5165\u6846\u3011\u4E2D\u3010\u7C98\u8D34\u3011\u5E76\u56DE\u8F66\u67E5\u8BE2\uFF01');
                                    window.open(\`https://testisp.info/?ip=\${newIp}\`, '_blank');
                                }).catch(() => {
                                    window.open(\`https://testisp.info/?ip=\${newIp}\`, '_blank');
                                });
                            };

                            loadNativeIpScore(newIp);
                        }
                    }
                }
                
                if (servers[0] && servers[0].logs) {
                    const isAtBottom = terminal.scrollHeight - terminal.scrollTop <= terminal.clientHeight + 30;
                    
                    let logHTML = servers[0].logs
                        .replace(/</g, '&lt;').replace(/>/g, '&gt;')
                        .replace(/\\[\\*\\]/g, '<span class="text-indigo-400 font-bold">[*]</span>')
                        .replace(/\\[\\+\\]/g, '<span class="text-emerald-400 font-bold">[+]</span>')
                        .replace(/\\[\\-\\]/g, '<span class="text-rose-400 font-bold">[-]</span>')
                        .replace(/\\[\\!\\]/g, '<span class="text-amber-400 font-bold">[!]</span>');
                        
                    terminal.innerHTML = '<pre class="whitespace-pre-wrap break-all">' + logHTML + '</pre>';
                    
                    if (isAtBottom) {
                        terminal.scrollTop = terminal.scrollHeight;
                    }
                }
                
            } catch (err) {
                console.error('fetchNodes failed', err);
                const terminal = document.getElementById('terminal-output');
                if (terminal) terminal.innerHTML = '<div class="text-amber-400">\u8282\u70B9\u63A5\u53E3\u52A0\u8F7D\u5931\u8D25\uFF0C\u8BF7\u5237\u65B0\u9875\u9762</div>';
            }
        }
        
        ['agent-ip-input', 'agent-port-input'].forEach(id => {
            document.getElementById(id)?.addEventListener('input', updateAgentCommands);
        });
        updateAgentCommands();
        fetchCountries();
        loadConfig();
        loadInstances();
        fetchNodes();
        // \u8282\u70B9\u77E9\u9635\u6539\u4E3A\u624B\u52A8\u5237\u65B0\uFF0C\u907F\u514D\u7F16\u8F91\u5355\u5B9E\u4F8B\u5730\u533A\u65F6\u88AB\u8F6E\u8BE2\u8986\u76D6\u3002
    <\/script>
</body>
</html>
`, "DASHBOARD_HTML");
export {
  index_default as default
};
//# sourceMappingURL=index.js.map
