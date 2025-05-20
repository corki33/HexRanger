import configparser
from scapy.all import sniff, IP, TCP, UDP, Ether
from collections import defaultdict
import time
from datetime import datetime
import os
import platform
import csv
import subprocess

# --- Load configuration ---
config = configparser.ConfigParser()
config.read("config.ini")

INTERFACE = config.get("network", "interface")
MY_IP = config.get("network", "my_ip")
LOCAL_NET = config.get("network", "local_net")

SAFE_IPS = set(ip.strip() for ip in config.get("safe", "safe_ips").split(","))
SAFE_PORTS = set(int(p) for p in config.get("safe", "safe_ports").split(","))

ALERT_THRESHOLD = config.getint("alerts", "alert_threshold")
TIME_WINDOW = config.getint("alerts", "time_window")
LOGFILE = config.get("alerts", "logfile")
BANFILE = "banned_ips.txt"
THREATS_CSV = "threats.csv"

# --- GLOBAL VARIABLES ---
ip_activity = defaultdict(list)
syn_packets = defaultdict(list)
portscan_attempts = defaultdict(set)
udp_packets = defaultdict(list)
banned_ips = set()

# --- BLOCKING /RESPONSE FUNCTIONS ---

def block_ip(ip):
    system = platform.system()
    try:
        if system == "Windows":
            rule_name = f"HexRanger_Block_{ip.replace('.', '_')}"
            check_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"]
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            if "No rules match the specified criteria" not in result.stdout:
                print(f"[i] Firewall rule for {ip} already exists.")
                return
            add_cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                       f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"]
            subprocess.run(add_cmd, capture_output=True, check=True)
            print(f"[+] Firewall rule added for IP: {ip}")
        elif system == "Linux":
            subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                           capture_output=True, check=False)
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                           capture_output=True, check=True)
            print(f"[+] IPTables: IP {ip} blocked.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to block IP {ip}: {e}")

def respond_to_threat(ip, reason):
    if ip not in banned_ips:
        banned_ips.add(ip)
        with open(BANFILE, "a") as f:
            f.write(f"{ip} # {reason} @ {datetime.now()}\n")
        print(f"[!] IP {ip} added to banned list for reason: {reason}")
        block_ip(ip)

# --- EXPORT TO CSV---

def export_to_csv(ip, mac, reason, details):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_exists = os.path.isfile(THREATS_CSV)
    with open(THREATS_CSV, "a", newline='') as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(["timestamp", "ip", "mac", "type", "details"])
        writer.writerow([now, ip, mac, reason, details])

# --- LOGING ---

def log_event_grouped(ip, mac, message):
    timestamp = datetime.now().strftime("%H:%M %d.%m.%Y")
    is_local = ip.startswith(LOCAL_NET)
    is_threat = any(keyword in message.lower() for keyword in ["flood", "scan", "external connection", "threat"])

    if is_threat:
        section_file = "================ [THREATS] =================="
    elif is_local:
        section_file = "================== [LOCAL NETWORK] ================"
    else:
        section_file = "============ [EXTERNAL IPs] =================="

    header = f"[{ip} | MAC: {mac}]"
    entry = f" - {timestamp}: {message}"

    with open(LOGFILE, "a", encoding="utf-8") as f:
        f.write(f"\n{section_file}\n")
        f.write(f"{header}\n")
        f.write(f"{entry}\n")

# --- FILTERS ---

def is_safe_ip(ip_src, ip_dst):
    if ip_src in SAFE_IPS or ip_dst in SAFE_IPS:
        return True
    if ip_src == MY_IP:
        return True
    if ip_src.startswith(LOCAL_NET) and ip_dst.startswith(LOCAL_NET):
        return True
    return False

def is_safe_port(packet):
    if TCP in packet:
        if packet[TCP].dport in SAFE_PORTS or packet[TCP].sport in SAFE_PORTS:
            return True
    if UDP in packet:
        if packet[UDP].dport in SAFE_PORTS or packet[UDP].sport in SAFE_PORTS:
            return True
    return False

def is_suspicious(packet):
    if IP not in packet:
        return False
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    if is_safe_ip(ip_src, ip_dst):
        return False
    if is_safe_port(packet):
        return False
    return True

def is_external_probe(packet):
    if IP not in packet:
        return False
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    return not ip_src.startswith(LOCAL_NET) and ip_dst.startswith(LOCAL_NET)

# --- THREAT DETECTION ---
def detect_threat(packet):
    if is_external_probe(packet):
        try:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            mac_src = packet[Ether].src if Ether in packet else "??:??:??:??:??:??"
            if TCP in packet:
                proto = "TCP"
                port = packet[TCP].dport
            elif UDP in packet:
                proto = "UDP"
                port = packet[UDP].dport
            else:
                proto = "OTHER"
                port = "-"
            msg = f"External connection to {ip_dst}:{port} ({proto})"
            print(f"[!] EXTERNAL: {ip_src} → {ip_dst}:{port}")
            log_event_grouped(ip_src, mac_src, msg)
            respond_to_threat(ip_src, "External connection")
            export_to_csv(ip_src, mac_src, "External connection", msg)
        except Exception as e:
            print(f"[!] Error analyzing external packet: {e}")
        return

    if not is_suspicious(packet):
        return

    if IP not in packet:
        return

    ip_src = packet[IP].src
    mac_src = packet[Ether].src if Ether in packet else "??:??:??:??:??:??"
    now = time.time()

    ip_activity[ip_src].append(now)
    ip_activity[ip_src] = [t for t in ip_activity[ip_src] if now - t <= TIME_WINDOW]

    if TCP in packet:
        flags = packet[TCP].flags
        if flags == "S":
            syn_packets[ip_src].append(now)
            syn_packets[ip_src] = [t for t in syn_packets[ip_src] if now - t <= TIME_WINDOW]
            portscan_attempts[ip_src].add(packet[TCP].dport)

            if len(syn_packets[ip_src]) > ALERT_THRESHOLD:
                msg = f"SYN flood attempt - {len(syn_packets[ip_src])} SYNs in {TIME_WINDOW}s"
                print(f"[!] ALERT: {ip_src} MAC: {mac_src} - {msg}")
                log_event_grouped(ip_src, mac_src, msg)
                respond_to_threat(ip_src, "SYN flood")
                export_to_csv(ip_src, mac_src, "SYN flood", msg)

            if len(portscan_attempts[ip_src]) > ALERT_THRESHOLD:
                ports = sorted(portscan_attempts[ip_src])
                msg = f"Port scan detected - ports: {ports}"
                print(f"[!] ALERT: {ip_src} MAC: {mac_src} - {msg}")
                log_event_grouped(ip_src, mac_src, msg)
                respond_to_threat(ip_src, "Port scan")
                export_to_csv(ip_src, mac_src, "Port scan", msg)

        if flags == "F":
            msg = f"Connection closed to {packet[IP].dst}:{packet[TCP].dport}"
            print(f"[i] {ip_src} MAC: {mac_src} {msg}")
            log_event_grouped(ip_src, mac_src, msg)

    if UDP in packet:
        udp_packets[ip_src].append(now)
        udp_packets[ip_src] = [t for t in udp_packets[ip_src] if now - t <= TIME_WINDOW]

        if len(udp_packets[ip_src]) > ALERT_THRESHOLD:
            msg = f"UDP flood attempt - {len(udp_packets[ip_src])} packets in {TIME_WINDOW}s"
            print(f"[!] ALERT: {ip_src} MAC: {mac_src} - {msg}")
            log_event_grouped(ip_src, mac_src, msg)
            respond_to_threat(ip_src, "UDP flood")
            export_to_csv(ip_src, mac_src, "UDP flood", msg)

        msg = f"UDP packet to {packet[IP].dst}:{packet[UDP].dport}"
        print(f"[i] {ip_src} MAC: {mac_src} {msg}")
        log_event_grouped(ip_src, mac_src, msg)

# --- MAIN FUNCTION ---
def main():
    print(f"[*] Listening on interface: {INTERFACE}...")
    if not os.path.exists(BANFILE):
        open(BANFILE, "w").close()
    sniff(iface=INTERFACE, prn=detect_threat, store=0)

if __name__ == "__main__":
    main()
