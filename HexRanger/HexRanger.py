"""
Features:
- Real-time packet sniffing with scapy
- Detection of SYN flood, UDP flood, and port scanning
- Detection of external probes into the local network
- Automatic IP blocking via nftables (Linux) or netsh (Windows)
- Temporary bans with auto-expiry
- Logging in text or JSON format
- Export of threats to CSV for further analysis
"""

import configparser
import logging
import json
from scapy.all import sniff, IP, TCP, UDP, Ether
from collections import defaultdict, deque
import time
from datetime import datetime
import os
import platform
import csv
import subprocess
import ipaddress

# --- Load configuration ---
config = configparser.ConfigParser()
config.read("config.ini")

INTERFACE = config.get("network", "interface")
MY_IP = config.get("network", "my_ip")
LOCAL_NET = ipaddress.ip_network(config.get("network", "local_net"))

SAFE_IPS = set(ip.strip() for ip in config.get("safe", "safe_ips").split(","))
SAFE_MACS = set(mac.strip().lower() for mac in config.get("safe", "safe_macs").split(","))
SAFE_PORTS = set(int(p) for p in config.get("safe", "safe_ports").split(","))

ALERT_THRESHOLD = config.getint("alerts", "alert_threshold")
TIME_WINDOW = config.getint("alerts", "time_window")
BAN_TIME = config.getint("alerts", "ban_time")
LOGFILE = config.get("alerts", "logfile")
LOG_FORMAT = config.get("alerts", "log_format").lower()
BANFILE = "banned_ips.txt"
THREATS_CSV = "threats.csv"

# --- Setup logging ---
logger = logging.getLogger("HexRanger")
logger.setLevel(logging.INFO)
fh = logging.FileHandler(LOGFILE, encoding="utf-8")
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
fh.setFormatter(formatter)
logger.addHandler(fh)

# --- Global state ---
ip_activity = defaultdict(deque)
syn_packets = defaultdict(deque)
portscan_attempts = defaultdict(set)
udp_packets = defaultdict(deque)
banned_ips = {}

# --- Helper logging ---
def log_event(ip, mac, event_type, message):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if LOG_FORMAT == "json":
        entry = json.dumps({
            "timestamp": now,
            "ip": ip,
            "mac": mac,
            "event": event_type,
            "message": message
        })
        logger.info(entry)
    else:
        logger.info(f"[{ip} | MAC: {mac}] {event_type}: {message}")

    export_to_csv(ip, mac, event_type, message)

# --- Blocking functions ---
def block_ip(ip):
    system = platform.system()
    try:
        if system == "Windows":
            rule_name = f"HexRanger_Block_{ip.replace('.', '_')}"
            check_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"]
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            if "No rules match" not in result.stdout:
                return
            add_cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                       f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"]
            subprocess.run(add_cmd, capture_output=True, check=True)
        elif system == "Linux":
            subprocess.run(["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"],
                           capture_output=True, check=False)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to block IP {ip}: {e}")

def unblock_ip(ip):
    system = platform.system()
    try:
        if system == "Windows":
            rule_name = f"HexRanger_Block_{ip.replace('.', '_')}"
            del_cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            subprocess.run(del_cmd, capture_output=True, check=False)
        elif system == "Linux":
            subprocess.run(["nft", "delete", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"],
                           capture_output=True, check=False)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to unblock IP {ip}: {e}")

def respond_to_threat(ip, mac, reason):
    now = time.time()
    if ip not in banned_ips:
        banned_ips[ip] = now
        with open(BANFILE, "a") as f:
            f.write(f"{ip} # {reason} @ {datetime.now()}\n")
        block_ip(ip)
        log_event(ip, mac, "BAN", f"IP banned for {reason}")

def check_unban():
    now = time.time()
    expired = [ip for ip, t in banned_ips.items() if now - t > BAN_TIME]
    for ip in expired:
        unblock_ip(ip)
        log_event(ip, "??:??:??:??:??:??", "UNBAN", "Ban expired")
        del banned_ips[ip]

# --- CSV export ---
def export_to_csv(ip, mac, reason, details):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_exists = os.path.isfile(THREATS_CSV)
    with open(THREATS_CSV, "a", newline='') as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(["timestamp", "ip", "mac", "type", "details"])
        writer.writerow([now, ip, mac, reason, details])

# --- Packet filters ---
def is_safe(packet):
    if IP not in packet:
        return True
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    mac_src = packet[Ether].src if Ether in packet else None

    if ip_src in SAFE_IPS or ip_dst in SAFE_IPS:
        return True
    if mac_src and mac_src.lower() in SAFE_MACS:
        return True
    if ip_src == MY_IP:
        return True
    if ipaddress.ip_address(ip_src) in LOCAL_NET and ipaddress.ip_address(ip_dst) in LOCAL_NET:
        return True
    if TCP in packet:
        if packet[TCP].dport in SAFE_PORTS or packet[TCP].sport in SAFE_PORTS:
            return True
    if UDP in packet:
        if packet[UDP].dport in SAFE_PORTS or packet[UDP].sport in SAFE_PORTS:
            return True
    return False

# --- Threat detection ---
def detect_threat(packet):
    check_unban()

    if not IP in packet:
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    mac_src = packet[Ether].src if Ether in packet else "??:??:??:??:??:??"
    now = time.time()

    if is_safe(packet):
        return

    # External probe detection
    if not ipaddress.ip_address(ip_src) in LOCAL_NET and ipaddress.ip_address(ip_dst) in LOCAL_NET:
        log_event(ip_src, mac_src, "EXTERNAL", f"External connection attempt to {ip_dst}")
        respond_to_threat(ip_src, mac_src, "External probe")
        return

    # Activity tracking
    ip_activity[ip_src].append(now)
    while ip_activity[ip_src] and now - ip_activity[ip_src][0] > TIME_WINDOW:
        ip_activity[ip_src].popleft()

    # SYN flood and port scan
    if TCP in packet:
        flags = packet[TCP].flags
        if flags == "S":
            syn_packets[ip_src].append(now)
            while syn_packets[ip_src] and now - syn_packets[ip_src][0] > TIME_WINDOW:
                syn_packets[ip_src].popleft()
            portscan_attempts[ip_src].add(packet[TCP].dport)

            if len(syn_packets[ip_src]) > ALERT_THRESHOLD:
                log_event(ip_src, mac_src, "SYN_FLOOD", f"{len(syn_packets[ip_src])} SYNs in {TIME_WINDOW}s")
                respond_to_threat(ip_src, mac_src, "SYN flood")

            if len(portscan_attempts[ip_src]) > ALERT_THRESHOLD:
                ports = sorted(portscan_attempts[ip_src])
                log_event(ip_src, mac_src, "PORT_SCAN", f"Ports scanned: {ports}")
                respond_to_threat(ip_src, mac_src, "Port scan")

    # UDP flood
    if UDP in packet:
        udp_packets[ip_src].append(now)
        while udp_packets[ip_src] and now - udp_packets[ip_src][0] > TIME_WINDOW:
            udp_packets[ip_src].popleft()

        if len(udp_packets[ip_src]) > ALERT_THRESHOLD:
            log_event(ip_src, mac_src, "UDP_FLOOD", f"{len(udp_packets[ip_src])} UDP packets in {TIME_WINDOW}s")
            respond_to_threat(ip_src, mac_src, "UDP flood")

# --- Main ---
def main():
    logger.info(f"[*] HexRanger listening on interface {INTERFACE}")
    if not os.path.exists(BANFILE):
        open(BANFILE, "w").close()
    sniff(iface=INTERFACE, prn=detect_threat, store=0)

if __name__ == "__main__":
    main()


