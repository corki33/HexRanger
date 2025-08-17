# HexRanger


**HexRanger** is a Python-based network security monitoring and defense tool.
It captures network traffic, detects suspicious activity such as SYN/UDP floods, port scans, and external probes, logs events,
and automatically blocks malicious IPs.


## HexRanger  continuously monitors a specified network interface and detects threats in real-time. It can detect SYN flood attacks, UDP flood attacks, port scanning attempts, and external connection probes.
When malicious activity is identified, HexRanger automatically blocks the IP address using Windows Firewall on Windows systems or iptables on Linux systems. All events are logged in `log.log`, and detected threats are exported to `threats.csv`.
Safe IP addresses and ports can be configured, and alert thresholds and time windows are adjustable.

## Requirements
To run HexRanger, you need Python 3.10 or higher, Scapy installed, and administrative/root privileges to block IPs.


## Usage 

Run HexRanger with administrative privileges using python HexRanger.py. 
The program will continuously sniff network traffic on the specified interface, detect suspicious activity,
log all events with timestamps, and automatically block malicious IPs. 
HexRanger writes grouped logs in log.log, keeps a CSV export of threats in threats.csv,
and maintains a list of blocked IPs with reasons and timestamps in banned_ips.txt.



## Logs and Exports 
The log file log.log contains detailed and grouped information about local network
events, external connections, and detected threats. The threats.csv file allows you to
analyze attacks in a structured format, while banned_ips.txt keeps track of all blocked IPs
with timestamps and the reason for the ban


## Installation 
Clone the repository using `git clone https://github.com/corki33/HexRanger.git` 
and navigate to the project directory. Install the required Python dependency using `pip install -r requirements.txt`. 
Then configure `config.ini` to match your network. The configuration file includes the network interface to monitor, 
your machine's IP, the local network range, safe IPs and ports, alert thresholds, time windows, and the log file location.
Example configuration:

.ini:
[network]
interface = wlan0
my_ip = 192.168.100.1
local_net = 192.168.100.

[safe]
safe_ips = 192.168.100.1
safe_ports = 22, 80, 443, 53

[alerts]
alert_threshold = 10
time_window = 5
logfile = log.log

## Notes 
HexRanger requires administrative/root privileges to modify firewall rules and works on both Windows and
