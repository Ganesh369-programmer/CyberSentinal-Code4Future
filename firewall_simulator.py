"""
Firewall Log Simulator
Generates realistic firewall log entries for testing
"""

import time
import random
import os
from datetime import datetime

# Sample IPs and data
SUSPICIOUS_IPS = ["185.220.101.47", "43.241.131.38", "192.168.1.100", "192.168.1.101"]
LOCAL_IPS = ["192.168.1.10", "192.168.1.1"]
EXTERNAL_SERVICES = ["8.8.8.8", "8.8.4.4", "52.94.236.248", "172.217.160.78", "157.240.22.35", "151.101.1.69"]

PROTOCOLS = ["TCP", "UDP", "ICMP"]
ACTIONS = ["DROP", "ALLOW"]

COMMON_PORTS = {
    "TCP": [22, 23, 53, 80, 123, 1433, 3389, 443, 445, 5060, 8080],
    "UDP": [53, 67, 123, 5060],
    "ICMP": [None]
}

def generate_log_entry():
    """Generate a single realistic firewall log entry"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 70% chance of DROP, 30% chance of ALLOW
    action = random.choices(ACTIONS, weights=[0.7, 0.3])[0]
    
    protocol = random.choice(PROTOCOLS)
    
    # Choose source and destination based on action
    if action == "DROP":
        # Drops are usually from external suspicious IPs to local
        src_ip = random.choice(SUSPICIOUS_IPS)
        dest_ip = random.choice(LOCAL_IPS)
    else:
        # Allows are usually from local to external services
        src_ip = random.choice(LOCAL_IPS)
        dest_ip = random.choice(EXTERNAL_SERVICES)
    
    # Select ports based on protocol
    if protocol == "ICMP":
        src_port = "-"
        dest_port = "-"
    else:
        available_ports = COMMON_PORTS.get(protocol, [80, 443])
        src_port = random.choice(available_ports) if src_ip.startswith("192.168") else "-"
        dest_port = random.choice(available_ports) if dest_ip.startswith("192.168") else random.choice(available_ports)
    
    # Build log line
    if protocol == "ICMP":
        log_line = f"{timestamp} {action} {protocol} {src_ip} {dest_ip} - - - - - - - - - 8 0 -"
    else:
        log_line = f"{timestamp} {action} {protocol} {src_ip} {dest_ip} {src_port} {dest_port} - - - - - - - - - -"
    
    return log_line

def append_new_log():
    """Append a new log entry to the firewall log file"""
    log_file = os.path.join(os.path.dirname(__file__), "data", "firewall.log")
    
    try:
        new_entry = generate_log_entry()
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(new_entry + "\n")
        print(f"[Firewall Simulator] Added: {new_entry}")
        return True
    except Exception as e:
        print(f"[Firewall Simulator] Error: {e}")
        return False

if __name__ == "__main__":
    print("[Firewall Simulator] Starting real-time log generation...")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            append_new_log()
            time.sleep(random.uniform(1, 3))  # Random interval between 1-3 seconds
    except KeyboardInterrupt:
        print("\n[Firewall Simulator] Stopped")
