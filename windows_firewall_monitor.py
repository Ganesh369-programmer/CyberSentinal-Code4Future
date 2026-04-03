"""
Windows Firewall Log Monitor
Real-time monitoring of Windows Defender Firewall logs
"""

import time
import os
import json
from datetime import datetime
from pathlib import Path

# Default Windows Firewall log path
DEFAULT_LOG_FILE = r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"

def parse_log(line):
    """
    Parse a single firewall log line into a structured dictionary.
    
    Format: date time action protocol src-ip dest-ip src-port dest-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
    Example: 2026-04-04 10:05:12 DROP TCP 185.220.101.47 192.168.1.10 443 22 - - - - - - - - - SEND
    """
    parts = line.strip().split()
    if len(parts) < 8:
        return None
    
    try:
        return {
            "timestamp": f"{parts[0]} {parts[1]}",
            "source": "firewall",
            "action": parts[2],
            "protocol": parts[3],
            "ip": parts[4],           # src IP
            "dest_ip": parts[5],      # dest IP
            "src_port": parts[6] if parts[6] != "-" else None,
            "port": int(parts[7]) if parts[7] != "-" else None,  # dest port
            "status": "blocked" if parts[2] == "DROP" else "allowed",
            "message": f"Firewall {parts[2]} {parts[3]} from {parts[4]}:{parts[6]} to {parts[5]}:{parts[7]}",
            "event_id": "5157" if parts[2] == "DROP" else "5156",  # Windows Security Event IDs
            "raw_log": line.strip()
        }
    except (ValueError, IndexError) as e:
        return None


def monitor(callback, log_file=None):
    """
    Monitor Windows Firewall log file in real-time.
    
    Args:
        callback: Function to call with each new log entry
        log_file: Path to firewall log (defaults to DEFAULT_LOG_FILE)
    """
    log_file = log_file or DEFAULT_LOG_FILE
    
    # Check if log file exists
    if not os.path.exists(log_file):
        print(f"[Firewall Monitor] WARNING: Log file not found: {log_file}")
        print(f"[Firewall Monitor] Please enable firewall logging first:")
        print(f"  1. Open Windows Defender Firewall with Advanced Security")
        print(f"  2. Click 'Properties' > 'Private Profile' > 'Customize'")
        print(f"  3. Set 'Log dropped packets' and 'Log successful connections' to 'Yes'")
        return
    
    print(f"[Firewall Monitor] Starting monitor for: {log_file}")
    
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            # Move to end of file to get new entries only
            f.seek(0, 2)
            
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                
                # Skip comment lines (headers)
                if line.startswith("#") or not line.strip():
                    continue
                
                log = parse_log(line)
                if log:
                    callback(log)
                    
    except KeyboardInterrupt:
        print("[Firewall Monitor] Stopped by user")
    except Exception as e:
        print(f"[Firewall Monitor] ERROR: {e}")


def read_all_logs(log_file=None):
    """
    Read all existing firewall logs from file.
    
    Returns:
        List of parsed log dictionaries
    """
    log_file = log_file or DEFAULT_LOG_FILE
    logs = []
    
    if not os.path.exists(log_file):
        return logs
    
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                log = parse_log(line)
                if log:
                    logs.append(log)
    except Exception as e:
        print(f"[Firewall Monitor] ERROR reading logs: {e}")
    
    return logs


def get_firewall_stats(log_file=None):
    """
    Get statistics from firewall logs.
    
    Returns:
        Dictionary with counts and top IPs
    """
    logs = read_all_logs(log_file)
    
    stats = {
        "total_entries": len(logs),
        "blocked": 0,
        "allowed": 0,
        "top_source_ips": {},
        "top_dest_ports": {},
        "protocols": {}
    }
    
    for log in logs:
        if log["status"] == "blocked":
            stats["blocked"] += 1
        else:
            stats["allowed"] += 1
        
        # Count source IPs
        src_ip = log["ip"]
        stats["top_source_ips"][src_ip] = stats["top_source_ips"].get(src_ip, 0) + 1
        
        # Count destination ports
        port = log.get("port")
        if port:
            stats["top_dest_ports"][port] = stats["top_dest_ports"].get(port, 0) + 1
        
        # Count protocols
        protocol = log.get("protocol", "UNKNOWN")
        stats["protocols"][protocol] = stats["protocols"].get(protocol, 0) + 1
    
    # Sort and get top 10
    stats["top_source_ips"] = dict(sorted(stats["top_source_ips"].items(), 
                                          key=lambda x: x[1], reverse=True)[:10])
    stats["top_dest_ports"] = dict(sorted(stats["top_dest_ports"].items(), 
                                          key=lambda x: x[1], reverse=True)[:10])
    
    return stats


# Test function
if __name__ == "__main__":
    def print_callback(log):
        print(f"[FIREWALL] {log['timestamp']} - {log['action']} from {log['ip']} to port {log['port']}")
    
    # First, show stats
    print("Current Firewall Stats:")
    stats = get_firewall_stats()
    print(json.dumps(stats, indent=2))
    print("\nStarting real-time monitoring (Ctrl+C to stop)...\n")
    
    # Start monitoring
    monitor(print_callback)
