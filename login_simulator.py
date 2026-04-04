"""
Login Log Simulator
Generates realistic authentication log entries for testing
"""

import json
import random
import os
import time
from datetime import datetime

# Sample data
USERS = ["admin", "root", "user", "test", "guest", "operator"]
SUSPICIOUS_IPS = ["185.220.101.47", "43.241.131.38", "192.168.1.100", "192.168.1.101"]
LOCAL_IPS = ["127.0.0.1", "192.168.1.10"]
COMMON_PASSWORDS = ["123456", "password", "admin", "123456789", "12345678", "12345", "1234567", "1234567890", "qwerty", "abc123"]

def generate_login_entry():
    """Generate a single realistic login log entry"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 80% chance of failure, 20% chance of success
    status = random.choices(["failure", "success"], weights=[0.8, 0.2])[0]
    
    # Choose IP and user
    if status == "failure":
        ip = random.choice(SUSPICIOUS_IPS + LOCAL_IPS)
        user = random.choice(USERS)
        source = "brute_force_simulator" if ip in SUSPICIOUS_IPS else "web_authentication"
        
        if source == "brute_force_simulator":
            password_tried = random.choice(COMMON_PASSWORDS)
            message = f"Login attempt with password: {password_tried}"
            return {
                "timestamp": timestamp,
                "source": source,
                "user": user,
                "ip": ip,
                "status": status,
                "message": message,
                "password_tried": password_tried,
                "attack_id": random.randint(1000000000000, 9999999999999)
            }
        else:
            message = f"Web authentication failed for user {user}: Invalid credentials"
            return {
                "timestamp": timestamp,
                "source": source,
                "user": user,
                "ip": ip,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "status": status,
                "event_id": 4625,
                "dest_ip": "127.0.0.1",
                "port": "5000",
                "message": message,
                "session_id": None,
                "login_method": "web_form"
            }
    else:
        # Success logins
        ip = random.choice(LOCAL_IPS)
        user = random.choice(USERS)
        source = "web_authentication"
        message = f"Web authentication successful for user {user}"
        
        return {
            "timestamp": timestamp,
            "source": source,
            "user": user,
            "ip": ip,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "status": status,
            "event_id": 4624,
            "dest_ip": "127.0.0.1",
            "port": "5000",
            "message": message,
            "session_id": None,
            "login_method": "web_form"
        }

def append_new_login():
    """Append a new login entry to the auth logs file"""
    logs_path = os.path.join(os.path.dirname(__file__), "real_json", "auth_logs.json")
    
    try:
        # Load existing logs
        with open(logs_path, 'r') as f:
            logs = json.load(f)
        
        # Generate new entry
        new_entry = generate_login_entry()
        
        # Generate new ID
        new_id = max([log.get('id', 0) for log in logs], default=0) + 1
        new_entry['id'] = new_id
        
        # Append to logs
        logs.append(new_entry)
        
        # Save back to file
        with open(logs_path, 'w') as f:
            json.dump(logs, f, indent=2)
        
        print(f"[Login Simulator] Added: ID {new_id}, User: {new_entry.get('user')}, Status: {new_entry.get('status')}")
        return True
    except Exception as e:
        print(f"[Login Simulator] Error: {e}")
        return False

if __name__ == "__main__":
    print("[Login Simulator] Starting real-time login log generation...")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            append_new_login()
            time.sleep(random.uniform(0.5, 2))  # Random interval between 0.5-2 seconds
    except KeyboardInterrupt:
        print("\n[Login Simulator] Stopped")
