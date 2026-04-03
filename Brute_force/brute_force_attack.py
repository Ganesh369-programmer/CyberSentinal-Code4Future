import threading
import time
import random
import string
import json
import os
from datetime import datetime
from flask import jsonify

class BruteForceAttack:
    def __init__(self):
        self.is_running = False
        self.attack_thread = None
        self.stats = {
            'attempts': 0,
            'successful_attempts': 0,
            'failed_attempts': 0,
            'start_time': None,
            'elapsed_time': 0,
            'target_ip': None,
            'target_username': None,
            'passwords_tried': [],
            'current_password': None,
            'status': 'stopped'
        }
        self.lock = threading.Lock()
        
    def generate_password_list(self, method='common'):
        """Generate password list based on method"""
        passwords = []
        
        if method == 'common':
            # Common passwords list
            passwords = [
                '123456', 'password', '123456789', '12345678', '12345', 
                '1234567', '1234567890', '1234', 'qwerty', 'abc123',
                '111111', 'password123', 'admin', 'letmein', 'welcome',
                'monkey', '1234567890', 'password1', 'qwertyuiop', 'starwars'
            ]
        elif method == 'numeric':
            # Numeric passwords
            for i in range(10000):
                passwords.append(str(i).zfill(4))
        elif method == 'alphabet':
            # Alphabet combinations
            for length in [4, 5, 6]:
                for combo in self._generate_combinations(string.ascii_lowercase, length):
                    passwords.append(''.join(combo))
                    if len(passwords) > 1000:  # Limit for demo
                        break
        
        return passwords
    
    def _generate_combinations(self, chars, length):
        """Generate combinations of given length"""
        if length == 1:
            for char in chars:
                yield char
        else:
            for char in chars:
                for combo in self._generate_combinations(chars, length - 1):
                    yield char + combo
    
    def simulate_login_attempt(self, username, password, target_ip):
        """Simulate a login attempt"""
        # Simulate network delay
        time.sleep(random.uniform(0.1, 0.5))
        
        # Random success rate (5% chance for demo)
        success = random.random() < 0.05
        
        # Create log entry
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source': 'brute_force_simulator',
            'user': username,
            'ip': target_ip,
            'status': 'success' if success else 'failure',
            'message': f'Login attempt with password: {password}',
            'password_tried': password,
            'attack_id': id(self)
        }
        
        # Save to auth logs
        self._save_auth_log(log_entry)
        
        return success
    
    def _save_auth_log(self, log_entry):
        """Save authentication log to real_json/auth_logs.json"""
        try:
            auth_logs_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "real_json", "auth_logs.json")
            
            # Load existing logs
            if os.path.exists(auth_logs_path):
                with open(auth_logs_path, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []
            
            # Generate new ID
            new_id = max([log.get('id', 0) for log in logs], default=0) + 1
            log_entry['id'] = new_id
            
            # Append to logs
            logs.append(log_entry)
            
            # Save back to file
            with open(auth_logs_path, 'w') as f:
                json.dump(logs, f, indent=2)
                
        except Exception as e:
            print(f"[BruteForce] ERROR: Could not save auth log: {e}")
    
    def run_attack(self, target_ip, target_username, password_method='common', max_attempts=100):
        """Run the brute force attack"""
        with self.lock:
            self.is_running = True
            self.stats['status'] = 'running'
            self.stats['target_ip'] = target_ip
            self.stats['target_username'] = target_username
            self.stats['start_time'] = time.time()
            self.stats['attempts'] = 0
            self.stats['successful_attempts'] = 0
            self.stats['failed_attempts'] = 0
            self.stats['passwords_tried'] = []
        
        passwords = self.generate_password_list(password_method)
        
        try:
            for password in passwords[:max_attempts]:
                if not self.is_running:
                    break
                
                with self.lock:
                    self.stats['current_password'] = password
                    self.stats['attempts'] += 1
                    self.stats['passwords_tried'].append(password)
                    self.stats['elapsed_time'] = time.time() - self.stats['start_time']
                
                # Simulate login attempt
                success = self.simulate_login_attempt(target_username, password, target_ip)
                
                with self.lock:
                    if success:
                        self.stats['successful_attempts'] += 1
                        # Stop on first success for demo
                        break
                    else:
                        self.stats['failed_attempts'] += 1
                
                # Small delay between attempts
                time.sleep(0.1)
        
        except Exception as e:
            print(f"[BruteForce] Attack error: {e}")
        
        finally:
            with self.lock:
                self.is_running = False
                self.stats['status'] = 'stopped'
                self.stats['elapsed_time'] = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
    
    def start_attack(self, target_ip, target_username, password_method='common', max_attempts=100):
        """Start the brute force attack in a separate thread"""
        if self.is_running:
            return False, "Attack is already running"
        
        self.attack_thread = threading.Thread(
            target=self.run_attack,
            args=(target_ip, target_username, password_method, max_attempts)
        )
        self.attack_thread.daemon = True
        self.attack_thread.start()
        
        return True, "Attack started"
    
    def stop_attack(self):
        """Stop the brute force attack"""
        if not self.is_running:
            return False, "No attack is running"
        
        with self.lock:
            self.is_running = False
            self.stats['status'] = 'stopping'
        
        # Wait for thread to finish
        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join(timeout=2)
        
        with self.lock:
            self.stats['status'] = 'stopped'
        
        return True, "Attack stopped"
    
    def get_stats(self):
        """Get current attack statistics"""
        with self.lock:
            if self.stats['start_time'] and self.is_running:
                self.stats['elapsed_time'] = time.time() - self.stats['start_time']
            
            return {
                'is_running': self.is_running,
                'stats': self.stats.copy()
            }

# Global instance
brute_force_instance = BruteForceAttack()
