# log_mitre_mapper.py — Security Log to MITRE Framework Mapping Engine
# Maps all security logs to MITRE ATT&CK, CAR, D3FEND, and Engage frameworks

import re
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
from collections import defaultdict

# Import all framework mappings
from mitre_map import get_mitre_info, get_all_mappings as get_attack_mappings
from mitre_car_map import get_car_info, get_all_car_mappings as get_car_mappings
from mitre_d3fend_map import get_d3fend_info, get_all_d3fend_mappings as get_d3fend_mappings
from mitre_engage_map import get_engage_info, get_all_engage_mappings as get_engage_mappings


class LogMITREMapper:
    def __init__(self):
        self.attack_mappings = get_attack_mappings()
        self.car_mappings = get_car_mappings()
        self.d3fend_mappings = get_d3fend_mappings()
        self.engage_mappings = get_engage_mappings()
        
        # Pattern matching for different log types
        self.patterns = {
            'brute_force': [
                r'brute_force',
                r'password.*failed',
                r'login.*attempt.*password',
                r'authentication.*failed',
                r'invalid.*credentials',
                r'event.*4625',  # Windows failed login
                r'ssh.*invalid.*user',
                r'multiple.*failed.*login'
            ],
            'port_scan': [
                r'port.*scan',
                r'service.*discovery',
                r'network.*scan',
                r'connection.*refused',
                r'port.*enumeration',
                r'service.*probe'
            ],
            'lateral_movement': [
                r'lateral.*movement',
                r'remote.*service',
                r'ssh.*hop',
                r'multiple.*hosts',
                r'pass.*the.*hash',
                r'remote.*execution'
            ],
            'malware': [
                r'malware',
                r'virus',
                r'trojan',
                r'backdoor',
                r'payload',
                r'executable.*suspicious'
            ],
            'data_exfiltration': [
                r'data.*exfil',
                r'file.*transfer',
                r'upload.*large',
                r'suspicious.*download',
                r'data.*theft'
            ],
            'privilege_escalation': [
                r'privilege.*escalation',
                r'sudo.*abuse',
                r'admin.*access',
                r'escalate.*privileges',
                r'event.*4672'  # Special privileges assigned
            ]
        }
        
        # Source to threat type mapping
        self.source_threat_mapping = {
            'brute_force_simulator': 'brute_force',
            'web_authentication': 'brute_force',
            'ssh': 'brute_force',
            'windows': 'brute_force',
            'firewall': 'port_scan',
            'ids': 'port_scan',
            'network': 'port_scan',
            'endpoint': 'malware',
            'antivirus': 'malware',
            'dlp': 'data_exfiltration',
            'file_system': 'data_exfiltration'
        }

    def analyze_log_entry(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single log entry and map it to all MITRE frameworks
        """
        # Extract key information from log
        source = log_entry.get('source', '').lower()
        message = log_entry.get('message', '').lower()
        user = log_entry.get('user', '')
        ip = log_entry.get('ip', '')
        status = log_entry.get('status', '')
        
        # Determine threat type based on multiple factors
        threat_type = self._determine_threat_type(source, message, status, log_entry)
        
        if not threat_type:
            return self._create_empty_mapping(log_entry)
        
        # Map to all frameworks
        mapping_result = {
            'log_entry': log_entry,
            'threat_type': threat_type,
            'confidence': self._calculate_confidence(log_entry, threat_type),
            'mitre_attack': self._map_to_attack(threat_type),
            'mitre_car': self._map_to_car(threat_type),
            'mitre_d3fend': self._map_to_d3fend(threat_type),
            'mitre_engage': self._map_to_engage(threat_type),
            'mapping_timestamp': datetime.now().isoformat(),
            'ip_address': ip,
            'user_account': user,
            'severity': self._determine_severity(threat_type, status)
        }
        
        return mapping_result

    def _determine_threat_type(self, source: str, message: str, status: str, log_entry: Dict) -> str:
        """
        Determine threat type based on log content and metadata
        """
        # Check source-based mapping first
        if source in self.source_threat_mapping:
            return self.source_threat_mapping[source]
        
        # Check message patterns
        for threat_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    return threat_type
        
        # Check for brute force indicators
        if (status == 'failure' and 
            ('password' in message or 'login' in message or 'auth' in message)):
            return 'brute_force'
        
        # Check for multiple failed attempts from same IP
        if 'password_tried' in log_entry or 'attack_id' in log_entry:
            return 'brute_force'
        
        # Check for Windows event IDs
        if 'event_id' in log_entry:
            event_id = str(log_entry['event_id'])
            if event_id in ['4625', '4624', '4672', '4688']:
                return 'brute_force'
        
        return None

    def _calculate_confidence(self, log_entry: Dict, threat_type: str) -> float:
        """
        Calculate confidence score for the mapping
        """
        confidence = 0.5  # Base confidence
        
        # Increase confidence for specific indicators
        if log_entry.get('source') in self.source_threat_mapping:
            confidence += 0.3
        
        if 'attack_id' in log_entry or 'password_tried' in log_entry:
            confidence += 0.2
        
        if log_entry.get('event_id'):
            confidence += 0.1
        
        # Check for strong pattern matches
        message = log_entry.get('message', '').lower()
        if threat_type in self.patterns:
            for pattern in self.patterns[threat_type]:
                if re.search(pattern, message, re.IGNORECASE):
                    confidence += 0.1
                    break
        
        return min(confidence, 1.0)

    def _map_to_attack(self, threat_type: str) -> Dict[str, Any]:
        """Map to MITRE ATT&CK framework"""
        for mapping in self.attack_mappings:
            if mapping.get('threat_type') == threat_type:
                return mapping
        return {}

    def _map_to_car(self, threat_type: str) -> Dict[str, Any]:
        """Map to MITRE CAR framework"""
        for mapping in self.car_mappings:
            if mapping.get('threat_type') == threat_type:
                return mapping
        return {}

    def _map_to_d3fend(self, threat_type: str) -> Dict[str, Any]:
        """Map to MITRE D3FEND framework"""
        for mapping in self.d3fend_mappings:
            if mapping.get('threat_type') == threat_type:
                return mapping
        return {}

    def _map_to_engage(self, threat_type: str) -> Dict[str, Any]:
        """Map to MITRE Engage framework"""
        for mapping in self.engage_mappings:
            if mapping.get('threat_type') == threat_type:
                return mapping
        return {}

    def _determine_severity(self, threat_type: str, status: str) -> str:
        """Determine severity level"""
        if threat_type == 'brute_force' and status == 'success':
            return 'CRITICAL'
        elif threat_type == 'brute_force':
            return 'HIGH'
        elif threat_type == 'malware':
            return 'HIGH'
        elif threat_type == 'data_exfiltration':
            return 'CRITICAL'
        elif threat_type == 'privilege_escalation':
            return 'HIGH'
        elif threat_type == 'lateral_movement':
            return 'HIGH'
        else:
            return 'MEDIUM'

    def _create_empty_mapping(self, log_entry: Dict) -> Dict[str, Any]:
        """Create empty mapping for unmapped logs"""
        return {
            'log_entry': log_entry,
            'threat_type': None,
            'confidence': 0.0,
            'mitre_attack': {},
            'mitre_car': {},
            'mitre_d3fend': {},
            'mitre_engage': {},
            'mapping_timestamp': datetime.now().isoformat(),
            'ip_address': log_entry.get('ip', ''),
            'user_account': log_entry.get('user', ''),
            'severity': 'LOW'
        }

    def analyze_logs_batch(self, logs: List[Dict]) -> List[Dict[str, Any]]:
        """
        Analyze multiple logs and return mappings
        """
        mappings = []
        for log in logs:
            mapping = self.analyze_log_entry(log)
            mappings.append(mapping)
        return mappings

    def get_ip_based_mappings(self, logs: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Group mappings by IP address
        """
        mappings = self.analyze_logs_batch(logs)
        ip_mappings = defaultdict(list)
        
        for mapping in mappings:
            ip = mapping['ip_address']
            if ip:
                ip_mappings[ip].append(mapping)
        
        return dict(ip_mappings)

    def get_technique_summary(self, logs: List[Dict]) -> Dict[str, Any]:
        """
        Get summary of all techniques detected
        """
        mappings = self.analyze_logs_batch(logs)
        
        summary = {
            'total_logs': len(logs),
            'mapped_logs': len([m for m in mappings if m['threat_type']]),
            'techniques_detected': defaultdict(int),
            'ips_by_technique': defaultdict(set),
            'framework_coverage': {
                'attack': set(),
                'car': set(),
                'd3fend': set(),
                'engage': set()
            }
        }
        
        for mapping in mappings:
            if mapping['threat_type']:
                threat_type = mapping['threat_type']
                summary['techniques_detected'][threat_type] += 1
                
                # Track IPs by technique
                ip = mapping['ip_address']
                if ip:
                    summary['ips_by_technique'][threat_type].add(ip)
                
                # Track framework coverage by technique ID (not threat_type)
                if mapping['mitre_attack']:
                    tech_id = mapping['mitre_attack'].get('technique_id', threat_type)
                    summary['framework_coverage']['attack'].add(tech_id)
                if mapping['mitre_car']:
                    car_id = mapping['mitre_car'].get('analytics_id', threat_type)
                    summary['framework_coverage']['car'].add(car_id)
                if mapping['mitre_d3fend']:
                    d3_id = mapping['mitre_d3fend'].get('technique_id', threat_type)
                    summary['framework_coverage']['d3fend'].add(d3_id)
                if mapping['mitre_engage']:
                    eng_id = mapping['mitre_engage'].get('technique_id', threat_type)
                    summary['framework_coverage']['engage'].add(eng_id)
        
        # Convert sets to lists for JSON serialization
        summary['ips_by_technique'] = {
            k: list(v) for k, v in summary['ips_by_technique'].items()
        }
        summary['framework_coverage'] = {
            k: list(v) for k, v in summary['framework_coverage'].items()
        }
        
        return summary

    def get_technique_details(self, technique_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific technique across all frameworks
        """
        details = {
            'technique_id': technique_id,
            'attack_framework': {},
            'car_framework': {},
            'd3fend_framework': {},
            'engage_framework': {}
        }
        
        # Find in ATT&CK
        for threat_type, mapping in self.attack_mappings.items():
            if mapping.get('technique_id') == technique_id:
                details['attack_framework'] = mapping
                details['threat_type'] = threat_type
                break
        
        # Find in other frameworks
        threat_type = details.get('threat_type')
        if threat_type:
            if threat_type in self.car_mappings:
                details['car_framework'] = self.car_mappings[threat_type]
            if threat_type in self.d3fend_mappings:
                details['d3fend_framework'] = self.d3fend_mappings[threat_type]
            if threat_type in self.engage_mappings:
                details['engage_framework'] = self.engage_mappings[threat_type]
        
        return details

    def extract_unique_techniques(self, mappings):
        """Extract unique ATT&CK techniques from mappings"""
        techniques = {}
        
        for mapping in mappings:
            data = mapping.get('mitre_attack', {})
            if data and data.get('technique_id'):
                key = data['technique_id']
                if key not in techniques:
                    techniques[key] = data
        
        return list(techniques.values())

    def extract_unique_analytics(self, mappings):
        """Extract unique CAR analytics from mappings"""
        analytics = {}
        
        for mapping in mappings:
            data = mapping.get('mitre_car', {})
            if data and data.get('analytics_id'):
                key = data['analytics_id']
                if key not in analytics:
                    analytics[key] = data
        
        return list(analytics.values())

    def extract_unique_defenses(self, mappings):
        """Extract unique D3FEND defenses from mappings"""
        defenses = {}
        
        for mapping in mappings:
            data = mapping.get('mitre_d3fend', {})
            if data and data.get('defend_id'):
                key = data['defend_id']
                if key not in defenses:
                    defenses[key] = data
        
        return list(defenses.values())

    def extract_unique_engage_techniques(self, mappings):
        """Extract unique ENGAGE techniques from mappings"""
        techniques = {}
        
        for mapping in mappings:
            data = mapping.get('mitre_engage', {})
            if data and data.get('engage_id'):
                key = data['engage_id']
                if key not in techniques:
                    techniques[key] = data
        
        return list(techniques.values())

    def has_framework_mapping(self, mapping, framework):
        """Check if mapping has data for specific framework"""
        if framework == 'attack':
            return mapping.get('mitre_attack') and len(mapping['mitre_attack']) > 0
        elif framework == 'car':
            return mapping.get('mitre_car') and len(mapping['mitre_car']) > 0
        elif framework == 'd3fend':
            return mapping.get('mitre_d3fend') and len(mapping['mitre_d3fend']) > 0
        elif framework == 'engage':
            return mapping.get('mitre_engage') and len(mapping['mitre_engage']) > 0
        return False


# Global instance
log_mitre_mapper = LogMITREMapper()
