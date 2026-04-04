"""
Investigation Case Management System
Handles persistence, AI memory, and case lifecycle
"""
import json
import os
from datetime import datetime
from typing import List, Dict, Optional
import uuid

CASES_DIR = os.path.join(os.path.dirname(__file__), "data", "cases")
os.makedirs(CASES_DIR, exist_ok=True)


class InvestigationCase:
    """Represents a single security investigation case."""
    
    def __init__(self, case_id: str, initial_alert: dict, analyst: str = "analyst"):
        self.case_id = case_id
        self.created_at = datetime.now().isoformat()
        self.updated_at = self.created_at
        self.status = "open"  # open, in_progress, resolved, closed
        self.priority = initial_alert.get("effective_severity", "MEDIUM")
        self.analyst = analyst
        
        # Initial alert that triggered the case
        self.initial_alert = initial_alert
        self.target_ip = initial_alert.get("src_ip", "UNKNOWN")
        self.threat_type = initial_alert.get("type", "unknown")
        
        # Accumulated data
        self.alerts = [initial_alert]
        self.notes = []  # Analyst notes with timestamps
        self.ai_findings = []  # AI-generated insights
        self.timeline_events = []
        self.related_ips = set([self.target_ip])
        self.evidence_hashes = []  # For integrity
        
        # AI conversation context for this case
        self.conversation_history = []
        
    def add_note(self, note: str, author: str = "analyst"):
        """Add an analyst note to the case."""
        self.notes.append({
            "timestamp": datetime.now().isoformat(),
            "author": author,
            "content": note
        })
        self.updated_at = datetime.now().isoformat()
        
    def add_ai_finding(self, finding: dict):
        """Add AI-generated insight to the case."""
        finding["timestamp"] = datetime.now().isoformat()
        self.ai_findings.append(finding)
        self.updated_at = datetime.now().isoformat()
        
    def add_alert(self, alert: dict):
        """Add related alert to the case."""
        self.alerts.append(alert)
        self.related_ips.add(alert.get("src_ip", "UNKNOWN"))
        self.updated_at = datetime.now().isoformat()
        
    def add_conversation(self, query: str, response: str):
        """Store AI conversation for context recall."""
        self.conversation_history.append({
            "timestamp": datetime.now().isoformat(),
            "query": query,
            "response": response
        })
        self.updated_at = datetime.now().isoformat()
        
    def get_ai_context(self) -> str:
        """Generate context summary for AI when reopening case."""
        context_parts = [
            f"Case {self.case_id}: Investigation of {self.threat_type} from {self.target_ip}",
            f"Status: {self.status} | Priority: {self.priority}",
            f"Alerts: {len(self.alerts)} | Notes: {len(self.notes)} | AI Findings: {len(self.ai_findings)}"
        ]
        
        if self.notes:
            context_parts.append(f"\nRecent analyst notes:")
            for note in self.notes[-3:]:
                context_parts.append(f"- [{note['timestamp'][:16]}] {note['content'][:100]}")
                
        if self.ai_findings:
            context_parts.append(f"\nPrevious AI findings:")
            for finding in self.ai_findings[-3:]:
                context_parts.append(f"- {finding.get('summary', 'Finding')[:100]}")
                
        return "\n".join(context_parts)
        
    def to_dict(self) -> dict:
        """Serialize case to dictionary."""
        return {
            "case_id": self.case_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "priority": self.priority,
            "analyst": self.analyst,
            "target_ip": self.target_ip,
            "threat_type": self.threat_type,
            "initial_alert": self.initial_alert,
            "alerts": self.alerts,
            "notes": self.notes,
            "ai_findings": self.ai_findings,
            "related_ips": list(self.related_ips),
            "conversation_history": self.conversation_history
        }
        
    @classmethod
    def from_dict(cls, data: dict) -> "InvestigationCase":
        """Deserialize case from dictionary."""
        case = cls.__new__(cls)
        case.case_id = data["case_id"]
        case.created_at = data["created_at"]
        case.updated_at = data["updated_at"]
        case.status = data["status"]
        case.priority = data["priority"]
        case.analyst = data.get("analyst", "analyst")
        case.target_ip = data["target_ip"]
        case.threat_type = data["threat_type"]
        case.initial_alert = data["initial_alert"]
        case.alerts = data.get("alerts", [])
        case.notes = data.get("notes", [])
        case.ai_findings = data.get("ai_findings", [])
        case.related_ips = set(data.get("related_ips", []))
        case.conversation_history = data.get("conversation_history", [])
        return case


class CaseManager:
    """Manages all investigation cases."""
    
    def __init__(self):
        self.cases: Dict[str, InvestigationCase] = {}
        self._load_all_cases()
        
    def _get_case_path(self, case_id: str) -> str:
        return os.path.join(CASES_DIR, f"{case_id}.json")
        
    def _load_all_cases(self):
        """Load all existing cases from disk."""
        if not os.path.exists(CASES_DIR):
            return
        for filename in os.listdir(CASES_DIR):
            if filename.endswith(".json"):
                case_id = filename[:-5]
                self.load_case(case_id)
                
    def create_case(self, alert: dict, analyst: str = "analyst") -> InvestigationCase:
        """Create a new investigation case from an alert."""
        case_id = f"CASE-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        case = InvestigationCase(case_id, alert, analyst)
        self.cases[case_id] = case
        self.save_case(case_id)
        return case
        
    def get_case(self, case_id: str) -> Optional[InvestigationCase]:
        """Get a case by ID."""
        return self.cases.get(case_id)
        
    def load_case(self, case_id: str) -> Optional[InvestigationCase]:
        """Load a case from disk."""
        path = self._get_case_path(case_id)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r") as f:
                data = json.load(f)
            case = InvestigationCase.from_dict(data)
            self.cases[case_id] = case
            return case
        except Exception as e:
            print(f"[CaseManager] Error loading case {case_id}: {e}")
            return None
            
    def save_case(self, case_id: str):
        """Save a case to disk."""
        case = self.cases.get(case_id)
        if not case:
            return
        path = self._get_case_path(case_id)
        try:
            with open(path, "w") as f:
                json.dump(case.to_dict(), f, indent=2)
        except Exception as e:
            print(f"[CaseManager] Error saving case {case_id}: {e}")
            
    def list_cases(self, status: str = None, limit: int = 50) -> List[dict]:
        """List all cases, optionally filtered by status."""
        cases = self.cases.values()
        if status:
            cases = [c for c in cases if c.status == status]
        # Sort by updated_at desc
        sorted_cases = sorted(cases, key=lambda c: c.updated_at, reverse=True)
        return [c.to_dict() for c in sorted_cases[:limit]]
        
    def update_case_status(self, case_id: str, status: str):
        """Update case status."""
        case = self.cases.get(case_id)
        if case:
            case.status = status
            case.updated_at = datetime.now().isoformat()
            self.save_case(case_id)
            
    def find_related_cases(self, ip: str) -> List[InvestigationCase]:
        """Find cases related to a specific IP."""
        return [c for c in self.cases.values() if ip in c.related_ips]
        
    def get_case_statistics(self) -> dict:
        """Get statistics about all cases."""
        total = len(self.cases)
        by_status = {}
        by_priority = {}
        for case in self.cases.values():
            by_status[case.status] = by_status.get(case.status, 0) + 1
            by_priority[case.priority] = by_priority.get(case.priority, 0) + 1
        return {
            "total_cases": total,
            "by_status": by_status,
            "by_priority": by_priority,
            "recent_cases": self.list_cases(limit=5)
        }


# Global case manager instance
case_manager = CaseManager()
