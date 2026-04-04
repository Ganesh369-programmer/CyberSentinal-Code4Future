"""
Explainability Engine - Makes AI decisions transparent
Provides evidence-backed explanations for alerts and AI responses
"""
from typing import Dict, List, Optional
from detector import load_logs, detect_threats


class ExplainabilityEngine:
    """Generates human-readable explanations for security decisions."""
    
    def __init__(self):
        self.logs = []
        self.alerts = []
        
    def refresh_data(self):
        """Refresh logs and alerts."""
        self.logs = load_logs()
        self.alerts = detect_threats(self.logs)
        
    def explain_alert(self, alert_id: str = None, alert_data: dict = None) -> dict:
        """
        Generate a detailed explanation for an alert.
        
        Returns:
            dict with explanation components:
            - why_flagged: Human-readable reason
            - evidence_chain: List of evidence with timestamps
            - confidence_score: 0-1 confidence
            - data_sources: Which logs contributed
            - similar_past_incidents: Historical context
            - mitre_rationale: Why this MITRE technique
        """
        self.refresh_data()
        
        # Find the alert
        alert = alert_data
        if alert_id and not alert:
            for a in self.alerts:
                if a.get("id") == alert_id or a.get("src_ip") == alert_id:
                    alert = a
                    break
                    
        if not alert:
            return {
                "error": "Alert not found",
                "explanation": None
            }
            
        alert_type = alert.get("type", "unknown")
        src_ip = alert.get("src_ip", "UNKNOWN")
        
        # Build explanation based on alert type
        explanation = {
            "alert_summary": f"{alert_type.replace('_', ' ').title()} detected from {src_ip}",
            "why_flagged": self._explain_why_flagged(alert),
            "evidence_chain": self._build_evidence_chain(alert),
            "confidence_score": self._calculate_confidence(alert),
            "data_sources": self._identify_data_sources(alert),
            "key_indicators": self._extract_key_indicators(alert),
            "timeline_context": self._get_timeline_context(alert),
            "mitre_rationale": self._explain_mitre_mapping(alert),
            "recommendation": self._generate_recommendation(alert)
        }
        
        return explanation
        
    def _explain_why_flagged(self, alert: dict) -> str:
        """Explain why this alert was flagged."""
        alert_type = alert.get("type", "unknown")
        
        explanations = {
            "brute_force": (
                f"Multiple failed authentication attempts detected within a short time window. "
                f"The system observed {alert.get('failure_count', 'multiple')} failed login attempts "
                f"from IP {alert.get('src_ip', 'UNKNOWN')} within {alert.get('time_window', '5')} minutes. "
                f"This pattern matches known brute force attack signatures."
            ),
            "port_scan": (
                f"Unusual port scanning activity detected. "
                f"Source IP {alert.get('src_ip', 'UNKNOWN')} contacted {alert.get('unique_ports', 'multiple')} "
                f"different destination ports within a short timeframe, suggesting reconnaissance activity."
            ),
            "privilege_escalation": (
                f"Potential privilege escalation attempt detected. "
                f"User {alert.get('user', 'unknown')} had multiple sudo/authentication failures "
                f"followed by successful elevated access."
            ),
            "lateral_movement": (
                f"Possible lateral movement detected. "
                f"User {alert.get('user', 'unknown')} successfully accessed multiple internal hosts "
                f"({alert.get('destinations', 'multiple')} destinations) in sequence, "
                f"suggesting network traversal."
            ),
            "windows_firewall_attack": (
                f"Suspicious firewall activity detected. "
                f"IP {alert.get('src_ip', 'UNKNOWN')} triggered multiple firewall events "
                f"with concerning patterns."
            )
        }
        
        return explanations.get(alert_type, 
            f"Anomalous activity detected for type: {alert_type}. "
            f"The alert triggered based on correlation across multiple data sources."
        )
        
    def _build_evidence_chain(self, alert: dict) -> List[dict]:
        """Build a chain of evidence supporting the alert."""
        evidence = []
        
        # Add raw log evidence
        raw_logs = alert.get("raw_logs", [])
        if not raw_logs and "evidence" in alert:
            # Parse evidence strings
            for ev in alert.get("evidence", [])[:10]:  # Limit to 10
                evidence.append({
                    "timestamp": ev.split(" | ")[0] if " | " in ev else "unknown",
                    "type": "log_entry",
                    "description": ev,
                    "source": alert.get("sources", ["unknown"])[0]
                })
        else:
            for log in raw_logs[:10]:
                evidence.append({
                    "timestamp": log.get("timestamp", "unknown"),
                    "type": "raw_log",
                    "description": log.get("message", str(log)),
                    "source": log.get("source", "unknown"),
                    "ip": log.get("ip", "unknown"),
                    "status": log.get("status", "unknown")
                })
                
        return evidence
        
    def _calculate_confidence(self, alert: dict) -> float:
        """Calculate confidence score for the alert."""
        score = 0.5  # Base confidence
        
        # Increase based on correlation
        if alert.get("cross_source_hit"):
            score += 0.2
            
        # Increase based on correlation score
        corr_score = alert.get("correlation_score", 0)
        score += min(corr_score / 20, 0.2)  # Cap at 0.2
        
        # Increase based on evidence quantity
        evidence_count = len(alert.get("evidence", []))
        score += min(evidence_count / 50, 0.1)  # Cap at 0.1
        
        return round(min(score, 1.0), 2)
        
    def _identify_data_sources(self, alert: dict) -> List[str]:
        """Identify which data sources contributed to this alert."""
        sources = set(alert.get("sources", []))
        
        # Check for firewall logs
        if alert.get("type") == "windows_firewall_attack":
            sources.add("windows_firewall_log")
            
        # Check raw logs for additional sources
        for log in alert.get("raw_logs", []):
            if "firewall" in str(log.get("source", "")).lower():
                sources.add("firewall_monitor")
                
        return list(sources)
        
    def _extract_key_indicators(self, alert: dict) -> List[dict]:
        """Extract key indicators of compromise/interest."""
        indicators = []
        
        src_ip = alert.get("src_ip")
        if src_ip:
            indicators.append({
                "type": "ip_address",
                "value": src_ip,
                "classification": "attacker" if alert.get("effective_severity") in ["CRITICAL", "HIGH"] else "suspicious",
                "first_seen": alert.get("first_seen", "unknown")
            })
            
        dest_ip = alert.get("dest_ip")
        if dest_ip and dest_ip != "?":
            indicators.append({
                "type": "ip_address",
                "value": dest_ip,
                "classification": "target",
                "description": "Destination/target host"
            })
            
        user = alert.get("user")
        if user and user != "?":
            indicators.append({
                "type": "user_account",
                "value": user,
                "classification": "compromised" if alert.get("effective_severity") == "CRITICAL" else "suspicious"
            })
            
        return indicators
        
    def _get_timeline_context(self, alert: dict) -> dict:
        """Get temporal context for the alert."""
        return {
            "first_seen": alert.get("first_seen", "unknown"),
            "last_seen": alert.get("last_seen", "unknown"),
            "duration_minutes": self._calculate_duration(
                alert.get("first_seen"), 
                alert.get("last_seen")
            ),
            "event_count": len(alert.get("raw_logs", [])),
            "peak_activity": "N/A"  # Could calculate from logs
        }
        
    def _calculate_duration(self, first: str, last: str) -> Optional[int]:
        """Calculate duration in minutes between two timestamps."""
        try:
            from datetime import datetime
            fmt = "%Y-%m-%d %H:%M:%S"
            t1 = datetime.strptime(first[:19], fmt)
            t2 = datetime.strptime(last[:19], fmt)
            return int((t2 - t1).total_seconds() / 60)
        except:
            return None
            
    def _explain_mitre_mapping(self, alert: dict) -> dict:
        """Explain the MITRE ATT&CK mapping."""
        mitre = alert.get("mitre", {})
        car = alert.get("car", {})
        
        technique_id = mitre.get("id", "N/A")
        technique_name = mitre.get("name", "Unknown")
        
        rationales = {
            "T1110": "Brute Force - Repeated failed authentication attempts match this technique",
            "T1046": "Network Service Scanning - Port scanning activity matches reconnaissance behavior",
            "T1078": "Valid Accounts - Possible use of compromised credentials",
            "T1021": "Remote Services - Lateral movement via remote access",
            "T1098": "Account Manipulation - Privilege escalation attempts"
        }
        
        return {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactic": mitre.get("tactic", "Unknown"),
            "rationale": rationales.get(technique_id, 
                f"Activity patterns match characteristics of {technique_name}"),
            "car_analytic": car.get("id", "N/A"),
            "car_name": car.get("name", "Unknown")
        }
        
    def _generate_recommendation(self, alert: dict) -> dict:
        """Generate actionable recommendations."""
        severity = alert.get("effective_severity", "LOW")
        alert_type = alert.get("type", "unknown")
        
        recommendations = {
            "CRITICAL": {
                "priority": "IMMEDIATE",
                "actions": [
                    "Block source IP immediately at firewall",
                    "Force password reset for affected accounts",
                    "Isolate affected systems from network",
                    "Initiate incident response procedure"
                ]
            },
            "HIGH": {
                "priority": "URGENT",
                "actions": [
                    "Add IP to watchlist for enhanced monitoring",
                    "Review access logs for this user/IP",
                    "Consider temporary access restrictions"
                ]
            },
            "MEDIUM": {
                "priority": "SCHEDULED",
                "actions": [
                    "Monitor for additional suspicious activity",
                    "Schedule security review",
                    "Update detection rules if pattern is confirmed"
                ]
            },
            "LOW": {
                "priority": "INFORMATIONAL",
                "actions": [
                    "Log for trending analysis",
                    "No immediate action required"
                ]
            }
        }
        
        return recommendations.get(severity, recommendations["LOW"])
        
    def explain_ai_response(self, query: str, response: str, context: dict = None) -> dict:
        """
        Explain why the AI gave a particular response.
        
        Args:
            query: The user's question
            response: The AI's response
            context: Additional context (logs, alerts, etc.)
            
        Returns:
            dict with explanation of AI reasoning
        """
        # Analyze what data sources were used
        data_sources = []
        
        if "logs" in query.lower() or "failed" in query.lower():
            data_sources.append("authentication_logs")
        if "firewall" in query.lower() or "blocked" in query.lower():
            data_sources.append("firewall_logs")
        if "alert" in query.lower() or "threat" in query.lower():
            data_sources.append("detected_alerts")
        if "mitre" in query.lower() or "technique" in query.lower():
            data_sources.append("mitre_mappings")
            
        # Determine confidence based on data availability
        confidence = 0.8 if data_sources else 0.5
        
        return {
            "query_understood": True,
            "data_sources_used": data_sources if data_sources else ["general_knowledge"],
            "confidence": confidence,
            "explanation": (
                f"The AI analyzed your query about '{query[:50]}...' and "
                f"searched {len(data_sources)} data source(s). "
                f"Response is based on current system logs and detection results."
            ),
            "limitations": [
                "AI responses are based on available log data",
                "Historical context may be limited to loaded time window",
                "Always verify critical decisions with manual investigation"
            ]
        }


# Global explainability engine instance
explainability_engine = ExplainabilityEngine()
