# mitre_framework_analyzer.py — Cross-Framework Log Analysis Engine
# Analyzes logs across all MITRE frameworks (ATT&CK, CAR, D3FEND, Engage)

import json
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any

# Import all framework mappings
from mitre_map import get_mitre_info, get_all_mappings as get_attack_mappings
from mitre_car_map import get_car_info, get_all_car_mappings as get_car_mappings
from mitre_d3fend_map import get_d3fend_info, get_all_d3fend_mappings as get_d3fend_mappings
from mitre_engage_map import get_engage_info, get_all_engage_mappings as get_engage_mappings


class MITREFrameworkAnalyzer:
    """Analyzes threats across all MITRE frameworks and provides unified insights."""
    
    def __init__(self):
        self.frameworks = {
            'attack': get_attack_mappings(),
            'car': get_car_mappings(), 
            'd3fend': get_d3fend_mappings(),
            'engage': get_engage_mappings()
        }
    
    def analyze_threat_across_frameworks(self, threat_type: str) -> Dict[str, Any]:
        """
        Analyze a single threat type across all MITRE frameworks.
        Returns comprehensive analysis with insights from each framework.
        """
        analysis = {
            'threat_type': threat_type,
            'timestamp': datetime.utcnow().isoformat(),
            'frameworks': {},
            'cross_framework_insights': {},
            'recommendations': []
        }
        
        # Get information from each framework
        attack_info = get_mitre_info(threat_type)
        car_info = get_car_info(threat_type)
        d3fend_info = get_d3fend_info(threat_type)
        engage_info = get_engage_info(threat_type)
        
        # Store framework-specific information
        analysis['frameworks']['attack'] = {
            'technique_id': attack_info.get('technique_id'),
            'technique_name': attack_info.get('technique_name'),
            'tactic': attack_info.get('tactic'),
            'severity': attack_info.get('severity'),
            'description': attack_info.get('description'),
            'url': attack_info.get('url')
        }
        
        analysis['frameworks']['car'] = {
            'analytics_id': car_info.get('analytics_id'),
            'analytics_name': car_info.get('analytics_name'),
            'hypothesis': car_info.get('hypothesis'),
            'information_domain': car_info.get('information_domain'),
            'confidence': car_info.get('confidence'),
            'data_sources': car_info.get('data_sources', []),
            'implementation': car_info.get('implementation', [])
        }
        
        analysis['frameworks']['d3fend'] = {
            'defend_id': d3fend_info.get('defend_id'),
            'defend_name': d3fend_info.get('defend_name'),
            'tactic': d3fend_info.get('tactic'),
            'technique': d3fend_info.get('technique'),
            'effectiveness': d3fend_info.get('effectiveness'),
            'countermeasures': d3fend_info.get('countermeasures', []),
            'implementation_cost': d3fend_info.get('implementation_cost')
        }
        
        analysis['frameworks']['engage'] = {
            'engage_id': engage_info.get('engage_id'),
            'engage_name': engage_info.get('engage_name'),
            'strategy': engage_info.get('strategy'),
            'technique': engage_info.get('technique'),
            'risk_level': engage_info.get('risk_level'),
            'deception_tactics': engage_info.get('deception_tactics', []),
            'engagement_goals': engage_info.get('engagement_goals', [])
        }
        
        # Generate cross-framework insights
        analysis['cross_framework_insights'] = self._generate_cross_insights(
            attack_info, car_info, d3fend_info, engage_info
        )
        
        # Generate unified recommendations
        analysis['recommendations'] = self._generate_recommendations(
            attack_info, car_info, d3fend_info, engage_info
        )
        
        return analysis
    
    def _generate_cross_insights(self, attack_info, car_info, d3fend_info, engage_info) -> Dict[str, Any]:
        """Generate insights by correlating information across frameworks."""
        insights = {
            'detection_confidence': 'UNKNOWN',
            'defense_posture': 'UNKNOWN',
            'engagement_opportunity': 'UNKNOWN',
            'data_source_coverage': [],
            'technique_maturity': 'UNKNOWN'
        }
        
        # Assess detection confidence based on CAR and ATT&CK
        car_confidence = car_info.get('confidence', 'LOW')
        attack_severity = attack_info.get('severity', 'LOW')
        
        if car_confidence in ['HIGH', 'CRITICAL'] and attack_severity in ['HIGH', 'CRITICAL']:
            insights['detection_confidence'] = 'HIGH'
        elif car_confidence in ['MEDIUM', 'HIGH'] or attack_severity in ['MEDIUM', 'HIGH']:
            insights['detection_confidence'] = 'MEDIUM'
        else:
            insights['detection_confidence'] = 'LOW'
        
        # Assess defense posture based on D3FEND effectiveness
        d3fend_effectiveness = d3fend_info.get('effectiveness', 'LOW')
        insights['defense_posture'] = d3fend_effectiveness
        
        # Assess engagement opportunity based on Engage risk level
        engage_risk = engage_info.get('risk_level', 'HIGH')
        if engage_risk == 'LOW':
            insights['engagement_opportunity'] = 'HIGH'
        elif engage_risk == 'MEDIUM':
            insights['engagement_opportunity'] = 'MEDIUM'
        else:
            insights['engagement_opportunity'] = 'LOW'
        
        # Compile required data sources
        insights['data_source_coverage'] = car_info.get('data_sources', [])
        
        # Assess technique maturity based on framework coverage
        framework_coverage = 0
        if attack_info.get('technique_id') != 'UNKNOWN':
            framework_coverage += 1
        if car_info.get('analytics_id') != 'CAR-UNKNOWN':
            framework_coverage += 1
        if d3fend_info.get('defend_id') != 'D3-UNKNOWN':
            framework_coverage += 1
        if engage_info.get('engage_id') != 'ENG-UNKNOWN':
            framework_coverage += 1
        
        if framework_coverage >= 3:
            insights['technique_maturity'] = 'WELL_ESTABLISHED'
        elif framework_coverage >= 2:
            insights['technique_maturity'] = 'EMERGING'
        else:
            insights['technique_maturity'] = 'NOVEL'
        
        return insights
    
    def _generate_recommendations(self, attack_info, car_info, d3fend_info, engage_info) -> List[str]:
        """Generate unified recommendations based on all frameworks."""
        recommendations = []
        
        # Detection recommendations from CAR
        car_sources = car_info.get('data_sources', [])
        if car_sources:
            recommendations.append(f"Ensure collection of data sources: {', '.join(car_sources)}")
        
        car_implementations = car_info.get('implementation', [])
        if car_implementations:
            recommendations.append(f"Implement CAR analytics using: {', '.join(car_implementations)}")
        
        # Defensive recommendations from D3FEND
        d3fend_countermeasures = d3fend_info.get('countermeasures', [])
        if d3fend_countermeasures:
            recommendations.extend([f"DEFEND: {cm}" for cm in d3fend_countermeasures[:3]])
        
        # Engagement recommendations from Engage
        engage_tactics = engage_info.get('deception_tactics', [])
        if engage_tactics and engage_info.get('risk_level') != 'HIGH':
            recommendations.append(f"ENGAGE: Consider {engage_tactics[0]} for adversary detection")
        
        # Severity-based response from ATT&CK
        severity = attack_info.get('severity', 'LOW')
        if severity in ['CRITICAL', 'HIGH']:
            recommendations.append("IMMEDIATE RESPONSE REQUIRED: Implement incident response procedures")
        elif severity == 'MEDIUM':
            recommendations.append("Monitor closely and prepare response procedures")
        
        return recommendations
    
    def compare_threats_across_frameworks(self, threat_types: List[str]) -> Dict[str, Any]:
        """
        Compare multiple threat types across all frameworks.
        Useful for understanding attack patterns and prioritizing defenses.
        """
        comparison = {
            'threats': {},
            'framework_coverage': {},
            'prioritized_defenses': [],
            'detection_gaps': [],
            'engagement_opportunities': []
        }
        
        # Analyze each threat
        for threat_type in threat_types:
            comparison['threats'][threat_type] = self.analyze_threat_across_frameworks(threat_type)
        
        # Calculate framework coverage
        for framework in ['attack', 'car', 'd3fend', 'engage']:
            coverage = sum(1 for threat in comparison['threats'].values() 
                          if threat['frameworks'][framework].get('technique_id') != 'UNKNOWN')
            comparison['framework_coverage'][framework] = {
                'covered_threats': coverage,
                'total_threats': len(threat_types),
                'coverage_percentage': (coverage / len(threat_types)) * 100
            }
        
        # Prioritize defenses based on D3FEND effectiveness and ATT&CK severity
        threat_scores = []
        for threat_type, analysis in comparison['threats'].items():
            attack_severity = analysis['frameworks']['attack'].get('severity', 'LOW')
            d3fend_effectiveness = analysis['frameworks']['d3fend'].get('effectiveness', 'LOW')
            
            score = self._calculate_priority_score(attack_severity, d3fend_effectiveness)
            threat_scores.append((threat_type, score, analysis))
        
        threat_scores.sort(key=lambda x: x[1], reverse=True)
        comparison['prioritized_defenses'] = [
            {
                'threat_type': threat,
                'priority_score': score,
                'top_recommendations': analysis['recommendations'][:3]
            }
            for threat, score, analysis in threat_scores
        ]
        
        # Identify detection gaps
        for threat_type, analysis in comparison['threats'].items():
            car_confidence = analysis['frameworks']['car'].get('confidence', 'LOW')
            if car_confidence in ['LOW', 'UNKNOWN']:
                comparison['detection_gaps'].append({
                    'threat_type': threat_type,
                    'gap_reason': f'Low CAR confidence ({car_confidence})',
                    'recommended_action': 'Enhance data collection and analytics'
                })
        
        # Identify engagement opportunities
        for threat_type, analysis in comparison['threats'].items():
            engage_opportunity = analysis['cross_framework_insights'].get('engagement_opportunity', 'LOW')
            if engage_opportunity in ['HIGH', 'MEDIUM']:
                comparison['engagement_opportunities'].append({
                    'threat_type': threat_type,
                    'opportunity_level': engage_opportunity,
                    'suggested_tactics': analysis['frameworks']['engage'].get('deception_tactics', [])[:2]
                })
        
        return comparison
    
    def _calculate_priority_score(self, severity: str, effectiveness: str) -> float:
        """Calculate priority score for threat defense."""
        severity_scores = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        effectiveness_scores = {'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'UNKNOWN': 1}
        
        return severity_scores.get(severity, 1) * effectiveness_scores.get(effectiveness, 1)
    
    def get_framework_summary(self) -> Dict[str, Any]:
        """Get summary statistics for all frameworks."""
        summary = {
            'total_threats_mapped': len(self.frameworks['attack']),
            'framework_statistics': {}
        }
        
        for framework_name, mappings in self.frameworks.items():
            summary['framework_statistics'][framework_name] = {
                'total_mappings': len(mappings),
                'coverage_percentage': (len(mappings) / len(self.frameworks['attack'])) * 100
            }
        
        return summary


# ── Quick self-test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    analyzer = MITREFrameworkAnalyzer()
    
    print("=== MITRE Framework Analyzer Test ===\n")
    
    # Test single threat analysis
    print("Single Threat Analysis (brute_force):")
    analysis = analyzer.analyze_threat_across_frameworks('brute_force')
    print(f"  Detection Confidence: {analysis['cross_framework_insights']['detection_confidence']}")
    print(f"  Defense Posture: {analysis['cross_framework_insights']['defense_posture']}")
    print(f"  Recommendations: {len(analysis['recommendations'])} generated")
    print()
    
    # Test multi-threat comparison
    print("Multi-Threat Comparison:")
    comparison = analyzer.compare_threats_across_frameworks(['brute_force', 'port_scan', 'lateral_movement'])
    print(f"  Framework Coverage: {comparison['framework_coverage']}")
    print(f"  Prioritized Defenses: {len(comparison['prioritized_defenses'])} threats")
    print(f"  Detection Gaps: {len(comparison['detection_gaps'])} identified")
    print()
    
    # Test framework summary
    print("Framework Summary:")
    summary = analyzer.get_framework_summary()
    print(f"  Total Threats Mapped: {summary['total_threats_mapped']}")
    for framework, stats in summary['framework_statistics'].items():
        print(f"  {framework.upper()}: {stats['total_mappings']} mappings ({stats['coverage_percentage']:.1f}% coverage)")
    print()
