# MITRE Frameworks Integration Guide

This guide explains how to use all MITRE frameworks integrated into the CyberSentinel SOC Co-Pilot for comprehensive threat analysis and defense.

## Overview

The system now integrates **four major MITRE frameworks**:

1. **MITRE ATT&CK** - Adversary tactics, techniques, and procedures
2. **MITRE CAR** - Cyber Analytics Repository (detection analytics)
3. **MITRE D3FEND** - Defensive countermeasures and techniques
4. **MITRE Engage** - Adversary engagement and deception strategies

## Framework Coverage

All frameworks cover the following threat types:
- **Brute Force** (T1110) - Credential access attacks
- **Port Scan** (T1046) - Network discovery techniques
- **Lateral Movement** (T1021) - Remote service exploitation
- **Privilege Escalation** (T1548) - Elevation control abuse

## API Endpoints

### Framework Mappings

```bash
# Get ATT&CK mappings
GET /api/mitre

# Get CAR analytics mappings
GET /api/mitre/car

# Get D3FEND defensive mappings
GET /api/mitre/d3fend

# Get Engage deception mappings
GET /api/mitre/engage
```

### Cross-Framework Analysis

```bash
# Analyze single threat across all frameworks
GET /api/mitre/analyze/{threat_type}

# Compare multiple threats across frameworks
POST /api/mitre/compare
{
  "threat_types": ["brute_force", "port_scan", "lateral_movement", "privilege_escalation"]
}

# Get framework summary statistics
GET /api/mitre/summary
```

## Dashboard Access

Visit `http://localhost:5000/dashboard` to access the unified MITRE Frameworks Analysis Dashboard.

## Framework Details

### MITRE ATT&CK (Adversary Tactics)

**Purpose**: Catalogs adversary behavior and techniques
**Key Features**:
- Technique IDs and names
- Tactics and phases
- Severity assessments
- Response recommendations

**Example Output**:
```json
{
  "technique_id": "T1110",
  "technique_name": "Brute Force",
  "tactic": "Credential Access",
  "severity": "HIGH",
  "response": "block_ip,force_password_reset,notify_admin"
}
```

### MITRE CAR (Cyber Analytics Repository)

**Purpose**: Provides detection analytics and methodologies
**Key Features**:
- Hypothesis-driven analytics
- Information domains (host, network, process)
- Confidence levels
- Data source requirements
- Implementation examples

**Example Output**:
```json
{
  "analytics_id": "CAR-2023-01-001",
  "analytics_name": "Brute Force Attack Detection",
  "hypothesis": "An adversary is attempting to gain access...",
  "information_domain": "host",
  "confidence": "HIGH",
  "data_sources": ["authentication_logs", "windows_event_logs", "ssh_logs"]
}
```

### MITRE D3FEND (Defensive Framework)

**Purpose**: Maps defensive techniques to offensive methods
**Key Features**:
- Defensive tactics (Harden, Detect, Isolate)
- Countermeasure recommendations
- Implementation examples
- Effectiveness ratings
- Cost and maintenance assessments

**Example Output**:
```json
{
  "defend_id": "D3-PSA",
  "defend_name": "Password Security Authentication",
  "tactic": "Harden",
  "technique": "Password Policy Enforcement",
  "effectiveness": "HIGH",
  "countermeasures": [
    "Implement account lockout policies",
    "Enforce password complexity requirements",
    "Deploy multi-factor authentication"
  ]
}
```

### MITRE Engage (Adversary Engagement)

**Purpose**: Plans and executes adversary engagement strategies
**Key Features**:
- Engagement strategies (Deny, Detect, Disrupt)
- Deception tactics
- Risk assessments
- Success metrics
- Resource requirements

**Example Output**:
```json
{
  "engage_id": "ENG-ATD-001",
  "engage_name": "Attack Technique Deception",
  "strategy": "Deny",
  "technique": "Credential Decoy",
  "risk_level": "LOW",
  "deception_tactics": [
    "Deploy honeytoken accounts with weak credentials",
    "Create fake login portals with credential harvesting"
  ]
}
```

## Cross-Framework Analysis

### Single Threat Analysis

When analyzing a threat type across all frameworks, the system provides:

1. **Detection Confidence** - Based on CAR analytics and ATT&CK severity
2. **Defense Posture** - Based on D3FEND effectiveness ratings
3. **Engagement Opportunity** - Based on Engage risk assessments
4. **Unified Recommendations** - Combined insights from all frameworks

### Multi-Threat Comparison

Comparing multiple threats provides:

1. **Framework Coverage** - Percentage of threats covered by each framework
2. **Prioritized Defenses** - Threats ranked by severity and defense effectiveness
3. **Detection Gaps** - Threats with low detection confidence
4. **Engagement Opportunities** - Threats suitable for deception tactics

## Usage Examples

### Example 1: Analyzing Brute Force Attacks

```bash
# Get comprehensive analysis
curl http://localhost:5000/api/mitre/analyze/brute_force

# Response includes:
# - ATT&CK technique details (T1110)
# - CAR detection analytics
# - D3FEND defensive measures
# - Engage deception opportunities
# - Cross-framework insights
# - Unified recommendations
```

### Example 2: Comparing All Threat Types

```bash
# Compare all threats
curl -X POST http://localhost:5000/api/mitre/compare \
  -H "Content-Type: application/json" \
  -d '{"threat_types": ["brute_force", "port_scan", "lateral_movement", "privilege_escalation"]}'

# Response includes:
# - Framework coverage statistics
# - Prioritized defense list
# - Detection gaps analysis
# - Engagement opportunities
```

### Example 3: Framework-Specific Queries

```bash
# Get all CAR analytics
curl http://localhost:5000/api/mitre/car

# Get all D3FEND defenses
curl http://localhost:5000/api/mitre/d3fend

# Get all Engage tactics
curl http://localhost:5000/api/mitre/engage
```

## Dashboard Features

The unified dashboard provides:

1. **Framework Coverage Overview** - Visual representation of framework coverage
2. **Threat Analysis** - Detailed analysis for selected threats
3. **Cross-Framework Comparison** - Side-by-side framework comparisons
4. **Framework Details** - Detailed information from each framework
5. **Interactive Elements** - Real-time updates and filtering

## Integration with Existing System

The MITRE frameworks integrate seamlessly with existing components:

- **Detector Module** - Uses framework mappings for enhanced threat detection
- **SOAR Module** - Incorporates framework-specific response recommendations
- **Alert System** - Enriches alerts with multi-framework context
- **Timeline Analysis** - Correlates events across framework perspectives

## Benefits

1. **Comprehensive Coverage** - Multiple perspectives on each threat
2. **Enhanced Detection** - CAR analytics improve detection capabilities
3. **Better Defense** - D3FEND provides proven defensive techniques
4. **Active Engagement** - Engage enables proactive adversary engagement
5. **Unified Analysis** - Cross-framework insights provide holistic view

## Extending the Frameworks

To add new threat types or frameworks:

1. **Update Framework Mappings** - Add entries to the appropriate mapping file
2. **Update Analyzer** - Modify `mitre_framework_analyzer.py` if needed
3. **Update Dashboard** - Add new options to the UI
4. **Test Integration** - Verify API endpoints and dashboard functionality

## File Structure

```
mitre_map.py           # ATT&CK framework mappings
mitre_car_map.py       # CAR framework mappings  
mitre_d3fend_map.py    # D3FEND framework mappings
mitre_engage_map.py    # Engage framework mappings
mitre_framework_analyzer.py  # Cross-framework analysis engine
templates/mitre_dashboard.html # Unified dashboard
app.py                 # Updated with new API endpoints
```

## Security Considerations

- All framework mappings are read-only and non-executable
- Dashboard uses client-side rendering with secure API calls
- No external dependencies on MITRE services
- Framework data is locally cached for performance

## Future Enhancements

1. **Real-time Updates** - Automatic framework updates from MITRE
2. **Custom Frameworks** - Support for organization-specific frameworks
3. **Machine Learning** - Enhanced threat correlation across frameworks
4. **Export Capabilities** - PDF/CSV exports of analysis results
5. **Integration APIs** - External system integration capabilities
