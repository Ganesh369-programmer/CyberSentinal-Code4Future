# CyberSentinel SOC Co-Pilot

AI-Driven Security Operations Assistant for real-time threat investigation.

## Quick Start (2 minutes)

```bash
# Install dependencies
pip install flask flask-cors requests

# Start the application
python app.py

# Open browser
http://localhost:5000
```

## Demo Script (4 minutes)

### 1. Dashboard Overview (30s)
- Show real-time alerts from auth logs + firewall
- Point out MITRE ATT&CK mappings on alerts
- Show severity badges (CRITICAL/HIGH/MEDIUM)

### 2. Live AI Chat (1 min)
- Ask: "Show me failed logins"
- Ask: "Any suspicious activity?"
- AI responds with real data from auth_logs.json

### 3. Investigation Case (1 min)
- Click "Create Case" on any alert
- Show case created with unique ID
- AI now remembers this case context

### 4. Deep Investigation (1 min)
- Click "Investigate" on an alert
- Show attack timeline reconstruction
- Show MITRE mappings + SOAR playbook
- Click "Explain Alert" (NEW)

### 5. Explainability Demo (30s)
- Show why alert was flagged
- Show evidence chain
- Show confidence score
- Show data sources used

## Key Features Implemented

### Core Requirements ✅
- ✅ Natural language querying (`/ai/chat`)
- ✅ Multi-source correlation (auth + firewall logs)
- ✅ Explainability with evidence (`/api/explain/alert`)
- ✅ AI safety (hallucination guard in nvidia_chat.py)
- ✅ SOAR playbooks (automated response workflows)

### Brownie Points ✅
- ✅ **Investigation Memory**: Cases persist to disk, AI recalls context
- ✅ **Explainability Engine**: Every alert has human-readable reasoning
- ✅ **Attack Simulation**: Brute force simulator validates detection
- ✅ **Multi-Agent**: NVIDIA LLM + local detection + SOAR orchestration

## API Endpoints

### Core
- `GET /api/alerts` - Live threat detection
- `POST /api/investigate` - Deep investigation report
- `POST /api/query` - Natural language queries

### Cases (NEW)
- `POST /api/cases` - Create investigation case
- `GET /api/cases` - List all cases
- `GET /api/cases/<id>` - Get case details
- `GET /api/cases/<id>/ai-context` - AI memory recall

### Explainability (NEW)
- `POST /api/explain/alert` - Why was this alert triggered?
- `POST /api/explain/ai-response` - Why did AI say that?

## Architecture

```
Frontend (index.html) → Flask API → Detection Engine
                              ↓
                        ┌────┴────┐
                        ↓         ↓
                   NVIDIA AI   MITRE Map
                   (Llama-4)    SOAR Playbooks
                        ↓
                   Case Manager
                   (Persistence)
```

## Files Structure

```
CyberSentinal-Code4Future/
├── app.py                    # Main Flask server
├── detector.py               # Threat detection engine
├── cases.py                  # Investigation case management ⭐
├── explainability.py         # Explainability engine ⭐
├── real_json/auth_logs.json  # Auth log data
├── windows_firewall_monitor.py  # Firewall monitoring
├── static/script.js          # Frontend logic
└── templates/index.html      # Main dashboard
```

## Judging Points

**Problem Statement Coverage:**
- ✅ Natural language queries over security data
- ✅ Multi-source log correlation
- ✅ Explainable AI with evidence
- ✅ AI risk handling (hallucination guard)
- ✅ SOAR-like response workflows

**Brownie Points:**
- ✅ **Investigation Memory**: Cases persist, AI recalls context
- ✅ **Multi-Agent**: Detection + AI + SOAR collaboration
- ✅ **Attack Simulation**: Validate detection with safe simulations

## What Makes This Special

1. **Grounded AI**: Every AI response is based on actual log data
2. **Explainable**: Click "Explain" on any alert to understand why
3. **Persistent Memory**: Investigation cases survive server restarts
4. **Real-time**: Live firewall monitoring + instant detection
5. **Framework Mapping**: MITRE/CAR/D3FEND/Engage integration

---

**Built for:** AI-Driven SOC Co-Pilot Hackathon  
**Time to demo:** 4 minutes  
**Setup time:** 2 minutes
