# LLM Chatbot for CyberSentinel

An intelligent security log analysis chatbot powered by Ollama LLM. Provides dynamic, context-aware responses based on real security logs without any hardcoded queries or responses.

## Features

- **Dynamic Analysis**: Uses LLM to analyze logs and answer any user query
- **No Hardcoded Responses**: Every response is generated fresh based on actual log data
- **Real-time Context**: Always uses the latest log data from `real_json/auth_logs.json`
- **Threat Detection**: Identifies brute force attempts, suspicious users, and anomalies
- **REST API**: Flask endpoints for frontend integration

## Prerequisites

1. **Install Ollama**: Download from [ollama.com](https://ollama.com)
2. **Pull a Model**: 
   ```bash
   ollama pull llama3.2
   ```
3. **Start Ollama Server**:
   ```bash
   ollama serve
   ```

## Installation

```bash
cd llm
pip install -r requirements.txt
```

## Usage

### Command Line
```bash
python chatbot.py
```

### As Module
```python
from llm.chatbot import SecurityLogChatbot

bot = SecurityLogChatbot()
response = bot.ask("What threats were detected today?")
print(response['response'])
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/llm/status` | GET | Check Ollama status and stats |
| `/api/llm/chat` | POST | Send query to LLM |
| `/api/llm/stats` | GET | Get log statistics |
| `/api/llm/threats` | GET | Get detected threats |
| `/api/llm/query` | POST | Direct log search |
| `/api/llm/suggest` | GET | Get query suggestions |

### Example API Usage

```bash
# Check status
curl http://localhost:5000/api/llm/status

# Chat with bot
curl -X POST http://localhost:5000/api/llm/chat \
  -H "Content-Type: application/json" \
  -d '{"query": "What are the top threats?"}'

# Get statistics
curl http://localhost:5000/api/llm/stats
```

## Architecture

```
User Query → LLM Prompt (with log context) → Ollama API → Dynamic Response
```

The chatbot:
1. Loads security logs from `real_json/auth_logs.json`
2. Generates summary statistics and threat analysis
3. Creates a context-rich prompt with log data
4. Sends to Ollama LLM for intelligent analysis
5. Returns natural language response based on actual data
