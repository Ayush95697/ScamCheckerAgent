# Agentic Honey-Pot for Scam Detection & Intelligence Extraction

A production-ready MVP implementation of an agentic honeypot system designed to detect scams, autonomously engage with scammers to extract intelligence, and report findings via mandatory callbacks.

## Features

- **Honeypot API**: Receives incoming messages and maintains conversation history.
- **Scam Detection**: Hybrid rule-based and keyword scoring system (extensible with LLM).
- **Autonomous Agent**: Engages scammers with believable, human-like replies using LLM (OpenAI) to extract:
  - UPI IDs (`name@bank`)
  - Bank Account Numbers
  - Phishing Links
  - Phone Numbers
- **Intelligence Extraction**: Regex-based extraction and normalization.
- **Session Management**: Redis-backed persistence with automatic in-memory fallback.
- **Callback System**: Mandatory reporting of confirmed scams and intelligence to central server.

## Tech Stack

- **Python 3.11+**
- **FastAPI** + **Uvicorn**
- **Pydantic v2** (Strict Schema Validation)
- **httpx** (Async HTTP Client)
- **Redis** (Optional Persistence)
- **OpenAI** (LLM Provider)

## Setup Instructions

### Prerequisites
- Python 3.11+
- [uv](https://github.com/astral-sh/uv) (Recommended) or pip

### Installation

1. **Install uv** (if not installed):
   ```bash
   # Windows (PowerShell)
   powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
   
   # Linux/macOS
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. **Create Virtual Environment**:
   ```bash
   uv venv
   ```

3. **Activate Virtual Environment**:
   - **Windows**:
     ```powershell
     .venv\Scripts\activate
     ```
   - **Linux/macOS**:
     ```bash
     source .venv/bin/activate
     ```

4. **Install Dependencies**:
   ```bash
   uv pip install -e .
   ```

5. **Configure Environment**:
   - Rename `.env.example` to `.env`.
   - Update `HONEYPOT_API_KEY` and `LLM_API_KEY`.

### Running the Application

1. **Start the Server**:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

2. **Run Tests**:
   ```bash
   pytest -q
   ```

## API Documentation

### POST /api/honeypot

**Headers**:
- `x-api-key`: YOUR_SECRET_API_KEY
- `Content-Type`: application/json

**Request Body**:
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Please verify your KYC immediately",
    "timestamp": "2023-10-27T10:00:00Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "en",
    "locale": "IN"
  }
}
```

**Success Response (200)**:
```json
{
  "status": "success",
  "scamDetected": true,
  "engagementMetrics": {
    "engagementDurationSeconds": 120,
    "totalMessagesExchanged": 5
  },
  "extractedIntelligence": {
    "bankAccounts": [],
    "upiIds": [],
    "phishingLinks": [],
    "phoneNumbers": [],
    "suspiciousKeywords": ["verify", "kyc", "urgent"]
  },
  "agentNotes": "Scam detected. Suspicious keywords found."
}
```

**Error Custom Responses**:
- **401 Unauthorized**: Invalid API key
- **400 Bad Request**: Malformed JSON or missing fields

## Logic & Configuration

- **Engagement Completion**: Triggers when scam is detected AND (8+ messages exchanged OR high-value intel found).
- **Callback**: Sent automatically to configured URL once engagement is complete.
- **Scam Threshold**: Configurable confidence score (default 0.65).

## Directory Structure
```
honeypot_api/
  app/
    __init__.py
    main.py         # Entry point
    config.py       # Configuration
    auth.py         # Authentication
    models.py       # Pydantic Schemas
    store.py        # Redis/Memory Store
    scam_detection.py
    agent.py        # LLM Agent
    extraction.py   # Regex Extraction
    callback.py     # Reporting
    utils.py        # Helpers
  tests/
    test_auth.py
    test_schema.py
    test_callback_logic.py
  README.md
  pyproject.toml
  .env.example
```
