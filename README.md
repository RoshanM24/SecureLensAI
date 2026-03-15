# Secure Lens AI

**AI-Powered Cybersecurity Log Analysis Platform**

Secure Lens AI is a full-stack web application that analyzes Zscaler web proxy logs to detect security anomalies, map threats to the MITRE ATT&CK framework, and provide actionable intelligence through an interactive dashboard.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.1-green?logo=flask)
![SQLite](https://img.shields.io/badge/SQLite-3-blue?logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Features

- **Multi-Format Log Parsing** — Supports JSON, CSV, and pipe-delimited Zscaler proxy log formats with automatic format detection and field normalization.
- **10-Rule Anomaly Detection Engine** — Detects high request frequency, malicious URL categories, blocked actions, unusual HTTP status codes, large data transfers, suspicious user agents, off-hours activity, DNS tunneling indicators, repeated failed requests, and data exfiltration patterns.
- **MITRE ATT&CK Mapping** — Automatically maps detected anomalies to MITRE ATT&CK techniques and tactics for standardized threat classification.
- **AI-Enhanced Analysis (Optional)** — Integrates with OpenAI GPT-4 for executive summaries, risk scoring, and advanced threat correlation when an API key is configured.
- **Interactive Dashboard** — Real-time visualization with risk score gauges, anomaly timelines, category breakdowns, and filterable log views.
- **JWT Authentication** — Secure user registration and login with token-based session management.
- **File Upload & History** — Drag-and-drop file upload with persistent analysis history per user account.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | Vanilla HTML5, CSS3, JavaScript ES6 (no frameworks) |
| **Backend** | Python 3.10+, Flask 3.1 |
| **Database** | SQLite3 (auto-created on first run) |
| **Authentication** | JWT via PyJWT |
| **AI Integration** | OpenAI GPT-4 (optional) |
| **Analysis** | Custom rule engine + MITRE ATT&CK mapper |

---

## Project Structure

```
SecuLens/
├── backend/
│   ├── app.py                  # Flask application & API routes
│   ├── auth.py                 # Authentication endpoints (register/login)
│   ├── models.py               # SQLAlchemy ORM models
│   ├── config.py               # Configuration management
│   ├── run.py                  # Application entry point
│   ├── requirements.txt        # Python dependencies
│   ├── analyzers/
│   │   ├── rule_engine.py      # 10-rule anomaly detection engine
│   │   ├── ai_analyzer.py      # OpenAI GPT-4 integration
│   │   └── mitre_mapper.py     # MITRE ATT&CK technique mapping
│   ├── parsers/
│   │   └── zscaler_parser.py   # Multi-format log parser
│   ├── sample_logs/            # Sample log files for testing
│   ├── uploads/                # User-uploaded files (auto-created)
│   └── vendor/                 # Flask-compatible shim packages
│
├── frontend/
│   ├── index.html              # Landing page
│   ├── login.html              # Authentication page
│   ├── analysis.html           # Main analysis dashboard
│   ├── account.html            # User account & statistics
│   ├── contact.html            # Contact form
│   ├── serve.py                # Frontend development server
│   ├── demo.mp4                # Product demo video
│   ├── css/styles.css          # Application styles
│   └── js/
│       ├── api-client.js       # Centralized API client
│       └── navbar.js           # Dynamic navigation bar
│
├── .env.example                # Environment variable template
├── .gitignore                  # Git ignore rules
└── README.md
```

---

## Quick Start

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/SecuLens.git
cd SecuLens
```

### 2. Set Up Python Environment

```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # macOS / Linux
# venv\Scripts\activate         # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment (Optional)

```bash
cp .env.example .env
```

Edit `.env` to add your OpenAI API key for AI-enhanced analysis:

```
OPENAI_API_KEY=your-openai-api-key-here
```

> The application works fully without an OpenAI key. AI analysis is an optional enhancement — the rule-based engine handles all core detection.

### 5. Start the Backend Server

```bash
python run.py
```

The backend API starts on `http://localhost:5000`.

### 6. Start the Frontend Server

Open a new terminal:

```bash
cd frontend
python serve.py
```

The frontend is available at `http://localhost:3000`.

### 7. Login

Open `http://localhost:3000` in your browser. A demo account is created automatically:

| | |
|---|---|
| **Username** | `admin` |
| **Password** | `admin123` |

---

## Usage

### Uploading Log Files

1. Navigate to the **Analysis** page.
2. Drag and drop a log file onto the upload zone, or click to browse.
3. Supported formats: `.json`, `.csv`, `.log`, `.txt`
4. The file is parsed, analyzed, and results are displayed automatically.

### Sample Log Files

The `backend/sample_logs/` directory includes test files:

| File | Entries | Description |
|------|---------|-------------|
| `sample_normal.json` | 50 | Normal corporate web traffic (baseline) |
| `sample_suspicious.json` | 100 | Mixed traffic with attack patterns |
| `sample_data_exfil.json` | 10 | Data exfiltration scenario |
| `sample_csv.csv` | 10 | CSV format with mixed threats |
| `sample_pipe_delimited.txt` | 10 | Pipe-delimited format |

### Understanding Results

The analysis dashboard provides five tabs:

- **Overview** — Risk score, total events, unique IPs, anomaly count, executive summary
- **Anomalies** — Detailed list of detected threats with severity and confidence scores
- **MITRE ATT&CK** — Mapped techniques and tactics for standardized classification
- **Timeline** — Chronological event visualization
- **Logs** — Searchable, paginated raw log entries

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/health` | No | Health check |
| `POST` | `/api/auth/register` | No | Register new user |
| `POST` | `/api/auth/login` | No | Login and get JWT token |
| `GET` | `/api/auth/me` | Yes | Get current user profile |
| `POST` | `/api/upload` | Yes | Upload and analyze log file |
| `GET` | `/api/analyses` | Yes | List user's analyses (paginated) |
| `GET` | `/api/analyses/:id` | Yes | Get full analysis details |
| `GET` | `/api/analyses/:id/logs` | Yes | Get paginated log entries |
| `POST` | `/api/contact` | Yes | Submit contact form |
| `GET` | `/api/account/stats` | Yes | Get account statistics |

All authenticated endpoints require the header: `Authorization: Bearer <token>`

---

## Detection Rules

The rule engine implements 10 security detection rules:

| # | Rule | Trigger |
|---|------|---------|
| 1 | High Request Frequency | >100 requests/hour from a single user |
| 2 | Malicious URL Categories | Requests to Malware, Phishing, Botnet, C2 categories |
| 3 | Blocked Actions | Blocked requests indicating policy violations |
| 4 | Unusual HTTP Status Codes | 401, 403, 500, 502, 503 responses |
| 5 | Large Data Transfers | Transfers exceeding 50MB |
| 6 | Suspicious User Agents | curl, wget, python-requests, scrapy |
| 7 | Off-Hours Activity | Activity before 6 AM or after 10 PM |
| 8 | DNS Tunneling Indicators | Hostnames exceeding 50 characters |
| 9 | Repeated Failed Requests | 5+ failures from the same IP |
| 10 | Data Exfiltration Patterns | Large outbound transfers to external services |

---

## Configuration

Key environment variables (set in `.env` or system environment):

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | auto-generated | Flask secret key |
| `JWT_SECRET_KEY` | auto-generated | JWT signing key |
| `OPENAI_API_KEY` | *(none)* | OpenAI API key for AI analysis |
| `PORT` | `5000` | Backend server port |
| `HOST` | `0.0.0.0` | Backend server host |
| `CORS_ORIGINS` | `http://localhost:3000` | Allowed CORS origins (comma-separated) |
| `MAX_CONTENT_LENGTH` | `52428800` | Max upload size in bytes (50MB) |

---

## Development

### Running Tests

```bash
cd backend
python test_backend.py
```

### Reset Database

The SQLite database is auto-created on first run. To reset:

```bash
rm backend/securelensai.db
python run.py    # Recreates fresh database with demo user
```

### Vendor Directory

The `backend/vendor/` directory contains lightweight Flask-compatible shim packages built with Python's standard library. These provide the full Flask API surface using only stdlib + PyJWT, making the application portable across environments where pip access may be restricted.

---

## Security

- Passwords hashed with PBKDF2-SHA256 (600,000 iterations)
- JWT tokens expire after 24 hours
- CORS configured per environment
- File uploads validated by extension and size
- Users can only access their own analyses
- SQL injection protected via parameterized queries

---

## License

MIT License
