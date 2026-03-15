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
SecureLensAI/
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
git clone https://github.com/yourusername/SecureLensAI.git
cd SecureLensAI
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

### 7. Login & Create Account

Open `http://localhost:3000` in your browser. You'll be directed to the login page. Click **"Create an account"** to register a new user with your own credentials. Once registered, you can log in and start uploading log files for analysis.

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

- **Password Security** — Passwords hashed with PBKDF2-SHA256 (600,000 iterations); users must create strong passwords during registration
- **JWT Authentication** — Tokens expire after 24 hours; issued upon successful login and required for all protected endpoints
- **CORS Protection** — Cross-Origin Resource Sharing configured per environment to prevent unauthorized API access
- **File Upload Validation** — Uploaded files validated by extension and file size (50MB limit); only `.json`, `.csv`, `.log`, `.txt` formats accepted
- **Access Control** — Users can only view their own uploaded files and analyses; no cross-user data leakage
- **SQL Injection Prevention** — All database queries use parameterized statements to prevent injection attacks
- **Log Data Privacy** — Log files uploaded for analysis are stored temporarily and deleted after processing; consider data residency policies if using AI analysis
- **Credential Security** — API keys and secrets must never be hardcoded; use environment variables only
- **No Default Credentials** — No admin accounts or default passwords are pre-configured

---

## Production Deployment

### Environment Configuration

Before deploying to production, ensure the following environment variables are securely configured:

```bash
# Generate strong secret keys
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
JWT_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Export to your hosting platform (e.g., Vercel, Render, Heroku)
export SECRET_KEY="your-generated-secret-here"
export JWT_SECRET_KEY="your-generated-jwt-secret-here"
export OPENAI_API_KEY="your-api-key-here"
export CORS_ORIGINS="https://yourdomain.com,https://www.yourdomain.com"
```

### Security Best Practices

- **Never commit `.env` files** — The `.gitignore` excludes `.env` and all database files
- **Use HTTPS only** — Ensure your deployment enforces HTTPS for all traffic
- **Rotate secrets regularly** — Change SECRET_KEY and JWT_SECRET_KEY periodically
- **Database backups** — Set up automated backups of the SQLite database before production use
- **Rate limiting** — Consider adding rate limiting to the API endpoints to prevent abuse
- **Log rotation** — Configure log file rotation to manage disk space
- **Monitor API usage** — Track OpenAI API calls and costs to avoid unexpected charges
- **Use environment-specific configs** — Maintain separate .env files for development, staging, and production

### Deploying to Vercel, Render, or Heroku

1. Push your repository to GitHub
2. Connect your GitHub repo to your deployment platform
3. Add environment variables in the platform's settings (do **not** commit `.env`)
4. Configure the start command:
   ```bash
   cd backend && python run.py
   ```
5. Set Node.js version and Python version as needed
6. Deploy and monitor logs

---

## License

MIT License
