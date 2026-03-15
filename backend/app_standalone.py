"""
Secure Lens AI Backend - Standalone server using only Python stdlib + PyJWT + python-dotenv
Provides REST API for log analysis, user auth, and security analytics.
"""

import os
import sys
import json
import sqlite3
import hashlib
import secrets
import uuid
import re
from datetime import datetime, timedelta
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from io import BytesIO
import cgi

try:
    import jwt
except ImportError:
    raise ImportError("PyJWT not installed. Install with: pip install PyJWT")

try:
    from dotenv import load_dotenv
except ImportError:
    raise ImportError("python-dotenv not installed. Install with: pip install python-dotenv")

# Load environment variables
load_dotenv()

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "securelensai-dev-secret-key-change-in-production")
DATABASE_PATH = os.getenv("DATABASE_PATH", "./securelensai.db")
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
ALLOWED_EXTENSIONS = {"txt", "csv", "json", "log"}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
SERVER_PORT = int(os.getenv("SERVER_PORT", 5000))

# Import local modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parsers import parse_log_file
from analyzers import RuleEngine, analyze_with_ai, map_anomalies_to_mitre, get_mitre_summary


# ============================================================================
# Database Setup
# ============================================================================

def init_database():
    """Initialize SQLite database with required schema."""
    os.makedirs(os.path.dirname(DATABASE_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # Uploaded files table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS uploaded_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            error_message TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Analysis results table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER UNIQUE NOT NULL,
            summary TEXT,
            total_events INTEGER DEFAULT 0,
            anomaly_count INTEGER DEFAULT 0,
            risk_score REAL DEFAULT 0.0,
            timeline_data TEXT,
            anomalies TEXT,
            mitre_mappings TEXT,
            stats TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (file_id) REFERENCES uploaded_files(id)
        )
    """)

    conn.commit()

    # Seed demo user if not exists
    cursor.execute("SELECT id FROM users WHERE username = 'admin' LIMIT 1")
    if not cursor.fetchone():
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            "admin123".encode(),
            bytes.fromhex(salt),
            100000
        ).hex()
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
            ("admin", password_hash, salt, datetime.utcnow().isoformat())
        )
        conn.commit()

    conn.close()


def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================================
# Authentication & Utilities
# ============================================================================

def hash_password(password, salt=None):
    """Hash password with salt using PBKDF2."""
    if salt is None:
        salt = secrets.token_hex(16)
    else:
        salt = salt if isinstance(salt, str) else salt.hex()

    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        bytes.fromhex(salt),
        100000
    ).hex()

    return password_hash, salt


def verify_password(password, password_hash, salt):
    """Verify password against hash."""
    computed_hash, _ = hash_password(password, salt)
    return computed_hash == password_hash


def create_token(user_id):
    """Create JWT token."""
    payload = {
        "sub": str(user_id),
        "exp": datetime.utcnow() + timedelta(hours=24),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_token(token):
    """Verify and decode JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def extract_token(authorization_header):
    """Extract token from Authorization header."""
    if not authorization_header:
        return None
    parts = authorization_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


# ============================================================================
# HTTP Request Handler
# ============================================================================

class SecureLensHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Secure Lens AI API."""

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def send_cors_headers(self):
        """Send CORS headers with response."""
        self.send_header("Access-Control-Allow-Origin", FRONTEND_URL)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Credentials", "true")

    def send_json_response(self, status_code, data):
        """Send JSON response with proper headers."""
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def get_request_body(self):
        """Read and parse request body."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return None
        body = self.rfile.read(content_length)
        return json.loads(body.decode())

    def get_user_from_token(self):
        """Extract user ID from Authorization header."""
        auth_header = self.headers.get("Authorization")
        token = extract_token(auth_header)

        if not token:
            return None

        payload = verify_token(token)
        if not payload:
            return None

        try:
            user_id = int(payload["sub"])
            return user_id
        except (ValueError, KeyError):
            return None

    def require_auth(self):
        """Check authentication and return user_id or None."""
        user_id = self.get_user_from_token()
        if not user_id:
            self.send_json_response(401, {"error": "Unauthorized"})
            return None
        return user_id

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    # ========================================================================
    # API Endpoints
    # ========================================================================

    def do_GET(self):
        """Handle GET requests."""
        path = urlparse(self.path).path

        if path == "/api/health":
            self.get_health()
        elif path == "/api/auth/me":
            self.get_auth_me()
        elif path == "/api/analyses":
            self.get_analyses()
        elif path.startswith("/api/analyses/") and "/logs" in path:
            self.get_analysis_logs()
        elif path.startswith("/api/analyses/"):
            self.get_analysis_detail()
        elif path == "/api/account/stats":
            self.get_account_stats()
        else:
            self.send_json_response(404, {"error": "Endpoint not found"})

    def do_POST(self):
        """Handle POST requests."""
        path = urlparse(self.path).path

        if path == "/api/auth/register":
            self.post_register()
        elif path == "/api/auth/login":
            self.post_login()
        elif path == "/api/upload":
            self.post_upload()
        elif path == "/api/contact":
            self.post_contact()
        else:
            self.send_json_response(404, {"error": "Endpoint not found"})

    # ========================================================================
    # Health
    # ========================================================================

    def get_health(self):
        """GET /api/health"""
        self.send_json_response(200, {
            "status": "ok",
            "service": "Secure Lens AI Backend"
        })

    # ========================================================================
    # Authentication
    # ========================================================================

    def post_register(self):
        """POST /api/auth/register"""
        try:
            data = self.get_request_body()
            if not data:
                self.send_json_response(400, {"error": "Invalid request"})
                return

            username = data.get("username", "").strip()
            password = data.get("password", "")

            if not username or not password:
                self.send_json_response(400, {"error": "Username and password required"})
                return

            if len(password) < 6:
                self.send_json_response(400, {"error": "Password must be at least 6 characters"})
                return

            conn = get_db()
            cursor = conn.cursor()

            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                conn.close()
                self.send_json_response(409, {"error": "Username already exists"})
                return

            # Create user
            salt = secrets.token_hex(16)
            password_hash, _ = hash_password(password, salt)
            now = datetime.utcnow().isoformat()

            cursor.execute(
                "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
                (username, password_hash, salt, now)
            )
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()

            self.send_json_response(201, {
                "message": "User created successfully",
                "user": {
                    "id": user_id,
                    "username": username,
                    "created_at": now
                }
            })

        except Exception as e:
            self.send_json_response(500, {"error": str(e)})

    def post_login(self):
        """POST /api/auth/login"""
        try:
            data = self.get_request_body()
            if not data:
                self.send_json_response(400, {"error": "Invalid request"})
                return

            username = data.get("username", "").strip()
            password = data.get("password", "")

            if not username or not password:
                self.send_json_response(400, {"error": "Username and password required"})
                return

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id, password_hash, salt, created_at FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            conn.close()

            if not user or not verify_password(password, user["password_hash"], user["salt"]):
                self.send_json_response(401, {"error": "Invalid credentials"})
                return

            token = create_token(user["id"])

            self.send_json_response(200, {
                "message": "Login successful",
                "access_token": token,
                "user": {
                    "id": user["id"],
                    "username": username,
                    "created_at": user["created_at"]
                }
            })

        except Exception as e:
            self.send_json_response(500, {"error": str(e)})

    def get_auth_me(self):
        """GET /api/auth/me"""
        user_id = self.require_auth()
        if not user_id:
            return

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, created_at FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            conn.close()

            if not user:
                self.send_json_response(404, {"error": "User not found"})
                return

            self.send_json_response(200, {
                "id": user["id"],
                "username": user["username"],
                "created_at": user["created_at"]
            })

        except Exception as e:
            self.send_json_response(500, {"error": str(e)})

    # ========================================================================
    # File Upload & Analysis
    # ========================================================================

    def post_upload(self):
        """POST /api/upload"""
        user_id = self.require_auth()
        if not user_id:
            return

        try:
            content_type = self.headers.get("Content-Type", "")

            if "multipart/form-data" not in content_type:
                self.send_json_response(400, {"error": "Content-Type must be multipart/form-data"})
                return

            # Parse multipart form data
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": content_type,
                }
            )

            if "file" not in form:
                self.send_json_response(400, {"error": "No file provided"})
                return

            fileitem = form["file"]
            if not fileitem.filename:
                self.send_json_response(400, {"error": "No file selected"})
                return

            original_filename = os.path.basename(fileitem.filename)
            file_ext = original_filename.rsplit(".", 1)[-1].lower() if "." in original_filename else ""

            if file_ext not in ALLOWED_EXTENSIONS:
                self.send_json_response(400, {
                    "error": f"File type not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
                })
                return

            # Read file content
            file_content = fileitem.file.read()
            file_size = len(file_content)

            if file_size > MAX_FILE_SIZE:
                self.send_json_response(413, {"error": "File too large (max 50MB)"})
                return

            # Create uploads directory
            os.makedirs(UPLOAD_DIR, exist_ok=True)

            # Save file with unique name
            unique_filename = f"{uuid.uuid4()}_{original_filename}"
            file_path = os.path.join(UPLOAD_DIR, unique_filename)

            with open(file_path, "wb") as f:
                f.write(file_content)

            # Create database record
            conn = get_db()
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()

            cursor.execute(
                """INSERT INTO uploaded_files
                   (filename, original_filename, user_id, uploaded_at, file_size, status)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (unique_filename, original_filename, user_id, now, file_size, "processing")
            )
            conn.commit()
            file_id = cursor.lastrowid

            # Analyze file
            analysis_result = self._analyze_file(file_path, file_id, cursor)

            if analysis_result["success"]:
                cursor.execute(
                    "UPDATE uploaded_files SET status = ? WHERE id = ?",
                    ("completed", file_id)
                )
                conn.commit()
            else:
                cursor.execute(
                    "UPDATE uploaded_files SET status = ?, error_message = ? WHERE id = ?",
                    ("failed", analysis_result["error"], file_id)
                )
                conn.commit()

            conn.close()

            if not analysis_result["success"]:
                self.send_json_response(500, {
                    "error": "Analysis failed",
                    "details": analysis_result["error"]
                })
                return

            # Return analysis
            analysis_data = analysis_result["data"]

            self.send_json_response(201, {
                "message": "File uploaded and analyzed successfully",
                "file_id": file_id,
                "analysis": analysis_data
            })

        except Exception as e:
            self.send_json_response(500, {"error": str(e)})

    def _analyze_file(self, file_path, file_id, cursor):
        """Analyze uploaded file using parsers and analyzers."""
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()

            # Parse log entries
            entries = parse_log_file(content)

            if not entries:
                entries = []

            # Initialize rule engine and analyze
            engine = RuleEngine()
            anomalies, stats = engine.analyze(entries)

            # Get MITRE mappings
            mitre_mappings = map_anomalies_to_mitre(anomalies)
            mitre_summary = get_mitre_summary(anomalies)

            # Get AI analysis
            ai_result = analyze_with_ai(anomalies, entries, stats)

            # Build timeline data
            timeline_data = self._build_timeline(entries)

            # Use AI result values
            anomaly_count = len(anomalies)
            total_events = len(entries)
            risk_score = ai_result.get("risk_score", min(100, int((anomaly_count / max(total_events, 1)) * 100)))
            summary = ai_result.get("executive_summary", f"Analyzed {total_events} events, detected {anomaly_count} anomalies.")
            timeline_from_ai = ai_result.get("timeline", [])
            if timeline_from_ai:
                timeline_data = timeline_from_ai

            # Store in database
            cursor.execute(
                """INSERT INTO analysis_results
                   (file_id, summary, total_events, anomaly_count, risk_score,
                    timeline_data, anomalies, mitre_mappings, stats, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    file_id,
                    summary,
                    total_events,
                    anomaly_count,
                    risk_score,
                    json.dumps(timeline_data),
                    json.dumps(anomalies),
                    json.dumps(mitre_mappings),
                    json.dumps(stats),
                    datetime.utcnow().isoformat()
                )
            )

            return {
                "success": True,
                "data": {
                    "file_id": file_id,
                    "summary": summary,
                    "total_events": total_events,
                    "anomaly_count": anomaly_count,
                    "risk_score": risk_score,
                    "timeline_data": timeline_data,
                    "anomalies": anomalies,
                    "mitre_mappings": mitre_mappings,
                    "stats": {
                        **stats,
                        "ai_enabled": ai_result.get("ai_enabled", False),
                        "risk_assessment": ai_result.get("risk_assessment", ""),
                        "recommendations": ai_result.get("recommendations", []),
                        "additional_findings": ai_result.get("additional_findings", ""),
                    }
                }
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _build_timeline(self, entries):
        """Build timeline data from log entries."""
        timeline = {}

        for entry in entries:
            if isinstance(entry, dict) and "timestamp" in entry:
                ts = entry.get("timestamp", "")
                if ts:
                    # Extract date part
                    date_key = ts.split("T")[0] if "T" in ts else ts[:10]
                    timeline[date_key] = timeline.get(date_key, 0) + 1

        return [{"date": k, "count": v} for k, v in sorted(timeline.items())]

    def get_analyses(self):
        """GET /api/analyses"""
        user_id = self.require_auth()
        if not user_id:
            return

        try:
            query_params = parse_qs(urlparse(self.path).query)
            page = int(query_params.get("page", ["1"])[0])
            per_page = int(query_params.get("per_page", ["10"])[0])

            if page < 1:
                page = 1
            if per_page < 1 or per_page > 100:
                per_page = 10

            offset = (page - 1) * per_page

            conn = get_db()
            cursor = conn.cursor()

            # Get total count
            cursor.execute(
                """SELECT COUNT(*) as count FROM analysis_results ar
                   JOIN uploaded_files uf ON ar.file_id = uf.id
                   WHERE uf.user_id = ?""",
                (user_id,)
            )
            total = cursor.fetchone()["count"]

            # Get analyses
            cursor.execute(
                """SELECT ar.id, ar.file_id, uf.original_filename, ar.summary,
                          ar.total_events, ar.anomaly_count, ar.risk_score, ar.created_at
                   FROM analysis_results ar
                   JOIN uploaded_files uf ON ar.file_id = uf.id
                   WHERE uf.user_id = ?
                   ORDER BY ar.created_at DESC
                   LIMIT ? OFFSET ?""",
                (user_id, per_page, offset)
            )

            analyses = []
            for row in cursor.fetchall():
                analyses.append({
                    "id": row["id"],
                    "file_id": row["file_id"],
                    "filename": row["original_filename"],
                    "summary": row["summary"],
                    "total_events": row["total_events"],
                    "anomaly_count": row["anomaly_count"],
                    "risk_score": row["risk_score"],
                    "created_at": row["created_at"]
                })

            conn.close()

            self.send_json_response(200, {
                "analyses": analyses,
                "pagination": {
                    "total": total,
                    "page": page,
                    "per_page": per_page,
                    "total_pages": (total + per_page - 1) // per_page
                }
            })

        except Exception as e:
            self.send_json_response(500, {"error": str(e)})

    def get_analysis_detail(self):
        """GET /api/analyses/<id>"""
        user_id = self.require_auth()
        if not user_id:
            return

        try:
            analysis_id = int(self.path.split("/")[-1].split("?")[0])

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                """SELECT ar.* FROM analysis_results ar
                   JOIN uploaded_files uf ON ar.file_id = uf.id
                   WHERE ar.id = ? AND uf.user_id = ?""",
                (analysis_id, user_id)
            )

            analysis = cursor.fetchone()

            if not analysis:
                conn.close()
                self.send_json_response(404, {"error": "Analysis not found"})
                return

            # Get filename
            cursor.execute(
                "SELECT original_filename FROM uploaded_files WHERE id = ?",
                (analysis["file_id"],)
            )
            file_record = cursor.fetchone()
            conn.close()

            response_data = {
                "id": analysis["id"],
                "file_id": analysis["file_id"],
                "filename": file_record["original_filename"] if file_record else "unknown",
                "summary": analysis["summary"],
                "total_events": analysis["total_events"],
                "anomaly_count": analysis["anomaly_count"],
                "risk_score": analysis["risk_score"],
                "timeline_data": json.loads(analysis["timeline_data"] or "[]"),
                "anomalies": json.loads(analysis["anomalies"] or "[]"),
                "mitre_mappings": json.loads(analysis["mitre_mappings"] or "{}"),
                "stats": json.loads(analysis["stats"] or "{}"),
                "created_at": analysis["created_at"]
            }

            self.send_json_response(200, response_data)

        except ValueError:
            self.send_json_response(400, {"error": "Invalid analysis ID"})
        except Exception as e:
            self.send_json_response(500, {"error": str(e)})

    def get_analysis_logs(self):
        """GET /api/analyses/<id>/logs"""
        user_id = self.require_auth()
        if not user_id:
            return

        try:
            path_parts = self.path.split("/")
            analysis_id = int(path_parts[3])

            query_params = parse_qs(urlparse(self.path).query)
            page = int(query_params.get("page", ["1"])[0])
            per_page = int(query_params.get("per_page", ["50"])[0])
            anomaly_only = query_params.get("anomaly_only", ["false"])[0].lower() == "true"

            if page < 1:
                page = 1
            if per_page < 1 or per_page > 500:
                per_page = 50

            # Get analysis and associated file
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                """SELECT ar.anomalies, uf.filename FROM analysis_results ar
                   JOIN uploaded_files uf ON ar.file_id = uf.id
                   WHERE ar.id = ? AND uf.user_id = ?""",
                (analysis_id, user_id)
            )

            result = cursor.fetchone()
            conn.close()

            if not result:
                self.send_json_response(404, {"error": "Analysis not found"})
                return

            # Re-parse the actual log file
            filepath = os.path.join(UPLOAD_DIR, result["filename"])
            if not os.path.exists(filepath):
                self.send_json_response(404, {"error": "Log file not found"})
                return

            with open(filepath, "r", errors="ignore") as f:
                content = f.read()

            entries = parse_log_file(content)

            # Filter to anomalies only if requested
            if anomaly_only:
                anomalies = json.loads(result["anomalies"] or "[]")
                anomaly_indices = set()
                for anomaly in anomalies:
                    anomaly_indices.update(anomaly.get("affected_entries", []))
                entries = [e for i, e in enumerate(entries) if i in anomaly_indices]

            total = len(entries)
            offset = (page - 1) * per_page
            paginated_logs = entries[offset:offset + per_page]

            self.send_json_response(200, {
                "logs": paginated_logs,
                "total": total,
                "page": page,
                "per_page": per_page
            })

        except ValueError:
            self.send_json_response(400, {"error": "Invalid analysis ID"})
        except Exception as e:
            self.send_json_response(500, {"error": str(e)})

    # ========================================================================
    # Contact & Account
    # ========================================================================

    def post_contact(self):
        """POST /api/contact"""
        user_id = self.require_auth()
        if not user_id:
            return

        try:
            data = self.get_request_body()
            if not data:
                self.send_json_response(400, {"error": "Invalid request"})
                return

            name = data.get("name", "").strip()
            email = data.get("email", "").strip()
            subject = data.get("subject", "").strip()
            priority = data.get("priority", "normal")
            message = data.get("message", "").strip()

            if not all([name, email, subject, message]):
                self.send_json_response(400, {"error": "All fields required"})
                return

            # Generate ticket ID
            ticket_id = f"SEC-{uuid.uuid4().hex[:8].upper()}"

            self.send_json_response(200, {
                "message": f"Thank you for contacting Secure Lens AI. We'll review your {priority} priority request.",
                "ticket_id": ticket_id
            })

        except Exception as e:
            self.send_json_response(500, {"error": str(e)})

    def get_account_stats(self):
        """GET /api/account/stats"""
        user_id = self.require_auth()
        if not user_id:
            return

        try:
            conn = get_db()
            cursor = conn.cursor()

            cursor.execute(
                "SELECT COUNT(*) as count FROM analysis_results ar JOIN uploaded_files uf ON ar.file_id = uf.id WHERE uf.user_id = ?",
                (user_id,)
            )
            total_analyses = cursor.fetchone()["count"]

            cursor.execute(
                "SELECT COUNT(*) as count FROM uploaded_files WHERE user_id = ?",
                (user_id,)
            )
            files_uploaded = cursor.fetchone()["count"]

            cursor.execute(
                "SELECT MAX(uploaded_at) as last_active FROM uploaded_files WHERE user_id = ?",
                (user_id,)
            )
            last_active_row = cursor.fetchone()
            last_active = last_active_row["last_active"] if last_active_row and last_active_row["last_active"] else datetime.utcnow().isoformat()

            conn.close()

            self.send_json_response(200, {
                "total_analyses": total_analyses,
                "files_uploaded": files_uploaded,
                "account_type": "Professional",
                "last_active": last_active
            })

        except Exception as e:
            self.send_json_response(500, {"error": str(e)})


# ============================================================================
# Server Startup
# ============================================================================

def run_server(host="0.0.0.0", port=SERVER_PORT):
    """Start the Secure Lens AI backend server."""
    # Initialize database
    init_database()

    # Create server
    server = ThreadingHTTPServer((host, port), SecureLensHandler)

    print(f"\n{'='*60}")
    print(f"Secure Lens AI Backend Server")
    print(f"{'='*60}")
    print(f"Server running at http://{host}:{port}")
    print(f"Database: {DATABASE_PATH}")
    print(f"Frontend URL: {FRONTEND_URL}")
    print(f"Demo user: admin / admin123")
    print(f"{'='*60}\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    run_server()
