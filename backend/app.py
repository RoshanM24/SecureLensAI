"""
Main Flask application for Secure Lens AI.
"""

import os
import mimetypes
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from datetime import datetime

from config import get_config
from models import db, User, UploadedFile, AnalysisResult
from auth import auth_bp
from parsers import parse_log_file
from analyzers import RuleEngine, analyze_with_ai, map_anomalies_to_mitre, get_mitre_summary


def create_app():
    """Create and configure Flask application."""
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(get_config())

    # Initialize extensions
    db.init_app(app)
    CORS(app, origins=app.config["CORS_ORIGINS"])
    jwt = JWTManager(app)

    # Create upload folder
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # Register blueprints
    app.register_blueprint(auth_bp)

    # Initialize database and seed data
    with app.app_context():
        db.create_all()
        _seed_demo_user()

    # Routes
    @app.route("/api/health", methods=["GET"])
    def health_check():
        """Health check endpoint."""
        return jsonify({"status": "ok", "service": "Secure Lens AI Backend"}), 200

    @app.route("/api/upload", methods=["POST"])
    @jwt_required()
    def upload_file():
        """
        Upload and analyze a log file.

        Returns:
            201: File uploaded and analysis started
            400: Bad request (missing file, invalid format)
            413: File too large
            500: Server error
        """
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)

        if not user:
            return jsonify({"error": "User not found"}), 404

        # Check if file is in request
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]
        print(f"[APP] File received: {file.filename}")

        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        # Validate file extension
        if not _allowed_file(file.filename, app.config['ALLOWED_EXTENSIONS']):
            return jsonify({
                "error": f"File type not allowed. Allowed: {', '.join(app.config['ALLOWED_EXTENSIONS'])}"
            }), 400

        # Check file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)

        if file_size > app.config["MAX_CONTENT_LENGTH"]:
            return jsonify({
                "error": f"File too large. Maximum: {app.config['MAX_CONTENT_LENGTH'] // (1024*1024)}MB"
            }), 413

        # Save file
        original_filename = secure_filename(file.filename)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_")
        filename = timestamp + original_filename
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        try:
            file.save(filepath)
            print(f"[APP] File saved: {filepath}")

            # Check saved file size
            saved_size = os.path.getsize(filepath)
            print(f"[APP] Saved file size: {saved_size} bytes")

            if saved_size == 0:
                print(f"[APP] WARNING: Saved file is empty! File object data: {len(file._data) if hasattr(file, '_data') else 'N/A'}")

            # Create file record
            file_record = UploadedFile(
                filename=filename,
                original_filename=original_filename,
                user_id=user_id,
                file_size=file_size,
                status="processing",
            )
            db.session.add(file_record)
            db.session.commit()
            print(f"[APP] File record created: {file_record.id}")

            # Perform analysis
            try:
                analysis_result = _analyze_file(filepath, file_record)
                print(f"[APP] Analysis completed for file {file_record.id}")

                # Return analysis result
                analysis_dict = analysis_result.to_dict()
                analysis_dict["filename"] = original_filename
                return jsonify({
                    "message": "File uploaded and analyzed successfully",
                    "file_id": file_record.id,
                    "analysis": analysis_dict,
                }), 201

            except Exception as e:
                # Mark file as failed
                file_record.status = "failed"
                file_record.error_message = str(e)
                db.session.commit()
                print(f"[APP] Analysis failed: {str(e)}")

                return jsonify({
                    "error": f"Analysis failed: {str(e)}",
                    "file_id": file_record.id,
                }), 500

        except Exception as e:
            print(f"[APP] File upload error: {str(e)}")
            return jsonify({"error": f"Failed to save file: {str(e)}"}), 500

    @app.route("/api/analyses", methods=["GET"])
    @jwt_required()
    def list_analyses():
        """
        List all analyses for current user.

        Query params:
            - page: int (default: 1)
            - per_page: int (default: 10)

        Returns:
            200: List of analyses
        """
        user_id = int(get_jwt_identity())
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 10, type=int)

        # Get user's files with analyses
        files = UploadedFile.query.filter_by(user_id=user_id).order_by(
            UploadedFile.uploaded_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)

        analyses = []
        for file in files.items:
            if file.analysis:
                analyses.append({
                    "file": file.to_dict(),
                    "analysis": file.analysis.to_dict(include_details=False),
                })

        return jsonify({
            "analyses": analyses,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": files.total,
                "pages": files.pages,
            },
        }), 200

    @app.route("/api/analyses/<int:analysis_id>", methods=["GET"])
    @jwt_required()
    def get_analysis(analysis_id):
        """
        Get full analysis result.

        Returns:
            200: Full analysis details
            404: Analysis not found
        """
        user_id = int(get_jwt_identity())

        # Get analysis and verify user owns it
        analysis = AnalysisResult.query.filter_by(id=analysis_id).first()

        if not analysis:
            return jsonify({"error": "Analysis not found"}), 404

        if analysis.file.user_id != user_id:
            return jsonify({"error": "Unauthorized"}), 403

        # Flatten response to match frontend expectations
        analysis_data = analysis.to_dict(include_details=True)
        analysis_data["filename"] = analysis.file.original_filename

        return jsonify(analysis_data), 200

    @app.route("/api/analyses/<int:analysis_id>/logs", methods=["GET"])
    @jwt_required()
    def get_analysis_logs(analysis_id):
        """
        Get parsed log entries for an analysis.

        Query params:
            - page: int (default: 1)
            - per_page: int (default: 50)
            - anomaly_only: bool (default: false)

        Returns:
            200: Paginated log entries
            404: Analysis not found
        """
        user_id = int(get_jwt_identity())
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 50, type=int)
        anomaly_only = request.args.get("anomaly_only", "false").lower() == "true"

        # Get analysis and verify ownership
        analysis = AnalysisResult.query.filter_by(id=analysis_id).first()

        if not analysis:
            return jsonify({"error": "Analysis not found"}), 404

        if analysis.file.user_id != user_id:
            return jsonify({"error": "Unauthorized"}), 403

        # Read and parse log file
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], analysis.file.filename)

        if not os.path.exists(filepath):
            return jsonify({"error": "Log file not found"}), 404

        try:
            with open(filepath, "r") as f:
                content = f.read()

            entries = parse_log_file(content)

            # Filter to anomalies only if requested
            if anomaly_only and analysis.anomalies:
                anomaly_indices = set()
                for anomaly in analysis.anomalies:
                    anomaly_indices.update(anomaly.get("affected_entries", []))
                entries = [e for i, e in enumerate(entries) if i in anomaly_indices]

            # Paginate
            total = len(entries)
            start = (page - 1) * per_page
            end = start + per_page
            page_entries = entries[start:end]

            return jsonify({
                "logs": page_entries,
                "total": total,
                "page": page,
                "per_page": per_page,
            }), 200

        except Exception as e:
            print(f"[APP] Error reading logs: {str(e)}")
            return jsonify({"error": f"Failed to read logs: {str(e)}"}), 500

    @app.route("/api/contact", methods=["POST"])
    @jwt_required()
    def contact_form():
        """Handle contact form submissions."""
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        name = data.get("name", "").strip()
        email = data.get("email", "").strip()
        subject = data.get("subject", "").strip()
        priority = data.get("priority", "medium").strip()
        message = data.get("message", "").strip()

        if not name or not email or not message:
            return jsonify({"error": "Name, email, and message are required"}), 400

        # Log the contact submission (in production, send email)
        print(f"[CONTACT] New submission from {name} ({email})")
        print(f"[CONTACT] Subject: {subject} | Priority: {priority}")
        print(f"[CONTACT] Message: {message[:200]}")

        return jsonify({
            "message": "Thank you for contacting us! Our team will respond within 24 hours.",
            "ticket_id": f"SEC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        }), 200

    @app.route("/api/account/stats", methods=["GET"])
    @jwt_required()
    def account_stats():
        """Get account statistics."""
        user_id = int(get_jwt_identity())
        total_analyses = AnalysisResult.query.join(UploadedFile).filter(
            UploadedFile.user_id == user_id
        ).count()
        files_uploaded = UploadedFile.query.filter_by(user_id=user_id).count()

        return jsonify({
            "total_analyses": total_analyses,
            "files_uploaded": files_uploaded,
            "account_type": "Professional",
            "last_active": datetime.utcnow().isoformat()
        }), 200

    # ── Static file serving (production) ────────────────────────────────
    # In production (Render), the backend also serves frontend files.
    # In local development, the separate frontend server (serve.py) is used.
    FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
    FRONTEND_DIR = os.path.abspath(FRONTEND_DIR)

    def _serve_file(filepath):
        """Read a file and return a Response with correct MIME type."""
        if not os.path.isfile(filepath):
            return None
        # Security: ensure file is within frontend directory
        real_path = os.path.realpath(filepath)
        if not real_path.startswith(os.path.realpath(FRONTEND_DIR)):
            return None
        mime_type, _ = mimetypes.guess_type(filepath)
        if mime_type is None:
            mime_type = "application/octet-stream"
        with open(filepath, "rb") as f:
            data = f.read()
        return Response(data, status=200, headers={"Content-Type": mime_type})

    @app.route("/", methods=["GET"])
    def serve_index():
        """Serve the landing page."""
        result = _serve_file(os.path.join(FRONTEND_DIR, "index.html"))
        if result:
            return result
        return jsonify({"status": "ok", "service": "Secure Lens AI"}), 200

    @app.route("/css/<path:filename>", methods=["GET"])
    def serve_css(filename):
        """Serve CSS files."""
        result = _serve_file(os.path.join(FRONTEND_DIR, "css", filename))
        if result:
            return result
        return jsonify({"error": "Not found"}), 404

    @app.route("/js/<path:filename>", methods=["GET"])
    def serve_js(filename):
        """Serve JavaScript files."""
        result = _serve_file(os.path.join(FRONTEND_DIR, "js", filename))
        if result:
            return result
        return jsonify({"error": "Not found"}), 404

    @app.route("/images/<path:filename>", methods=["GET"])
    def serve_images(filename):
        """Serve image files."""
        result = _serve_file(os.path.join(FRONTEND_DIR, "images", filename))
        if result:
            return result
        return jsonify({"error": "Not found"}), 404

    @app.route("/<path:filename>", methods=["GET"])
    def serve_frontend(filename):
        """Serve frontend HTML and other static files."""
        # Try exact file first
        filepath = os.path.join(FRONTEND_DIR, filename)
        result = _serve_file(filepath)
        if result:
            return result
        # Try with .html extension (e.g. /login -> login.html)
        if "." not in filename:
            result = _serve_file(filepath + ".html")
            if result:
                return result
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors."""
        return jsonify({"error": "Endpoint not found"}), 404

    @app.errorhandler(500)
    def server_error(error):
        """Handle 500 errors."""
        return jsonify({"error": "Internal server error"}), 500

    return app


def _allowed_file(filename: str, allowed_extensions: set) -> bool:
    """Check if file extension is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def _analyze_file(filepath: str, file_record: UploadedFile) -> AnalysisResult:
    """
    Analyze a log file and create analysis result.

    Args:
        filepath: Path to log file
        file_record: UploadedFile database record

    Returns:
        AnalysisResult database record

    Raises:
        Exception: If analysis fails
    """
    # Read file
    with open(filepath, "r") as f:
        content = f.read()

    print(f"[ANALYSIS] Parsing file: {filepath}")

    # Parse logs
    entries = parse_log_file(content)
    print(f"[ANALYSIS] Parsed {len(entries)} entries")

    # Run rule engine
    rule_engine = RuleEngine()
    anomalies, stats = rule_engine.analyze(entries)
    print(f"[ANALYSIS] Rule engine found {len(anomalies)} anomalies")

    # Enrich with MITRE mappings
    anomalies = map_anomalies_to_mitre(anomalies)
    mitre_summary = get_mitre_summary(anomalies)

    # Run AI analysis
    ai_result = analyze_with_ai(anomalies, entries, stats)
    print(f"[ANALYSIS] AI analysis complete (enabled: {ai_result.get('ai_enabled')})")

    # Create analysis record
    analysis = AnalysisResult(
        file_id=file_record.id,
        summary=ai_result.get("executive_summary", ""),
        total_events=len(entries),
        anomaly_count=len(anomalies),
        risk_score=ai_result.get("risk_score", 0),
        timeline_data=ai_result.get("timeline", []),
        anomalies=anomalies,
        mitre_mappings=mitre_summary,
        stats={
            **stats,
            "ai_enabled": ai_result.get("ai_enabled", False),
            "risk_assessment": ai_result.get("risk_assessment", ""),
            "recommendations": ai_result.get("recommendations", []),
            "additional_findings": ai_result.get("additional_findings", ""),
        },
    )

    db.session.add(analysis)

    # Update file record
    file_record.status = "completed"

    db.session.commit()
    print(f"[ANALYSIS] Analysis record created: {analysis.id}")

    return analysis


def _seed_demo_user():
    """Create demo user if it doesn't exist."""
    if User.query.filter_by(username="admin").first():
        return

    user = User(username="admin")
    user.set_password("admin123")
    db.session.add(user)
    db.session.commit()
    print("[APP] Demo user created: admin / admin123")


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, host="0.0.0.0", port=5000)
