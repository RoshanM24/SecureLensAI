"""
SQLAlchemy ORM models for Secure Lens AI application.
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import json

db = SQLAlchemy()


class User(db.Model):
    """User model for authentication."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    files = db.relationship("UploadedFile", backref="owner", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        """Hash and set the password."""
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256")

    def check_password(self, password):
        """Check if provided password matches hash."""
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        """Convert user to dictionary."""
        return {
            "id": self.id,
            "username": self.username,
            "created_at": self.created_at.isoformat(),
        }


class UploadedFile(db.Model):
    """Model for uploaded log files."""

    __tablename__ = "uploaded_files"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    file_size = db.Column(db.Integer, nullable=False)  # in bytes
    status = db.Column(
        db.String(50),
        default="pending",
        nullable=False,
    )  # pending, processing, completed, failed
    error_message = db.Column(db.Text, nullable=True)

    # Relationships
    analysis = db.relationship("AnalysisResult", uselist=False, backref="file", cascade="all, delete-orphan")

    def to_dict(self):
        """Convert file record to dictionary."""
        return {
            "id": self.id,
            "filename": self.filename,
            "original_filename": self.original_filename,
            "uploaded_at": self.uploaded_at.isoformat(),
            "file_size": self.file_size,
            "status": self.status,
            "error_message": self.error_message,
        }


class AnalysisResult(db.Model):
    """Model for analysis results."""

    __tablename__ = "analysis_results"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("uploaded_files.id"), nullable=False, unique=True, index=True)
    summary = db.Column(db.Text, nullable=True)
    total_events = db.Column(db.Integer, default=0)
    anomaly_count = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Float, default=0.0)

    # JSON fields stored as text
    _timeline_data = db.Column("timeline_data", db.Text, nullable=True)
    _anomalies = db.Column("anomalies", db.Text, nullable=True)
    _mitre_mappings = db.Column("mitre_mappings", db.Text, nullable=True)
    _stats = db.Column("stats", db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Properties for JSON handling
    @property
    def timeline_data(self):
        """Get timeline data as dictionary."""
        if self._timeline_data:
            return json.loads(self._timeline_data)
        return []

    @timeline_data.setter
    def timeline_data(self, value):
        """Set timeline data from dictionary."""
        self._timeline_data = json.dumps(value) if value else None

    @property
    def anomalies(self):
        """Get anomalies as dictionary."""
        if self._anomalies:
            return json.loads(self._anomalies)
        return []

    @anomalies.setter
    def anomalies(self, value):
        """Set anomalies from dictionary."""
        self._anomalies = json.dumps(value) if value else None

    @property
    def mitre_mappings(self):
        """Get MITRE mappings as dictionary."""
        if self._mitre_mappings:
            return json.loads(self._mitre_mappings)
        return {}

    @mitre_mappings.setter
    def mitre_mappings(self, value):
        """Set MITRE mappings from dictionary."""
        self._mitre_mappings = json.dumps(value) if value else None

    @property
    def stats(self):
        """Get statistics as dictionary."""
        if self._stats:
            return json.loads(self._stats)
        return {}

    @stats.setter
    def stats(self, value):
        """Set statistics from dictionary."""
        self._stats = json.dumps(value) if value else None

    def to_dict(self, include_details=True):
        """Convert analysis result to dictionary."""
        data = {
            "id": self.id,
            "file_id": self.file_id,
            "summary": self.summary,
            "total_events": self.total_events,
            "anomaly_count": self.anomaly_count,
            "risk_score": self.risk_score,
            "created_at": self.created_at.isoformat(),
        }
        if include_details:
            data.update({
                "timeline_data": self.timeline_data,
                "anomalies": self.anomalies,
                "mitre_mappings": self.mitre_mappings,
                "stats": self.stats,
            })
        return data
