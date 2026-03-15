"""
Flask application configuration.
Loads settings from environment variables with sensible defaults.
"""

import os
from datetime import timedelta


class Config:
    """Base configuration."""

    # Database
    # For Render: set DATABASE_URL to "sqlite:////var/data/securelensai.db"
    # For local development: uses backend/securelensai.db
    if os.environ.get("DATABASE_URL"):
        SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    else:
        db_path = os.path.join(os.path.dirname(__file__), 'securelensai.db')
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT Authentication
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "securelensai-dev-secret-key-change-in-production")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)

    # OpenAI API
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", None)

    # File Upload
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB max file size
    ALLOWED_EXTENSIONS = {"txt", "csv", "json", "log"}

    # Flask Environment
    FLASK_ENV = os.environ.get("FLASK_ENV", "development")
    DEBUG = FLASK_ENV == "development"

    # CORS
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(",")

    # Application
    JSON_SORT_KEYS = False


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


# Configuration factory
def get_config():
    """Get configuration based on FLASK_ENV."""
    env = os.environ.get("FLASK_ENV", "development").lower()
    if env == "production":
        return ProductionConfig
    elif env == "testing":
        return TestingConfig
    else:
        return DevelopmentConfig
