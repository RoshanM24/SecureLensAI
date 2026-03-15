"""
Entry point for running the Secure Lens AI Flask application.
"""

import os
import sys

# Add vendor directory to Python path FIRST so our shims are found
vendor_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")
sys.path.insert(0, vendor_dir)

# Also ensure backend dir is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app

# Load environment variables from .env if available
# Check both backend/ and project root for .env
try:
    from dotenv import load_dotenv
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(backend_dir)
    # Try project root first, then backend dir
    loaded = load_dotenv(os.path.join(project_root, ".env"))
    if not loaded:
        load_dotenv(os.path.join(backend_dir, ".env"))
except ImportError:
    # dotenv not available (e.g., pip blocked by proxy)
    # Fall back to environment variables only
    pass

if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")

    app.run(debug=True, host=host, port=port)
