#!/bin/bash
# Start Secure Lens AI Flask Backend
# This script sets the PYTHONPATH to include the venv site-packages
# and starts the Flask development server

cd "$(dirname "$0")"

export PYTHONPATH="$(pwd)/venv/lib/python3.9/site-packages:$PYTHONPATH"

echo "========================================"
echo "Secure Lens AI Backend Server"
echo "========================================"
echo "PYTHONPATH set to: $PYTHONPATH"
echo ""
echo "Starting Flask server..."
echo "Server will run on: http://localhost:5000"
echo "Press Ctrl+C to stop"
echo ""

python run.py
