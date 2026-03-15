"""
Authentication blueprint for user registration and login.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from models import db, User

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Register a new user.

    Request JSON:
        - username: str (required)
        - password: str (required)

    Returns:
        201: User created successfully
        400: Missing fields or validation error
        409: User already exists
    """
    data = request.get_json()

    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Missing username or password"}), 400

    username = data.get("username").strip()
    password = data.get("password")

    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    # Check if user already exists
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 409

    # Create new user
    user = User(username=username)
    user.set_password(password)

    try:
        db.session.add(user)
        db.session.commit()
        print(f"[AUTH] New user registered: {username}")
        return jsonify({"message": "User created successfully", "user": user.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        print(f"[AUTH] Registration error: {str(e)}")
        return jsonify({"error": "Failed to create user"}), 500


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate user and return JWT token.

    Request JSON:
        - username: str (required)
        - password: str (required)

    Returns:
        200: Login successful with access_token
        400: Missing credentials
        401: Invalid credentials
    """
    data = request.get_json()

    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Missing username or password"}), 400

    username = data.get("username").strip()
    password = data.get("password")

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        print(f"[AUTH] Failed login attempt for user: {username}")
        return jsonify({"error": "Invalid username or password"}), 401

    # Create JWT token
    access_token = create_access_token(identity=str(user.id))
    print(f"[AUTH] User logged in: {username}")

    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "user": user.to_dict(),
    }), 200


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_current_user():
    """
    Get current authenticated user info.

    Requires: JWT token in Authorization header

    Returns:
        200: User information
        401: Unauthorized
    """
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify(user.to_dict()), 200
