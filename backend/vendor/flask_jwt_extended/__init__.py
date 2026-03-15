"""Flask-JWT-Extended shim using PyJWT."""

import functools
import threading
from datetime import datetime, timedelta

import jwt as pyjwt

_jwt_ctx = threading.local()


class JWTManager:
    """JWT Manager that integrates with Flask app config."""

    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        app._extensions["jwt"] = self


def create_access_token(identity, expires_delta=None):
    """Create a JWT access token."""
    from flask import _request_ctx
    app = getattr(_request_ctx, "app", None)

    if app:
        secret = app.config.get("JWT_SECRET_KEY", "default-secret")
        if expires_delta is None:
            expires_delta = app.config.get("JWT_ACCESS_TOKEN_EXPIRES", timedelta(hours=24))
    else:
        secret = "default-secret"
        if expires_delta is None:
            expires_delta = timedelta(hours=24)

    payload = {
        "sub": str(identity),
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + expires_delta,
        "type": "access",
    }

    return pyjwt.encode(payload, secret, algorithm="HS256")


def get_jwt_identity():
    """Get the identity (sub claim) from the current JWT."""
    return getattr(_jwt_ctx, "identity", None)


def jwt_required(optional=False, fresh=False, refresh=False, locations=None):
    """Decorator that requires a valid JWT on the request."""

    def wrapper(fn):
        @functools.wraps(fn)
        def decorated(*args, **kwargs):
            from flask import request, jsonify, _request_ctx

            app = getattr(_request_ctx, "app", None)
            if app:
                secret = app.config.get("JWT_SECRET_KEY", "default-secret")
            else:
                secret = "default-secret"

            auth_header = request.headers.get("Authorization", "")
            token = None

            if auth_header.startswith("Bearer "):
                token = auth_header[7:]

            if not token:
                if optional:
                    _jwt_ctx.identity = None
                    return fn(*args, **kwargs)
                return jsonify({"msg": "Missing Authorization Header"}), 401

            try:
                payload = pyjwt.decode(token, secret, algorithms=["HS256"])
                _jwt_ctx.identity = payload.get("sub")
            except pyjwt.ExpiredSignatureError:
                return jsonify({"msg": "Token has expired"}), 401
            except pyjwt.InvalidTokenError:
                return jsonify({"msg": "Invalid token"}), 401

            result = fn(*args, **kwargs)
            _jwt_ctx.identity = None
            return result

        return decorated

    # Support both @jwt_required() and @jwt_required
    if callable(optional):
        fn = optional
        optional = False
        return wrapper(fn)

    return wrapper
