"""Minimal itsdangerous shim - Flask requires this for session signing."""


class BadSignature(Exception):
    pass


class SignatureExpired(BadSignature):
    pass


class URLSafeTimedSerializer:
    def __init__(self, secret_key, salt="itsdangerous"):
        self.secret_key = secret_key
        self.salt = salt

    def dumps(self, obj):
        import json, hashlib, base64
        payload = base64.urlsafe_b64encode(json.dumps(obj).encode()).decode()
        sig = hashlib.sha256(f"{payload}{self.secret_key}{self.salt}".encode()).hexdigest()[:16]
        return f"{payload}.{sig}"

    def loads(self, s, max_age=None):
        import json, base64
        parts = s.rsplit(".", 1)
        if len(parts) != 2:
            raise BadSignature("Invalid signature")
        payload = base64.urlsafe_b64decode(parts[0]).decode()
        return json.loads(payload)
