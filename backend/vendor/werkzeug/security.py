"""Werkzeug password hashing shim using hashlib."""

import hashlib
import secrets


def generate_password_hash(password, method="pbkdf2:sha256", salt_length=16):
    """Hash a password with the given method."""
    if method.startswith("pbkdf2:"):
        hash_func = method.split(":")[1] if ":" in method else "sha256"
    else:
        hash_func = "sha256"

    salt = secrets.token_hex(salt_length)
    iterations = 600000

    dk = hashlib.pbkdf2_hmac(
        hash_func,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )

    return f"pbkdf2:{hash_func}:{iterations}${salt}${dk.hex()}"


def check_password_hash(pwhash, password):
    """Check a password against a given hash."""
    try:
        method_part, rest = pwhash.split("$", 1)
        salt, hash_value = rest.split("$", 1)

        # Parse method
        parts = method_part.split(":")
        hash_func = parts[1] if len(parts) > 1 else "sha256"
        iterations = int(parts[2]) if len(parts) > 2 else 600000

        dk = hashlib.pbkdf2_hmac(
            hash_func,
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        )

        return dk.hex() == hash_value
    except (ValueError, IndexError):
        return False
