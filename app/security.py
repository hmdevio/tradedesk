"""Password hashing and short-lived, session-bound bearer tokens."""
from datetime import datetime
from uuid import UUID

import jwt
from pwdlib import PasswordHash

from app.config import get_settings

password_hasher = PasswordHash.recommended()
settings = get_settings()
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    """Hash a password with the recommended Argon2 configuration."""
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password without exposing whether the email exists."""
    try:
        return password_hasher.verify(password, password_hash)
    except Exception:
        # Malformed hashes should fail closed instead of crashing login.
        return False


def create_access_token(user_id: int, session_id: str, expires_at: datetime) -> str:
    """Create a JWT tied to a persisted, revocable server-side session."""
    payload = {
        "sub": str(user_id),
        "jti": str(UUID(session_id)),
        "iat": datetime.now(expires_at.tzinfo),
        "exp": expires_at,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
