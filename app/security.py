"""Password hashing and short-lived bearer-token utilities."""
from datetime import datetime, timedelta, timezone
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


def create_access_token(user_id: int) -> str:
    """Create a signed token with a subject and expiry."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
