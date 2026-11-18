"""Redis-backed rate limiting for authentication endpoints."""
from functools import lru_cache
import hashlib
import hmac
import ipaddress
from urllib.parse import parse_qs, urlsplit

from fastapi import HTTPException, Request
from redis import Redis
from app.config import get_settings

_INCREMENT_WITH_TTL = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('TTL', KEYS[1])
return {count, ttl}
"""

@lru_cache(maxsize=1)
def get_redis_client() -> Redis:
    settings = get_settings()
    if not settings.redis_url:
        raise RuntimeError("REDIS_URL is not configured")
    return Redis.from_url(settings.redis_url, decode_responses=True, socket_connect_timeout=2, socket_timeout=2)


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    settings = get_settings()
    trusted = []
    for item in settings.trusted_proxy_cidrs.split(","):
        item = item.strip()
        if item:
            try:
                trusted.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                raise HTTPException(status_code=503, detail="Rate limiting proxy configuration is invalid") from None
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if not any(peer_ip in network for network in trusted):
        return str(peer_ip)
    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        return str(peer_ip)
    chain = []
    for value in forwarded.split(","):
        try:
            chain.append(ipaddress.ip_address(value.strip()))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid forwarded client address") from None
    current = peer_ip
    for candidate in reversed(chain):
        if not any(current in network for network in trusted):
            break
        current = candidate
    return str(current)


def _client_key_digest(client_address: str) -> str:
    secret = get_settings().secret_key.encode("utf-8")
    return hmac.new(secret, client_address.encode("utf-8"), hashlib.sha256).hexdigest()


def _is_production(settings) -> bool:
    # Match app/main.py and app/config.py: "Production " counts as production
    # (re-audit finding S8). An exact comparison let rate limiting fail open.
    return settings.environment.strip().lower() == "production"


def enforce_rate_limit(request: Request, bucket: str, limit: int, window_seconds: int) -> None:
    settings = get_settings()
    if not settings.redis_url:
        if _is_production(settings):
            raise HTTPException(status_code=503, detail="Authentication service temporarily unavailable")
        return
    key = f"tradedesk:rate-limit:{bucket}:{_client_key_digest(client_ip(request))}"
    try:
        count, ttl = get_redis_client().eval(_INCREMENT_WITH_TTL, 1, key, window_seconds)
    except Exception:
        if _is_production(settings):
            raise HTTPException(status_code=503, detail="Authentication service temporarily unavailable") from None
        return
    if int(count) > limit:
        raise HTTPException(status_code=429, detail="Too many requests. Please try again later.",
                            headers={"Retry-After": str(max(int(ttl), 1))})


def _validate_production_redis_url(redis_url: str) -> None:
    parsed = urlsplit(redis_url)
    cert_mode = parse_qs(parsed.query).get("ssl_cert_reqs", ["required"])[0].lower()
    if parsed.scheme != "rediss" or not parsed.hostname or not parsed.password:
        raise RuntimeError("Production REDIS_URL must use rediss:// with a hostname and password")
    if cert_mode not in {"required", "cert_required", "true"}:
        raise RuntimeError("Production Redis TLS certificate verification must remain enabled")


def verify_redis_connection() -> None:
    settings = get_settings()
    _validate_production_redis_url(settings.redis_url)
    try:
        get_redis_client().ping()
    except Exception:
        raise RuntimeError("Redis is required and must be reachable in production") from None
