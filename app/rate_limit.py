"""Redis-backed rate limiting for authentication endpoints."""
from functools import lru_cache
import ipaddress

from fastapi import HTTPException, Request
from redis import Redis

from app.config import get_settings

# Redis executes this atomically, so counters are shared safely by workers.
_INCREMENT_WITH_TTL = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {count, ttl}
"""


@lru_cache(maxsize=1)
def get_redis_client() -> Redis:
    """Return one process-local connection pool; counters remain in shared Redis."""
    settings = get_settings()
    if not settings.redis_url:
        raise RuntimeError("REDIS_URL is not configured")
    return Redis.from_url(settings.redis_url, decode_responses=True, socket_connect_timeout=2, socket_timeout=2)


def client_ip(request: Request) -> str:
    """Resolve the client IP, trusting forwarded headers only from configured proxies."""
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

    forwarded = request.headers.get("x-forwarded-for", "")
    chain = []
    for value in forwarded.split(","):
        try:
            chain.append(ipaddress.ip_address(value.strip()))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid forwarded client address") from None
    # Walk from the proxy nearest the application toward the original client.
    current = peer_ip
    for candidate in reversed(chain):
        if not any(current in network for network in trusted):
            break
        current = candidate
    return str(current)


def enforce_rate_limit(request: Request, bucket: str, limit: int, window_seconds: int) -> None:
    """Enforce a fixed-window limit; production fails closed if Redis is unavailable."""
    settings = get_settings()
    if not settings.redis_url:
        if settings.environment == "production":
            raise HTTPException(status_code=503, detail="Authentication service temporarily unavailable")
        return

    key = f"tradedesk:rate-limit:{bucket}:{client_ip(request)}"
    try:
        count, ttl = get_redis_client().eval(_INCREMENT_WITH_TTL, 1, key, window_seconds)
    except Exception:
        if settings.environment == "production":
            raise HTTPException(status_code=503, detail="Authentication service temporarily unavailable") from None
        # Local development can continue when Redis has not been started.
        return

    if int(count) > limit:
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(max(int(ttl), 1))},
        )


def verify_redis_connection() -> None:
    """Fail application startup in production if the shared limiter is unavailable."""
    try:
        get_redis_client().ping()
    except Exception:
        raise RuntimeError("Redis is required and must be reachable in production") from None
