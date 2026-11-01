"""Configurable SMTP delivery for account verification messages."""
from email.message import EmailMessage
from urllib.parse import quote
import smtplib
import ssl

from app.config import get_settings


def send_verification_email(recipient: str, token: str) -> None:
    """Send a verification link using explicitly configured SMTP settings."""
    settings = get_settings()
    if not settings.smtp_host or not settings.smtp_from_email:
        if settings.environment == "production":
            raise RuntimeError("Email delivery is not configured")
        return
    if settings.smtp_use_ssl and settings.smtp_use_starttls:
        raise RuntimeError("Configure either SMTP implicit TLS or STARTTLS, not both")
    link = settings.app_base_url.rstrip("/") + "/?verify=" + quote(token, safe="")
    message = EmailMessage()
    message["Subject"] = "Verify your TradeDesk email"
    message["From"] = settings.smtp_from_email
    message["To"] = recipient
    message.set_content(
        "Verify your TradeDesk email address by opening this link:\n"
        + link
        + "\n\nIf you did not create this account, you can ignore this message."
    )
    context = ssl.create_default_context()
    if settings.smtp_use_ssl:
        with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=10, context=context) as server:
            if settings.smtp_username:
                server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(message)
    else:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
            if settings.smtp_use_starttls:
                server.starttls(context=context)
            if settings.smtp_username:
                server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(message)
