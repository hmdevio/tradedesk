"""Configurable SMTP delivery for account verification messages."""

from email.message import EmailMessage
from urllib.parse import quote
import smtplib
import ssl

from app.config import get_settings


def _build_link(fragment_key: str, token: str) -> str:
    """Build an app link that carries the token in the URL fragment.

    The configured application URL is used rather than the incoming Host
    header. The fragment keeps the token out of normal HTTP requests.
    """
    settings = get_settings()
    return (
        settings.app_base_url.rstrip("/")
        + f"/#{fragment_key}="
        + quote(token, safe="")
    )


def send_verification_email(recipient: str, token: str) -> None:
    """Send an email verification link using configured SMTP settings."""
    link = _build_link("verify", token)
    _send_email(
        recipient,
        "Verify your TradeDesk email",
        "Verify your TradeDesk email address by opening this link:\n"
        + link
        + "\n\nIf you did not create this account, you can ignore this message.",
    )


def send_password_reset_email(recipient: str, token: str) -> None:
    """Send a single-use password reset link."""
    settings = get_settings()
    link = _build_link("reset", token)
    _send_email(
        recipient,
        "Reset your TradeDesk password",
        "A password reset was requested for your TradeDesk account.\n"
        "Open this link to choose a new password:\n"
        + link
        + f"\n\nThe link expires in {settings.password_reset_minutes} minutes "
        "and can be used once. If you did not request this, you can ignore "
        "this message; your password has not changed.",
    )


def send_existing_account_email(recipient: str, token: str) -> None:
    """Tell the address owner an account exists and offer a setup link.

    Sent when someone registers an email that already has an account. The
    link is a password reset link: opening it proves control of the inbox.
    """
    settings = get_settings()
    link = _build_link("reset", token)
    _send_email(
        recipient,
        "Your TradeDesk account",
        "Someone tried to create a TradeDesk account with this email "
        "address, but an account already exists for it.\n\n"
        "If that was you, open this link to choose your password and "
        "finish setting up your account:\n"
        + link
        + f"\n\nThe link expires in {settings.password_reset_minutes} minutes "
        "and can be used once. If this wasn't you, you can ignore this "
        "message; nothing on the account has changed.",
    )


def _send_email(recipient: str, subject: str, body: str) -> None:
    """Send a plain-text message using the configured SMTP settings."""
    settings = get_settings()

    is_production = (
        settings.environment.strip().lower() == "production"
    )

    # Email delivery must never silently succeed when SMTP is missing.
    # Development and test environments may start without SMTP configured,
    # but sending an email requires an actual configured SMTP server.
    if not settings.smtp_host or not settings.smtp_from_email:
        raise RuntimeError(
            "Email delivery is not configured"
        )

    # Prevent conflicting SMTP encryption configurations.
    if settings.smtp_use_ssl and settings.smtp_use_starttls:
        raise RuntimeError(
            "Configure either SMTP implicit TLS or STARTTLS, not both"
        )

    # Production email must always use encrypted transport.
    if is_production and not (
        settings.smtp_use_ssl or settings.smtp_use_starttls
    ):
        raise RuntimeError(
            "Production SMTP requires encrypted transport"
        )

    # SMTP authentication requires both a username and a password,
    # or neither when the SMTP server does not require authentication.
    if bool(settings.smtp_username) != bool(settings.smtp_password):
        raise RuntimeError(
            "SMTP username and password must be configured together"
        )

    # Never send SMTP authentication credentials over an unencrypted
    # connection.
    if settings.smtp_username and not (
        settings.smtp_use_ssl or settings.smtp_use_starttls
    ):
        raise RuntimeError(
            "SMTP authentication requires SSL or STARTTLS"
        )

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from_email
    message["To"] = recipient
    message.set_content(body)

    # Use the system's trusted certificate authorities to verify the SMTP server.
    context = ssl.create_default_context()

    if settings.smtp_use_ssl:
        # Implicit TLS: encryption starts when the SMTP connection opens.
        with smtplib.SMTP_SSL(
            settings.smtp_host,
            settings.smtp_port,
            timeout=10,
            context=context,
        ) as server:
            if settings.smtp_username:
                server.login(
                    settings.smtp_username,
                    settings.smtp_password,
                )

            server.send_message(message)

    else:
        # STARTTLS: establish SMTP connection, then upgrade it to TLS.
        with smtplib.SMTP(
            settings.smtp_host,
            settings.smtp_port,
            timeout=10,
        ) as server:
            if settings.smtp_use_starttls:
                server.starttls(context=context)

            if settings.smtp_username:
                server.login(
                    settings.smtp_username,
                    settings.smtp_password,
                )

            server.send_message(message)
