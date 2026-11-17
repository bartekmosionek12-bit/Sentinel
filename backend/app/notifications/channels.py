"""Kanały zewnętrzne powiadomień. Jedyny moduł powiadomień z dostępem do sieci.

Każdy kanał jest domyślnie wyłączony i działa dopiero po świadomym ustawieniu adresu
w `.env`. Webhooki łączą się wyłącznie z hostami dostawcy, bez przekierowań. Treść
zawiera nazwę zasobu i identyfikatory CVE, bez adresów IP.
"""

from __future__ import annotations

import smtplib
from collections.abc import Callable
from email.message import EmailMessage
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from app.core.config import Settings

EXTERNAL_CHANNELS = ("email", "slack", "teams")
_WEBHOOK_HOSTS = {
    "slack": ("hooks.slack.com",),
    "teams": (".webhook.office.com", ".logic.azure.com"),
}


class ChannelError(Exception):
    """Kanał jest źle skonfigurowany albo dostawca odrzucił wiadomość."""


class Sender(Protocol):
    def configured(self) -> set[str]: ...

    def send(self, channel: str, title: str, body: str) -> None: ...


def _host_allowed(channel: str, url: str) -> bool:
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme != "https":
        return False
    return any(
        host.endswith(allowed) if allowed.startswith(".") else host == allowed
        for allowed in _WEBHOOK_HOSTS[channel]
    )


class ChannelSender:
    def __init__(
        self,
        settings: Settings,
        *,
        client: httpx.Client | None = None,
        smtp_factory: Callable[[str, int], smtplib.SMTP] | None = None,
    ) -> None:
        self._settings = settings
        self._client = client
        self._smtp_factory = smtp_factory or (
            lambda host, port: smtplib.SMTP(host, port, timeout=15)
        )

    def configured(self) -> set[str]:
        settings = self._settings
        channels = set()
        if settings.smtp_host and settings.smtp_from and settings.notify_email_to:
            channels.add("email")
        if settings.slack_webhook_url:
            channels.add("slack")
        if settings.teams_webhook_url:
            channels.add("teams")
        return channels

    def send(self, channel: str, title: str, body: str) -> None:
        if channel not in self.configured():
            raise ChannelError(f"Kanał {channel} nie jest skonfigurowany")
        if channel == "email":
            self._email(title, body)
        else:
            url = (
                self._settings.slack_webhook_url
                if channel == "slack"
                else self._settings.teams_webhook_url
            )
            self._webhook(channel, url, f"{title}\n{body}")

    def _webhook(self, channel: str, url: str, text: str) -> None:
        if not _host_allowed(channel, url):
            raise ChannelError(f"Adres webhooka {channel} nie należy do hostów dostawcy")
        client = self._client or httpx.Client(timeout=15, follow_redirects=False)
        try:
            response = client.post(url, json={"text": text})
        except httpx.HTTPError as error:
            raise ChannelError(
                f"{channel}: błąd połączenia ({error.__class__.__name__})"
            ) from error
        finally:
            if self._client is None:
                client.close()
        if response.status_code >= 300:
            raise ChannelError(f"{channel}: odpowiedź HTTP {response.status_code}")

    def _email(self, title: str, body: str) -> None:
        settings = self._settings
        message = EmailMessage()
        message["Subject"] = f"[Sentinel ASI] {title}"
        message["From"] = settings.smtp_from
        message["To"] = settings.notify_email_to
        message.set_content(body)
        try:
            with self._smtp_factory(settings.smtp_host, settings.smtp_port) as smtp:
                smtp.starttls()
                if settings.smtp_user:
                    smtp.login(settings.smtp_user, settings.smtp_password)
                smtp.send_message(message)
        except (smtplib.SMTPException, OSError) as error:
            raise ChannelError(f"email: {error.__class__.__name__}") from error
