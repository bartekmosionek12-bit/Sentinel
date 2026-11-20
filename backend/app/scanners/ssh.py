"""Skan uwierzytelniony (L2): lista pakietów przez SSH z certyfikatem JIT, tylko odczyt.

Klucz prywatny powstaje w pamięci na jedno połączenie i nie jest nigdzie zapisywany. Na
hoście wykonuje się wyłącznie polecenie z listy (bez powłoki interaktywnej, bez sudo).
Klucz hosta musi być znany (`known_hosts`), inaczej połączenie jest odrzucane.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import paramiko

from app.core.scope_guard import Intrusiveness, ScopedTarget
from app.scanners.runner import ToolError

# Polecenia tylko do odczytu; pierwsze, które zadziała, wygrywa.
PACKAGE_COMMANDS = (
    ("dpkg", "dpkg-query -W -f='${Package}\\t${Version}\\n'"),
    ("apk", "apk info -v"),
    ("rpm", "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'"),
)
MAX_OUTPUT = 1_000_000


@dataclass(frozen=True)
class Package:
    name: str
    version: str


def parse_packages(manager: str, output: str) -> list[Package]:
    packages = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if manager == "apk":
            # nginx-1.24.0-r7 → nginx, 1.24.0-r7
            parts = line.rsplit("-", 2)
            if len(parts) == 3:
                packages.append(Package(parts[0], f"{parts[1]}-{parts[2]}"))
            continue
        name, _, version = line.partition("\t")
        if name and version:
            packages.append(Package(name.strip(), version.strip()))
    return packages


class SshSession(Protocol):
    def run(self, command: str) -> tuple[int, str]: ...

    def close(self) -> None: ...


class SshConnector(Protocol):
    def connect(
        self, target: ScopedTarget, *, username: str, private_key: object, certificate: str
    ) -> SshSession: ...


class ParamikoSession:
    def __init__(self, client: paramiko.SSHClient) -> None:
        self._client = client

    def run(self, command: str) -> tuple[int, str]:
        _, stdout, _ = self._client.exec_command(command, timeout=60)
        output = stdout.read(MAX_OUTPUT).decode("utf-8", "replace")
        return stdout.channel.recv_exit_status(), output

    def close(self) -> None:
        self._client.close()


class ParamikoConnector:
    def __init__(self, known_hosts: Path, port: int = 22) -> None:
        self._known_hosts = known_hosts
        self._port = port

    def connect(
        self, target: ScopedTarget, *, username: str, private_key: object, certificate: str
    ) -> SshSession:
        if not isinstance(private_key, paramiko.PKey):
            raise ToolError("ssh: nieprawidłowy klucz")
        private_key.load_certificate(certificate)
        client = paramiko.SSHClient()
        if self._known_hosts.exists():
            client.load_host_keys(str(self._known_hosts))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(
                target.address,
                port=self._port,
                username=username,
                pkey=private_key,
                allow_agent=False,
                look_for_keys=False,
                timeout=10,
                auth_timeout=10,
            )
        except (paramiko.SSHException, OSError) as error:
            client.close()
            raise ToolError(f"ssh: {error.__class__.__name__}") from error
        return ParamikoSession(client)


def new_keypair() -> tuple[object, str]:
    """Para kluczy Ed25519 w pamięci: (klucz prywatny paramiko, klucz publiczny OpenSSH)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    import io

    private = paramiko.Ed25519Key.from_private_key(io.StringIO(pem.decode()))
    public = f"{private.get_name()} {private.get_base64()}"
    return private, public


def collect_packages(session: SshSession) -> tuple[str, list[Package]]:
    for manager, command in PACKAGE_COMMANDS:
        code, output = session.run(command)
        if code == 0 and output.strip():
            return manager, parse_packages(manager, output)
    raise ToolError("ssh: nie udało się odczytać listy pakietów")


def check_level(target: ScopedTarget) -> None:
    if not isinstance(target, ScopedTarget):
        raise TypeError("Skan uwierzytelniony przyjmuje wyłącznie ScopedTarget")
    if target.intrusiveness < Intrusiveness.INTRUSIVE:
        raise ToolError("Skan uwierzytelniony wymaga poziomu L2 i zgody")
