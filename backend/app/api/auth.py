"""Własny profil i wylogowanie. Logowanie odbywa się w Keycloaku (OIDC z PKCE)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel

from app.api.deps import SessionDep
from app.core import audit
from app.iam.deps import (
    SESSION_TTL_SECONDS,
    SessionRegistry,
    authenticated,
    get_session_registry,
)
from app.iam.tokens import Principal

router = APIRouter(prefix="/api", tags=["tożsamość"])
CurrentPrincipal = Annotated[Principal, Depends(authenticated())]


class MeOut(BaseModel):
    username: str
    display_name: str
    email: str
    kind: str
    roles: list[str]
    permissions: list[str]
    mfa: bool
    client_id: str


@router.get("/me", response_model=MeOut)
def me(principal: CurrentPrincipal) -> MeOut:
    """Kim jestem i co mogę. Interfejs ukrywa na tej podstawie przyciski; o dostępie i tak
    decyduje backend przy każdym wywołaniu."""
    return MeOut(
        username=principal.username,
        display_name=principal.display_name,
        email=principal.email,
        kind=principal.kind,
        roles=sorted(principal.roles),
        permissions=sorted(principal.permissions),
        mfa=principal.mfa,
        client_id=principal.client_id,
    )


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    principal: CurrentPrincipal,
    request: Request,
    session: SessionDep,
    registry: Annotated[SessionRegistry, Depends(get_session_registry)],
) -> None:
    """Unieważnia sesję w API od razu, także dla tokenów, które jeszcze nie wygasły.
    Sesję w Keycloaku kończy interfejs przekierowaniem na `end_session_endpoint`."""
    if principal.session_id:
        registry.revoke(principal.session_id, SESSION_TTL_SECONDS)
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action="logout",
            reason="Wylogowanie",
            inputs={"client": principal.client_id, "session": principal.session_id},
            object_type="user",
            object_id=principal.subject,
        ),
    )
