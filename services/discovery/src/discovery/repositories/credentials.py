"""Credential repository — VC metadata lookup and status updates."""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.db.models.credentials import Credential


class CredentialRepository:
    @staticmethod
    async def get_by_jti(
        session: AsyncSession, jti: str
    ) -> Credential | None:
        result = await session.execute(
            select(Credential).where(Credential.jti == jti)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_active_by_subject(
        session: AsyncSession, subject_did: str, env: str
    ) -> list[Credential]:
        result = await session.execute(
            select(Credential).where(
                Credential.subject_did == subject_did,
                Credential.env == env,
                Credential.is_latest.is_(True),
            )
        )
        return list(result.scalars().all())

    @staticmethod
    async def create(session: AsyncSession, credential: Credential) -> Credential:
        session.add(credential)
        await session.flush()
        await session.refresh(credential)
        return credential

    @staticmethod
    async def update_status(
        session: AsyncSession,
        credential_id: uuid.UUID,
        new_status: str,
    ) -> Credential | None:
        result = await session.execute(
            select(Credential).where(Credential.id == credential_id)
        )
        cred = result.scalar_one_or_none()
        if cred is not None:
            cred.status = new_status
            await session.flush()
        return cred
