import secrets
from base64 import b64decode, b64encode
from typing import Annotated, Any
from uuid import UUID, uuid4

import redis
import uuid6
import uvicorn
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import Cookie, Depends, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from redis.client import Redis
from sqlalchemy import create_engine, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.status import (
    HTTP_401_UNAUTHORIZED,
    HTTP_404_NOT_FOUND,
    HTTP_409_CONFLICT,
    HTTP_422_UNPROCESSABLE_ENTITY,
)

from auth_server.settings import settings

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Base(DeclarativeBase): ...


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid6.uuid7)
    name: Mapped[str] = mapped_column(unique=True)
    pubkey: Mapped[bytes]


# TODO: keys table for multiple pubkeys


class UserRegister(BaseModel):
    username: str
    pubkey: bytes


class AuthRequest(BaseModel):
    decrypted_challenge: str


engine = create_async_engine(
    "postgresql+asyncpg://postgres:postgres@postgres/postgres",
    echo=settings.db_echo,
)

# TODO: create tables in sync
# Base.metadata.create_all(engine)

sessionfactory = async_sessionmaker(engine)


async def get_db_session() -> AsyncSession:
    session = sessionfactory()

    try:
        return session
    finally:
        await session.commit()
        await session.close()


def get_redis_client() -> Redis:
    return redis.Redis(host="redis", port=6379)


async def require_auth(
    auth_token: Annotated[str | None, Cookie()] = None,
    redis_client: Redis = Depends(get_redis_client),
    db_session: AsyncSession = Depends(get_db_session),
) -> User:
    if auth_token is None:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED)

    user_id = redis_client.get(f"user:{auth_token}:auth_token")

    if user_id is None:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED)

    assert isinstance(user_id, bytes)
    user = (
        await db_session.execute(select(User).where(User.id == UUID(bytes=user_id)))
    ).scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED)

    return user


@app.get("/test_auth")
async def test_auth(user: User = Depends(require_auth)) -> Any:
    print("user:", user.id, user.name)
    return None


@app.post("/users/register")
async def register_user(
    user_register: UserRegister,
    db_session: AsyncSession = Depends(get_db_session),
) -> UUID:
    user = (
        await db_session.execute(
            select(User).where(User.name == user_register.username)
        )
    ).scalar_one_or_none()

    if user is not None:
        raise HTTPException(status_code=HTTP_409_CONFLICT, detail="username taken")

    try:
        pubkey = serialization.load_ssh_public_key(user_register.pubkey)
        if not isinstance(pubkey, rsa.RSAPublicKey):
            raise HTTPException(
                status_code=HTTP_422_UNPROCESSABLE_ENTITY,
                detail="only rsa keys currently supported",
            )
    except ValueError:
        raise HTTPException(
            status_code=HTTP_422_UNPROCESSABLE_ENTITY, detail="invalid pubkey"
        )

    db_user = User(
        name=user_register.username,
        pubkey=user_register.pubkey,
    )

    db_session.add(db_user)
    await db_session.commit()
    await db_session.refresh(db_user)
    return db_user.id


@app.get("/auth/{username}/challenge")
async def send_challenge(
    username: str,
    db_session: AsyncSession = Depends(get_db_session),
    redis_client: Redis = Depends(get_redis_client),
) -> str:
    stmt = select(User).where(User.name == username)
    user = (await db_session.execute(stmt)).scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND)

    challenge = secrets.token_bytes(128)

    redis_client.set(
        f"user:{user.id}:challenge",
        challenge,
        ex=settings.auth_challenge_ttl_seconds,
    )

    public_key = serialization.load_ssh_public_key(user.pubkey)
    assert isinstance(public_key, rsa.RSAPublicKey)

    encrypted_challenge = public_key.encrypt(
        challenge,
        padding.OAEP(
            mgf=padding.MGF1(
                hashes.SHA256(),
            ),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return b64encode(encrypted_challenge).decode()


@app.post("/auth/{username}")
async def auth(
    response: Response,
    username: str,
    auth_request: AuthRequest,
    db_session: AsyncSession = Depends(get_db_session),
    redis_client: Redis = Depends(get_redis_client),
) -> str:
    stmt = select(User).where(User.name == username)
    user = (await db_session.execute(stmt)).scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND)

    challenge = redis_client.get(f"user:{user.id}:challenge")
    if b64decode(auth_request.decrypted_challenge) == challenge:
        auth_token = uuid4()

        redis_client.set(
            f"user:{auth_token.hex}:auth_token",
            user.id.bytes,
            ex=settings.auth_token_ttl_seconds,
        )

        # delete used challenge
        redis_client.delete(f"user:{user.id}:challenge")

        response.set_cookie(
            "auth_token",
            auth_token.hex,
            secure=False,
            max_age=settings.auth_token_ttl_seconds,
        )
        return auth_token.hex

    raise HTTPException(status_code=HTTP_401_UNAUTHORIZED)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        log_level="info",
        reload=True,
    )
