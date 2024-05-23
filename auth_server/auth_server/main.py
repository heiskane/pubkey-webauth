import secrets
from base64 import b64decode, b64encode
from typing import Annotated, Any, Optional
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
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.status import (
    HTTP_401_UNAUTHORIZED,
    HTTP_404_NOT_FOUND,
    HTTP_409_CONFLICT,
    HTTP_422_UNPROCESSABLE_ENTITY,
)

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
    challenge: Mapped[Optional[bytes]]


# TODO: keys table for multiple pubkeys


class UserRegister(BaseModel):
    username: str
    pubkey: bytes


class AuthRequest(BaseModel):
    decrypted_challenge: str


# engine = create_engine("sqlite+pysqlite:///:memory:", echo=True)
# TODO: async postgres?
engine = create_engine("postgresql://postgres:postgres@postgres/postgres", echo=True)
Base.metadata.create_all(engine)

sessionfactory = sessionmaker(engine)


def get_db_session() -> Session:
    session = sessionfactory()

    try:
        return session
    finally:
        session.commit()
        session.close()


def get_redis_client() -> Redis:
    return redis.Redis(
        host="redis",
        port=6379,
        decode_responses=True,
    )


def require_auth(
    auth_token: Annotated[str | None, Cookie()] = None,
    redis_client: Redis = Depends(get_redis_client),
    db_session: Session = Depends(get_db_session),
) -> User:
    if auth_token is None:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED)

    user_id = redis_client.get(auth_token)

    if user_id is None:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED)

    assert isinstance(user_id, str)
    user = db_session.execute(
        select(User).where(User.id == UUID(user_id))
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
    db_session: Session = Depends(get_db_session),
) -> UUID:
    user = db_session.execute(
        select(User).where(User.name == user_register.username)
    ).scalar_one_or_none()

    if user is not None:
        raise HTTPException(status_code=HTTP_409_CONFLICT, detail="username taken")

    try:
        print(user_register.pubkey)
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
    db_session.commit()
    db_session.refresh(db_user)
    return db_user.id


@app.get("/auth/{username}/challenge")
async def send_challenge(
    username: str,
    session: Session = Depends(get_db_session),
) -> str:
    stmt = select(User).where(User.name == username)
    user = session.execute(stmt).scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND)

    challenge = secrets.token_bytes(128)

    user.challenge = challenge
    session.add(user)
    session.commit()

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
    db_session: Session = Depends(get_db_session),
    redis_client: Redis = Depends(get_redis_client),
) -> str:
    stmt = select(User).where(User.name == username)
    user = db_session.execute(stmt).scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND)

    if b64decode(auth_request.decrypted_challenge) == user.challenge:
        auth_token = uuid4()

        # TODO: configure TTL somewhere else
        redis_client.set(auth_token.hex, str(user.id), ex=3600)
        response.set_cookie("auth_token", auth_token.hex, secure=False, max_age=3600)
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
