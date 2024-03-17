import secrets
from base64 import b64decode, b64encode
from uuid import UUID

import uuid6
import uvicorn
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.status import HTTP_404_NOT_FOUND

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

with open("test.pub", "rb") as key_file:
    raw_pub_key = key_file.read()


class Base(DeclarativeBase):
    ...


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid6.uuid7)
    name: Mapped[str] = mapped_column(unique=True)
    pubkey: Mapped[bytes]
    challenge: Mapped[bytes]


class AuthRequest(BaseModel):
    decrypted_challenge: str


engine = create_engine("sqlite+pysqlite:///:memory:", echo=True)
Base.metadata.create_all(engine)

sessionfactory = sessionmaker(engine)


def get_session() -> Session:
    session = sessionfactory()

    try:
        return session
    finally:
        session.commit()
        session.close()


with sessionfactory() as session:
    session.add(
        User(
            id=UUID("018e4b5d-9d6b-7288-bbbe-0c81e76a6a11"),
            name="bob",
            pubkey=raw_pub_key,
            challenge=secrets.token_bytes(128),
        )
    )
    session.commit()


# TODO: take user email instead
@app.get("/auth/{user_id}/challenge")
async def send_challenge(
    user_id: UUID,
    session: Session = Depends(get_session),
) -> str:
    stmt = select(User).where(User.id == user_id)
    user = session.execute(stmt).scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND)

    challenge = secrets.token_bytes(128)

    user.challenge = challenge
    session.add(user)
    session.commit()

    public_key = serialization.load_ssh_public_key(raw_pub_key)
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


# TODO: take user email instead
@app.post("/auth/{user_id}")
async def auth(
    user_id: UUID,
    auth_request: AuthRequest,
) -> bool:
    stmt = select(User).where(User.id == user_id)
    user = session.execute(stmt).scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND)

    if b64decode(auth_request.decrypted_challenge) == user.challenge:
        return True

    return False


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=5000,
        log_level="info",
        reload=True,
    )
