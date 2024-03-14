from base64 import b64encode, b64decode

import uvicorn
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

super_secret_challenge = b"potato is not a tomato but a potato indeed"


@app.get("/challenge")
async def send_challenge() -> str:
    with open("test.pub", "rb") as key_file:
        public_key = serialization.load_ssh_public_key(
            key_file.read(),
        )
        assert isinstance(public_key, rsa.RSAPublicKey)

    encrypted_challenge = public_key.encrypt(
        super_secret_challenge,
        padding.OAEP(
            mgf=padding.MGF1(
                hashes.SHA256(),
            ),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return b64encode(encrypted_challenge).decode()


@app.post("/auth")
async def auth(decrypted_challenge: str) -> bool:
    if b64decode(decrypted_challenge) == super_secret_challenge:
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
