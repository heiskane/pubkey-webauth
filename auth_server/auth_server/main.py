from base64 import b64encode

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


@app.get("/challenge")
async def send_challenge() -> str:
    with open("test.pub", "rb") as key_file:
        public_key: rsa.RSAPublicKey = serialization.load_ssh_public_key(
            key_file.read(),
        )
        encrypted_challenge = public_key.encrypt(
            b"potato is not a tomato but a potato indeed",
            padding.OAEP(
                mgf=padding.MGF1(
                    hashes.SHA256(),
                ),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        print(encrypted_challenge)
    return b64encode(encrypted_challenge).decode()


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=5000,
        log_level="info",
        reload=True,
    )
