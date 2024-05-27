from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    auth_challenge_ttl_seconds: int = 60 * 5  # 5min
    auth_token_ttl_seconds: int = 60 * 60  # 1h

    db_url: str = "postgresql+asyncpg://postgres:postgres@postgres/postgres"
    db_echo: bool = True


settings = Settings()
