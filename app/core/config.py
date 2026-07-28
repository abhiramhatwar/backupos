from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://backupos:backupos@localhost:5432/backupos"
    redis_url: str = "redis://localhost:6379/0"
    secret_key: str = "super-secret-key-change-in-prod"
    cas_store_path: str = "./cas_store"
    access_token_expire_minutes: int = 60 * 24
    algorithm: str = "HS256"

    class Config:
        env_file = ".env"


settings = Settings()
