from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    workload_jwt_public_key_path: str
    workload_jwt_issuer: str
    workload_jwt_audience: str

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


settings = Settings()