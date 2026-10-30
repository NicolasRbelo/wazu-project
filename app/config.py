from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # env_ignore_empty: "CHAVE=" vazio no .env conta como não configurado.
    # extra="ignore": variável desconhecida no .env não derruba a API. O erro de
    # validação do Pydantic exibiria parte do valor, ou seja, do segredo.
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", env_ignore_empty=True, extra="ignore"
    )

    # Sem valor padrão: se o token não estiver no .env, a API nem sobe.
    api_token: SecretStr
    database_url: str = "sqlite:///./alertas.db"
    api_host: str = "127.0.0.1"
    api_port: int = 8000

    # Enriquecimento: sem chave, a fonte aparece como "nao_configurado".
    abuseipdb_api_key: SecretStr | None = None
    virustotal_api_key: SecretStr | None = None
    cache_reputacao_horas: int = 24

    # Análise por IA.
    gemini_api_key: SecretStr | None = None
    gemini_modelo: str = "gemini-2.5-flash"

    # Feedback dos analistas para a IA (fora do git: tem dados do laboratório).
    feedback_arquivo: str = "dados/feedback_ia.json"


settings = Settings()
