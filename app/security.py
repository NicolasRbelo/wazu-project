import hmac

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings

# auto_error=False: sem header válido o FastAPI entrega None e o 401 é nosso,
# sempre com a mesma mensagem (não diferencia "sem token" de "token errado").
bearer = HTTPBearer(auto_error=False)


def verificar_token(
    credenciais: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> None:
    esperado = settings.api_token.get_secret_value().encode()
    # compare_digest em bytes: tempo constante e sem TypeError com caracteres não ASCII.
    if credenciais is None or not hmac.compare_digest(credenciais.credentials.encode(), esperado):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou ausente",
            headers={"WWW-Authenticate": "Bearer"},
        )
