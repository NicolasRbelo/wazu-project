from fastapi import APIRouter, Depends, HTTPException, status

from app import feedback
from app.schemas import FeedbackItem, UsoEntrada
from app.security import verificar_token

router = APIRouter(prefix="/api/feedback", tags=["feedback"], dependencies=[Depends(verificar_token)])


@router.get("", response_model=list[FeedbackItem])
def listar_feedback():
    """Mais recentes primeiro."""
    return sorted(feedback.carregar(), key=lambda item: item.criado_em, reverse=True)


@router.patch("/{feedback_id}", response_model=FeedbackItem)
def alterar_uso(feedback_id: str, entrada: UsoEntrada):
    """Libera um feedback da quarentena, ou devolve um exemplo para ela."""
    item = feedback.alterar_uso(feedback_id, entrada.uso)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feedback não encontrado")
    return item
