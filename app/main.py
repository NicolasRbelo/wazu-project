from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import models  # noqa: F401  (registra as tabelas no Base)
from app.database import Base, engine
from app.routes import alertas, feedback


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="wazuh-triagem", lifespan=lifespan)
app.include_router(alertas.router)
app.include_router(feedback.router)
