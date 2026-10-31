"""FastAPI app: endpoints /analizar, /health y frontend estático."""
import logging
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

sys.path.insert(0, str(Path(__file__).resolve().parent))

import config
import meta_model
from model import classifier, huggingface_classifier
from ssrf import validar_esquema, URLNoPermitida

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("detector-phishing")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Detector Inteligente de Phishing", version="1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[config.FRONTEND_ORIGIN, "http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class AnalizarRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def url_valida(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("La URL no puede estar vacía.")
        if len(v) > 2048:
            raise ValueError("URL demasiado larga.")
        if "://" not in v:
            v = "http://" + v
        try:
            validar_esquema(v)
        except URLNoPermitida as e:
            raise ValueError(str(e))
        return v


@app.on_event("startup")
def startup():
    log.info("Cargando modelo Random Forest...")
    classifier.cargar()
    log.info("Cargando modelo de Hugging Face...")
    huggingface_classifier.cargar()
    from analyzers import llm_online
    if llm_online.disponible():
        log.info("IA online (Gemini) disponible.")
    else:
        log.info("IA online no disponible: %s", llm_online.motivo_no_disponible())


@app.get("/health")
def health():
    from analyzers import llm_online
    return {"status": "ok", "rf_disponible": classifier.disponible(),
            "hf_disponible": huggingface_classifier.disponible(),
            "llm_disponible": llm_online.disponible()}


@app.post("/analizar")
@limiter.limit("20/minute")
async def analizar(request: Request, body: AnalizarRequest):
    try:
        return await meta_model.analizar(body.url)
    except URLNoPermitida as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception:
        log.exception("Error interno en /analizar")
        return JSONResponse(status_code=500,
                            content={"error": "Error interno procesando la URL. Intenta de nuevo."})


# Frontend estático servido por el mismo backend (evita problemas de CORS/file://)
_frontend = Path(__file__).resolve().parent.parent / "frontend"
if _frontend.exists():
    app.mount("/", StaticFiles(directory=str(_frontend), html=True), name="frontend")
