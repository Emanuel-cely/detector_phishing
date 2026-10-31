"""IA online (Google AI Studio / Gemini, free tier) para verificar existencia y
suplantación de marca comparando la URL dada con el dominio oficial.

Diseño defensivo de cuota:
  - Si el proveedor responde 429 / RESOURCE_EXHAUSTED, se activa un "circuit breaker"
    y NO se vuelven a hacer consultas en esta ejecución (evita llegar a facturación).
  - Tope local diario configurable (LLM_MAX_DIA).
  - Caché por URL para no repetir consultas.
  - Si el modelo configurado ya no está disponible (404), se prueban modelos de respaldo.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import date

import requests

import config

_TIMEOUT = 20
_CACHE: dict[str, tuple[float, "ResultadoLLM"]] = {}
_CACHE_TTL = 3600

# Si el modelo configurado deja de existir, se intentan estos (por orden de latencia).
_MODELOS_RESPALDO = ["gemini-3.5-flash", "gemini-flash-latest", "gemini-3.1-flash-lite"]

_agotado = False
_dia = date.today()
_contador_dia = 0


@dataclass
class ResultadoLLM:
    fuente: str = "gemini"
    score: float = 0.5
    detalle: dict = field(default_factory=dict)
    razon: str = ""
    error: str | None = None


def _reiniciar_dia_si_cambia() -> None:
    global _dia, _contador_dia
    if date.today() != _dia:
        _dia = date.today()
        _contador_dia = 0


def disponible() -> bool:
    _reiniciar_dia_si_cambia()
    return bool(
        config.LLM_ENABLED
        and config.GEMINI_API_KEY
        and not config.GEMINI_API_KEY.startswith("PON_AQUI")
        and not _agotado
        and _contador_dia < config.LLM_MAX_DIA
    )


def motivo_no_disponible() -> str | None:
    _reiniciar_dia_si_cambia()
    if not config.LLM_ENABLED:
        return "IA online desactivada (LLM_ENABLED=false)."
    if not config.GEMINI_API_KEY or config.GEMINI_API_KEY.startswith("PON_AQUI"):
        return "IA online no configurada (falta GEMINI_API_KEY)."
    if _agotado:
        return "Cuota de la IA online agotada; se detuvieron las consultas."
    if _contador_dia >= config.LLM_MAX_DIA:
        return f"Se alcanzó el tope diario de consultas ({config.LLM_MAX_DIA})."
    return None


_PROMPT = """Eres un analista de ciberseguridad experto en phishing. Analiza la siguiente URL
y responde ÚNICAMENTE con un JSON válido, sin texto adicional, con esta forma exacta:

{{"existe": true/false,
  "dominio_oficial": "dominio real de la marca si reconoces alguna, o null",
  "es_dominio_oficial": true/false,
  "es_imitacion": true/false,
  "confianza": 0.0,
  "razon": "explicación breve en español"}}

Reglas:
- "dominio_oficial": si la URL imita a una marca conocida (banco, red social, ecommerce,
  etc.), escribe su dominio legítimo.
- "es_imitacion": true si el dominio dado NO es el oficial y parece un typosquatting,
  homoglifo, subdominio engañoso o similar.
- Si no reconoces ninguna marca, usa null y false.
- "confianza" entre 0 y 1.
- URL a analizar: {url}
"""


def _extraer_json(texto: str) -> dict:
    texto = texto.strip()
    if texto.startswith("```"):
        texto = texto.strip("`")
        texto = texto.split("\n", 1)[-1] if "\n" in texto else texto
    ini, fin = texto.find("{"), texto.rfind("}")
    if ini != -1 and fin != -1:
        texto = texto[ini:fin + 1]
    return json.loads(texto)


def _score_desde(datos: dict) -> float:
    conf = float(datos.get("confianza") or 0)
    conf = max(0.0, min(1.0, conf))
    if datos.get("es_imitacion"):
        return round(0.6 + 0.4 * conf, 2)
    if datos.get("es_dominio_oficial"):
        return 0.05
    return 0.35  # dominio no reconocido: ni confirma ni descarta


def _modelos_a_probar() -> list[str]:
    return [config.GEMINI_MODEL] + [m for m in _MODELOS_RESPALDO if m != config.GEMINI_MODEL]


def _mensaje_error(r: requests.Response) -> str:
    try:
        cuerpo = r.json().get("error", {})
        return f"{cuerpo.get('status', r.status_code)}: {cuerpo.get('message', '')}".strip()[:200]
    except Exception:
        return f"HTTP {r.status_code}"


def analizar(url: str) -> ResultadoLLM:
    global _agotado, _contador_dia

    ahora = time.time()
    if url in _CACHE and ahora - _CACHE[url][0] < _CACHE_TTL:
        return _CACHE[url][1]

    motivo = motivo_no_disponible()
    if motivo:
        return ResultadoLLM(score=0.5, error=motivo)

    payload = {
        "contents": [{"parts": [{"text": _PROMPT.format(url=url)}]}],
        "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
    }
    _contador_dia += 1

    ultimo_error = "IA online no disponible."
    for modelo in _modelos_a_probar():
        endpoint = (f"https://generativelanguage.googleapis.com/v1beta/models/"
                    f"{modelo}:generateContent")
        try:
            r = requests.post(endpoint, params={"key": config.GEMINI_API_KEY},
                              json=payload, timeout=_TIMEOUT)
        except requests.RequestException as e:
            ultimo_error = f"IA online no disponible (red): {e.__class__.__name__}."
            continue

        if r.status_code == 429 or "RESOURCE_EXHAUSTED" in r.text:
            _agotado = True
            return ResultadoLLM(score=0.5,
                                error="Cuota de la IA online agotada; se detuvieron las consultas.")
        if r.status_code in (401, 403):
            return ResultadoLLM(score=0.5, error="La IA online rechazó la API key.")
        if r.status_code == 404:
            # El modelo ya no existe: probar el siguiente de respaldo.
            ultimo_error = f"IA online: modelo '{modelo}' no disponible."
            continue
        if r.status_code != 200:
            ultimo_error = f"IA online error ({_mensaje_error(r)})."
            continue

        try:
            contenido = r.json()["candidates"][0]["content"]["parts"][0]["text"]
            datos = _extraer_json(contenido)
        except Exception:
            ultimo_error = "IA online devolvió una respuesta no válida."
            continue

        resultado = ResultadoLLM(
            score=_score_desde(datos),
            detalle={"modelo": modelo,
                     "existe": datos.get("existe"),
                     "dominio_oficial": datos.get("dominio_oficial"),
                     "es_dominio_oficial": datos.get("es_dominio_oficial"),
                     "es_imitacion": datos.get("es_imitacion"),
                     "confianza": datos.get("confianza")},
            razon=datos.get("razon", ""),
        )
        _CACHE[url] = (ahora, resultado)
        return resultado

    return ResultadoLLM(score=0.5, error=ultimo_error)
