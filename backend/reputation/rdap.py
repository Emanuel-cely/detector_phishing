import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from .base import ProveedorReputacion, ResultadoReputacion

_CACHE: dict[str, tuple[float, dict]] = {}
_TTL = 3600


class Rdap(ProveedorReputacion):
    def evaluar_url(self, url: str) -> ResultadoReputacion:
        host = urlparse(url).hostname or ""
        partes = host.split(".")
        dominio = ".".join(partes[-2:]) if len(partes) >= 2 else host
        ahora = time.time()
        if dominio in _CACHE and ahora - _CACHE[dominio][0] < _TTL:
            return ResultadoReputacion("rdap", _CACHE[dominio][1]["score"],
                                       detalle=_CACHE[dominio][1]["detalle"])
        try:
            r = requests.get(f"https://rdap.org/domain/{dominio}", timeout=6,
                             headers={"Accept": "application/rdap+json"})
            if r.status_code == 429:
                return ResultadoReputacion("rdap", 0.5, error="Rate limit RDAP")
            r.raise_for_status()
            data = r.json()
            creacion = None
            for ev in data.get("events", []):
                if ev.get("eventAction") in ("registration", "registered"):
                    creacion = ev.get("eventDate")
                    break
            if not creacion:
                return ResultadoReputacion("rdap", 0.5, detalle={"edad_dias": None})
            fecha = datetime.fromisoformat(creacion.replace("Z", "+00:00"))
            edad = (datetime.now(timezone.utc) - fecha).days
            if edad < 30:
                score = 0.9
            elif edad < 180:
                score = 0.6
            elif edad < 365:
                score = 0.3
            else:
                score = 0.1
            detalle = {"edad_dias": edad}
            _CACHE[dominio] = (ahora, {"score": score, "detalle": detalle})
            return ResultadoReputacion("rdap", score, detalle=detalle)
        except Exception as e:
            return ResultadoReputacion("rdap", 0.5, error=str(e))
