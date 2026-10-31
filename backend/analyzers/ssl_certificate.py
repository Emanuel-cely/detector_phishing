"""SSL/TLS: lectura directa del certificado + historial en crt.sh (sin key, con caché)."""
from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from ssrf import validar_esquema, resolver_y_validar_host

_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 600  # 10 minutos


def _leer_certificado(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=6) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    return cert


def _crtsh(dominio: str) -> int | None:
    ahora = time.time()
    if dominio in _CACHE and ahora - _CACHE[dominio][0] < _CACHE_TTL:
        return _CACHE[dominio][1].get("crtsh_mas_reciente_dias")
    try:
        r = requests.get(f"https://crt.sh/?q={dominio}&output=json", timeout=6)
        data = r.json()
        fechas = sorted(d["not_before"] for d in data if "not_before" in d)
        if not fechas:
            return None
        mas_reciente = datetime.fromisoformat(fechas[-1].replace("Z", "+00:00"))
        dias = (datetime.now(timezone.utc) - mas_reciente).days
        return max(dias, 0)
    except Exception:
        return None


def analizar(url: str) -> dict:
    validar_esquema(url)
    host = urlparse(url).hostname
    if not host:
        return {"modulo": "ssl", "score": 0.5, "error": "Sin host", "hallazgos": ["URL sin host."]}
    try:
        validar_esquema(url)
        resolver_y_validar_host(url)
    except Exception as e:
        return {"modulo": "ssl", "score": 0.5, "error": str(e), "hallazgos": [f"URL no evaluable: {e}"]}

    hallazgos = []
    score = 0.0
    self_signed = False
    dias_desde_emision = None
    try:
        cert = _leer_certificado(host)
        emisor = dict(x[0] for x in cert.get("issuer", []))
        no_antes = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        dias_desde_emision = (datetime.now(timezone.utc) - no_antes).days
        if "self" in str(emisor).lower() or cert.get("issuer") == cert.get("subject"):
            self_signed = True
        if self_signed:
            score += 0.5
            hallazgos.append("El certificado parece autofirmado.")
        if dias_desde_emision is not None and dias_desde_emision < 30:
            score += 0.3
            hallazgos.append(f"El certificado fue emitido hace {dias_desde_emision} día(s).")
        else:
            hallazgos.append(f"Certificado emitido por '{emisor.get('organizationName', 'desconocido')}', "
                             f"hace {dias_desde_emision} días.")
    except Exception as e:
        hallazgos.append(f"No se pudo leer el certificado TLS: {e.__class__.__name__}")
        score += 0.3

    recientes = _crtsh(host)
    if recientes is not None and recientes < 7:
        score += 0.2
        hallazgos.append(f"crt.sh muestra un certificado reciente para este dominio (hace {recientes} días).")

    return {"modulo": "ssl", "score": min(1.0, round(score, 2)), "self_signed": self_signed,
            "dias_desde_emision": dias_desde_emision, "hallazgos": hallazgos}
