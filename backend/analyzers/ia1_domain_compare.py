"""IA-1: comparación de la URL recibida contra imitaciones (typosquatting) con dnstwist."""
from __future__ import annotations

import json
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import urlparse

import dnstwist

_REFERENCIAS_PATH = Path(__file__).resolve().parent.parent / "config" / "reference_domains.json"


def _cargar_referencias() -> list[str]:
    try:
        return json.loads(_REFERENCIAS_PATH.read_text(encoding="utf-8"))["domains"]
    except Exception:
        return []


def _dominio_base(url: str) -> str:
    host = urlparse(url if "://" in url else f"http://{url}").hostname or ""
    host = host.lower().lstrip("www.")
    partes = host.split(".")
    return ".".join(partes[-2:]) if len(partes) >= 2 else host


def _similaridad(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def analizar(url: str) -> dict:
    dominio = _dominio_base(url)
    referencias = _cargar_referencias()
    marca_cercana = None
    mejor_sim = 0.0
    for ref in referencias:
        sim = _similaridad(dominio, ref)
        if sim > mejor_sim:
            mejor_sim = sim
            marca_cercana = ref

    hallazgos = []
    coincidentes = []
    sospechoso = False
    score = 0.0

    # Si el dominio es muy parecido pero NO es la marca legítima, es señal de alerta
    if marca_cercana and dominio != marca_cercana and mejor_sim >= 0.75:
        sospechoso = True
        score = min(1.0, round(mejor_sim, 2))
        hallazgos.append(f"El dominio '{dominio}' es muy similar a '{marca_cercana}' (similitud {mejor_sim:.0%}).")

    # Generar variantes de la marca detectada y ver si el dominio recibido es una de ellas
    if marca_cercana and dominio != marca_cercana:
        try:
            fuzz = dnstwist.Fuzzer(marca_cercana)
            fuzz.generate()
            variantes = {p["domain"] for p in fuzz.permutations()}
            if dominio in variantes:
                sospechoso = True
                score = max(score, 0.95)
                coincidentes.append(dominio)
                hallazgos.append(f"'{dominio}' coincide con una variante de typosquatting de '{marca_cercana}'.")
        except Exception:
            hallazgos.append("No se pudieron generar variantes con dnstwist.")

    if not hallazgos:
        hallazgos.append(f"El dominio '{dominio}' no se parece a marcas conocidas de la lista de referencia.")

    return {"modulo": "ia1_domain_compare", "sospechoso": sospechoso, "score": score,
            "variantes_coincidentes": coincidentes, "hallazgos": hallazgos}
