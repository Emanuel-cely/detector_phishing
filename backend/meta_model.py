"""Meta-modelo: orquesta todos los módulos en paralelo y combina los scores."""
from __future__ import annotations

import asyncio

from analyzers import ia1_domain_compare, ia2_html_dom, llm_online, ssl_certificate
from analyzers import existencia
from model import classifier, huggingface_classifier
from reputation.rdap import Rdap
from reputation.urlscan import Urlscan
from reputation.virustotal import VirusTotal

# Pesos: 60% modelos de IA (RF + BERT + Gemini online), 40% heurísticas/reputación
PESOS = {
    "random_forest": 0.22,
    "huggingface": 0.22,
    "llm_online": 0.16,
    "ia2": 0.12,
    "ia1": 0.10,
    "ssl": 0.10,
    "reputacion": 0.08,
}

UMBRAL_SOSPECHOSA = 0.3
UMBRAL_PHISHING = 0.7

TIMEOUT_MODULO = 12


def _promedio_safe(scores) -> float | None:
    vals = [s for s in scores if s is not None]
    return sum(vals) / len(vals) if vals else None


def _con_punto(texto: str) -> str:
    texto = (texto or "").strip()
    return texto if texto.endswith((".", ")", "!", "?")) else texto + "."


async def _en_hilo(fn, *args):
    return await asyncio.to_thread(fn, *args)


async def analizar(url: str) -> dict:
    detalle_existencia = await _en_hilo(existencia.verificar, url)
    estado = detalle_existencia["estado"]
    if estado != "existe":
        mensajes = {
            "no_resuelve": "La URL no existe o su dominio no resuelve. No se emite veredicto.",
            "no_responde": "El dominio existe pero no responde. No se emite veredicto.",
            "bloqueada": "La URL fue bloqueada por seguridad (destino no público o esquema inválido). No se emite veredicto.",
        }
        return {
            "estado": estado,
            "veredicto": None,
            "riesgo": None,
            "explicacion": mensajes.get(estado, "URL no evaluable."),
            "detalle_modulos": {"existencia": detalle_existencia},
        }

    # IA-2 primero (secuencialmente barato) para reutilizar el HTML en el extractor de features
    try:
        ia2 = await asyncio.wait_for(_en_hilo(ia2_html_dom.analizar, url), timeout=TIMEOUT_MODULO)
    except Exception as e:
        ia2 = e
    html = ia2.get("html") if isinstance(ia2, dict) else None

    async def rf():
        if classifier.disponible():
            return await asyncio.wait_for(_en_hilo(classifier.predecir, url, html), timeout=TIMEOUT_MODULO)
        return None

    async def hf():
        if huggingface_classifier.disponible():
            return await asyncio.wait_for(_en_hilo(huggingface_classifier.predecir, url), timeout=TIMEOUT_MODULO)
        return None

    async def llm():
        return await asyncio.wait_for(_en_hilo(llm_online.analizar, url), timeout=TIMEOUT_MODULO + 6)

    ia1_t = _en_hilo(ia1_domain_compare.analizar, url)
    ssl_t = _en_hilo(ssl_certificate.analizar, url)
    vt_t = _en_hilo(VirusTotal().evaluar_url, url)
    us_t = _en_hilo(Urlscan().evaluar_url, url)
    rdap_t = _en_hilo(Rdap().evaluar_url, url)

    resultados = await asyncio.gather(ia1_t, ssl_t, vt_t, us_t, rdap_t, rf(), hf(), llm(),
                                      return_exceptions=True)
    ia1, ssl, vt, us, rdap, rf_score, hf_score, llm_res = resultados

    def _ok(x):
        return x if not isinstance(x, Exception) else None

    ia1, ssl = _ok(ia1), _ok(ssl)
    vt, us, rdap = _ok(vt), _ok(us), _ok(rdap)
    rf_score, hf_score = _ok(rf_score), _ok(hf_score)
    llm_res = _ok(llm_res)

    rep_score = _promedio_safe([
        vt.score if (vt and not vt.error) else None,
        us.score if (us and not us.error) else None,
        rdap.score if (rdap and not rdap.error) else None,
    ])

    llm_score = llm_res.score if (llm_res and llm_res.error is None) else None

    componentes = {
        "random_forest": rf_score,
        "huggingface": hf_score,
        "llm_online": llm_score,
        "ia1": ia1["score"] if ia1 else None,
        "ia2": ia2["score"] if isinstance(ia2, dict) else None,
        "ssl": ssl["score"] if ssl else None,
        "reputacion": rep_score,
    }

    num, den = 0.0, 0.0
    for k, v in componentes.items():
        if v is not None:
            num += PESOS[k] * v
            den += PESOS[k]
    riesgo = round(num / den, 3) if den > 0 else 0.5

    if riesgo < UMBRAL_SOSPECHOSA:
        veredicto = "legítima"
    elif riesgo < UMBRAL_PHISHING:
        veredicto = "sospechosa"
    else:
        veredicto = "phishing"

    explicacion = []
    if rf_score is not None:
        explicacion.append(f"El modelo de Random Forest le asignó {rf_score:.0%} de probabilidad de phishing.")
    else:
        explicacion.append("La señal del modelo Random Forest no estuvo disponible.")
    if hf_score is not None:
        explicacion.append(f"El modelo de IA (BERT) le asignó {hf_score:.0%} de probabilidad de phishing.")
    else:
        explicacion.append("La señal de deep learning no estuvo disponible.")
    if llm_res and llm_res.error is None:
        if llm_res.razon:
            explicacion.append(f"IA online ({llm_res.fuente}): {llm_res.razon}")
    elif llm_res and llm_res.error:
        explicacion.append(_con_punto(llm_res.error))
    for mod in (ia1, ia2 if isinstance(ia2, dict) else None, ssl):
        if mod:
            explicacion.extend(mod.get("hallazgos", []))
    for rep in (vt, us, rdap):
        if rep and rep.error:
            explicacion.append(_con_punto(f"Reputación ({rep.fuente}): {rep.error}"))
    if isinstance(ia2, Exception):
        explicacion.append(f"El análisis HTML no pudo completarse: {ia2}.")

    return {
        "estado": estado,
        "veredicto": veredicto,
        "riesgo": int(round(riesgo * 100)),
        "explicacion": " ".join(explicacion),
        "detalle_modulos": {
            "existencia": detalle_existencia,
            "random_forest": rf_score,
            "huggingface": hf_score,
            "llm_online": llm_res.__dict__ if llm_res else None,
            "ia1": ia1,
            "ia2": {k: v for k, v in ia2.items() if k != "html"} if isinstance(ia2, dict) else {"error": str(ia2)},
            "ssl": ssl,
            "reputacion": {
                "virustotal": vt.__dict__ if vt else None,
                "urlscan": us.__dict__ if us else None,
                "rdap": rdap.__dict__ if rdap else None,
            },
        },
    }
