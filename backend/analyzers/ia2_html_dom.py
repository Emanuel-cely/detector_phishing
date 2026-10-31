"""IA-2: descarga del HTML (con guardas anti-SSRF en cada salto) y análisis del DOM/redirecciones."""
from __future__ import annotations

import re
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from ssrf import validar_url_publica, URLNoPermitida

MAX_SALTOS = 5
TIMEOUT = 6
MAX_BYTES = 2_000_000


def _descargar(url: str) -> tuple[str, list[str], str]:
    """Devuelve (html, cadena_de_redirecciones, url_final). Valida SSRF en cada salto."""
    cadena: list[str] = []
    actual = url
    for _ in range(MAX_SALTOS + 1):
        validar_url_publica(actual)  # revalidar IP en cada salto
        try:
            r = requests.get(
                actual,
                timeout=TIMEOUT,
                allow_redirects=False,
                stream=True,
                headers={"User-Agent": "detector-phishing-academico/1.0"},
            )
        except requests.RequestException as e:
            raise RuntimeError(f"No se pudo descargar la página: {e.__class__.__name__}")
        if r.is_redirect or r.is_permanent_redirect:
            destino = r.headers.get("Location", "")
            if not destino:
                break
            cadena.append(destino)
            actual = requests.compat.urljoin(actual, destino)
            continue
        contenido = b""
        for chunk in r.iter_content(chunk_size=65536):
            contenido += chunk
            if len(contenido) > MAX_BYTES:
                break
        return contenido.decode(r.encoding or "utf-8", errors="replace"), cadena, actual
    raise RuntimeError("Demasiadas redirecciones.")


def analizar(url: str) -> dict:
    try:
        html, cadena, url_final = _descargar(url)
    except (URLNoPermitida, RuntimeError) as e:
        return {"modulo": "ia2_html_dom", "score": 0.5, "error": str(e),
                "hallazgos": [f"No se pudo analizar el HTML: {e}"], "saltos": 0}

    try:
        soup = BeautifulSoup(html, "html.parser")
        formularios = soup.find_all("form")
        campos_password = soup.find_all("input", {"type": "password"})
        iframes = soup.find_all("iframe")
        enlaces = soup.find_all("a", href=True)
        externos = [a for a in enlaces if urlparse(a["href"]).netloc and
                    urlparse(a["href"]).netloc != urlparse(url_final).netloc]
        favicon_ext = any("rel" in (l.get("rel") or []) for l in [] )  # placeholder
        fav = soup.find("link", rel=lambda v: v and "icon" in v)
        favicon_externo = bool(fav and fav.get("href") and urlparse(fav["href"]).netloc)
        scripts = " ".join(s.get_text() or "" for s in soup.find_all("script"))
        ofuscado = bool(re.search(r"(eval\(|unescape\(|fromCharCode|atob\()", scripts))
        metas_refresh = soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
        saltos_js = len(re.findall(r"window\.location|document\.location", scripts))

        hallazgos = []
        score = 0.0
        if campos_password:
            score += 0.25
            hallazgos.append(f"Se detectaron {len(campos_password)} campo(s) de contraseña.")
        if iframes:
            score += 0.15
            hallazgos.append(f"Uso de {len(iframes)} iframe(s).")
        if ofuscado:
            score += 0.2
            hallazgos.append("JavaScript ofuscado (eval/unescape/fromCharCode/atob).")
        if favicon_externo:
            score += 0.1
            hallazgos.append("Favicon cargado desde un dominio externo.")
        if enlaces and len(externos) / max(len(enlaces), 1) > 0.7:
            score += 0.1
            hallazgos.append("La mayoría de enlaces apuntan a dominios externos.")
        total_saltos = len(cadena) + len(metas_refresh) + (1 if saltos_js else 0)
        if total_saltos >= 3:
            score += 0.25
            hallazgos.append(f"Se detectaron {total_saltos} redirecciones antes del contenido final.")
        elif total_saltos > 0:
            score += 0.1
            hallazgos.append(f"{total_saltos} redirección(es) detectada(s).")

        score = min(1.0, round(score, 2))
        if not hallazgos:
            hallazgos.append("No se observaron señales claras en el HTML/DOM.")
        return {"modulo": "ia2_html_dom", "score": score, "saltos": total_saltos,
                "formularios": len(formularios), "hallazgos": hallazgos, "url_final": url_final,
                "html": html[:200_000]}
    except Exception as e:
        return {"modulo": "ia2_html_dom", "score": 0.5, "error": str(e),
                "hallazgos": [f"Error analizando el DOM: {e}"], "saltos": 0}
