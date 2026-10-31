"""Extracción en tiempo real de features tipo PhiUSIIL desde URL + HTML.

train_model.py usa la intersección entre estos nombres y las columnas reales del
dataset UCI; classifier.py usa exactamente las columnas guardadas en feature_columns.json.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from ssrf import validar_url_publica, URLNoPermitida


def _contar(patron: str, texto: str) -> int:
    return len(re.findall(patron, texto))


def _max_corrido(texto: str) -> int:
    mejor = actual = 0
    prev = None
    for c in texto:
        actual = actual + 1 if c == prev else 1
        mejor = max(mejor, actual)
        prev = c
    return mejor


def extraer(url: str, html: str | None = None) -> dict:
    p = urlparse(url if "://" in url else f"http://{url}")
    host = p.hostname or ""
    partes = host.split(".")
    tld = partes[-1] if partes else ""
    ruta = p.path or ""
    query = p.query or ""

    feats = {
        "URLLength": len(url),
        "DomainLength": len(host),
        "IsDomainIP": 1 if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host) else 0,
        "TLDLength": len(tld),
        "NoOfSubDomain": max(len(partes) - 2, 0),
        "NoOfOtherSpecialCharsInURL": _contar(r"[^\w\-\.\/\:]", url),
        "LetterRatioInURL": sum(c.isalpha() for c in url) / max(len(url), 1),
        "NoOfDegitsInURL": sum(c.isdigit() for c in url),
        "NoOfEqualsInURL": url.count("="),
        "NoOfQMarkInURL": url.count("?"),
        "NoOfAmpersandInURL": url.count("&"),
        "NoOfLettersInDir": sum(c.isalpha() for c in ruta),
        "NoOfOtherSpecialCharsInDir": _contar(r"[^\w\-\.\/]", ruta),
        "IsHTTPS": 1 if p.scheme == "https" else 0,
        "NoOfDotsInURL": url.count("."),
        "NoOfHypensInURL": url.count("-"),
        "NoOfUnderscoreInURL": url.count("_"),
        "NoOfPercentInURL": url.count("%"),
        "NoOfTopLevelDomain": 1,
        "NoOfLettersInDesi": sum(c.isalpha() for c in host),
        "NoOfDegitsInDesi": sum(c.isdigit() for c in host),
        "NoOfHypensInDesi": host.count("-"),
        "HasAtInURL": 1 if "@" in url else 0,
        "URLSimilarityIndex": round(len(set(url)) / max(len(url), 1), 3),
        "CharContinuationRate": round(_max_corrido(url) / max(len(url), 1), 3),
        "HasQuery": 1 if query else 0,
    }

    if html is None:
        try:
            validar_url_publica(url)
            r = requests.get(url, timeout=6, headers={"User-Agent": "detector-phishing-academico/1.0"})
            html = r.text[:200_000]
        except Exception:
            html = ""

    if html:
        soup = BeautifulSoup(html, "html.parser")
        feats.update({
            "HtmlForm": len(soup.find_all("form")),
            "HasTitle": 1 if soup.find("title") else 0,
            "HasInputTypePassword": len(soup.find_all("input", {"type": "password"})),
            "NoOfImageTags": len(soup.find_all("img")),
            "NoOfJSTags": len(soup.find_all("script")),
            "NoOfIframe": len(soup.find_all("iframe")),
            "NoOfLinkTags": len(soup.find_all("a")),
            "NoOfAudioTags": len(soup.find_all("audio")),
            "NoOfVideoTags": len(soup.find_all("video")),
        })
    else:
        feats.update({"HtmlForm": 0, "HasTitle": 0, "HasInputTypePassword": 0,
                      "NoOfImageTags": 0, "NoOfJSTags": 0, "NoOfIframe": 0,
                      "NoOfLinkTags": 0, "NoOfAudioTags": 0, "NoOfVideoTags": 0})
    return feats
