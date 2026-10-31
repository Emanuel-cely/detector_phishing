import time

import requests

from config import URLSCAN_API_KEY
from .base import ProveedorReputacion, ResultadoReputacion


class Urlscan(ProveedorReputacion):
    def evaluar_url(self, url: str) -> ResultadoReputacion:
        if not URLSCAN_API_KEY or URLSCAN_API_KEY.startswith("PON_AQUI"):
            return ResultadoReputacion("urlscan", 0.5, error="API key no configurada")
        headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
        try:
            r = requests.post("https://urlscan.io/api/v1/scan/", headers=headers,
                              json={"url": url, "visibility": "public"}, timeout=8)
            if r.status_code == 429:
                return ResultadoReputacion("urlscan", 0.5, error="Rate limit de urlscan.io")
            r.raise_for_status()
            uuid = r.json()["uuid"]
            for _ in range(3):
                time.sleep(3)
                g = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/", timeout=8)
                if g.status_code == 200:
                    verdict = g.json().get("verdicts", {}).get("overall", {})
                    malicioso = bool(verdict.get("malicious"))
                    score = 0.9 if malicioso else 0.1
                    return ResultadoReputacion("urlscan", score,
                                               detalle={"verdict": verdict.get("score"),
                                                        "malicious": malicioso})
            return ResultadoReputacion("urlscan", 0.5,
                                       error="El escaneo sigue en curso (no afecta el resultado).",
                                       detalle={"uuid": uuid})
        except Exception as e:
            return ResultadoReputacion("urlscan", 0.5, error=str(e))
