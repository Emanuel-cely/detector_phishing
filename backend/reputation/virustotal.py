import base64
import time

import requests

from config import VIRUSTOTAL_API_KEY
from .base import ProveedorReputacion, ResultadoReputacion


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


class VirusTotal(ProveedorReputacion):
    def evaluar_url(self, url: str) -> ResultadoReputacion:
        if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY.startswith("PON_AQUI"):
            return ResultadoReputacion("virustotal", 0.5, error="API key no configurada")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/urls/{_url_id(url)}",
                             headers=headers, timeout=8)
            if r.status_code == 404:
                r = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers,
                                  data={"url": url}, timeout=8)
                time.sleep(3)
                r = requests.get(f"https://www.virustotal.com/api/v3/urls/{_url_id(url)}",
                                 headers=headers, timeout=8)
            if r.status_code == 429:
                return ResultadoReputacion("virustotal", 0.5, error="Rate limit de VirusTotal")
            r.raise_for_status()
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            maliciosos = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values()) or 1
            score = round(min(1.0, maliciosos / max(total, 1) * 5), 2)
            return ResultadoReputacion("virustotal", score,
                                       detalle={"maliciosos": maliciosos, "total": total})
        except Exception as e:
            return ResultadoReputacion("virustotal", 0.5, error=str(e))
