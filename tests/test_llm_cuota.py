import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

import config  # noqa: E402
from analyzers import llm_online  # noqa: E402


class _FakeResp:
    def __init__(self, status_code, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http error")


def _reset(monkeypatch, max_dia=200):
    monkeypatch.setattr(config, "GEMINI_API_KEY", "fake-key")
    monkeypatch.setattr(config, "LLM_ENABLED", True)
    monkeypatch.setattr(config, "LLM_MAX_DIA", max_dia)
    monkeypatch.setattr(llm_online, "_agotado", False)
    monkeypatch.setattr(llm_online, "_contador_dia", 0)
    llm_online._CACHE.clear()


def test_circuit_breaker_en_429(monkeypatch):
    _reset(monkeypatch)
    llamadas = {"n": 0}

    def fake_post(*a, **k):
        llamadas["n"] += 1
        return _FakeResp(429, text="RESOURCE_EXHAUSTED")
    monkeypatch.setattr(llm_online.requests, "post", fake_post)

    r1 = llm_online.analizar("http://a.com")
    assert r1.error and "Cuota" in r1.error
    assert not llm_online.disponible()

    # Segunda consulta NO debe volver a llamar a la API
    r2 = llm_online.analizar("http://b.com")
    assert r2.error
    assert llamadas["n"] == 1


def test_tope_diario(monkeypatch):
    _reset(monkeypatch, max_dia=1)

    def fake_post(*a, **k):
        return _FakeResp(200, payload={"candidates": [{"content": {"parts": [{"text":
            '{"existe": true, "dominio_oficial": null, "es_dominio_oficial": false, '
            '"es_imitacion": false, "confianza": 0.2, "razon": "ok"}'}]}}]})
    monkeypatch.setattr(llm_online.requests, "post", fake_post)

    llm_online.analizar("http://uno.com")
    assert not llm_online.disponible()
    assert "tope diario" in (llm_online.motivo_no_disponible() or "")
