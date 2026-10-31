import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

import meta_model  # noqa: E402
from analyzers import existencia  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def test_no_emite_veredicto_si_no_existe(monkeypatch):
    monkeypatch.setattr(existencia, "verificar",
                        lambda url: {"estado": "no_resuelve", "detalle": "no existe"})
    r = _run(meta_model.analizar("http://no-existe-xyz.com"))
    assert r["estado"] == "no_resuelve"
    assert r["veredicto"] is None
    assert r["riesgo"] is None
    assert "no emite veredicto" in r["explicacion"].lower() or "no existe" in r["explicacion"].lower()


def test_no_emite_veredicto_si_no_responde(monkeypatch):
    monkeypatch.setattr(existencia, "verificar",
                        lambda url: {"estado": "no_responde", "detalle": "timeout"})
    r = _run(meta_model.analizar("http://caido.com"))
    assert r["veredicto"] is None
    assert r["riesgo"] is None
