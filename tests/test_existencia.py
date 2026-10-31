import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from analyzers import existencia  # noqa: E402


class _FakeResp:
    def __init__(self, status_code=200):
        self.status_code = status_code

    def close(self):
        pass


def test_no_resuelve(monkeypatch):
    def fake_getaddrinfo(*a, **k):
        raise socket.gaierror("gaierror")
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    r = existencia.verificar("http://dominio-que-no-existe-xyz.com")
    assert r["estado"] == "no_resuelve"


def test_no_responde(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])

    def fake_get(*a, **k):
        import requests
        raise requests.ConnectionError("timeout")
    monkeypatch.setattr(existencia.requests, "get", fake_get)
    r = existencia.verificar("http://sitio-caido.com")
    assert r["estado"] == "no_responde"


def test_existe(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    monkeypatch.setattr(existencia.requests, "get", lambda *a, **k: _FakeResp(403))
    r = existencia.verificar("http://sitio-real.com")
    assert r["estado"] == "existe"


def test_bloqueada_ip_privada(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("192.168.1.10", 0))])
    r = existencia.verificar("http://interno.local")
    assert r["estado"] == "bloqueada"
