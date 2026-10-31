import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from ssrf import validar_url_publica, URLNoPermitida  # noqa: E402


def test_rechaza_file_scheme():
    with pytest.raises(URLNoPermitida):
        validar_url_publica("file:///etc/passwd")


def test_rechaza_ip_privada_literal():
    with pytest.raises(URLNoPermitida):
        validar_url_publica("http://192.168.1.1/admin")


def test_rechaza_loopback():
    with pytest.raises(URLNoPermitida):
        validar_url_publica("http://127.0.0.1:8000/")


def test_rechaza_link_local():
    with pytest.raises(URLNoPermitida):
        validar_url_publica("http://169.254.169.254/latest/meta-data")


def test_rechaza_esquema_raro():
    with pytest.raises(URLNoPermitida):
        validar_url_publica("gopher://ejemplo.com/")
