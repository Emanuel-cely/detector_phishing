"""Verificación de existencia de la URL (DNS + conectividad HTTP).

Estados posibles:
  - existe:       el dominio resuelve y acepta conexión (cualquier código HTTP).
  - no_resuelve:  el dominio no resuelve por DNS (NXDOMAIN / fallo de resolución).
  - no_responde:  resuelve, pero la conexión HTTP/TCP falla o expira.
  - bloqueada:    resuelve a una IP privada/reservada (SSRF) o esquema no permitido.

Si el estado no es "existe", el meta-modelo NO emite veredicto.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import requests

from ssrf import validar_esquema, URLNoPermitida

TIMEOUT = 5


def _host_ascii(host: str) -> str:
    return host.encode("idna").decode("ascii")


def _es_ip_privada(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def verificar(url: str) -> dict:
    try:
        validar_esquema(url)
    except URLNoPermitida as e:
        return {"estado": "bloqueada", "detalle": str(e)}

    host = urlparse(url).hostname
    if not host:
        return {"estado": "bloqueada", "detalle": "URL sin host válido."}

    try:
        host_ascii = _host_ascii(host)
    except (UnicodeError, ValueError):
        return {"estado": "bloqueada", "detalle": "Host inválido."}

    try:
        infos = socket.getaddrinfo(host_ascii, None)
    except socket.gaierror as e:
        return {"estado": "no_resuelve", "detalle": f"El dominio '{host}' no existe o no resuelve ({e})."}

    for info in infos:
        ip = info[4][0]
        if _es_ip_privada(ip):
            return {"estado": "bloqueada",
                    "detalle": f"El dominio resuelve a una IP no pública ({ip}); request bloqueado."}

    try:
        r = requests.get(url, timeout=TIMEOUT, stream=True, allow_redirects=True,
                         headers={"User-Agent": "detector-phishing-academico/1.0"})
        r.close()
        return {"estado": "existe", "detalle": f"El sitio respondió con HTTP {r.status_code}."}
    except requests.RequestException as e:
        return {"estado": "no_responde",
                "detalle": f"El dominio resuelve pero no respondió ({e.__class__.__name__})."}
