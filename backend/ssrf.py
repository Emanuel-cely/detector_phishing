"""Guardas de seguridad para URLs controladas por el usuario (anti-SSRF)."""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

ESQUEMAS_PERMITIDOS = {"http", "https"}


class URLNoPermitida(ValueError):
    pass


def _es_ip_privada(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # si no se puede parsear, mejor rechazar
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validar_esquema(url: str) -> None:
    esquema = urlparse(url).scheme.lower()
    if esquema not in ESQUEMAS_PERMITIDOS:
        raise URLNoPermitida(f"Esquema no permitido: {esquema or '(vacío)'}. Solo http/https.")


def resolver_y_validar_host(url: str) -> None:
    """Resuelve el host y rechaza IPs privadas/reservadas (incl. IPv6 e IDN)."""
    host = urlparse(url).hostname
    if not host:
        raise URLNoPermitida("URL sin host válido.")
    try:
        host_ascii = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        raise URLNoPermitida("Host inválido.")
    try:
        infos = socket.getaddrinfo(host_ascii, None)
    except socket.gaierror:
        raise URLNoPermitida(f"No se pudo resolver el dominio: {host}")
    for info in infos:
        ip = info[4][0]
        if _es_ip_privada(ip):
            raise URLNoPermitida(f"El dominio resuelve a una IP no pública ({ip}).")


def validar_url_publica(url: str) -> None:
    """Validación completa que debe aplicarse a la URL inicial y a cada redirección."""
    validar_esquema(url)
    resolver_y_validar_host(url)
