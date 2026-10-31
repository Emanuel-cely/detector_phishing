from .base import FuenteURL


class FuenteManual(FuenteURL):
    """La URL llega directamente del body del request HTTP (form del frontend)."""

    def __init__(self, url: str):
        self._url = url

    def obtener_url(self) -> str:
        return self._url
