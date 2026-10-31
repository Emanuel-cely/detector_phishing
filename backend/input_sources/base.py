from abc import ABC, abstractmethod


class FuenteURL(ABC):
    """Interfaz para cualquier fuente de URLs sospechosas.

    El pipeline (analyzers, reputation, meta_model) solo recibe el string de la URL,
    así agregar Gmail/Outlook en el futuro no toca main.py más allá de registrar la fuente.
    """

    @abstractmethod
    def obtener_url(self) -> str:
        ...
