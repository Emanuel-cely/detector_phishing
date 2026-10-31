from dataclasses import dataclass, field


@dataclass
class ResultadoReputacion:
    fuente: str
    score: float  # 0-1, 1 = más sospechoso
    detalle: dict = field(default_factory=dict)
    error: str | None = None


class ProveedorReputacion:
    def evaluar_url(self, url: str) -> ResultadoReputacion:  # noqa: D401
        raise NotImplementedError
