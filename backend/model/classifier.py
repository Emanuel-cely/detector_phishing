"""Carga el Random Forest entrenado y predice sobre features de una URL."""
import json
from pathlib import Path

import joblib
import pandas as pd

from model.feature_extractor import extraer

_DIR = Path(__file__).resolve().parent
_model = None
_columnas: list[str] = []


def cargar() -> bool:
    global _model, _columnas
    try:
        _model = joblib.load(_DIR / "phishing_model.joblib")
        _columnas = json.loads((_DIR / "feature_columns.json").read_text(encoding="utf-8"))
        return True
    except Exception as e:
        print(f"[classifier] No se pudo cargar el modelo: {e}")
        _model = None
        return False


def disponible() -> bool:
    return _model is not None


def predecir(url: str, html: str | None = None) -> float:
    """Devuelve probabilidad de phishing (0-1)."""
    if _model is None:
        raise RuntimeError("Modelo no cargado")
    feats = extraer(url, html)
    fila = pd.DataFrame([[float(feats.get(c, 0) or 0) for c in _columnas]], columns=_columnas)
    proba = _model.predict_proba(fila)[0]
    clases = list(_model.classes_)
    return float(proba[clases.index(1)]) if 1 in clases else float(proba[-1])
