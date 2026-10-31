"""BERT pretrained (Hugging Face) para detección de phishing. CPU, sin token."""
from __future__ import annotations

_tokenizer = None
_model = None
_disponible = False
_phishing_idx = 1


def cargar() -> bool:
    global _tokenizer, _model, _disponible, _phishing_idx
    try:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        import torch  # noqa: F401

        nombre = "ealvaradob/bert-finetuned-phishing"
        print(f"[huggingface] Descargando/cargando modelo {nombre} (primera vez ~400MB)...")
        _tokenizer = AutoTokenizer.from_pretrained(nombre)
        _model = AutoModelForSequenceClassification.from_pretrained(nombre)
        _model.eval()

        # Averiguar qué índice de etiqueta corresponde a phishing
        id2label = getattr(_model.config, "id2label", {}) or {}
        _phishing_idx = 1
        for idx, label in id2label.items():
            if "phish" in str(label).lower():
                _phishing_idx = int(idx)
                break
        _disponible = True
        print(f"[huggingface] Modelo cargado. id2label={id2label}, índice phishing={_phishing_idx}")
        return True
    except Exception as e:
        print(f"[huggingface] No disponible: {e}. El sistema seguirá sin esta señal.")
        _disponible = False
        return False


def disponible() -> bool:
    return _disponible


def predecir(url: str) -> float:
    if not _disponible:
        raise RuntimeError("Modelo HF no disponible")
    import torch

    inputs = _tokenizer(url, return_tensors="pt", truncation=True, max_length=256)
    with torch.no_grad():
        logits = _model(**inputs).logits
    probs = torch.softmax(logits, dim=-1)[0]
    return float(probs[_phishing_idx])
