"""Entrena Random Forest con PhiUSIIL (UCI id 967) y guarda .joblib + feature_columns.json."""
import json
import sys
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from ucimlrepo import fetch_ucirepo

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from model.feature_extractor import extraer  # noqa: E402

MODEL_PATH = Path(__file__).resolve().parent / "phishing_model.joblib"
FEATURES_PATH = Path(__file__).resolve().parent / "feature_columns.json"


def main():
    print("Descargando PhiUSIIL (ucimlrepo id=967)...")
    ds = fetch_ucirepo(id=967)
    X = ds.data.features
    y = ds.data.targets
    target_col = y.columns[0]
    y = y.iloc[:, 0]

    # Normalizar target a 0/1 (phishing = 1)
    if y.dtype == object or str(y.dtype).startswith("str"):
        y = y.astype(str).str.lower().map(
            lambda v: 1 if ("phish" in v or v == "1") else 0
        )
    else:
        y = y.astype(int)

    # Intersección: solo features que también podemos calcular en tiempo real
    candidatas = set(extraer("http://ejemplo.com/").keys())
    columnas = [c for c in X.columns if c in candidatas]
    print(f"Columnas del dataset: {X.shape[1]} | usables en tiempo real: {len(columnas)}")
    print(columnas)
    if len(columnas) < 5:
        print("AVISO: muy pocas columnas coinciden; se usarán todas las numéricas del dataset.")
        columnas = [c for c in X.columns if X[c].dtype != object]

    Xs = X[columnas].apply(lambda s: s.astype(float) if s.dtype != object else s)
    Xs = Xs.fillna(0)
    X_train, X_test, y_train, y_test = train_test_split(Xs, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)
    pred = clf.predict(X_test)
    print(f"accuracy={accuracy_score(y_test, pred):.4f} precision={precision_score(y_test, pred, average='binary'):.4f} "
          f"recall={recall_score(y_test, pred, average='binary'):.4f} f1={f1_score(y_test, pred, average='binary'):.4f}")

    joblib.dump(clf, MODEL_PATH)
    FEATURES_PATH.write_text(json.dumps(columnas, indent=2), encoding="utf-8")
    print(f"Modelo guardado en {MODEL_PATH} y columnas en {FEATURES_PATH}")


if __name__ == "__main__":
    main()
