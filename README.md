# Detector Inteligente de Páginas de Phishing mediante IA

Aplicación web académica (Escuela Colombiana de Ingeniería Julio Garavito) que clasifica una URL sospechosa como **legítima / sospechosa / phishing**, con nivel de riesgo 0-100 y una explicación en lenguaje simple.

## Arquitectura

```
URL → input_sources → verificación de existencia (DNS + HTTP)
                          │
       ┌──────────────────┴─────────────────────────────┐
       │  no existe / no responde → "no evaluable"       │
       │  (sin veredicto)                                │
       └──────────────────┬─────────────────────────────┘
                          │ existe
   ┌──────────────────────┴──────────────────────────┐
   │ IA-1 (dnstwist) · IA-2 (HTML/DOM) · SSL/crt.sh  │
   │ Reputación (VT/urlscan/RDAP)                    │
   │ IA: Random Forest · BERT HF · Gemini online     │
   └──────────────────────┬──────────────────────────┘
                          ▼
             meta_model (60% IA / 40% heurísticas)
                          ▼
              veredicto + riesgo + explicación
```

Los modelos de IA (Random Forest, BERT y Gemini online) pesan el 60% de la decisión; las señales heurísticas y de reputación el 40%.

Si la URL **no existe o no responde**, la API responde con `veredicto: null` y un mensaje neutro: no se emite un veredicto de "segura".

## IA online (Google AI Studio / Gemini, free tier)

Además de los modelos offline, se consulta **Gemini** para verificar la existencia del sitio, identificar el dominio oficial de la marca y comparar la URL dada con el dominio real (detección de typosquatting por conocimiento del mundo real).

Control de cuota para no llegar a facturación:

- **Circuit breaker**: ante un `429`/`RESOURCE_EXHAUSTED` se detienen todas las consultas de esa ejecución.
- **Tope diario local** (`LLM_MAX_DIA`, por defecto 200).
- **Caché por URL** para no repetir consultas.
- Sin key o agotado, el sistema sigue funcionando con los demás módulos (degradación con gracia).

## Requisitos

- Python 3.12 (probado) / 3.11+
- Windows: ver nota de torch CPU en la instalación

## Instalación

```bash
cd detector-phishing/backend
pip install torch==2.2.2+cpu --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
cp .env.example .env   # y edita las keys reales (VIRUSTOTAL_API_KEY, URLSCAN_API_KEY, GEMINI_API_KEY)
```

## Entrenar el modelo Random Forest (una sola vez)

```bash
cd backend
python model/train_model.py
```

Descarga PhiUSIIL desde UCI (id 967), entrena, imprime métricas y guarda `model/phishing_model.joblib` + `model/feature_columns.json`.

El modelo de Hugging Face (`ealvaradob/bert-finetuned-phishing`) **no requiere entrenamiento**: se descarga automáticamente la primera vez que arranca el backend (~400 MB, log claro en consola).

## Ejecutar

```bash
cd backend
uvicorn main:app --reload
```

Abrir http://127.0.0.1:8000/ (el frontend se sirve desde el mismo backend). Documentación Swagger en http://127.0.0.1:8000/docs.

## Endpoints

- `POST /analizar` — body `{"url": "https://..."}` → `{veredicto, riesgo, explicacion, detalle_modulos}`
- `GET /health` — healthcheck + disponibilidad de modelos

## Módulos

| Módulo | Fuente de decisión |
|---|---|
| Existencia (`analyzers/existencia.py`) | DNS + conectividad HTTP; si no existe, no hay veredicto |
| IA-1 (`analyzers/ia1_domain_compare.py`) | dnstwist: typosquatting/homoglifos vs lista de marcas (`config/reference_domains.json`) |
| IA-2 (`analyzers/ia2_html_dom.py`) | Scraping HTML: formularios, passwords, iframes, JS ofuscado, redirecciones |
| SSL (`analyzers/ssl_certificate.py`) | Certificado directo vía `ssl`/`socket` + historial en crt.sh |
| Reputación | VirusTotal, urlscan.io (APIs con key), RDAP (edad de dominio, sin key) |
| Modelo RF | PhiUSIIL (UCI) entrenado offline |
| Modelo HF | `ealvaradob/bert-finetuned-phishing` (pretrained, CPU) |
| IA online (`analyzers/llm_online.py`) | Gemini (Google AI Studio): dominio oficial, imitación, existencia |

### Pesos del meta-modelo

| Señal | Peso |
|---|---|
| Random Forest | 0.22 |
| BERT (Hugging Face) | 0.22 |
| Gemini online | 0.16 |
| IA-2 (HTML/DOM) | 0.12 |
| IA-1 (dnstwist) | 0.10 |
| SSL | 0.10 |
| Reputación | 0.08 |

Los pesos se renormalizan si algún módulo no está disponible.

## Tests

```bash
pip install pytest
pytest tests/
```

## Limitaciones conocidas (MVP)

- Sin integración de Gmail/Outlook todavía (la interfaz `input_sources/base.py` ya lo permite).
- Rate limits de las APIs gratuitas de VirusTotal/urlscan.
- crt.sh/RDAP pueden estar lentos: caché por dominio y degradación con gracia.
- La heurística de IA-1 tiene falsos negativos (marcas no listadas).
- Gemini puede alucinar sobre la titularidad de un dominio: por eso pesa 0.16 y no decide solo.
- La IA online añade ~1-3s al análisis; en el free tier, si se agota la cuota, se detiene hasta la siguiente ejecución.
- Google puede retirar modelos: si `GEMINI_MODEL` deja de existir (404), el sistema prueba modelos de respaldo automáticamente (`gemini-3.5-flash`, `gemini-flash-latest`, `gemini-3.1-flash-lite`).

## Seguridad

- Keys solo en `.env` (en `.gitignore`), nunca en código ni respuestas.
- Protección SSRF: se validan IP privadas/reservadas en la URL inicial **y en cada redirección**.
- Rate limiting del endpoint (20 req/min por IP), CORS restringido al origen del frontend, timeouts y límite de tamaño de descarga.
- Errores internos no exponen stack traces al cliente.
