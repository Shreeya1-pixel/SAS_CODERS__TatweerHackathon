# BACKEND — FastAPI Decision Engine

**Port:** `8001` · **Entry:** `safeo_backend/main.py`

Python API that scores untrusted text and returns **ALLOW · WARN · BLOCK**.

## Run

```bash
cd backend
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH="$(pwd)"
uvicorn safeo_backend.main:app --host 127.0.0.1 --port 8001 --reload
```

## Key files

| Path | Role |
|------|------|
| `safeo_backend/main.py` | App entry — registers all routes |
| **routes/** | HTTP API surface |
| `routes/universal.py` | `POST /v1/scan` — universal API |
| `routes/whatsapp.py` | **WhatsApp** Meta webhook + live demo stream |
| `routes/scanner.py` | Website crawl + Risk Passport data |
| `routes/simulate.py` | 28-payload attack benchmark |
| `routes/waf.py` | Legacy WAF + shared request log |
| `routes/erp.py` | ERP gate endpoints |
| `routes/investigations.py` | Investigation room REST |
| `routes/metrics.py` | `/ml/tier-stats`, dashboard stats |
| **core/ml/** | ML pipeline |
| `core/ml/risk_scorer.py` | Tier-1 heuristics + fusion |
| `core/ml/tiered_llm.py` | Tier 2/3 routing |
| `core/ml/tier2_classifier.py` | DistilBERT |
| **agents/** | Investigation agents (policy, forensics, multilingual) |
| `agents/policy_agent.py` | UAE law article mapping |
| `utils/xai_breakdown.py` | Explainable AI audit payloads |
| `routers/ws.py` | WebSocket investigation stream |
| `middleware/auth.py` | Bearer auth on `/v1/*` |

## Integrations (backend)

- **WhatsApp:** `routes/whatsapp.py` — webhook verify, inbound scan, outbound BLOCK reply, demo sequence  
  Full connector checklist (Meta app, 4 env vars, webhook URL, ngrok): [root README § WhatsApp](../README.md#what-you-need--whatsapp-connector-checklist)
- **Jira:** not in backend — escalations are created from the **Odoo ERP module** (`frontend/odoo_module/`)

See root [README.md](../README.md) for full API list.
