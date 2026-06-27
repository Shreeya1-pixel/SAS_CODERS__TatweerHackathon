# FRONTEND — Demo UI + Odoo ERP Module

Two frontends share the same backend (`:8001`).

## 1. WEBSITE — React demo (`frontend/website/`)

**Port:** `5174` · **Stack:** Vite + React

```bash
cd frontend/website
npm install && npm run dev
```

Open http://127.0.0.1:5174 — proxies `/api/*` → backend.

| File | Page / role |
|------|-------------|
| `src/pages/Home.jsx` | Landing |
| `src/pages/WebScanner.jsx` | Website scan + Risk Passport + snippets |
| `src/pages/WhatsappDemo.jsx` | **WhatsApp Business simulator** |
| `src/pages/RiskAssessment.jsx` | Am I at Risk? stepper quiz |
| `src/pages/Dashboard.jsx` | Live stats |
| `src/pages/Logs.jsx` | Risk engine logs |
| `src/pages/Connect.jsx` | ERP / API connect |
| `src/components/Layout.jsx` | Nav |
| `src/components/AISecurityAuditLog.jsx` | XAI audit card |
| `src/styles/safeo.css` | Global styles |

## 2. ODOO ERP — School / business module (`frontend/odoo_module/`)

**Port:** `8069` · **Module:** `securec_odoo`

| File | Role |
|------|------|
| `models/securec_log.py` | Audit log + **auto Jira ticket** on BLOCK |
| `models/securec_settings.py` | API URL, thresholds, **Jira credentials** |
| `models/crm_lead.py` | CRM input protection |
| `models/ir_http_monitor.py` | Request interception |
| `static/src/js/dashboard.js` | OWL dashboard (Sandbox, Investigations) |
| `views/securec_settings_views.xml` | Settings UI incl. Jira block |

Install in Odoo → Settings → SafeO API URL `http://127.0.0.1:8001`
