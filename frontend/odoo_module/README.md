# SafeO — Odoo integration module

**Technical folder name:** `securec_odoo` (Odoo uses the directory name as the add-on technical name — do not rename without updating all XML IDs and imports).

This is the **SafeO ERP Protection Layer** for **Odoo 19**: native models, menus, OWL dashboard, HTTP hooks, and CRM integration that call the FastAPI decision engine.

## What it hooks into

| Area | Mechanism |
|------|-----------|
| **CRM** | `crm.lead` inherit — scores lead text before save |
| **HTTP / website** | `ir.http` inherit + website controllers — optional global monitor |
| **Auth / audit** | Login events → `securec.audit.log` |
| **Settings** | `res.config.settings` — `securec.api_url` points to FastAPI |
| **Dashboard** | Client action loads OWL `SafeODashboard` |

## Install (judge checklist)

1. **PostgreSQL** running; create a database.
2. **Backend** running on `http://127.0.0.1:8001` (see `SafeO/README.md`).
3. Start Odoo with addons path including **this folder’s parent** `odoo_module`:

   ```bash
   ./odoo-bin -c odoo.conf -d your_db
   ```

   Example `addons_path` fragment:

   `...,/path/to/repo/SafeO/odoo_module`

4. **Apps** → remove “Apps” filter → search **SafeO** → **Install**.
5. **Settings → SafeO / General** → confirm **API URL** = `http://127.0.0.1:8001`.

## Jira ERP alerts (BLOCK → ticket)

When SafeO **BLOCK**s ERP input with risk `>= 70%`, Odoo auto-creates a Jira alert ticket.

| File | Role |
|------|------|
| `models/securec_log.py` | `_try_create_jira_ticket()` on `securec.log` create |
| `models/securec_settings.py` | Jira URL, email, API token, project key |
| `views/securec_settings_views.xml` | Settings → **Jira Integration** block |
| `views/securec_log_views.xml` | Shows `jira_ticket_id` + link |
| `static/src/js/dashboard.js` | **Risk → Action** panel with Jira ticket |
| `controllers/main.py` | `/safeo/logs` returns Jira fields |

**Configure in Odoo:** Settings → SafeO → Jira Integration

- Jira Base URL: `https://yourorg.atlassian.net`
- Jira User Email + API Token
- Project Key: `SEC`

**Demo:** Sandbox → paste `' OR 1=1; DROP TABLE students;--` → BLOCK → check dashboard **Risk → Action** panel and Security Logs filter **Jira Alert Created**.

## Connection to FastAPI

- `controllers/main.py` — JSON-RPC `/safeo/metrics`, `/safeo/logs`, `/safeo/context`, `/safeo/erp_module_summary`, etc., forwarding to the configured `securec.api_url`.
- `models/crm_lead.py` — POSTs lead payload to `/erp/crm/lead` on the engine.

No secrets in the module; optional LLM keys live only on the FastAPI host (`.env`).
