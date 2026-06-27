# Jira ERP Alerts

SafeO creates Jira alert tickets when Odoo ERP input is **BLOCKED** with risk `>= 70%`.

## Why This Matters

Schools and small businesses often do not have a security operations center. A BLOCK decision needs to become an action item that an admin can review.

Relevant context:

- Education was the **#1 most targeted industry globally** in 2024.
- Education organizations saw **3,086 weekly cyberattacks** on average.
- **63%** of K-12 organizations were hit by ransomware in 2024.
- Mean lower-education ransomware recovery cost was **$3.76M**.

## Code Map

| File | Role |
|------|------|
| `frontend/odoo_module/securec_odoo/models/securec_log.py` | Creates Jira issue in `_try_create_jira_ticket()` |
| `frontend/odoo_module/securec_odoo/models/securec_settings.py` | Stores Jira URL, email, token, project |
| `frontend/odoo_module/securec_odoo/views/securec_settings_views.xml` | Odoo Settings UI |
| `frontend/odoo_module/securec_odoo/views/securec_log_views.xml` | Shows ticket ID and URL |
| `frontend/odoo_module/securec_odoo/static/src/js/dashboard.js` | Risk → Action Jira panel |

## Configure in Odoo

Open:

```text
Settings → SafeO → Jira Integration
```

Set:

| Field | Example |
|-------|---------|
| Jira Base URL | `https://yourorg.atlassian.net` |
| Jira User Email | `admin@yourorg.com` |
| Jira API Token | Atlassian API token |
| Jira Project Key | `SEC` |

## What Triggers a Ticket

In `securec.log`, Jira is created only when:

```text
decision == block
risk_score >= 0.70
Jira settings are configured
```

## Ticket Payload

The Jira ticket includes:

- Risk score
- Decision
- ERP module
- User
- Timestamp
- Truncated suspicious input
- AI explanation
- Matched patterns
- UAE policy context when available

## Demo Verification

1. Start SafeO backend on `http://127.0.0.1:8001`.
2. Start Odoo on `http://127.0.0.1:8069`.
3. Install or upgrade **SafeO — ERP Risk Decision Engine**.
4. Configure Jira settings.
5. Open `http://127.0.0.1:8069/odoo/safeo`.
6. In Sandbox, paste:

```text
' OR 1=1; DROP TABLE students;--
```

Expected:

- SafeO returns **BLOCK**.
- Security Logs show a BLOCK entry.
- Jira ticket `SEC-*` appears if credentials are valid.
- The Risk → Action panel shows the ticket ID/link.
