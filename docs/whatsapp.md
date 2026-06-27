# WhatsApp Connector

SafeO connects to WhatsApp Business Cloud API so incoming customer messages can be scanned before they trigger risky business actions.

## What It Blocks

SafeO returns **ALLOW / WARN / BLOCK** for WhatsApp text and can block:

- Phishing links
- OTP theft attempts
- Fake payment confirmation messages
- Impersonation of support, banks, or delivery services
- Prompt-injection messages aimed at AI-enabled support flows
- Arabic / Arabizi evasion patterns

## Code Map

| File | Role |
|------|------|
| `backend/safeo_backend/routes/whatsapp.py` | Meta webhook verification, inbound scan, BLOCK reply |
| `frontend/website/src/pages/WhatsappDemo.jsx` | Judge-visible WhatsApp flow |
| `backend/safeo_backend/routes/universal.py` | Shared `/v1/scan` decision path |

## Live Meta Setup

Create a Meta Developer app and add the **WhatsApp** product.

You need:

| Item | Where |
|------|-------|
| Meta Business account | https://business.facebook.com |
| WhatsApp Business phone number | Meta WhatsApp API setup |
| Phone number ID | WhatsApp → API Setup |
| Access token | WhatsApp → API Setup or System User token |
| App secret | App Settings → Basic |
| Public HTTPS backend URL | Deployed backend or ngrok tunnel |

## Backend Env Vars

Set these before starting FastAPI:

```bash
export WHATSAPP_PHONE_NUMBER_ID="123456789012345"
export WHATSAPP_ACCESS_TOKEN="EAAxxxxxxxx..."
export WHATSAPP_VERIFY_TOKEN="my_safeo_verify_token_2026"
export WHATSAPP_APP_SECRET="abc123def456..."
```

Then run:

```bash
cd backend
source .venv/bin/activate
export PYTHONPATH="$(pwd)"
uvicorn safeo_backend.main:app --host 0.0.0.0 --port 8001 --reload
```

## Meta Webhook

In Meta Console, set:

| Meta field | SafeO value |
|------------|-------------|
| Callback URL | `https://<your-public-host>/webhooks/whatsapp` |
| Verify token | Same as `WHATSAPP_VERIFY_TOKEN` |
| Fields | Subscribe to `messages` |

Meta verifies with:

```text
GET /webhooks/whatsapp?hub.mode=subscribe&hub.verify_token=...&hub.challenge=...
```

SafeO returns the challenge when the token matches.

## Local Tunnel

```bash
ngrok http 8001
```

Use the HTTPS URL from ngrok as the Meta callback:

```text
https://xxxx.ngrok-free.app/webhooks/whatsapp
```

## BLOCK Reply

When SafeO blocks a message, it uses:

```text
POST https://graph.facebook.com/v19.0/{WHATSAPP_PHONE_NUMBER_ID}/messages
Authorization: Bearer {WHATSAPP_ACCESS_TOKEN}
```

The reply is customer-safe and avoids security jargon.
