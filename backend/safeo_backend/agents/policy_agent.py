"""
PolicyAgent — maps a risk decision to violated compliance policies by jurisdiction.
UAE Federal Law No. 34 of 2021 (Combating Cybercrimes) articles cited explicitly.
Pure logic; no ML model. agent_post logging is handled by investigation_room.py.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# ─── UAE Federal Law No. 34 of 2021 article mapping ──────────────────────────
# Each entry: (article_ref, english_summary, arabic_summary, pattern_hint)
_UAE_ARTICLES: List[Tuple[str, str, str, Optional[re.Pattern]]] = [
    (
        "Article 2",
        "Unauthorised access to an electronic system or network",
        "الوصول غير المصرح به إلى نظام إلكتروني أو شبكة",
        re.compile(r"(?i)(union\s+select|or\s+1=1|drop\s+table|admin['\"]?\s*--|bypass|unauthori[zs]ed)", re.I),
    ),
    (
        "Article 3",
        "Disruption of an information system or network",
        "تعطيل نظام معلومات أو شبكة",
        re.compile(r"(?i)(sleep\s*\(|waitfor\s+delay|benchmark\(|dos\b|denial.of.service|flood)", re.I),
    ),
    (
        "Article 4",
        "Theft or disclosure of confidential electronic data",
        "سرقة أو إفشاء البيانات الإلكترونية السرية",
        re.compile(r"(?i)(select.*(password|api_key|secret|token)|exfil|data.leak|dump)", re.I),
    ),
    (
        "Article 9",
        "Producing or disseminating content that violates public order",
        "إنتاج أو نشر محتوى يخل بالنظام العام",
        re.compile(r"(?i)(hate|discriminat|incit|propaganda|illegal\s+content)", re.I),
    ),
    (
        "Article 12",
        "Electronic fraud and deception",
        "الاحتيال والخداع الإلكتروني",
        re.compile(r"(?i)(phish|spoof|impersonat|social\s+engineer|fake\s+(id|identity))", re.I),
    ),
    (
        "Article 19",
        "Unlawful disclosure of personal data",
        "الإفصاح غير المشروع عن البيانات الشخصية",
        re.compile(r"(?i)(personal\s+data|pii|national\s+id|passport|date.of.birth|email.*dump)", re.I),
    ),
]

_RULES: Dict[str, Dict[str, Any]] = {
    "UAE": {
        "block_threshold": 0.60,
        "warn_threshold":  0.30,
        "policies": [
            "UAE Federal Law No. 34 of 2021 — Combating Cybercrimes",
            "UAE Personal Data Protection Law (Federal Decree-Law No. 45/2021)",
            "UAE Critical Infrastructure Protection Regulations (TRA)",
        ],
        "severity_map": {"block": "critical", "warn": "high", "allow": "info"},
    },
    "EU": {
        "block_threshold": 0.65,
        "warn_threshold":  0.35,
        "policies": [
            "GDPR Article 32 — Security of Processing",
            "NIS2 Directive — Incident Reporting",
            "EU Cybersecurity Act (ENISA framework)",
        ],
        "severity_map": {"block": "critical", "warn": "medium", "allow": "low"},
    },
    "US": {
        "block_threshold": 0.70,
        "warn_threshold":  0.40,
        "policies": [
            "NIST Cybersecurity Framework (CSF 2.0)",
            "SOX Section 302/404 — Financial data integrity",
            "CCPA — Consumer data protection (if California subjects)",
        ],
        "severity_map": {"block": "high", "warn": "medium", "allow": "low"},
    },
    "Global": {
        "block_threshold": 0.70,
        "warn_threshold":  0.40,
        "policies": [
            "ISO/IEC 27001 Control A.14.2.5 — Secure system engineering",
            "OWASP Top 10 (2021)",
        ],
        "severity_map": {"block": "high", "warn": "medium", "allow": "low"},
    },
}


def _match_uae_articles(payload: str, normalised: str) -> List[str]:
    """Return article references from UAE Law No. 34/2021 that this payload triggers."""
    combined = f"{payload} {normalised}"
    matched = []
    for art_ref, en_summary, ar_summary, pattern in _UAE_ARTICLES:
        if pattern and pattern.search(combined):
            matched.append(f"{art_ref} — {en_summary} | {ar_summary}")
    return matched


class PolicyAgent:
    name = "PolicyAgent"

    def check(
        self,
        payload: str,
        context: Dict[str, Any],
        normalised_text: str,
        risk_score: float,
        decision: str,
    ) -> Dict[str, Any]:
        jurisdiction = (context.get("jurisdiction") or "Global").upper()
        rules = _RULES.get(jurisdiction, _RULES["Global"])
        violated: List[str] = []
        dec_lower = (decision or "allow").lower()

        if risk_score >= rules["block_threshold"]:
            violated = list(rules["policies"])
        elif risk_score >= rules["warn_threshold"]:
            violated = rules["policies"][:1]

        # For UAE jurisdiction, add specific article references
        uae_articles: List[str] = []
        uae_block_msg = ""
        if jurisdiction == "UAE" and dec_lower in ("block", "warn"):
            uae_articles = _match_uae_articles(payload, normalised_text or "")
            if uae_articles:
                uae_block_msg = f"This input violates {uae_articles[0].split(' — ')[0]} of UAE Federal Law No. 34 of 2021."

        severity = rules["severity_map"].get(dec_lower, "info")
        if not violated:
            recommendation = "No policy action required — input within acceptable risk threshold."
        elif dec_lower == "block":
            base = "Block and log. Escalate to compliance team within 24 hours."
            recommendation = f"{uae_block_msg} {base}".strip() if uae_block_msg else base
        else:
            recommendation = "Flag for manual review. Retain audit evidence per data retention policy."

        result: Dict[str, Any] = {
            "policies_violated": violated,
            "jurisdiction": jurisdiction,
            "severity": severity,
            "recommendation": recommendation,
        }
        if uae_articles:
            result["uae_articles_triggered"] = uae_articles
        return result
