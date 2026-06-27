"""
Explainable AI (XAI) security audit breakdown for scan responses.
Surfaces threat vectors, highlighted substrings, heuristic triggers, and mitigations.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# Substring patterns for highlighting (English + Arabic + Arabizi)
_HIGHLIGHT_PATTERNS: List[Tuple[str, str]] = [
    ("critical", r"(?i)(ignore\s+(all\s+)?(previous|prior)\s+instructions?)"),
    ("critical", r"(?i)(bypass\s+(all\s+)?(current\s+)?(rules?|filters?|security|restrictions?))"),
    ("critical", r"(?i)(system\s*prompt|jailbreak|dan\s+mode|developer\s+mode)"),
    ("critical", r"(?i)(reveal\s+(the\s+)?(api\s*keys?|secrets?|credentials?|passwords?))"),
    ("critical", r"(?i)(drop\s+table|union\s+select|or\s+1\s*=\s*1)"),
    ("critical", r"(?i)(<script[\s>]|javascript\s*:|onerror\s*=)"),
    ("high", r"(تجاهل|تخطى|تجاوز|أعطني|انسى|انسَ)"),
    ("high", r"(?i)(forget\s+your|act\s+as|pretend\s+you|override\s+)"),
    ("high", r"(?i)(3tiini|ensa\s+el|ta3limat|system\s+prompt)"),
    ("medium", r"https?://[^\s<>\"']+"),
    ("medium", r"(?i)(eval\s*\(|document\.write|innerHTML)"),
    ("medium", r"(--\s*$|;\s*drop|;\s*delete)"),
]

_VECTOR_MAP: Dict[str, Dict[str, str]] = {
    "prompt_injection": {
        "layer": "Prompt Injection / System Override Attempt",
        "vector": "Indirect Prompt Injection (Privilege Escalation Request)",
        "heuristic": "Override command language — attempts to alter LLM baseline instructions.",
    },
    "sql_injection": {
        "layer": "SQL Injection / Database Manipulation",
        "vector": "SQL Injection (Data Exfiltration / Destruction)",
        "heuristic": "SQL metacharacters and tautology patterns detected in user input.",
    },
    "xss": {
        "layer": "Cross-Site Scripting (XSS)",
        "vector": "Reflected / Stored XSS Payload",
        "heuristic": "HTML/JavaScript injection markers in untrusted input.",
    },
    "command_injection": {
        "layer": "OS Command Injection",
        "vector": "Remote Code Execution Attempt",
        "heuristic": "Shell metacharacters or subprocess invocation patterns.",
    },
    "path_traversal": {
        "layer": "Path Traversal / LFI",
        "vector": "Local File Inclusion Attempt",
        "heuristic": "Directory traversal sequences targeting system files.",
    },
    "sensitive_data": {
        "layer": "Sensitive Data Exposure",
        "vector": "Credential / API Key Harvesting",
        "heuristic": "Patterns matching secrets, tokens, or PII exfiltration requests.",
    },
    "obfuscation": {
        "layer": "Encoding / Obfuscation Evasion",
        "vector": "WAF Evasion via Encoded Payload",
        "heuristic": "Multi-layer encoding or char-code obfuscation detected.",
    },
    "erp_privilege_abuse": {
        "layer": "Privilege Escalation / Policy Bypass",
        "vector": "Workflow Override Attempt",
        "heuristic": "Language requesting bypass of approval or security controls.",
    },
}

_DEFAULT_VECTOR = {
    "layer": "Anomalous Input Structure",
    "vector": "Suspicious User Input Pattern",
    "heuristic": "Heuristic and structural signals exceeded risk threshold.",
}

_HEURISTIC_LABELS = [
    "Override commands",
    "Role impersonation",
    "Instruction hierarchy violation",
    "SQL metacharacter injection",
    "Script tag injection",
    "Encoding evasion",
    "Arabic/Arabizi bypass attempt",
    "Multilingual evasion",
    "High entropy payload",
    "Behavioural anomaly",
]


def _primary_category(patterns: List[str]) -> str:
    for p in patterns:
        base = p.split(":")[0].strip().lower().replace(" ", "_")
        for key in _VECTOR_MAP:
            if key in base or base in key:
                return key
        if "prompt" in base:
            return "prompt_injection"
        if "sql" in base:
            return "sql_injection"
        if "xss" in base:
            return "xss"
    if patterns:
        first = patterns[0].lower()
        if "prompt" in first or "injection" in first:
            return "prompt_injection"
        if "sql" in first:
            return "sql_injection"
    return "obfuscation"


def _extract_highlights(payload: str) -> List[Dict[str, str]]:
    if not payload:
        return []
    found: List[Dict[str, str]] = []
    seen_spans: set = set()
    for severity, pat in _HIGHLIGHT_PATTERNS:
        for m in re.finditer(pat, payload):
            span = (m.start(), m.end())
            if span in seen_spans:
                continue
            seen_spans.add(span)
            found.append({
                "text": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "severity": severity,
            })
    found.sort(key=lambda x: x["start"])
    return found


def _matched_heuristics(patterns: List[str], meta: Dict[str, Any], payload: str) -> List[str]:
    labels: List[str] = []
    combined = " ".join(patterns).lower() + " " + payload.lower()
    if re.search(r"(?i)(ignore|bypass|override|forget|system\s*prompt|jailbreak)", combined):
        labels.append("Override commands")
    if re.search(r"(?i)(act\s+as|pretend|you\s+are\s+now|dan\s+mode)", combined):
        labels.append("Role impersonation")
    if re.search(r"(?i)(previous\s+instructions|new\s+instructions)", combined):
        labels.append("Instruction hierarchy violation")
    if re.search(r"(?i)(union|select|drop\s+table|or\s+1\s*=\s*1)", combined):
        labels.append("SQL metacharacter injection")
    if re.search(r"(?i)(<script|javascript:|onerror)", combined):
        labels.append("Script tag injection")
    if re.search(r"(%[0-9a-f]{2}|\\x[0-9a-f]{2}|base64)", combined):
        labels.append("Encoding evasion")
    if re.search(r"[\u0600-\u06FF]", payload):
        labels.append("Arabic/Arabizi bypass attempt")
    if meta.get("script_detected") in ("arabic", "arabizi", "mixed"):
        labels.append("Multilingual evasion")
    if meta.get("evasion_suspected"):
        labels.append("Encoding evasion")
    if not labels:
        labels = [h for h in _HEURISTIC_LABELS[:3] if any(h.lower().split()[0] in combined for h in _HEURISTIC_LABELS)]
    return labels[:6] if labels else ["Structural anomaly scoring"]


def _reasoning_matrix(
    category: str,
    patterns: List[str],
    explanations: List[str],
    payload: str,
    tier_used: int,
) -> str:
    vec = _VECTOR_MAP.get(category, _DEFAULT_VECTOR)
    parts = [
        f"The input contains a structural attempt consistent with {vec['layer'].lower()}.",
        vec["heuristic"],
    ]
    if patterns:
        parts.append(f"Matched signatures: {', '.join(patterns[:4])}.")
    if tier_used == 1:
        parts.append("Tier 1 heuristic engine flagged the payload before any ML inference.")
    elif tier_used == 2:
        parts.append("Tier 2 DistilBERT classifier elevated confidence after heuristic pre-screen.")
    elif tier_used >= 3:
        parts.append("Tier 3 local LLM corroborated the threat assessment.")
    if re.search(r"[\u0600-\u06FF]", payload):
        parts.append("Multilingual pipeline normalised Arabic script before pattern matching.")
    if explanations:
        parts.append(explanations[0][:200])
    return " ".join(parts)


def _suggested_action(decision: str, risk_score: float) -> str:
    d = (decision or "allow").lower()
    if d == "block" or risk_score >= 0.85:
        return "Block user session, quarantine payload structure, log to audit trail, and notify administrator."
    if d == "warn" or risk_score >= 0.5:
        return "Flag for manual review, rate-limit source IP, and retain forensic evidence."
    return "Allow with monitoring — continue behavioural baseline tracking."


def _severity_label(decision: str, risk_score: float) -> str:
    d = (decision or "allow").lower()
    if d == "block" or risk_score >= 0.85:
        return "Critical"
    if d == "warn" or risk_score >= 0.5:
        return "High"
    if risk_score >= 0.3:
        return "Medium"
    return "Low"


def build_xai_breakdown(
    payload: str,
    patterns: List[str],
    explanations: List[str],
    meta: Dict[str, Any],
    risk_score: float,
    decision: str,
    tier_used: int = 1,
    policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build explainable audit object for API and UI consumers."""
    category = _primary_category(patterns)
    vec = _VECTOR_MAP.get(category, _DEFAULT_VECTOR)
    highlights = _extract_highlights(payload)
    heuristics = _matched_heuristics(patterns, meta or {}, payload)
    confidence = round(min(99.9, max(52.0, risk_score * 100 + len(patterns) * 2.5 + len(highlights) * 1.5)), 1)

    trigger_examples = [h["text"] for h in highlights[:5]]
    if not trigger_examples and patterns:
        trigger_examples = [p.split(":")[-1].strip()[:60] for p in patterns[:3]]

    heuristic_trigger = vec["heuristic"]
    if trigger_examples:
        quoted = " / ".join(f'"{t[:40]}"' for t in trigger_examples[:2])
        heuristic_trigger = f"Detected explicit override language ({quoted})."

    llm_summary = _reasoning_matrix(category, patterns, explanations, payload, tier_used)

    mitigation = _suggested_action(decision, risk_score)
    if policy and policy.get("uae_articles_triggered"):
        art = policy["uae_articles_triggered"][0].split(" — ")[0]
        mitigation += f" UAE compliance: cite {art} in block response."

    return {
        "detected_anomaly_layer": vec["layer"],
        "primary_threat_vector": vec["vector"],
        "severity": _severity_label(decision, risk_score),
        "confidence_pct": confidence,
        "heuristic_trigger": heuristic_trigger,
        "triggering_substrings": highlights,
        "highlighted_tokens": trigger_examples,
        "matched_heuristics": heuristics,
        "risk_reasoning_matrix": llm_summary,
        "llm_reasoning_summary": llm_summary,
        "suggested_action": mitigation,
        "recommended_mitigation": mitigation,
        "tier_used": tier_used,
        "category": category,
    }
