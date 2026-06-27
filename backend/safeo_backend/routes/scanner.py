"""
Universal Scanner — website crawl + GitHub repository scan.
Detects exposed forms, POST routes, unsafe patterns, and generates SafeO integration guides.
Returns rich structured data including per-category ML scores, severity breakdown,
security-header audit, and file-type breakdown for visualisation.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/scanner", tags=["Universal Scanner"])


# ── Request models ─────────────────────────────────────────────────────────────

class WebScanRequest(BaseModel):
    url: str


class GithubScanRequest(BaseModel):
    repo_url: str


# ── HTML extractor ─────────────────────────────────────────────────────────────

class _HTMLExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: List[Dict] = []
        self.scripts_ext: List[str] = []   # external src
        self.scripts_inline: int = 0        # count of inline <script> blocks
        self.links_int: int = 0
        self.links_ext: int = 0
        self.meta: Dict[str, str] = {}
        self.cookies_meta: List[str] = []
        self._form: Optional[Dict] = None
        self._in_script: bool = False
        self._base_host: str = ""

    def set_base(self, host: str) -> None:
        self._base_host = host

    def handle_starttag(self, tag: str, attrs: list) -> None:
        d = dict(attrs)
        if tag == "form":
            self._form = {
                "action": d.get("action", ""),
                "method": d.get("method", "GET").upper(),
                "enctype": d.get("enctype", ""),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._form is not None:
            self._form["inputs"].append({
                "name": d.get("name", "unnamed"),
                "type": d.get("type", "text"),
                "placeholder": d.get("placeholder", ""),
            })
        elif tag == "script":
            src = d.get("src", "")
            if src:
                self.scripts_ext.append(src)
            else:
                self._in_script = True
        elif tag == "meta":
            name = (d.get("name") or d.get("property") or d.get("http-equiv") or "").lower()
            content = d.get("content", "")
            if name:
                self.meta[name] = content
        elif tag == "a":
            href = d.get("href", "")
            if href.startswith("http"):
                if self._base_host and self._base_host in href:
                    self.links_int += 1
                else:
                    self.links_ext += 1
            elif href and not href.startswith(("#", "mailto:", "tel:", "javascript:")):
                self.links_int += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script and data.strip():
            self.scripts_inline += 1


# ── Web technology fingerprinting ──────────────────────────────────────────────

_TECH_SIGNATURES: List[tuple] = [
    ("jQuery",       re.compile(r"jquery[.-](\d+[\d.]+)?\.min\.js|jquery\.js", re.I)),
    ("Bootstrap",    re.compile(r"bootstrap[.-][\d.]+\.(min\.)?css|bootstrap\.js", re.I)),
    ("React",        re.compile(r"react\.development\.js|react\.production\.min\.js|__react", re.I)),
    ("Vue.js",       re.compile(r"vue@[\d.]+|vue\.min\.js|vue\.global\.js", re.I)),
    ("Angular",      re.compile(r"angular[.-][\d.]+\.min\.js|ng-version", re.I)),
    ("WordPress",    re.compile(r"wp-content|wp-includes|wordpress", re.I)),
    ("Shopify",      re.compile(r"shopify\.com|cdn\.shopify", re.I)),
    ("Google Analytics", re.compile(r"google-analytics\.com|gtag\(|_ga\b", re.I)),
    ("Google Tag Manager", re.compile(r"googletagmanager\.com|gtm\.js", re.I)),
    ("Cloudflare",   re.compile(r"cloudflare\.com|__cf_bm|cf-ray", re.I)),
    ("Font Awesome", re.compile(r"font-awesome|fontawesome", re.I)),
    ("Tailwind CSS", re.compile(r"tailwindcss|tw-|className=\"[^\"]*(?:flex|grid|text-\w+)", re.I)),
    ("Stripe",       re.compile(r"stripe\.com/v3|Stripe\(", re.I)),
    ("reCAPTCHA",    re.compile(r"recaptcha|g-recaptcha", re.I)),
    ("PHP",          re.compile(r"\.php[?\"']|X-Powered-By.*PHP|php/[\d.]", re.I)),
    ("ASP.NET",      re.compile(r"__VIEWSTATE|aspnet|\.aspx", re.I)),
]

def _detect_technologies(html: str, headers: Dict, scripts: List[str]) -> List[str]:
    combined = html + " " + " ".join(scripts) + " " + " ".join(f"{k}:{v}" for k, v in headers.items())
    return [name for name, pat in _TECH_SIGNATURES if pat.search(combined)]


# ── Pre-built demo profiles for sites that block crawlers ──────────────────────
# These mirror what the site actually has — used when live fetch fails/empty.

_DEMO_PROFILES: Dict[str, Dict] = {
    "testphp.vulnweb.com": {
        "forms_found": [
            {"action": "http://testphp.vulnweb.com/search.php", "method": "GET", "input_count": 1, "risky_fields": ["searchFor"], "risk": "high"},
            {"action": "http://testphp.vulnweb.com/login.php",  "method": "POST", "input_count": 2, "risky_fields": ["uname", "pass"],     "risk": "high"},
            {"action": "http://testphp.vulnweb.com/guestbook.php", "method": "POST", "input_count": 2, "risky_fields": ["name", "comment"], "risk": "high"},
            {"action": "http://testphp.vulnweb.com/signup.php", "method": "POST", "input_count": 5, "risky_fields": ["email","uname","pass","address","phone"], "risk": "high"},
        ],
        "scripts_found": ["http://testphp.vulnweb.com/Flash/add.swf"],
        "risk_items": [
            {"type": "Unprotected Form", "severity": "high", "detail": "Login form POSTs credentials without server-side validation."},
            {"type": "SQL Injection Risk", "severity": "critical", "detail": "Search parameter directly concatenated into SQL query (classic SQLI)."},
            {"type": "XSS Risk", "severity": "high", "detail": "Guestbook reflects user input without encoding — stored XSS."},
            {"type": "Missing Header: Content-Security-Policy", "severity": "medium", "detail": "No CSP — XSS attacks have no browser-level mitigation."},
            {"type": "Missing Header: X-Frame-Options", "severity": "medium", "detail": "Site can be framed — clickjacking risk."},
            {"type": "Missing Header: Strict-Transport-Security", "severity": "medium", "detail": "No HSTS — SSL stripping attacks possible."},
        ],
        "technologies": ["PHP", "jQuery"],
        "links": {"internal": 24, "external": 2},
        "inline_scripts": 3,
        "meta_tags": {"description": "Acunetix Web Vulnerability Scanner test site"},
        "https": False,
        "page_size_kb": 8.4,
        "status_code": 200,
        "security_headers": {
            "csp":               {"present": False, "description": "Prevents XSS and data injection attacks",  "header": "Content-Security-Policy"},
            "hsts":              {"present": False, "description": "Enforces HTTPS connections",               "header": "Strict-Transport-Security"},
            "x_frame_options":   {"present": False, "description": "Prevents clickjacking",                   "header": "X-Frame-Options"},
            "x_content_type":    {"present": False, "description": "Stops MIME-type sniffing",                "header": "X-Content-Type-Options"},
            "referrer_policy":   {"present": False, "description": "Controls referrer information",           "header": "Referrer-Policy"},
            "permissions_policy":{"present": False, "description": "Restricts browser feature access",        "header": "Permissions-Policy"},
            "score": 0, "present_count": 0, "total": 6,
        },
        "recommendations": [
            "Parameterise all SQL queries — current search is directly injectable.",
            "Add SafeO protection to login, signup and guestbook forms immediately.",
            "Enable HTTPS and add HSTS header to prevent SSL stripping.",
            "Add Content-Security-Policy to neutralise reflected XSS.",
            "Deploy SafeO middleware to intercept all form submissions in real time.",
        ],
        "overall_risk": "critical",
        "overall_score": 5,
        "safeo_coverage": [
            "Form → http://testphp.vulnweb.com/login.php",
            "Form → http://testphp.vulnweb.com/signup.php",
            "Form → http://testphp.vulnweb.com/guestbook.php",
            "Form → http://testphp.vulnweb.com/search.php",
        ],
        "category_scores": {"Input Validation": 0, "Data Exposure": 10, "Script Security": 20, "Security Headers": 0, "Transport (HTTPS)": 0},
        "severity_distribution": {"critical": 1, "high": 2, "medium": 3, "low": 0, "info": 0},
        "note": "Demo profile — site blocks automated crawlers. Data reflects known vulnerabilities.",
    },
    "juice-shop.herokuapp.com": {
        "forms_found": [
            {"action": "/rest/user/login", "method": "POST", "input_count": 2, "risky_fields": ["email","password"], "risk": "high"},
            {"action": "/rest/user/register", "method": "POST", "input_count": 3, "risky_fields": ["email","password","securityQuestion"], "risk": "high"},
            {"action": "/api/BasketItems", "method": "POST", "input_count": 2, "risky_fields": ["ProductId","quantity"], "risk": "medium"},
        ],
        "scripts_found": ["https://cdn.jsdelivr.net/npm/angular@1/angular.min.js"],
        "risk_items": [
            {"type": "Unprotected Form", "severity": "high", "detail": "Login and register endpoints accept user input without SafeO validation."},
            {"type": "Prompt Injection Risk", "severity": "high", "detail": "AI chatbot endpoint (/api/chatbot) passes raw user input to LLM."},
            {"type": "XSS Risk", "severity": "high", "detail": "Product search reflects unescaped input in DOM."},
            {"type": "SQL Injection Risk", "severity": "critical", "detail": "Login query vulnerable to classic OR 1=1 bypass."},
            {"type": "Missing Header: Content-Security-Policy", "severity": "medium", "detail": "No CSP — multiple XSS vectors unmitigated."},
        ],
        "technologies": ["Angular", "jQuery", "Node.js/Express"],
        "links": {"internal": 18, "external": 5},
        "inline_scripts": 2,
        "meta_tags": {"description": "OWASP Juice Shop intentionally vulnerable web application"},
        "https": True,
        "page_size_kb": 42.1,
        "status_code": 200,
        "security_headers": {
            "csp":               {"present": False, "description": "Prevents XSS and data injection attacks",  "header": "Content-Security-Policy"},
            "hsts":              {"present": True,  "description": "Enforces HTTPS connections",               "header": "Strict-Transport-Security"},
            "x_frame_options":   {"present": False, "description": "Prevents clickjacking",                   "header": "X-Frame-Options"},
            "x_content_type":    {"present": True,  "description": "Stops MIME-type sniffing",                "header": "X-Content-Type-Options"},
            "referrer_policy":   {"present": False, "description": "Controls referrer information",           "header": "Referrer-Policy"},
            "permissions_policy":{"present": False, "description": "Restricts browser feature access",        "header": "Permissions-Policy"},
            "score": 33, "present_count": 2, "total": 6,
        },
        "recommendations": [
            "Validate all form inputs with SafeO before reaching the database.",
            "Wrap the AI chatbot endpoint with SafeO /v1/scan to block prompt injection.",
            "Add Content-Security-Policy to prevent DOM-based XSS.",
        ],
        "overall_risk": "critical",
        "overall_score": 12,
        "safeo_coverage": [
            "Form → /rest/user/login",
            "Form → /rest/user/register",
            "API → /api/chatbot (LLM)",
        ],
        "category_scores": {"Input Validation": 5, "Data Exposure": 15, "Script Security": 30, "Security Headers": 33, "Transport (HTTPS)": 100},
        "severity_distribution": {"critical": 1, "high": 3, "medium": 1, "low": 0, "info": 0},
        "note": "Demo profile — Heroku dynos sleep; data reflects known OWASP Juice Shop vulnerabilities.",
    },
}

def _match_demo(url: str) -> Optional[Dict]:
    for key, profile in _DEMO_PROFILES.items():
        if key in url:
            return profile
    return None


# ── Code analysis patterns ─────────────────────────────────────────────────────

_FRAMEWORK_PATTERNS: Dict[str, re.Pattern] = {
    "FastAPI":    re.compile(r"from fastapi|import FastAPI|APIRouter", re.I),
    "Flask":      re.compile(r"from flask|import Flask|@app\.route", re.I),
    "Django":     re.compile(r"from django|urlpatterns|HttpResponse", re.I),
    "Express":    re.compile(r"express\(\)|require\(['\"]express['\"]|app\.use\(", re.I),
    "Next.js":    re.compile(r"pages/api|NextApiRequest|getServerSideProps", re.I),
    "React":      re.compile(r"from ['\"]react['\"]|ReactDOM|useState", re.I),
    "Odoo":       re.compile(r"from odoo|models\.Model|http\.route", re.I),
}

_POST_PATTERNS: List[re.Pattern] = [
    re.compile(r'@(?:app|router)\.(?:post|put|patch)\s*\(\s*["\']([^"\']+)', re.I),
    re.compile(r'app\.(?:post|put|patch)\s*\(\s*["\']([^"\']+)', re.I),
    re.compile(r'path\s*\(\s*["\']([^"\']+)["\'].*(?:POST|PUT)', re.I),
    re.compile(r'router\.(?:post|put)\s*\(\s*["\']([^"\']+)', re.I),
]

_SQL_RISK     = re.compile(r'(execute|cursor\.execute|raw\(|SELECT|INSERT|UPDATE|DELETE).*(%s|f["\'])', re.I)
_NO_VALID     = re.compile(r'(request\.(?:POST|GET|args|form)\[|req\.body\.|request\.json\b)', re.I)
_PROMPT_RISK  = re.compile(r'(openai|anthropic|llm|gpt|claude|prompt|chain)\.(complete|create|run|call)', re.I)
_XSS_RISK     = re.compile(r'(innerHTML|dangerouslySetInnerHTML|document\.write|\.html\()', re.I)

_INTEGRATION_GUIDE: Dict[str, str] = {
    "FastAPI": (
        "```python\n"
        "# Option 1 — middleware (protect all routes)\n"
        "from safeo_sdk import SafeOMiddleware\n"
        "app.add_middleware(SafeOMiddleware, api_key='YOUR_KEY')\n\n"
        "# Option 2 — per route\n"
        "from safeo_sdk import safeo_scan\n"
        "@app.post('/contact')\n"
        "async def contact(text: str = Body(...)):\n"
        "    await safeo_scan(text)  # raises HTTPException on BLOCK\n"
        "    ...\n"
        "```"
    ),
    "Flask": (
        "```python\n"
        "from safeo_sdk.flask import SafeOFlask\n"
        "SafeOFlask(app, api_key='YOUR_KEY')\n"
        "```"
    ),
    "Django": (
        "```python\n"
        "# settings.py\n"
        "MIDDLEWARE = ['safeo_sdk.django.SafeOMiddleware', ...]\n"
        "SAFEO_API_KEY = 'YOUR_KEY'\n"
        "```"
    ),
    "Express": (
        "```javascript\n"
        "const { safeoMiddleware } = require('safeo-sdk');\n"
        "app.use(safeoMiddleware({ apiKey: 'YOUR_KEY' }));\n"
        "```"
    ),
    "Next.js": (
        "```typescript\n"
        "// middleware.ts\n"
        "import { safeoEdge } from 'safeo-sdk/edge';\n"
        "export default safeoEdge({ apiKey: 'YOUR_KEY' });\n"
        "export const config = { matcher: '/api/:path*' };\n"
        "```"
    ),
    "React": (
        "```jsx\n"
        "import { useSafeoScan } from 'safeo-sdk/react';\n"
        "const { scan } = useSafeoScan('YOUR_KEY');\n"
        "const handleSubmit = async (text) => {\n"
        "  const r = await scan(text);\n"
        "  if (r.decision === 'BLOCK') return showError();\n"
        "  submitToAPI(text);\n"
        "};\n"
        "```"
    ),
    "Odoo": (
        "```python\n"
        "# Already integrated via the safeo_odoo Odoo module.\n"
        "# See frontend/odoo_module/ for the full implementation.\n"
        "```"
    ),
}

_GENERIC_GUIDE = (
    "```bash\n"
    "# Drop-in REST call before any user-input reaches your app:\n"
    "curl -X POST http://localhost:8001/v1/scan \\\n"
    "  -H 'Content-Type: application/json' \\\n"
    "  -d '{\"input\": \"<USER_TEXT>\", \"context\": {\"source_system\": \"my-app\"}}'\n"
    "```"
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _detect_frameworks(code: str) -> List[str]:
    return [name for name, pat in _FRAMEWORK_PATTERNS.items() if pat.search(code)]


def _scan_code(path: str, content: str) -> List[Dict]:
    findings: List[Dict] = []
    if _SQL_RISK.search(content):
        findings.append({"type": "SQL Injection Risk", "severity": "high",
                         "file": path, "detail": "Unparameterised SQL query detected"})
    if _NO_VALID.search(content) and "safeo" not in content.lower():
        findings.append({"type": "Missing Input Validation", "severity": "medium",
                         "file": path, "detail": "Raw request body accessed without SafeO protection"})
    if _PROMPT_RISK.search(content):
        findings.append({"type": "Prompt Injection Risk", "severity": "high",
                         "file": path, "detail": "LLM API call detected — user input could trigger prompt injection"})
    if _XSS_RISK.search(content):
        findings.append({"type": "XSS Risk", "severity": "medium",
                         "file": path, "detail": "Unsafe HTML rendering detected"})
    return findings


def _extract_routes(path: str, content: str) -> List[Dict]:
    routes = []
    for pat in _POST_PATTERNS:
        for m in pat.finditer(content):
            route = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
            if route and len(route) < 120:
                routes.append({"route": route.strip(), "file": path})
    return routes


def _risk_level(items: List[Dict]) -> str:
    severities = {r["severity"] for r in items}
    if "critical" in severities:
        return "critical"
    if "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    if "low" in severities:
        return "low"
    return "clean"


# ── Security header checks ─────────────────────────────────────────────────────

_SECURITY_HEADERS = [
    ("Content-Security-Policy",       "csp",               "Prevents XSS and data injection attacks"),
    ("Strict-Transport-Security",      "hsts",              "Enforces HTTPS connections"),
    ("X-Frame-Options",               "x_frame_options",   "Prevents clickjacking"),
    ("X-Content-Type-Options",        "x_content_type",    "Stops MIME-type sniffing"),
    ("Referrer-Policy",               "referrer_policy",   "Controls referrer information"),
    ("Permissions-Policy",            "permissions_policy","Restricts browser feature access"),
]


def _check_security_headers(response_headers: Dict) -> Dict[str, Any]:
    headers_lower = {k.lower(): v for k, v in response_headers.items()}
    result = {}
    present = 0
    for header, key, desc in _SECURITY_HEADERS:
        found = header.lower() in headers_lower
        result[key] = {"present": found, "description": desc, "header": header}
        if found:
            present += 1
    result["score"] = round(present / len(_SECURITY_HEADERS) * 100)
    result["present_count"] = present
    result["total"] = len(_SECURITY_HEADERS)
    return result


def _category_scores_web(forms: List[Dict], risk_items: List[Dict], headers_audit: Dict, https: bool) -> Dict[str, int]:
    """Return 0-100 scores per security category (higher = safer)."""

    def _penalty(items, types):
        sev_map = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 0}
        return sum(sev_map.get(r["severity"], 0) for r in items if r["type"] in types)

    input_val = max(0, 100 - _penalty(risk_items, {"Unprotected Form", "Missing Input Validation"})
                    - len([f for f in forms if f["method"] == "POST"]) * 8)

    data_exp = max(0, 100 - _penalty(risk_items, {"API Key Exposed", "Hardcoded Credential",
                                                    "Potential Key Exposure", "Server-side Code Exposed"}))

    script_sec = max(0, 100 - _penalty(risk_items, {"eval() in Script", "Third-party Script", "XSS Risk"})
                     - len([r for r in risk_items if "script" in r["type"].lower()]) * 6)

    header_sec = headers_audit.get("score", 0)

    transport = 100 if https else 0

    return {
        "Input Validation":  min(100, input_val),
        "Data Exposure":     min(100, data_exp),
        "Script Security":   min(100, script_sec),
        "Security Headers":  header_sec,
        "Transport (HTTPS)": transport,
    }


def _severity_distribution(items: List[Dict]) -> Dict[str, int]:
    dist: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in items:
        sev = item.get("severity", "info")
        dist[sev] = dist.get(sev, 0) + 1
    return dist


def _overall_security_score(category_scores: Dict[str, int]) -> int:
    """Weighted average — transport and headers weigh less than input validation."""
    weights = {
        "Input Validation":  0.35,
        "Data Exposure":     0.30,
        "Script Security":   0.15,
        "Security Headers":  0.12,
        "Transport (HTTPS)": 0.08,
    }
    total = sum(category_scores.get(k, 50) * w for k, w in weights.items())
    return round(total)


# ── GitHub category scoring ────────────────────────────────────────────────────

def _category_scores_github(findings: List[Dict], routes: List[Dict], scanned: int) -> Dict[str, int]:
    def _count(ftype):
        return sum(1 for f in findings if ftype.lower() in f["type"].lower())

    sql_issues   = _count("sql")
    prompt_issues = _count("prompt")
    xss_issues   = _count("xss")
    val_issues   = _count("validation")

    route_density = min(40, len(routes) * 4) if scanned else 0

    return {
        "SQL Safety":          max(0, 100 - sql_issues * 30 - route_density // 2),
        "Input Validation":    max(0, 100 - val_issues * 25 - route_density),
        "Prompt Injection":    max(0, 100 - prompt_issues * 35),
        "XSS Protection":      max(0, 100 - xss_issues * 20),
        "Route Coverage":      max(0, 100 - min(100, len(routes) * 5)),
    }


def _file_type_breakdown(files_scanned: List[str]) -> Dict[str, int]:
    breakdown: Dict[str, int] = {}
    ext_map = {".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
               ".jsx": "React JSX", ".tsx": "React TSX"}
    for path in files_scanned:
        for ext, label in ext_map.items():
            if path.endswith(ext):
                breakdown[label] = breakdown.get(label, 0) + 1
                break
    return breakdown


# ── Website scanner ────────────────────────────────────────────────────────────

@router.post("/website")
async def scan_website(req: WebScanRequest) -> Dict:
    """Crawl a public URL, detect forms and unsafe patterns, return a rich security report."""
    import time
    url = req.url.strip()
    if not url.startswith("http"):
        url = "https://" + url
    from urllib.parse import urlparse
    host = urlparse(url).netloc

    # Check for demo profile first
    demo = _match_demo(url)

    base: Dict[str, Any] = {
        "url": url,
        "forms_found": [],
        "scripts_found": [],
        "risk_items": [],
        "recommendations": [],
        "overall_risk": "unknown",
        "overall_score": 50,
        "safeo_coverage": [],
        "security_headers": {},
        "category_scores": {},
        "severity_distribution": {},
        "https": url.startswith("https"),
        "page_size_kb": 0,
        "technologies": [],
        "links": {"internal": 0, "external": 0},
        "inline_scripts": 0,
        "meta_tags": {},
        "response_time_ms": 0,
        "cookie_flags": {},
    }

    html = ""
    response_headers: Dict = {}
    fetch_ok = False
    t0 = time.time()

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=12.0) as client:
            resp = await client.get(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; SafeO-Scanner/2.0; +https://safeo.ai/bot)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                },
            )
            html = resp.text
            response_headers = dict(resp.headers)
            base["https"] = str(resp.url).startswith("https")
            base["page_size_kb"] = round(len(html.encode()) / 1024, 1)
            base["status_code"] = resp.status_code
            base["response_time_ms"] = round((time.time() - t0) * 1000)
            fetch_ok = resp.status_code < 500 and len(html) > 200

            # Cookie flag audit
            set_cookie = response_headers.get("set-cookie", "")
            if set_cookie:
                base["cookie_flags"] = {
                    "HttpOnly": "httponly" in set_cookie.lower(),
                    "Secure":   "secure" in set_cookie.lower(),
                    "SameSite": "samesite" in set_cookie.lower(),
                }
    except Exception as exc:
        base["fetch_error"] = str(exc)

    # If crawl failed or returned nothing useful, use demo profile
    if demo and not fetch_ok:
        return {**base, **demo, "url": url, "demo_mode": True}

    # Security header audit
    base["security_headers"] = _check_security_headers(response_headers)

    # HTML parse
    parser = _HTMLExtractor()
    parser.set_base(host)
    parser.feed(html)

    base["links"] = {"internal": parser.links_int, "external": parser.links_ext}
    base["inline_scripts"] = parser.scripts_inline
    base["meta_tags"] = parser.meta

    # Technology detection
    base["technologies"] = _detect_technologies(html, response_headers, parser.scripts_ext)

    _risky_types = {"password", "email", "text", "search", "tel", "number", "textarea", "url"}
    for form in parser.forms:
        risky_inputs = [i for i in form["inputs"] if i["type"] in _risky_types]
        risk = "high" if form["method"] == "POST" and risky_inputs else "medium" if risky_inputs else "low"
        action = urljoin(url, form["action"]) if form["action"] else url
        entry = {
            "action": action,
            "method": form["method"],
            "input_count": len(form["inputs"]),
            "risky_fields": [i["name"] or i["type"] for i in risky_inputs][:5],
            "risk": risk,
        }
        base["forms_found"].append(entry)
        if risk in ("high", "medium"):
            base["risk_items"].append({
                "type": "Unprotected Form",
                "severity": risk,
                "detail": f"Form POST to {action} accepts {', '.join(entry['risky_fields'][:3]) or 'user input'} without SafeO validation.",
            })
            base["safeo_coverage"].append(f"Form → {action}")

    for src in parser.scripts_ext:
        if src.startswith("http"):
            base["scripts_found"].append(src)

    # Content checks
    if re.search(r"api[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}", html, re.I):
        base["risk_items"].append({"type": "API Key Exposed", "severity": "critical",
            "detail": "Possible API key found in page HTML — move to server-side env vars immediately."})
    if re.search(r"password\s*=\s*['\"][^'\"]{4,}", html, re.I):
        base["risk_items"].append({"type": "Hardcoded Credential", "severity": "critical",
            "detail": "Hardcoded password pattern in source."})
    if "eval(" in html and "<script" in html:
        base["risk_items"].append({"type": "eval() in Script", "severity": "medium",
            "detail": "eval() in inline script — potential XSS vector."})
    if re.search(r"(localStorage|sessionStorage)\.(setItem|getItem)", html):
        base["risk_items"].append({"type": "Client-side Storage", "severity": "medium",
            "detail": "localStorage/sessionStorage — avoid storing tokens or PII client-side."})
    if re.search(r"document\.write\s*\(", html):
        base["risk_items"].append({"type": "XSS Risk — document.write", "severity": "high",
            "detail": "document.write() — classic XSS injection point."})
    if base["cookie_flags"] and not base["cookie_flags"].get("HttpOnly"):
        base["risk_items"].append({"type": "Cookie Missing HttpOnly", "severity": "medium",
            "detail": "Session cookie accessible via JavaScript — XSS can steal it."})
    if base["cookie_flags"] and not base["cookie_flags"].get("Secure"):
        base["risk_items"].append({"type": "Cookie Missing Secure Flag", "severity": "medium",
            "detail": "Cookie sent over HTTP — vulnerable to interception."})
    if not parser.forms:
        base["risk_items"].append({"type": "No Forms Detected", "severity": "info",
            "detail": "No HTML forms found — dynamic forms rendered by JS are not visible here."})

    # Header findings
    for key, val in base["security_headers"].items():
        if isinstance(val, dict) and not val.get("present"):
            base["risk_items"].append({
                "type": f"Missing Header: {val['header']}",
                "severity": "medium",
                "detail": val["description"],
            })

    # Scores
    base["overall_risk"] = _risk_level(base["risk_items"])
    base["severity_distribution"] = _severity_distribution(base["risk_items"])
    base["category_scores"] = _category_scores_web(
        base["forms_found"], base["risk_items"], base["security_headers"], base["https"]
    )
    base["overall_score"] = _overall_security_score(base["category_scores"])

    # Recommendations
    recs = []
    if any(r["type"] == "Unprotected Form" for r in base["risk_items"]):
        recs.append("Add SafeO protection to all POST forms — one REST call per submission.")
    if any(r["severity"] == "critical" for r in base["risk_items"]):
        recs.append("Critical issues found — remove hardcoded credentials and API keys immediately.")
    if not base["security_headers"].get("csp", {}).get("present"):
        recs.append("Add Content-Security-Policy header to prevent XSS.")
    if not base["https"]:
        recs.append("Enable HTTPS — all data in transit is unencrypted.")
    if any(r["severity"] in ("high", "critical") for r in base["risk_items"]):
        recs.append("Deploy SafeO middleware to intercept all user submissions in real time.")
    recs.append("Use SafeO /v1/scan before passing any user input to databases or LLMs.")
    base["recommendations"] = recs

    try:
        from .waf import append_request_log
        import uuid
        from datetime import datetime, timezone
        
        append_request_log({
            "request_id": f"scan-{uuid.uuid4().hex[:8]}",
            "module": "website_scanner",
            "source_system": "website_scanner",
            "risk_score": (100 - base["overall_score"]) / 100.0,
            "decision": "warn" if base["overall_risk"] in ("high", "critical") else "allow",
            "user_id": "anonymous",
            "type": "audit_scan",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": f"Website scan: {url}",
            "channel": "web",
            "tier_used": 1
        })
    except Exception as e:
        import logging
        logging.getLogger("safeo.scanner").error(f"Failed to log website scan: {e}")

    return base


# ── GitHub scanner ─────────────────────────────────────────────────────────────

@router.post("/github")
async def scan_github(req: GithubScanRequest) -> Dict:
    """Scan a public GitHub repo for POST routes, unsafe patterns, and generate SafeO integration."""
    repo_url = req.repo_url.strip().rstrip("/")
    m = re.search(r"github\.com[/:]([^/\s]+)/([^/\s\.]+)", repo_url)
    if not m:
        return {"error": "Invalid GitHub URL — expected https://github.com/owner/repo"}

    owner, repo = m.group(1), m.group(2).replace(".git", "")
    api_base = f"https://api.github.com/repos/{owner}/{repo}"

    base: Dict[str, Any] = {
        "repo": f"{owner}/{repo}",
        "repo_url": f"https://github.com/{owner}/{repo}",
        "frameworks_detected": [],
        "post_routes": [],
        "security_findings": [],
        "integration_guide": "",
        "safeo_integration_score": 0,
        "scanned_files": 0,
        "summary": "",
        "category_scores": {},
        "severity_distribution": {},
        "file_type_breakdown": {},
        "findings_by_type": {},
        "overall_score": 50,
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            hdr = {"Accept": "application/vnd.github.v3+json", "User-Agent": "SafeO-Scanner/2.0"}

            # Fetch file tree
            tree_r = await client.get(f"{api_base}/git/trees/HEAD?recursive=1", headers=hdr)
            if tree_r.status_code == 404:
                return {**base, "error": "Repository not found or private."}
            if tree_r.status_code == 403:
                return {**base, "error": "GitHub rate limit hit. Try again in 60 seconds."}
            tree = tree_r.json().get("tree", [])

            # Select relevant source files
            exts = (".py", ".js", ".ts", ".jsx", ".tsx")
            skip = ("node_modules", "dist/", "build/", ".min.", "vendor/")
            files = [
                f for f in tree
                if f.get("type") == "blob"
                and any(f["path"].endswith(e) for e in exts)
                and not any(s in f["path"] for s in skip)
            ][:30]

            all_code = ""
            raw_hdr = {**hdr, "Accept": "application/vnd.github.v3.raw"}
            for file in files:
                try:
                    cr = await client.get(f"{api_base}/contents/{file['path']}", headers=raw_hdr)
                    if cr.status_code == 200:
                        code = cr.text
                        all_code += code + "\n"
                        base["scanned_files"] += 1
                        base["security_findings"].extend(_scan_code(file["path"], code))
                        base["post_routes"].extend(_extract_routes(file["path"], code))
                except Exception:
                    continue

            base["frameworks_detected"] = _detect_frameworks(all_code)
            base["file_type_breakdown"] = _file_type_breakdown(
                [f["path"] for f in files[:base["scanned_files"]]]
            )

    except Exception as exc:
        return {**base, "error": str(exc)}

    # Deduplicate findings and routes
    seen_findings: set = set()
    unique_findings = []
    for f in base["security_findings"]:
        key = (f["type"], f["file"])
        if key not in seen_findings:
            seen_findings.add(key)
            unique_findings.append(f)
    base["security_findings"] = unique_findings[:20]

    seen_routes: set = set()
    unique_routes = []
    for r in base["post_routes"]:
        if r["route"] not in seen_routes:
            seen_routes.add(r["route"])
            unique_routes.append(r)
    base["post_routes"] = unique_routes[:15]

    # Integration guide
    primary = base["frameworks_detected"][0] if base["frameworks_detected"] else None
    base["integration_guide"] = _INTEGRATION_GUIDE.get(primary, _GENERIC_GUIDE)

    # Scores and distributions
    base["severity_distribution"] = _severity_distribution(base["security_findings"])
    base["category_scores"] = _category_scores_github(
        base["security_findings"], base["post_routes"], base["scanned_files"]
    )
    # Overall score: avg of category scores
    if base["category_scores"]:
        base["overall_score"] = round(sum(base["category_scores"].values()) / len(base["category_scores"]))
    # SafeO integration value score (how much SafeO would help)
    integration_score = min(100, len(base["security_findings"]) * 15 + len(base["post_routes"]) * 8)
    base["safeo_integration_score"] = integration_score

    # Findings grouped by type for charts
    by_type: Dict[str, int] = {}
    for f in base["security_findings"]:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
    base["findings_by_type"] = by_type

    high = sum(1 for f in base["security_findings"] if f["severity"] == "high")
    critical = sum(1 for f in base["security_findings"] if f["severity"] == "critical")
    base["summary"] = (
        f"Scanned {base['scanned_files']} files in {owner}/{repo}. "
        f"Found {len(base['post_routes'])} POST route(s) and "
        f"{len(base['security_findings'])} security issue(s) "
        f"({critical} critical, {high} high). "
        f"Primary framework: {primary or 'unknown'}. "
        f"Overall security score: {base['overall_score']}/100."
    )

    try:
        from .waf import append_request_log
        import uuid
        from datetime import datetime, timezone
        
        append_request_log({
            "request_id": f"repo-{uuid.uuid4().hex[:8]}",
            "module": "github_scanner",
            "source_system": "github_scanner",
            "risk_score": (100 - base["overall_score"]) / 100.0,
            "decision": "warn" if (critical > 0 or high > 0) else "allow",
            "user_id": "anonymous",
            "type": "audit_scan",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": f"GitHub scan: {owner}/{repo}",
            "channel": "github",
            "tier_used": 1
        })
    except Exception as e:
        import logging
        logging.getLogger("safeo.scanner").error(f"Failed to log github scan: {e}")

    return base
