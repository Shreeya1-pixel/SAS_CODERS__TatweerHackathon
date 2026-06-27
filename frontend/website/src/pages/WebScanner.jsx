/**
 * Website Security Scanner — with rich ML analysis and recharts visuals
 */
import { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";
import { useToast } from "../components/Toast";
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer,
  PieChart, Pie, Cell, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from "recharts";

const API = "/api";

const SEV_COLORS = { critical: "#dc2626", high: "#ea580c", medium: "#ca8a04", low: "#16a34a", info: "#6b7280" };

const TECH_INFO = {
  jQuery:                { risk: "medium", note: "Older versions have known XSS vulnerabilities. Ensure version ≥ 3.7." },
  Bootstrap:             { risk: "low",    note: "UI framework — no direct security risk if kept updated." },
  React:                 { risk: "low",    note: "Escapes HTML by default. Risk arises with dangerouslySetInnerHTML." },
  "Vue.js":              { risk: "low",    note: "Safe by default. v-html directive can introduce XSS." },
  Angular:               { risk: "low",    note: "Built-in XSS protection. Watch for bypassSecurityTrust* misuse." },
  WordPress:             { risk: "high",   note: "High attack surface — plugin vulnerabilities are the #1 exploit vector." },
  Shopify:               { risk: "low",    note: "Hosted platform — security managed by Shopify." },
  "Google Analytics":    { risk: "medium", note: "Third-party script with broad DOM access — data privacy concern." },
  "Google Tag Manager":  { risk: "medium", note: "Can inject arbitrary scripts — a compromised GTM account is critical." },
  Cloudflare:            { risk: "low",    note: "WAF and CDN in place — good baseline protection." },
  "Font Awesome":        { risk: "low",    note: "CDN dependency — low risk, but monitor for supply chain attacks." },
  "Tailwind CSS":        { risk: "low",    note: "CSS framework — no security risk." },
  Stripe:                { risk: "low",    note: "PCI-DSS compliant payment SDK — low risk if used correctly." },
  reCAPTCHA:             { risk: "low",    note: "Bot protection present — good signal." },
  PHP:                   { risk: "high",   note: "Server-side PHP — SQL injection and file inclusion risks if unpatched." },
  "ASP.NET":             { risk: "medium", note: "Watch for ViewState tampering and outdated framework versions." },
  "Node.js/Express":     { risk: "medium", note: "No built-in input sanitisation — SafeO middleware strongly recommended." },
};
const RADAR_COLOR = "#E8202A";

const SAMPLE_URLS = [
  "https://example.com",
  "https://httpbin.org",
  "https://neverssl.com",
];

// ── Score Gauge (SVG arc) ──────────────────────────────────────────────────────
function ScoreGauge({ score, label }) {
  const r = 52;
  const cx = 70; const cy = 70;
  const totalArc = Math.PI; // half-circle
  const angle = (score / 100) * totalArc;
  const x = cx - r * Math.cos(Math.PI - angle);
  const y = cy - r * Math.sin(Math.PI - angle);
  const color = score >= 70 ? "#16a34a" : score >= 40 ? "#ca8a04" : "#dc2626";
  const trackD = `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`;
  const fillD  = score > 0
    ? `M ${cx - r} ${cy} A ${r} ${r} 0 ${angle > Math.PI / 2 ? 1 : 0} 1 ${x} ${y}`
    : "";
  return (
    <svg viewBox="0 0 140 85" width="160" height="100">
      <path d={trackD} fill="none" stroke="#e5e7eb" strokeWidth="10" strokeLinecap="round" />
      {fillD && <path d={fillD} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round" />}
      <text x={cx} y={cy - 4} textAnchor="middle" fontSize="22" fontWeight="800" fill={color}>{score}</text>
      <text x={cx} y={cy + 12} textAnchor="middle" fontSize="10" fill="#6b7280">{label}</text>
    </svg>
  );
}

// ── Severity donut ─────────────────────────────────────────────────────────────
function SeverityDonut({ distribution }) {
  const data = Object.entries(distribution)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ name: k.charAt(0).toUpperCase() + k.slice(1), value: v, fill: SEV_COLORS[k] || "#9ca3af" }));
  if (!data.length) return <p className="safeo-muted" style={{ fontSize: 12 }}>No issues found.</p>;
  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Pie data={data} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" label={({ name, value }) => `${name}: ${value}`} labelLine={false}>
          {data.map((d, i) => <Cell key={i} fill={d.fill} />)}
        </Pie>
        <Tooltip formatter={(v, n) => [v, n]} />
        <Legend />
      </PieChart>
    </ResponsiveContainer>
  );
}

// ── Category radar ─────────────────────────────────────────────────────────────
function CategoryRadar({ scores }) {
  const data = Object.entries(scores).map(([k, v]) => ({ subject: k, score: v, fullMark: 100 }));
  if (!data.length) return null;
  return (
    <ResponsiveContainer width="100%" height={240}>
      <RadarChart data={data}>
        <PolarGrid stroke="#e5e7eb" />
        <PolarAngleAxis dataKey="subject" tick={{ fontSize: 11, fill: "#374151" }} />
        <PolarRadiusAxis angle={90} domain={[0, 100]} tick={{ fontSize: 9 }} />
        <Radar name="Security Score" dataKey="score" stroke={RADAR_COLOR} fill={RADAR_COLOR} fillOpacity={0.18} strokeWidth={2} />
        <Tooltip formatter={(v) => [`${v}/100`, "Score"]} />
      </RadarChart>
    </ResponsiveContainer>
  );
}

// ── Security headers bar ───────────────────────────────────────────────────────
function HeadersBar({ headers }) {
  if (!headers || !headers.present_count) return null;
  const items = Object.entries(headers)
    .filter(([k, v]) => typeof v === "object" && "present" in v)
    .map(([, v]) => ({ name: v.header.replace("Content-Security-Policy", "CSP").replace("Strict-Transport-Security", "HSTS").replace("X-Frame-Options","X-Frame").replace("X-Content-Type-Options","X-Content-Type").replace("Referrer-Policy","Referrer").replace("Permissions-Policy","Permissions"), value: v.present ? 1 : 0 }));
  return (
    <ResponsiveContainer width="100%" height={160}>
      <BarChart data={items} layout="vertical" margin={{ left: 10, right: 20, top: 4, bottom: 4 }}>
        <CartesianGrid horizontal={false} stroke="#f3f4f6" />
        <XAxis type="number" domain={[0, 1]} hide />
        <YAxis type="category" dataKey="name" tick={{ fontSize: 11 }} width={100} />
        <Bar dataKey="value" radius={[0, 4, 4, 0]}>
          {items.map((d, i) => <Cell key={i} fill={d.value ? "#16a34a" : "#fecdd3"} />)}
        </Bar>
        <Tooltip formatter={(v) => [v ? "Present ✓" : "Missing ✗", "Header"]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

function RiskBadge({ level }) {
  const map = {
    critical: { cls: "risk-critical", label: "CRITICAL" },
    high:     { cls: "risk-high",     label: "HIGH RISK" },
    medium:   { cls: "risk-medium",   label: "MEDIUM RISK" },
    low:      { cls: "risk-low",      label: "LOW RISK" },
    clean:    { cls: "risk-clean",    label: "CLEAN" },
    unknown:  { cls: "risk-unknown",  label: "UNKNOWN" },
  };
  const { cls, label } = map[level] || map.unknown;
  return <span className={`scanner-risk-badge ${cls}`}>{label}</span>;
}

function SeverityDot({ sev }) {
  return <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%",
    background: SEV_COLORS[sev] || "#9ca3af", marginRight: 6, flexShrink: 0 }} />;
}

function hostFromUrl(scanUrl) {
  try {
    return new URL(scanUrl).hostname;
  } catch {
    return scanUrl?.replace(/https?:\/\//, "").split("/")[0] || "your-site";
  }
}

function buildRiskPassport(result) {
  const score = result.overall_score ?? 50;
  const forms = result.forms_found?.length ?? 0;
  const findings = result.risk_items?.filter((r) => !r.type?.startsWith("Missing Header")) ?? [];
  const critical = result.severity_distribution?.critical ?? 0;
  const high = result.severity_distribution?.high ?? 0;
  const missingHeaders = (result.security_headers?.total ?? 0) - (result.security_headers?.present_count ?? 0);
  const hasInputRisk = forms > 0 || findings.some((f) => /form|injection|xss|input/i.test(f.type || ""));

  let status = "Launch Ready";
  let tone = "green";
  let verdict = "This site has a reasonable public-facing security baseline.";
  if (score < 40 || critical > 0) {
    status = "Needs Protection Before Growth";
    tone = "red";
    verdict = "Your site accepts or exposes risky inputs that should be protected before customer traffic grows.";
  } else if (score < 70 || high > 0 || missingHeaders >= 2) {
    status = "Fix This Week";
    tone = "amber";
    verdict = "Your site can operate, but a few missing controls leave customer forms and browser sessions exposed.";
  }

  const nextActions = [];
  if (hasInputRisk) nextActions.push("Put SafeO in front of every form, chatbot, and API endpoint that accepts free text.");
  if (!result.https) nextActions.push("Enable HTTPS and HSTS before collecting customer data.");
  if (missingHeaders > 0) nextActions.push("Add missing browser security headers, starting with CSP and X-Frame-Options.");
  if ((result.scripts_found?.length ?? 0) > 3) nextActions.push("Review third-party scripts and remove anything not essential.");
  if (!nextActions.length) nextActions.push("Keep SafeO monitoring enabled and rescan after each website change.");

  return {
    status,
    tone,
    verdict,
    host: hostFromUrl(result.url),
    score,
    forms,
    findings: findings.length,
    missingHeaders: Math.max(missingHeaders, 0),
    trustBadge: score >= 70 && high === 0 && critical === 0 ? "Eligible after monitoring" : "Not ready yet",
    nextActions: nextActions.slice(0, 3),
  };
}

function RiskPassport({ result }) {
  const passport = buildRiskPassport(result);
  return (
    <div className={`safeo-card risk-passport passport-${passport.tone}`}>
      <div className="risk-passport-top">
        <div>
          <div className="passport-kicker">Community Cyber Risk Passport</div>
          <h3>{passport.host}</h3>
          <p>{passport.verdict}</p>
        </div>
        <div className="passport-score">
          <span>{passport.score}</span>
          <small>/100</small>
        </div>
      </div>

      <div className="passport-status-row">
        <span className={`passport-status passport-${passport.tone}`}>{passport.status}</span>
        <span className="passport-trust">Trust badge: {passport.trustBadge}</span>
      </div>

      <div className="passport-grid">
        <div><strong>{passport.forms}</strong><span>customer input surfaces</span></div>
        <div><strong>{passport.findings}</strong><span>active risk findings</span></div>
        <div><strong>{passport.missingHeaders}</strong><span>missing browser controls</span></div>
      </div>

      <div className="passport-actions">
        <div className="passport-section-title">First 3 actions</div>
        <ol>
          {passport.nextActions.map((action) => <li key={action}>{action}</li>)}
        </ol>
      </div>
    </div>
  );
}

function FirstIncidentResponse({ result }) {
  const visibleFindings = result.risk_items?.filter((r) => !r.type?.startsWith("Missing Header")) ?? [];
  const primaryFinding = visibleFindings[0];
  const severity = primaryFinding?.severity || result.overall_risk || "medium";
  const responseSteps = [
    result.safeo_coverage?.length > 0
      ? "Pause or protect the detected forms before accepting more customer submissions."
      : "Keep monitoring this page and treat the scan as a baseline.",
    "Save the scan result, URL, timestamp, and top finding as your incident evidence.",
    "Add SafeO to the affected input path so future malicious text is blocked before storage.",
    "Apply the listed header/config fixes, then rescan to verify the risk score improves.",
  ];

  return (
    <div className="safeo-card incident-card">
      <div className="incident-header">
        <div>
          <div className="passport-kicker">First Incident Response</div>
          <h3>What to do if this risk is live</h3>
        </div>
        <span className={`scanner-sev-pill sev-${severity}`}>{severity.toUpperCase()}</span>
      </div>
      <p className="safeo-muted">
        {primaryFinding
          ? `Primary concern: ${primaryFinding.type} — ${primaryFinding.detail}`
          : "No urgent exploit pattern was found, but these steps keep the business ready."}
      </p>
      <div className="incident-steps">
        {responseSteps.map((step, idx) => (
          <div className="incident-step" key={step}>
            <span>{idx + 1}</span>
            <p>{step}</p>
          </div>
        ))}
      </div>
      <div className="incident-safeo-fix">
        <strong>What SafeO fixes once integrated:</strong> every submitted message is scanned, risky payloads return BLOCK/WARN, and the decision log explains why.
      </div>
    </div>
  );
}

function buildSnippets(result) {
  const source = hostFromUrl(result.url);
  const endpoint = result.safeo_coverage?.[0]?.replace("Form → ", "") || "/contact";
  return {
    react: {
      label: "React form",
      code: `async function submitWithSafeO(message) {
  const scan = await fetch("/api/v1/scan", {
    method: "POST",
    headers: {
      "Authorization": "Bearer internal",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      input: message,
      context: {
        source_system: "${source}",
        field_name: "contact_message",
        jurisdiction: "UAE"
      }
    })
  }).then((r) => r.json());

  if (scan.decision === "BLOCK") {
    throw new Error("SafeO blocked this message before it reached your CRM.");
  }

  return fetch("${endpoint}", {
    method: "POST",
    body: JSON.stringify({ message })
  });
}`,
    },
    fastapi: {
      label: "FastAPI guard",
      code: `from fastapi import HTTPException
import httpx

async def safeo_guard(text: str):
    async with httpx.AsyncClient(timeout=3) as client:
        scan = await client.post(
            "http://127.0.0.1:8001/v1/scan",
            headers={"Authorization": "Bearer internal"},
            json={
                "input": text,
                "context": {
                    "source_system": "${source}",
                    "jurisdiction": "UAE"
                },
            },
        )
    decision = scan.json()["decision"]
    if decision == "BLOCK":
        raise HTTPException(status_code=403, detail="Blocked by SafeO")
    return scan.json()`,
    },
    express: {
      label: "Express middleware",
      code: `async function safeoMiddleware(req, res, next) {
  const input = req.body.message || req.body.comment || "";
  const scan = await fetch("http://127.0.0.1:8001/v1/scan", {
    method: "POST",
    headers: {
      "Authorization": "Bearer internal",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      input,
      context: {
        source_system: "${source}",
        jurisdiction: "UAE"
      }
    })
  }).then((r) => r.json());

  if (scan.decision === "BLOCK") {
    return res.status(403).json({ error: "Blocked by SafeO", scan_id: scan.scan_id });
  }
  req.safeo = scan;
  next();
}`,
    },
  };
}

function IntegrationFixKit({ result, activeSnippet, onSnippetChange, onCopy }) {
  const snippets = buildSnippets(result);
  const current = snippets[activeSnippet] || snippets.react;
  const fixItems = [
    "Paste the snippet into the handler that receives customer text.",
    "Send every form field, WhatsApp message, or chatbot prompt to /v1/scan before saving.",
    "If SafeO returns BLOCK, stop the write and show a neutral support message.",
    "Keep the scan_id with your order, ticket, or CRM record for audit history.",
  ];

  return (
    <div className="safeo-card integration-kit">
      <div className="integration-kit-head">
        <div>
          <div className="passport-kicker">One-Click Protection Snippets</div>
          <h3>Copy, paste, and let SafeO fix the risky input path</h3>
          <p className="safeo-muted">
            Use this on the first endpoint SafeO found, then repeat for every public form or chat channel.
          </p>
        </div>
        <button type="button" className="safeo-refresh-btn" onClick={() => onCopy(current.code)}>
          Copy snippet
        </button>
      </div>

      <div className="snippet-tabs">
        {Object.entries(snippets).map(([key, snippet]) => (
          <button
            type="button"
            key={key}
            className={activeSnippet === key ? "active" : ""}
            onClick={() => onSnippetChange(key)}
          >
            {snippet.label}
          </button>
        ))}
      </div>

      <pre className="gh-integration-code">{current.code}</pre>

      <div className="fix-checklist">
        <div className="passport-section-title">SafeO fix checklist</div>
        {fixItems.map((item) => (
          <label key={item}>
            <input type="checkbox" readOnly />
            <span>{item}</span>
          </label>
        ))}
      </div>
    </div>
  );
}

export default function WebScanner() {
  const location = useLocation();
  const { showToast } = useToast();
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [activeSnippet, setActiveSnippet] = useState("react");

  useEffect(() => {
    const p = new URLSearchParams(location.search).get("url");
    if (p) { setUrl(p); }
  }, [location.search]);

  async function runScan(scanUrl) {
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const res = await fetch(`${API}/scanner/website`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: scanUrl }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data.error && !data.forms_found) throw new Error(data.error);
      setResult(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  function handleSubmit(e) {
    e.preventDefault();
    if (url.trim()) runScan(url.trim());
  }

  function copySnippet(code) {
    navigator.clipboard?.writeText(code);
    showToast("SafeO integration snippet copied");
  }

  return (
    <div className="safeo-page">
      <div className="safeo-page-header">
        <h2>Website Security Scanner</h2>
        <p>
          Enter any public URL. SafeO crawls the page, audits security headers,
          detects unprotected forms, and scores each security category using ML heuristics.
        </p>
      </div>

      {/* Input */}
      <div className="scanner-input-card">
        <form onSubmit={handleSubmit} className="scanner-form">
          <input className="scanner-url-input" placeholder="https://yourwebsite.com"
            value={url} onChange={(e) => setUrl(e.target.value)} disabled={loading} />
          <button className="sim-run-btn" type="submit" disabled={loading || !url.trim()}>
            {loading ? "Scanning…" : "Scan Website →"}
          </button>
        </form>
        <div className="scanner-samples">
          Try:
          {SAMPLE_URLS.map((s) => (
            <button key={s} className="scanner-sample-pill" onClick={() => { setUrl(s); runScan(s); }}>
              {s.replace("https://", "")}
            </button>
          ))}
        </div>
      </div>

      {loading && (
        <div className="scanner-loading">
          <div className="scanner-spinner" />
          <span>Crawling {url} and running security analysis…</span>
        </div>
      )}
      {error && <div className="scanner-error">{error}</div>}

      {result && !loading && (
        <div className="scanner-results">

          {/* Header row */}
          <div className="scanner-result-header">
            <div>
              <div className="scanner-result-url">{result.url}</div>
              <div style={{ fontSize: 12, color: "#6b7280", marginTop: 2 }}>
                {result.https ? "HTTPS ✓" : "HTTP only ✗"} &nbsp;·&nbsp;
                {result.page_size_kb} KB &nbsp;·&nbsp;
                Status {result.status_code || "—"}
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
              <ScoreGauge score={result.overall_score ?? 50} label="Security Score" />
              <RiskBadge level={result.overall_risk} />
            </div>
          </div>

          {/* Summary cards */}
          <div className="scanner-summary-row">
            <div className="scanner-summary-card">
              <div className="scanner-summary-num">{result.forms_found?.length ?? 0}</div>
              <div className="scanner-summary-label">Forms detected</div>
            </div>
            <div className="scanner-summary-card">
              <div className="scanner-summary-num">{result.risk_items?.filter(r => !r.type?.startsWith("Missing Header")).length ?? 0}</div>
              <div className="scanner-summary-label">Risk findings</div>
            </div>
            <div className="scanner-summary-card">
              <div className="scanner-summary-num">{result.security_headers?.present_count ?? 0}/{result.security_headers?.total ?? 6}</div>
              <div className="scanner-summary-label">Security headers</div>
            </div>
            <div className="scanner-summary-card">
              <div className="scanner-summary-num">{result.scripts_found?.length ?? 0}</div>
              <div className="scanner-summary-label">External scripts</div>
            </div>
          </div>

          <RiskPassport result={result} />

          {/* Two-column charts */}
          <div className="viz-grid-2">
            <div className="safeo-card">
              <h3>Security Category Scores</h3>
              <p className="safeo-muted" style={{ fontSize: 12, marginTop: 0 }}>100 = fully protected in this category</p>
              <CategoryRadar scores={result.category_scores || {}} />
            </div>
            <div className="safeo-card">
              <h3>Findings by Severity</h3>
              <SeverityDonut distribution={result.severity_distribution || {}} />
            </div>
          </div>

          {/* Security headers */}
          {result.security_headers && Object.keys(result.security_headers).length > 2 && (
            <div className="safeo-card">
              <h3>Security Headers Audit</h3>
              <p className="safeo-muted" style={{ fontSize: 12, marginTop: 0 }}>
                {result.security_headers.present_count}/{result.security_headers.total} headers present — score: {result.security_headers.score}/100
              </p>
              <HeadersBar headers={result.security_headers} />
            </div>
          )}

          {/* Forms table */}
          {result.forms_found?.length > 0 && (
            <div className="safeo-card">
              <h3>Detected Forms</h3>
              <table className="safeo-table">
                <thead><tr><th>Endpoint</th><th>Method</th><th>Fields</th><th>Risky Fields</th><th>Risk</th></tr></thead>
                <tbody>
                  {result.forms_found.map((f, i) => (
                    <tr key={i}>
                      <td style={{ fontSize: 11, maxWidth: 200, wordBreak: "break-all" }}>{f.action}</td>
                      <td><span className={`decision-badge ${f.method === "POST" ? "block" : "allow"}`}>{f.method}</span></td>
                      <td>{f.input_count}</td>
                      <td style={{ fontSize: 11 }}>{f.risky_fields?.join(", ") || "—"}</td>
                      <td><RiskBadge level={f.risk} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Risk findings */}
          {result.risk_items?.filter(r => !r.type?.startsWith("Missing Header")).length > 0 && (
            <div className="safeo-card">
              <h3>Security Findings</h3>
              <div className="scanner-findings">
                {result.risk_items.filter(r => !r.type?.startsWith("Missing Header")).map((r, i) => (
                  <div key={i} className="scanner-finding">
                    <div className="scanner-finding-top">
                      <SeverityDot sev={r.severity} />
                      <span className="scanner-finding-type">{r.type}</span>
                      <span className={`scanner-sev-pill sev-${r.severity}`}>{r.severity.toUpperCase()}</span>
                    </div>
                    <div className="scanner-finding-detail">{r.detail}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <FirstIncidentResponse result={result} />

          {/* Technology stack + link analysis */}
          <div className="viz-grid-2">
            {result.technologies?.length > 0 && (
              <div className="safeo-card">
                <h3>Technology Stack</h3>
                <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 10 }}>
                  {result.technologies.map((t) => {
                    const info = TECH_INFO[t] || { risk: "low", note: "Detected on this page." };
                    return (
                      <div key={t} style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
                        <span className="gh-framework-chip" style={{ background: TECH_COLORS[t] || "#374151", flexShrink: 0, fontSize: 12 }}>{t}</span>
                        <div>
                          <div style={{ fontSize: 12, color: "#374151", lineHeight: 1.4 }}>{info.note}</div>
                          <div style={{ fontSize: 11, color: SEV_COLORS[info.risk] || "#6b7280", marginTop: 2, fontWeight: 600 }}>
                            {info.risk.toUpperCase()} exposure
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
            <div className="safeo-card">
              <h3>Page Analysis</h3>
              <table className="safeo-table" style={{ marginTop: 4 }}>
                <tbody>
                  <tr><td>Internal links</td><td><strong>{result.links?.internal ?? "—"}</strong></td></tr>
                  <tr><td>External links</td><td><strong>{result.links?.external ?? "—"}</strong></td></tr>
                  <tr><td>External scripts</td><td><strong>{result.scripts_found?.length ?? 0}</strong></td></tr>
                  <tr><td>Inline scripts</td><td><strong>{result.inline_scripts ?? 0}</strong></td></tr>
                  <tr><td>Page size</td><td><strong>{result.page_size_kb} KB</strong></td></tr>
                  <tr><td>Response time</td><td><strong>{result.response_time_ms ?? "—"} ms</strong></td></tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Cookie flags + meta tags */}
          {(result.cookie_flags && Object.keys(result.cookie_flags).length > 0) || result.meta_tags ? (
            <div className="viz-grid-2">
              {result.cookie_flags && Object.keys(result.cookie_flags).length > 0 && (
                <div className="safeo-card">
                  <h3>Cookie Security Flags</h3>
                  <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 8 }}>
                    {Object.entries(result.cookie_flags).map(([flag, present]) => (
                      <div key={flag} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 13 }}>
                        <span style={{ width: 18, height: 18, borderRadius: 4, background: present ? "#dcfce7" : "#fef2f2",
                          display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, flexShrink: 0 }}>
                          {present ? "✓" : "✗"}
                        </span>
                        <span style={{ fontWeight: 600 }}>{flag}</span>
                        <span style={{ color: "#6b7280", fontSize: 11 }}>{present ? "present" : "missing"}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {result.meta_tags && Object.keys(result.meta_tags).length > 0 && (
                <div className="safeo-card">
                  <h3>Meta Tags</h3>
                  <table className="safeo-table" style={{ marginTop: 4 }}>
                    <tbody>
                      {Object.entries(result.meta_tags).slice(0, 6).map(([k, v]) => (
                        <tr key={k}>
                          <td style={{ fontSize: 11, fontWeight: 600, width: 120 }}>{k}</td>
                          <td style={{ fontSize: 11, color: "#374151", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>{String(v).slice(0, 80)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          ) : null}

          {/* Recommendations + SafeO protection plan */}
          {result.recommendations?.length > 0 && (
            <div className="safeo-card scanner-recs">
              <h3>Recommendations</h3>
              <ul className="scanner-rec-list">
                {result.recommendations.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
              {result.safeo_coverage?.length > 0 && (
                <div className="scanner-connect-cta">
                  <span>SafeO can protect {result.safeo_coverage.length} endpoint(s) on this site</span>
                  <a href="/connect" className="sim-run-btn" style={{ fontSize: 13 }}>Connect Now →</a>
                </div>
              )}
            </div>
          )}

          <IntegrationFixKit
            result={result}
            activeSnippet={activeSnippet}
            onSnippetChange={setActiveSnippet}
            onCopy={copySnippet}
          />
          {result.demo_mode && (
            <div className="scanner-demo-note">
              Demo profile — this site blocks automated crawlers. Results reflect known published vulnerabilities.
            </div>
          )}

        </div>
      )}
    </div>
  );
}

const TECH_COLORS = {
  jQuery: "#1565c0", Bootstrap: "#7952b3", React: "#0ea5e9", "Vue.js": "#42b883",
  Angular: "#dd0031", WordPress: "#21759b", Shopify: "#96bf48",
  "Google Analytics": "#f57c00", "Google Tag Manager": "#4285f4",
  Cloudflare: "#f38020", "Font Awesome": "#339af0", "Tailwind CSS": "#38bdf8",
  Stripe: "#635bff", reCAPTCHA: "#4285f4", PHP: "#777bb4", "ASP.NET": "#512bd4",
  "Node.js/Express": "#2c3e50",
};
