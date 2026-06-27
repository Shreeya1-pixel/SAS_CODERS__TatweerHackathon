/**
 * SafeO Universal Trust Gateway — landing page
 * "Protect Any Digital Application with AI"
 */
import { Link } from "react-router-dom";
import { useState, useEffect } from "react";

const USE_CASES = [
  { icon: "🏛️", title: "Government Portals",    desc: "Block injection attacks on citizen complaint & permit submission forms." },
  { icon: "🏥", title: "Healthcare Systems",     desc: "Protect appointment booking and patient data entry from SQL injection." },
  { icon: "🎓", title: "Education Platforms",    desc: "Screen student admission forms and feedback for prompt injection." },
  { icon: "🏪", title: "Small Businesses",       desc: "Secure contact forms, quote requests, and checkout inputs." },
  { icon: "🌍", title: "NGO & Community",        desc: "Protect volunteer registrations and donation forms." },
  { icon: "👨‍💻", title: "Developers & Students",  desc: "Add one API call to your project and show production-grade security." },
  { icon: "🏢", title: "Enterprise ERP",         desc: "Odoo, SAP, and custom ERP hooks with full investigation audit trail." },
  { icon: "🤖", title: "AI Applications",        desc: "Stop prompt injection before it reaches your LLM — no API cost wasted." },
];

const HOW_IT_WORKS = [
  {
    step: "01",
    title: "User submits input",
    desc: "A citizen, employee, or customer types into any form, API, or chatbot.",
  },
  {
    step: "02",
    title: "SafeO evaluates in < 5 ms",
    desc: "3-tier ML pipeline: heuristics → DistilBERT → local Mistral. No cloud LLM calls.",
  },
  {
    step: "03",
    title: "ALLOW · WARN · BLOCK",
    desc: "Clean inputs pass through. Threats are blocked with a UAE law citation and Jira ticket.",
  },
];

const CONNECTORS = [
  "FastAPI", "Flask", "Django", "Express", "Next.js", "React", "Odoo", "REST API",
];

const STATS = [
  { value: "< 5 ms", label: "Decision latency" },
  { value: "92%",    label: "LLM calls eliminated" },
  { value: "6",      label: "UAE law articles mapped" },
];

function AnimatedCounter({ target, suffix = "" }) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (typeof target !== "number") return;
    const step = Math.ceil(target / 40);
    const t = setInterval(() => {
      setVal((v) => {
        if (v + step >= target) { clearInterval(t); return target; }
        return v + step;
      });
    }, 30);
    return () => clearInterval(t);
  }, [target]);
  if (typeof target !== "number") return <span>{target}</span>;
  return <span>{val}{suffix}</span>;
}

export default function Home() {
  const [demoUrl, setDemoUrl] = useState("");

  return (
    <div className="home-page">

      {/* ── Hero ─────────────────────────────────────────────────────────────── */}
      <section className="home-hero">
        <div className="home-hero-badge">Universal AI Trust Layer</div>
        <h1 className="home-hero-h1">
          Protect Any Digital<br />Application with AI
        </h1>
        <p className="home-hero-sub">
          Deploy SafeO in minutes to secure websites, APIs, government services,
          enterprise software, and student projects using explainable,
          privacy-preserving AI. No cloud LLM. No lock-in.
        </p>
        <div className="home-hero-ctas">
          <Link to="/scan/website" className="home-cta-primary">
            Scan Your Website Free →
          </Link>
          <Link to="/whatsapp-demo" className="home-cta-secondary">
            WhatsApp Demo
          </Link>
        </div>
        <div className="home-hero-stats">
          {STATS.map((s) => (
            <div key={s.label} className="home-stat">
              <div className="home-stat-val">{s.value}</div>
              <div className="home-stat-lbl">{s.label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Quick scan strip ──────────────────────────────────────────────────── */}
      <section className="home-scan-strip">
        <div className="home-scan-half" style={{ maxWidth: 640, margin: "0 auto", width: "100%" }}>
          <div className="home-scan-label">Scan any website</div>
          <div className="home-scan-row">
            <input
              className="home-scan-input"
              placeholder="https://yoursite.com"
              value={demoUrl}
              onChange={(e) => setDemoUrl(e.target.value)}
            />
            <Link
              to={`/scan/website${demoUrl ? `?url=${encodeURIComponent(demoUrl)}` : ""}`}
              className="home-scan-btn"
            >
              Scan →
            </Link>
          </div>
        </div>
      </section>

      {/* ── How it works ─────────────────────────────────────────────────────── */}
      <section className="home-section">
        <h2 className="home-section-title">How SafeO Works</h2>
        <div className="home-steps">
          {HOW_IT_WORKS.map((s) => (
            <div key={s.step} className="home-step">
              <div className="home-step-num">{s.step}</div>
              <h3 className="home-step-title">{s.title}</h3>
              <p className="home-step-desc">{s.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Connectors ───────────────────────────────────────────────────────── */}
      <section className="home-connectors-section">
        <p className="home-connectors-label">Works with any stack</p>
        <div className="home-connectors">
          {CONNECTORS.map((c) => (
            <span key={c} className="home-connector-pill">{c}</span>
          ))}
        </div>
      </section>

      {/* ── Who uses SafeO ───────────────────────────────────────────────────── */}
      <section className="home-section">
        <h2 className="home-section-title">Who Uses SafeO?</h2>
        <p className="home-section-sub">
          One engine. Any application accepting user input.
        </p>
        <div className="home-usecase-grid">
          {USE_CASES.map((u) => (
            <div key={u.title} className="home-usecase-card">
              <div className="home-usecase-icon">{u.icon}</div>
              <h3 className="home-usecase-title">{u.title}</h3>
              <p className="home-usecase-desc">{u.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── SDK snippet ──────────────────────────────────────────────────────── */}
      <section className="home-section">
        <h2 className="home-section-title">One call. Any language.</h2>
        <div className="home-sdk-grid">
          <div className="home-sdk-card">
            <div className="home-sdk-lang">Python</div>
            <pre className="home-sdk-code">{`from safeo_sdk import safeo_scan

result = safeo_scan(user_input)
if result["decision"] == "BLOCK":
    raise ValueError("Input blocked")`}</pre>
          </div>
          <div className="home-sdk-card">
            <div className="home-sdk-lang">JavaScript</div>
            <pre className="home-sdk-code">{`const { scan } = require('safeo-sdk');

const result = await scan(userInput);
if (result.decision === 'BLOCK') {
  return res.status(400).json({ error: 'Blocked' });
}`}</pre>
          </div>
          <div className="home-sdk-card">
            <div className="home-sdk-lang">REST</div>
            <pre className="home-sdk-code">{`POST /v1/scan
{
  "input": "<user text>",
  "context": { "source_system": "my-app" }
}
→ { "decision": "ALLOW|WARN|BLOCK" }`}</pre>
          </div>
        </div>
      </section>

      {/* ── Bottom CTA ───────────────────────────────────────────────────────── */}
      <section className="home-bottom-cta">
        <h2>Your form is open. We close it.</h2>
        <p>Start with a free website scan — no account needed.</p>
        <div className="home-hero-ctas">
          <Link to="/scan/website" className="home-cta-primary">
            Scan My Website →
          </Link>

        </div>
      </section>

    </div>
  );
}
