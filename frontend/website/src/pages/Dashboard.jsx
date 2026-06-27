import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { fetchFullStats, fetchOdooHealth } from "../api";
import {
  countReachableConnections,
  seedOdooIfReachable,
} from "../utils/connections";

// ─── GPT-4o pricing (USD) — used in cost damage calculator ───────────────────
const GPT4O_INPUT_PER_TOKEN  = 2.50 / 1_000_000;   // $2.50 / 1M input tokens
const GPT4O_OUTPUT_PER_TOKEN = 10.0 / 1_000_000;   // $10.00 / 1M output tokens
const AVG_OUTPUT_TOKENS = 120;   // typical LLM response to a prompt
const USD_TO_AED = 3.67;

function estimateCost(blockedCount) {
  if (!blockedCount) return null;
  // Assume each blocked scan would have sent an avg 350-token prompt to GPT-4o
  const inputTokens  = blockedCount * 350;
  const outputTokens = blockedCount * AVG_OUTPUT_TOKENS;
  const usd = inputTokens * GPT4O_INPUT_PER_TOKEN + outputTokens * GPT4O_OUTPUT_PER_TOKEN;
  return (usd * USD_TO_AED).toFixed(2);
}

function StatCard({ label, value, accent, sub }) {
  return (
    <div className={`safeo-stat-card${accent ? ` accent-${accent}` : ""}`}>
      <div className="safeo-stat-value">{value}</div>
      <div className="safeo-stat-label">{label}</div>
      {sub && <div className="safeo-stat-sub">{sub}</div>}
    </div>
  );
}

function CostDamageWidget({ blockedCount }) {
  const aed = estimateCost(blockedCount);
  if (aed === null) return null;
  return (
    <div className="safeo-cost-widget">
      <div className="safeo-cost-icon">🛡️</div>
      <div className="safeo-cost-body">
        <div className="safeo-cost-headline">
          If {blockedCount} blocked payload{blockedCount === 1 ? "" : "s"} had reached your OpenAI API…
        </div>
        <div className="safeo-cost-amount">AED {aed} estimated cost</div>
        <div className="safeo-cost-sub">
          Based on GPT-4o pricing · {blockedCount} × ~350 input tokens + 120 output tokens · 1 USD = 3.67 AED
        </div>
        <div className="safeo-cost-badge">SafeO blocked these before any LLM call was made.</div>
      </div>
    </div>
  );
}

function ThreatCounter({ blocked24h }) {
  return (
    <div className="safeo-threat-counter">
      <span className="safeo-threat-pulse" />
      <span className="safeo-threat-text">
        <strong>{blocked24h ?? 0}</strong> attacks blocked in the last 24h across community platforms
      </span>

    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [odooUp, setOdooUp] = useState(false);
  const [connectedCount, setConnectedCount] = useState(0);

  useEffect(() => {
    const refresh = async () => {
      try {
        const [full, odoo] = await Promise.all([fetchFullStats(), fetchOdooHealth()]);
        setStats(full);
        setOdooUp(odoo);
        const conns = seedOdooIfReachable(odoo);
        setConnectedCount(countReachableConnections(odoo, conns));
      } catch {
        setStats(null);
        const odoo = await fetchOdooHealth();
        setOdooUp(odoo);
        const conns = seedOdooIfReachable(odoo);
        setConnectedCount(countReachableConnections(odoo, conns));
      }
    };
    refresh();
    const t = setInterval(refresh, 8000);
    return () => clearInterval(t);
  }, []);

  const summary = stats?.summary || {};
  const blocked = summary.blocked ?? 0;

  return (
    <div className="safeo-page">
      <div className="safeo-page-header">
        <h2>Business Risk Dashboard</h2>
        <p>Real-time business risk decisions — standalone view. Connect to Odoo for full ERP integration.</p>
      </div>

      <ThreatCounter blocked24h={blocked} />

      <div className="safeo-stat-grid">
        <StatCard label="Total Scans" value={summary.total_scans ?? "—"} />
        <StatCard label="Blocked" value={summary.blocked ?? "—"} accent="danger" />
        <StatCard label="LLM Calls Saved" value={`${summary.llm_calls_saved_pct ?? 0}%`} sub="vs. cloud-only approach" />
        <StatCard label="Avg Risk Score" value={summary.avg_score ?? "—"} />
        <StatCard label="Open Investigations" value={summary.active_investigations ?? 0} />
      </div>

      <CostDamageWidget blockedCount={blocked} />

      <Link to="/connect" className="safeo-erp-banner">
        <span>
          SafeO is connected to <strong>{connectedCount}</strong> ERP system{connectedCount === 1 ? "" : "s"}
        </span>
        <span className="safeo-erp-banner-cta">Manage Connections →</span>
      </Link>

      <div className="safeo-card">
        <h3>Recent Decisions</h3>
        {!stats?.recent_decisions?.length ? (
          <p className="safeo-muted">No decisions yet. Run a scan from Sandbox or connect Odoo.</p>
        ) : (
          <table className="safeo-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Risk</th>
                <th>Decision</th>
              </tr>
            </thead>
            <tbody>
              {stats.recent_decisions.slice(0, 8).map((row) => (
                <tr key={row.request_id || row.time}>
                  <td>{formatTime(row.time)}</td>
                  <td>{row.source_system || "—"}</td>
                  <td>{Math.round((row.risk_score || 0) * 100)}%</td>
                  <td>
                    <span className={`decision-badge ${decisionClass(row.decision)}`}>{row.decision}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="safeo-status-strip">
        <span>Backend API: {stats ? "Connected" : "Checking…"}</span>
        <span>Odoo ERP: {odooUp ? "Connected" : "Not running"}</span>
      </div>
    </div>
  );
}

function formatTime(ts) {
  if (!ts) return "—";
  try {
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return ts;
    return d.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  } catch {
    return ts;
  }
}

function decisionClass(d) {
  const v = String(d || "").toLowerCase();
  if (v === "block") return "block";
  if (v === "warn") return "warn";
  return "allow";
}
