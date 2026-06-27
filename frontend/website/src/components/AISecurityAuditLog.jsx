/**
 * SafeO AI Security Audit Log — explainable breakdown with highlighted payload tokens.
 */
import { useMemo } from "react";

function HighlightedPayload({ text, highlights }) {
  const segments = useMemo(() => {
    if (!text) return [{ text: "", severity: null }];
    if (!highlights?.length) return [{ text, severity: null }];
    const parts = [];
    let cursor = 0;
    const sorted = [...highlights].sort((a, b) => a.start - b.start);
    for (const h of sorted) {
      if (h.start > cursor) {
        parts.push({ text: text.slice(cursor, h.start), severity: null });
      }
      parts.push({ text: text.slice(h.start, h.end), severity: h.severity || "high" });
      cursor = h.end;
    }
    if (cursor < text.length) {
      parts.push({ text: text.slice(cursor), severity: null });
    }
    return parts;
  }, [text, highlights]);

  return (
    <div className="xai-highlight-box" dir="auto">
      {segments.map((seg, i) =>
        seg.severity ? (
          <mark key={i} className={`xai-mark xai-mark-${seg.severity}`}>{seg.text}</mark>
        ) : (
          <span key={i}>{seg.text}</span>
        )
      )}
    </div>
  );
}

function AuditRow({ label, value, accent }) {
  if (!value) return null;
  return (
    <div className="xai-audit-row">
      <div className="xai-audit-label">{label}</div>
      <div className={`xai-audit-value${accent ? ` xai-accent-${accent}` : ""}`}>{value}</div>
    </div>
  );
}

export default function AISecurityAuditLog({
  payload,
  audit,
  riskScore,
  decision,
  compact = false,
}) {
  if (!audit) return null;

  const sev = (audit.severity || "low").toLowerCase();
  const conf = audit.confidence_pct ?? (riskScore ? Math.round(riskScore * 100) : null);

  return (
    <div className={`xai-audit-card${compact ? " xai-audit-compact" : ""}`}>
      <div className="xai-audit-header">
        <h3>SafeO AI Security Audit Log</h3>
        <div className="xai-audit-badges">
          {decision && (
            <span className={`decision-badge ${String(decision).toLowerCase()}`}>
              {String(decision).toUpperCase()}
            </span>
          )}
          <span className={`xai-sev-pill xai-sev-${sev}`}>{audit.severity}</span>
          {conf != null && <span className="xai-conf-pill">Confidence {conf}%</span>}
        </div>
      </div>

      {payload && (
        <div className="xai-audit-section">
          <div className="xai-section-title">Analysed Input (threat highlights)</div>
          <HighlightedPayload text={payload} highlights={audit.triggering_substrings} />
        </div>
      )}

      <div className="xai-audit-grid">
        <AuditRow label="Detected Anomaly Layer" value={audit.detected_anomaly_layer} accent="layer" />
        <AuditRow label="Primary Threat Vector" value={audit.primary_threat_vector} accent="vector" />
        <AuditRow label="Heuristic Trigger" value={audit.heuristic_trigger} />
        <AuditRow label="Confidence Level" value={conf != null ? `${conf}%` : null} />
        <AuditRow label="Suggested Action" value={audit.suggested_action} accent="action" />
      </div>

      {audit.matched_heuristics?.length > 0 && (
        <div className="xai-audit-section">
          <div className="xai-section-title">Matched Heuristics</div>
          <div className="xai-chip-row">
            {audit.matched_heuristics.map((h) => (
              <span key={h} className="xai-heuristic-chip">{h}</span>
            ))}
          </div>
        </div>
      )}

      {audit.highlighted_tokens?.length > 0 && (
        <div className="xai-audit-section">
          <div className="xai-section-title">Highlighted Tokens</div>
          <div className="xai-chip-row">
            {audit.highlighted_tokens.map((t) => (
              <code key={t} className="xai-token-chip">{t}</code>
            ))}
          </div>
        </div>
      )}

      <div className="xai-audit-section">
        <div className="xai-section-title">Risk Reasoning Matrix</div>
        <p className="xai-reasoning-text">{audit.risk_reasoning_matrix || audit.llm_reasoning_summary}</p>
      </div>

      {audit.recommended_mitigation && (
        <div className="xai-mitigation-bar">
          <strong>Recommended Mitigation:</strong> {audit.recommended_mitigation}
        </div>
      )}
    </div>
  );
}

export { HighlightedPayload };
