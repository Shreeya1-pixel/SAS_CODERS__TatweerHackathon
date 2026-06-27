import { useState } from "react";
import { Link } from "react-router-dom";
import Modal from "../components/Modal";

const QUESTIONS = [
  {
    id: "ai_tools",
    ar: "هل تستخدم أدوات ذكاء اصطناعي مثل ChatGPT في عملك؟",
    en: "Do you use AI tools like ChatGPT in your work?",
    weight: 2,
    options: [
      { label: "نعم، يومياً / Yes, daily", value: 2 },
      { label: "أحياناً / Sometimes", value: 1 },
      { label: "لا / No", value: 0 },
    ],
  },
  {
    id: "contact_form",
    ar: "هل لديك نموذج اتصال أو إدخال نص على موقعك؟",
    en: "Do you have a contact form or free-text input on your website?",
    weight: 3,
    options: [
      { label: "نعم / Yes", value: 3 },
      { label: "لا / No", value: 0 },
    ],
  },
  {
    id: "arabic_inputs",
    ar: "هل يُدخل عملاؤك نصوصاً بالعربية أو العامية المكتوبة بالأحرف اللاتينية؟",
    en: "Do your customers input Arabic text or Arabizi (Arabic written in Latin letters)?",
    weight: 3,
    options: [
      { label: "نعم / Yes", value: 3 },
      { label: "أحياناً / Sometimes", value: 2 },
      { label: "لا / No", value: 0 },
    ],
  },
  {
    id: "erp",
    ar: "هل تستخدم نظام ERP أو برنامج محاسبة يتصل بالإنترنت؟",
    en: "Do you use an ERP or accounting system connected to the internet?",
    weight: 2,
    options: [
      { label: "نعم / Yes", value: 2 },
      { label: "لا / No", value: 0 },
    ],
  },
  {
    id: "monitoring",
    ar: "هل تراجع سجلات النشاط أو تلقى تنبيهات أمنية بانتظام؟",
    en: "Do you regularly review activity logs or receive security alerts?",
    weight: 2,
    options: [
      { label: "لا / No", value: 2 },
      { label: "أحياناً / Sometimes", value: 1 },
      { label: "نعم / Yes", value: 0 },
    ],
  },
];

const MAX_SCORE = QUESTIONS.reduce((s, q) => s + Math.max(...q.options.map((o) => o.value)), 0);

function getRiskLevel(score) {
  const pct = Math.round((score / MAX_SCORE) * 100);
  if (pct >= 70) {
    return {
      level: "HIGH RISK",
      levelAr: "خطر عالي",
      color: "#E8202A",
      bg: "#fff1f2",
      gaugeLabel: "Critical Vulnerability Exposure",
      action: "Your business has critical unguarded input surfaces.",
      detail:
        "Attackers — including those using Arabic and Arabizi — can exploit your forms, ERP, or AI tools before you notice. SafeO blocks threats at the front door.",
      cta: "/scan/website",
    };
  }
  if (pct >= 40) {
    return {
      level: "MEDIUM RISK",
      levelAr: "خطر متوسط",
      color: "#f59e0b",
      bg: "#fffbeb",
      gaugeLabel: "Moderate Vulnerability Exposure",
      action: "Some risks are present and growing.",
      detail:
        "Arabic-language inputs or connected ERP systems create gaps that standard tools miss. SafeO's multilingual engine closes them before damage happens.",
      cta: "/scan/website",
    };
  }
  return {
    level: "LOW RISK",
    levelAr: "خطر منخفض",
    color: "#16a34a",
    bg: "#f0fdf4",
    gaugeLabel: "Low Vulnerability Exposure",
    action: "You are in reasonable shape today.",
    detail:
      "Your current setup has lower immediate risk. As you add web forms, WhatsApp sales, or AI tools, SafeO scales with your business at zero OpenAI cost.",
    cta: "/scan/website",
  };
}

function buildRiskBadges(answers) {
  const badges = [];

  if ((answers.arabic_inputs ?? 0) >= 2) {
    badges.push({
      severity: "high",
      text: "High Exposure to Multilingual Prompt Injections",
      textAr: "تعرّض عالٍ لهجمات الحقن متعددة اللغات",
    });
  }
  if ((answers.erp ?? 0) >= 2) {
    badges.push({
      severity: "high",
      text: "Vulnerable ERP Endpoints Detected",
      textAr: "نقاط ضعف في نظام ERP متصل بالإنترنت",
    });
  }
  if ((answers.contact_form ?? 0) >= 3) {
    badges.push({
      severity: "medium",
      text: "Unguarded Website Contact Form",
      textAr: "نموذج اتصال على الموقع بدون حماية",
    });
  }
  if ((answers.ai_tools ?? 0) >= 2) {
    badges.push({
      severity: "medium",
      text: "AI Tool Attack Surface — Prompt Injection Risk",
      textAr: "سطح هجوم عبر أدوات الذكاء الاصطناعي",
    });
  }
  if ((answers.monitoring ?? 0) >= 2) {
    badges.push({
      severity: "medium",
      text: "No Regular Security Monitoring",
      textAr: "لا توجد مراقبة أمنية منتظمة",
    });
  }

  if (!badges.length) {
    badges.push({
      severity: "low",
      text: "No critical exposure flags detected — stay protected as you grow",
      textAr: "لا توجد مخاطر حرجة — استمر في الحماية مع نمو عملك",
    });
  }

  return badges;
}

function RiskGauge({ pct, color, label }) {
  const r = 72;
  const cx = 100;
  const cy = 100;
  const circumference = 2 * Math.PI * r;
  const offset = circumference - (pct / 100) * circumference;

  return (
    <div className="risk-gauge-wrap">
      <svg viewBox="0 0 200 200" width="200" height="200" className="risk-gauge-svg">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#e5e7eb" strokeWidth="14" />
        <circle
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="14"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform={`rotate(-90 ${cx} ${cy})`}
          className="risk-gauge-arc"
        />
        <text x={cx} y={cy - 6} textAnchor="middle" fontSize="36" fontWeight="800" fill={color}>
          {pct}%
        </text>
        <text x={cx} y={cy + 18} textAnchor="middle" fontSize="11" fill="#6b7280">
          {label}
        </text>
      </svg>
    </div>
  );
}

export default function RiskAssessment() {
  const [answers, setAnswers] = useState({});
  const [step, setStep] = useState(0);
  const [showResult, setShowResult] = useState(false);
  const [direction, setDirection] = useState("forward");

  const current = QUESTIONS[step];
  const answeredCount = Object.keys(answers).length;
  const progressPct = Math.round(((step + (answers[current?.id] !== undefined ? 1 : 0)) / QUESTIONS.length) * 100);
  const score = Object.values(answers).reduce((s, v) => s + v, 0);
  const result = showResult ? getRiskLevel(score) : null;
  const exposurePct = Math.round((score / MAX_SCORE) * 100);
  const badges = showResult ? buildRiskBadges(answers) : [];

  function handleAnswer(qid, value) {
    setAnswers((prev) => ({ ...prev, [qid]: value }));
  }

  function goNext() {
    if (answers[current.id] === undefined) return;
    if (step < QUESTIONS.length - 1) {
      setDirection("forward");
      setStep((s) => s + 1);
    } else {
      setShowResult(true);
    }
  }

  function goBack() {
    if (step > 0) {
      setDirection("back");
      setStep((s) => s - 1);
    }
  }

  function resetQuiz() {
    setAnswers({});
    setStep(0);
    setShowResult(false);
    setDirection("forward");
  }

  return (
    <div className="safeo-page risk-assess-page">
      <div className="safeo-page-header">
        <h2>هل أنا في خطر؟ / Am I at Risk?</h2>
        <p>5 quick questions for UAE small business owners — no jargon, ~2 minutes.</p>
      </div>

      <div className="risk-stepper-shell">
        <div className="risk-stepper-progress">
          <div className="risk-stepper-progress-meta">
            <span>Question {step + 1} of {QUESTIONS.length}</span>
            <span>{answeredCount} answered</span>
          </div>
          <div className="risk-stepper-track">
            <div className="risk-stepper-fill" style={{ width: `${progressPct}%` }} />
          </div>
        </div>

        <div className={`risk-stepper-card risk-step-${direction}`} key={current.id}>
          <div className="risk-stepper-num">{step + 1}</div>
          <div className="safeo-quiz-body">
            <div className="safeo-quiz-ar">{current.ar}</div>
            <div className="safeo-quiz-en">{current.en}</div>
            <div className="safeo-quiz-options risk-stepper-options">
              {current.options.map((opt) => (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => handleAnswer(current.id, opt.value)}
                  className={`safeo-quiz-opt${answers[current.id] === opt.value ? " selected" : ""}`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="risk-stepper-nav">
          <button
            type="button"
            className="risk-stepper-back"
            onClick={goBack}
            disabled={step === 0}
          >
            ← Back
          </button>
          <button
            type="button"
            className="sim-run-btn risk-stepper-next"
            onClick={goNext}
            disabled={answers[current.id] === undefined}
          >
            {step < QUESTIONS.length - 1 ? "Next →" : "See My Risk Level →"}
          </button>
        </div>
      </div>

      <Modal
        open={showResult && !!result}
        title="Your Risk Assessment"
        onClose={() => setShowResult(false)}
      >
        {result && (
          <div className="risk-result-modal" style={{ background: result.bg }}>
            <div className="risk-result-header">
              <span className="risk-result-level" style={{ background: result.color }}>
                {result.level}
              </span>
              <span className="risk-result-level-ar">{result.levelAr}</span>
            </div>

            <RiskGauge pct={exposurePct} color={result.color} label={result.gaugeLabel} />

            <p className="risk-result-headline">{result.action}</p>
            <p className="risk-result-detail">{result.detail}</p>

            <div className="risk-badge-section">
              <div className="risk-badge-title">Personalized Risk Breakdown</div>
              <div className="risk-badge-list">
                {badges.map((b) => (
                  <div key={b.text} className={`risk-badge risk-badge-${b.severity}`}>
                    <span className="risk-badge-icon">
                      {b.severity === "high" ? "⚠️" : b.severity === "medium" ? "🔶" : "✅"}
                    </span>
                    <div>
                      <div className="risk-badge-text">{b.text}</div>
                      <div className="risk-badge-text-ar">{b.textAr}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="risk-result-score-row">
              <span>Exposure score</span>
              <strong>{score} / {MAX_SCORE}</strong>
            </div>

            <Link to={result.cta} className="risk-result-cta" onClick={() => setShowResult(false)}>
              🛡️ Deploy SafeO AI Trust Layer to Your Website Now
            </Link>

            <div className="risk-result-secondary">
              <Link to="/whatsapp-demo" className="risk-result-link" onClick={() => setShowResult(false)}>
                Try WhatsApp protection demo
              </Link>
              <button type="button" className="safeo-quiz-reset" onClick={resetQuiz}>
                Retake Quiz
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
