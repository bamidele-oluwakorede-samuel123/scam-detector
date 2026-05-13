// Result.jsx
// ─────────────────────────────────────────────────────────────
// Displays the full analysis result for a scan.
//
// TWO WAYS TO ARRIVE HERE:
// 1. From Home.jsx after a new analysis → result is in router state
// 2. Directly via URL /result/:id → fetch the scan from the API
//
// LAYOUT:
//   - Header with back button + input preview
//   - Left column: RiskMeter + type info
//   - Right column: AnalysisCard + ComparisonView
// ─────────────────────────────────────────────────────────────

import React, { useEffect, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import RiskMeter from "../components/RiskMeter";
import AnalysisCard from "../components/AnalysisCard";
import ComparisonView from "../components/ComparisonView";
import { getScanById } from "../services/api";

const TYPE_LABELS = {
  url: { label: "URL / Link", icon: "🔗" },
  phone: { label: "Phone Number", icon: "📞" },
  email: { label: "Email Address", icon: "✉️" },
  text: { label: "Message / SMS", icon: "💬" },
};

const Result = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { id } = useParams();

  // State: result data, loading, error
  const [result, setResult] = useState(location.state?.result || null);
  const [loading, setLoading] = useState(!result && !!id);
  const [error, setError] = useState(null);

  // If we don't have result in state but have an ID in the URL, fetch it
  useEffect(() => {
    if (!result && id) {
      (async () => {
        try {
          const data = await getScanById(id);
          setResult(data.scan);
        } catch {
          setError("Could not load this scan. It may have been deleted.");
        } finally {
          setLoading(false);
        }
      })();
    }
  }, [id, result]);

  if (loading) {
    return (
      <div style={styles.centered}>
        <div style={styles.loadingSpinner} />
        <p style={styles.loadingText}>Loading analysis…</p>
      </div>
    );
  }

  if (error || !result) {
    return (
      <div style={styles.centered}>
        <p style={styles.errorText}>{error || "No result found."}</p>
        <button style={styles.backBtn} onClick={() => navigate("/")}>
          ← Analyze something new
        </button>
      </div>
    );
  }

  const typeInfo = TYPE_LABELS[result.inputType] || TYPE_LABELS.text;

  return (
    <div style={styles.page}>
      <div style={styles.gridBg} aria-hidden="true" />

      {/* ── Nav ─────────────────────────────────────────────── */}
      <nav style={styles.nav}>
        <div style={styles.logo}>
          <svg width="26" height="26" viewBox="0 0 32 32" fill="none">
            <path d="M16 2L4 7v9c0 7 5.3 13.5 12 15.2C22.7 29.5 28 23 28 16V7L16 2z" fill="url(#sg2)" opacity="0.9" />
            <line x1="8" y1="16" x2="24" y2="16" stroke="#0a0f1e" strokeWidth="2" strokeLinecap="round" />
            <line x1="8" y1="12" x2="20" y2="12" stroke="#0a0f1e" strokeWidth="1.5" strokeLinecap="round" opacity="0.5" />
            <line x1="8" y1="20" x2="18" y2="20" stroke="#0a0f1e" strokeWidth="1.5" strokeLinecap="round" opacity="0.5" />
            <defs>
              <linearGradient id="sg2" x1="4" y1="2" x2="28" y2="32" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="#63dcaa" />
                <stop offset="100%" stopColor="#3bb8f5" />
              </linearGradient>
            </defs>
          </svg>
          <span style={styles.logoText}>ScamShield</span>
        </div>
        <div style={styles.navActions}>
          <button style={styles.navBtn} onClick={() => navigate("/")}>
            ← New Scan
          </button>
          <button style={styles.navBtn} onClick={() => navigate("/dashboard")}>
            History
          </button>
        </div>
      </nav>

      {/* ── Content ─────────────────────────────────────────── */}
      <main style={styles.main}>
        {/* Input preview banner */}
        <div style={styles.inputBanner}>
          <span style={styles.inputIcon}>{typeInfo.icon}</span>
          <span style={styles.inputPreview}>
            {result.input.length > 80 ? result.input.slice(0, 80) + "…" : result.input}
          </span>
          <span style={styles.inputTypeBadge}>{typeInfo.label}</span>
        </div>

        {/* Main two-column layout */}
        <div style={styles.columns}>
          {/* Left: Risk Meter */}
          <div style={styles.leftCol}>
            <div style={styles.card}>
              <RiskMeter score={result.riskScore} riskLevel={result.riskLevel} />
            </div>
          </div>

          {/* Right: Analysis + Comparison */}
          <div style={styles.rightCol}>
            <div style={styles.card}>
              <AnalysisCard
                verdict={result.verdict}
                explanation={result.explanation}
                redFlags={result.redFlags}
                inputType={result.inputType}
              />
            </div>
            <div style={styles.card}>
              <ComparisonView comparison={result.comparison} />
            </div>
          </div>
        </div>

        {/* Actions */}
        <div style={styles.actionsRow}>
          <button style={styles.primaryBtn} onClick={() => navigate("/")}>
            Analyze Something Else
          </button>
          <button style={styles.secondaryBtn} onClick={() => navigate("/dashboard")}>
            View History
          </button>
        </div>
      </main>
    </div>
  );
};

const styles = {
  page: {
    minHeight: "100vh",
    background: "#0a0f1e",
    color: "#ffffff",
    display: "flex",
    flexDirection: "column",
    position: "relative",
    overflow: "hidden",
  },
  gridBg: {
    position: "fixed",
    inset: 0,
    backgroundImage:
      "linear-gradient(rgba(99,220,170,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(99,220,170,0.03) 1px, transparent 1px)",
    backgroundSize: "60px 60px",
    pointerEvents: "none",
    zIndex: 0,
  },
  nav: {
    position: "relative",
    zIndex: 10,
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "20px 32px",
    borderBottom: "1px solid rgba(255,255,255,0.05)",
  },
  logo: { display: "flex", alignItems: "center", gap: "10px" },
  logoText: {
    fontFamily: "'Syne', sans-serif",
    fontWeight: 800,
    fontSize: "18px",
    background: "linear-gradient(135deg, #63dcaa, #3bb8f5)",
    WebkitBackgroundClip: "text",
    WebkitTextFillColor: "transparent",
  },
  navActions: { display: "flex", gap: "10px" },
  navBtn: {
    background: "rgba(255,255,255,0.06)",
    border: "1px solid rgba(255,255,255,0.1)",
    borderRadius: "10px",
    color: "rgba(255,255,255,0.7)",
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 500,
    fontSize: "13px",
    padding: "7px 15px",
    cursor: "pointer",
  },
  main: {
    position: "relative",
    zIndex: 10,
    flex: 1,
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    padding: "32px 24px 48px",
    gap: "24px",
    maxWidth: "1000px",
    margin: "0 auto",
    width: "100%",
    boxSizing: "border-box",
  },
  inputBanner: {
    display: "flex",
    alignItems: "center",
    gap: "12px",
    width: "100%",
    background: "rgba(255,255,255,0.03)",
    border: "1px solid rgba(255,255,255,0.07)",
    borderRadius: "14px",
    padding: "14px 20px",
    flexWrap: "wrap",
  },
  inputIcon: { fontSize: "18px", flexShrink: 0 },
  inputPreview: {
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 400,
    fontSize: "13.5px",
    color: "rgba(255,255,255,0.6)",
    flex: 1,
    wordBreak: "break-all",
  },
  inputTypeBadge: {
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 500,
    fontSize: "11px",
    color: "rgba(99,220,170,0.8)",
    background: "rgba(99,220,170,0.08)",
    border: "1px solid rgba(99,220,170,0.2)",
    borderRadius: "8px",
    padding: "3px 10px",
    flexShrink: 0,
    letterSpacing: "0.04em",
  },
  columns: {
    display: "flex",
    gap: "20px",
    width: "100%",
    flexWrap: "wrap",
    alignItems: "flex-start",
  },
  leftCol: {
    flex: "0 0 280px",
    display: "flex",
    flexDirection: "column",
    gap: "20px",
  },
  rightCol: {
    flex: 1,
    minWidth: "280px",
    display: "flex",
    flexDirection: "column",
    gap: "20px",
  },
  card: {
    background: "rgba(255,255,255,0.025)",
    border: "1px solid rgba(255,255,255,0.08)",
    borderRadius: "20px",
    padding: "28px",
    backdropFilter: "blur(12px)",
  },
  actionsRow: {
    display: "flex",
    gap: "12px",
    flexWrap: "wrap",
    justifyContent: "center",
  },
  primaryBtn: {
    background: "linear-gradient(135deg, #63dcaa 0%, #3bb8f5 100%)",
    border: "none",
    borderRadius: "12px",
    color: "#0a0f1e",
    fontFamily: "'Syne', sans-serif",
    fontWeight: 700,
    fontSize: "14px",
    padding: "13px 28px",
    cursor: "pointer",
    letterSpacing: "0.02em",
  },
  secondaryBtn: {
    background: "rgba(255,255,255,0.06)",
    border: "1px solid rgba(255,255,255,0.12)",
    borderRadius: "12px",
    color: "rgba(255,255,255,0.7)",
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 500,
    fontSize: "14px",
    padding: "13px 28px",
    cursor: "pointer",
  },
  centered: {
    minHeight: "100vh",
    background: "#0a0f1e",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    gap: "16px",
    color: "#fff",
  },
  loadingSpinner: {
    width: "40px",
    height: "40px",
    border: "3px solid rgba(99,220,170,0.2)",
    borderTopColor: "#63dcaa",
    borderRadius: "50%",
    animation: "spin 0.8s linear infinite",
  },
  loadingText: {
    fontFamily: "'DM Sans', sans-serif",
    color: "rgba(255,255,255,0.4)",
    fontSize: "14px",
    margin: 0,
  },
  errorText: {
    fontFamily: "'DM Sans', sans-serif",
    color: "#f55a5a",
    fontSize: "15px",
    margin: 0,
  },
  backBtn: {
    background: "rgba(255,255,255,0.06)",
    border: "1px solid rgba(255,255,255,0.1)",
    borderRadius: "10px",
    color: "rgba(255,255,255,0.7)",
    fontFamily: "'DM Sans', sans-serif",
    fontSize: "14px",
    padding: "10px 20px",
    cursor: "pointer",
    marginTop: "8px",
  },
};

export default Result;
