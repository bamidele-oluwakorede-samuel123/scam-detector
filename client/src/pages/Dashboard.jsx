// Dashboard.jsx
// ─────────────────────────────────────────────────────────────
// The scan history dashboard.
// Fetches and displays the 20 most recent scans from MongoDB.
// Shows summary stats and a clickable history list.
// ─────────────────────────────────────────────────────────────

import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import HistoryList from "../components/HistoryList";
import { getHistory } from "../services/api";

const Dashboard = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const data = await getHistory();
        setScans(data.scans || []);
      } catch {
        setError("Could not load history. Make sure the server is running.");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  // ── Compute summary stats ──────────────────────────────────
  const total = scans.length;
  const dangerous = scans.filter((s) => s.riskLevel === "dangerous").length;
  const safe = scans.filter((s) => s.riskLevel === "safe").length;
  const avgScore =
    total > 0 ? Math.round(scans.reduce((acc, s) => acc + s.riskScore, 0) / total) : 0;

  return (
    <div style={styles.page}>
      <div style={styles.gridBg} aria-hidden="true" />

      {/* ── Nav ─────────────────────────────────────────────── */}
      <nav style={styles.nav}>
        <div style={styles.logo}>
          <svg width="26" height="26" viewBox="0 0 32 32" fill="none">
            <path d="M16 2L4 7v9c0 7 5.3 13.5 12 15.2C22.7 29.5 28 23 28 16V7L16 2z" fill="url(#sg3)" opacity="0.9" />
            <line x1="8" y1="16" x2="24" y2="16" stroke="#0a0f1e" strokeWidth="2" strokeLinecap="round" />
            <line x1="8" y1="12" x2="20" y2="12" stroke="#0a0f1e" strokeWidth="1.5" strokeLinecap="round" opacity="0.5" />
            <line x1="8" y1="20" x2="18" y2="20" stroke="#0a0f1e" strokeWidth="1.5" strokeLinecap="round" opacity="0.5" />
            <defs>
              <linearGradient id="sg3" x1="4" y1="2" x2="28" y2="32" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="#63dcaa" />
                <stop offset="100%" stopColor="#3bb8f5" />
              </linearGradient>
            </defs>
          </svg>
          <span style={styles.logoText}>ScamShield</span>
        </div>
        <button style={styles.navBtn} onClick={() => navigate("/")}>
          ← New Scan
        </button>
      </nav>

      <main style={styles.main}>
        {/* Page title */}
        <div style={styles.titleRow}>
          <h1 style={styles.title}>Scan History</h1>
          <span style={styles.titleSub}>Last {total} scans</span>
        </div>

        {/* Stats row */}
        {total > 0 && (
          <div style={styles.statsRow}>
            {[
              { label: "Total Scans", value: total, color: "#ffffff" },
              { label: "Dangerous", value: dangerous, color: "#f55a5a" },
              { label: "Safe", value: safe, color: "#63dcaa" },
              { label: "Avg. Score", value: avgScore, color: "#3bb8f5" },
            ].map((stat) => (
              <div key={stat.label} style={styles.statCard}>
                <span style={{ ...styles.statValue, color: stat.color }}>{stat.value}</span>
                <span style={styles.statLabel}>{stat.label}</span>
              </div>
            ))}
          </div>
        )}

        {/* Error state */}
        {error && (
          <div style={styles.errorBox}>
            <span>⚠️</span>
            <span style={{ fontFamily: "'DM Sans', sans-serif", color: "#f55a5a", fontSize: "14px" }}>
              {error}
            </span>
          </div>
        )}

        {/* History list */}
        <div style={styles.listCard}>
          <HistoryList scans={scans} loading={loading} />
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
    padding: "36px 24px 48px",
    gap: "24px",
    maxWidth: "800px",
    margin: "0 auto",
    width: "100%",
    boxSizing: "border-box",
  },
  titleRow: {
    display: "flex",
    alignItems: "baseline",
    gap: "14px",
  },
  title: {
    fontFamily: "'Syne', sans-serif",
    fontWeight: 800,
    fontSize: "32px",
    margin: 0,
    letterSpacing: "-0.02em",
  },
  titleSub: {
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 300,
    fontSize: "14px",
    color: "rgba(255,255,255,0.3)",
  },
  statsRow: {
    display: "flex",
    gap: "12px",
    flexWrap: "wrap",
  },
  statCard: {
    flex: "1 1 100px",
    background: "rgba(255,255,255,0.03)",
    border: "1px solid rgba(255,255,255,0.07)",
    borderRadius: "14px",
    padding: "16px 20px",
    display: "flex",
    flexDirection: "column",
    gap: "4px",
  },
  statValue: {
    fontFamily: "'Syne', sans-serif",
    fontWeight: 800,
    fontSize: "28px",
    lineHeight: 1,
  },
  statLabel: {
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 400,
    fontSize: "11px",
    color: "rgba(255,255,255,0.35)",
    letterSpacing: "0.06em",
    textTransform: "uppercase",
  },
  errorBox: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    background: "rgba(245, 90, 90, 0.08)",
    border: "1px solid rgba(245, 90, 90, 0.25)",
    borderRadius: "10px",
    padding: "14px 18px",
  },
  listCard: {
    background: "rgba(255,255,255,0.02)",
    border: "1px solid rgba(255,255,255,0.07)",
    borderRadius: "20px",
    padding: "20px",
  },
};

export default Dashboard;
