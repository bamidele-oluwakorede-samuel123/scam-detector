// Home.jsx
// ─────────────────────────────────────────────────────────────
// The main landing page. Users land here, paste their suspicious
// content, and are navigated to /result after analysis completes.
//
// LAYOUT:
//   - Top nav: Logo + Dashboard link
//   - Hero: tagline + stats
//   - Input section: InputBox component
//   - Footer: trust indicators
// ─────────────────────────────────────────────────────────────

import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import InputBox from "../components/InputBox";
import useLiveAnalysis from "../hooks/useLiveAnalysis";
import { analyzeImage } from "../services/api";

const Home = () => {
  const navigate = useNavigate();
  const { result, loading, error, analyze, reset } = useLiveAnalysis();
  const [imageLoading, setImageLoading] = useState(false);
  const [imageError,   setImageError]   = useState(null);

  useEffect(() => {
    if (result) navigate("/result", { state: { result } });
  }, [result, navigate]);

  // ── Image analysis handler ────────────────────────────────
  // Called by InputBox when a user selects an image.
  // We call the image API directly here (not via useLiveAnalysis
  // because image analysis doesn't need debouncing).
  const handleImageAnalyze = async (base64Image, mimeType) => {
    setImageLoading(true);
    setImageError(null);
    try {
      const data = await analyzeImage(base64Image, mimeType);
      navigate("/result", { state: { result: data } });
    } catch (err) {
      setImageError(
        err.response?.data?.error ||
        "Image analysis failed. Please try again or type the content manually."
      );
    } finally {
      setImageLoading(false);
    }
  };

  const isLoading = loading || imageLoading;
  const displayError = error || imageError;

  return (
    <div style={styles.page}>
      {/* ── Background grid decoration ─────────────────────── */}
      <div style={styles.gridBg} aria-hidden="true" />

      {/* ── Nav ───────────────────────────────────────────── */}
      <nav style={styles.nav}>
        <div style={styles.logo}>
          {/* SVG Logo: a shield with a scan line */}
          <svg width="32" height="32" viewBox="0 0 32 32" fill="none" style={styles.logoSvg}>
            <path
              d="M16 2L4 7v9c0 7 5.3 13.5 12 15.2C22.7 29.5 28 23 28 16V7L16 2z"
              fill="url(#shieldGrad)"
              opacity="0.9"
            />
            {/* Scan line */}
            <line x1="8" y1="16" x2="24" y2="16" stroke="#0a0f1e" strokeWidth="2" strokeLinecap="round" />
            <line x1="8" y1="12" x2="20" y2="12" stroke="#0a0f1e" strokeWidth="1.5" strokeLinecap="round" opacity="0.5" />
            <line x1="8" y1="20" x2="18" y2="20" stroke="#0a0f1e" strokeWidth="1.5" strokeLinecap="round" opacity="0.5" />
            <defs>
              <linearGradient id="shieldGrad" x1="4" y1="2" x2="28" y2="32" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="#63dcaa" />
                <stop offset="100%" stopColor="#3bb8f5" />
              </linearGradient>
            </defs>
          </svg>
          <span style={styles.logoText}>ScamShield</span>
        </div>
        <button style={styles.navBtn} onClick={() => navigate("/dashboard")}>
          History
        </button>
      </nav>

      {/* ── Main content ──────────────────────────────────── */}
      <main style={styles.main}>
        {/* Hero */}
        <div style={styles.hero}>
          <div style={styles.heroBadge}>
            <span style={styles.heroBadgeDot} />
            AI-Powered · Real-Time Analysis
          </div>
          <h1 style={styles.headline}>
            Is this a
            <br />
            <span style={styles.headlineAccent}>scam?</span>
          </h1>
          <p style={styles.subline}>
            Paste any suspicious link, phone number, email address,<br />
            or message — we'll tell you instantly.
          </p>
        </div>

        {/* Input Card */}
        <div style={styles.card}>
          <InputBox
            onAnalyze={analyze}
            onAnalyzeImage={handleImageAnalyze}
            onClear={reset}
            loading={isLoading}
          />

          {/* Error state */}
          {displayError && (
            <div style={styles.errorBox}>
              <span style={styles.errorIcon}>⚠️</span>
              <span style={styles.errorText}>{displayError}</span>
            </div>
          )}
        </div>

        {/* Trust indicators */}
        <div style={styles.trustRow}>
          {["URLs & Links", "Phone Numbers", "Emails", "SMS & Messages"].map((item) => (
            <div key={item} style={styles.trustItem}>
              <span style={styles.trustCheck}>✓</span>
              <span style={styles.trustText}>{item}</span>
            </div>
          ))}
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
  // Subtle grid background — CSS-drawn using repeating-linear-gradient
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
  logo: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
  },
  logoSvg: {
    flexShrink: 0,
  },
  logoText: {
    fontFamily: "'Syne', sans-serif",
    fontWeight: 800,
    fontSize: "20px",
    letterSpacing: "-0.02em",
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
    fontSize: "14px",
    padding: "8px 18px",
    cursor: "pointer",
    transition: "background 0.2s ease",
  },
  main: {
    position: "relative",
    zIndex: 10,
    flex: 1,
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    padding: "48px 24px",
    gap: "32px",
    maxWidth: "680px",
    margin: "0 auto",
    width: "100%",
  },
  hero: {
    textAlign: "center",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    gap: "16px",
  },
  heroBadge: {
    display: "inline-flex",
    alignItems: "center",
    gap: "8px",
    background: "rgba(99,220,170,0.08)",
    border: "1px solid rgba(99,220,170,0.2)",
    borderRadius: "20px",
    padding: "6px 16px",
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 500,
    fontSize: "12px",
    color: "rgba(99,220,170,0.9)",
    letterSpacing: "0.04em",
  },
  heroBadgeDot: {
    width: "6px",
    height: "6px",
    borderRadius: "50%",
    background: "#63dcaa",
    animation: "pulse 2s infinite",
    display: "inline-block",
  },
  headline: {
    fontFamily: "'Syne', sans-serif",
    fontWeight: 800,
    fontSize: "clamp(48px, 8vw, 80px)",
    lineHeight: "1.0",
    margin: 0,
    color: "#ffffff",
    letterSpacing: "-0.03em",
  },
  headlineAccent: {
    background: "linear-gradient(135deg, #63dcaa 0%, #3bb8f5 100%)",
    WebkitBackgroundClip: "text",
    WebkitTextFillColor: "transparent",
    display: "inline-block",
  },
  subline: {
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 300,
    fontSize: "16px",
    color: "rgba(255,255,255,0.45)",
    lineHeight: "1.7",
    margin: 0,
  },
  card: {
    width: "100%",
    background: "rgba(255,255,255,0.025)",
    border: "1px solid rgba(255,255,255,0.08)",
    borderRadius: "24px",
    padding: "28px",
    backdropFilter: "blur(12px)",
    display: "flex",
    flexDirection: "column",
    gap: "16px",
  },
  errorBox: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    background: "rgba(245, 90, 90, 0.08)",
    border: "1px solid rgba(245, 90, 90, 0.25)",
    borderRadius: "10px",
    padding: "12px 16px",
  },
  errorIcon: {
    fontSize: "16px",
  },
  errorText: {
    fontFamily: "'DM Sans', sans-serif",
    fontSize: "13.5px",
    color: "#f55a5a",
    fontWeight: 400,
  },
  trustRow: {
    display: "flex",
    flexWrap: "wrap",
    justifyContent: "center",
    gap: "8px 20px",
  },
  trustItem: {
    display: "flex",
    alignItems: "center",
    gap: "6px",
  },
  trustCheck: {
    color: "#63dcaa",
    fontSize: "12px",
    fontWeight: 700,
  },
  trustText: {
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 400,
    fontSize: "13px",
    color: "rgba(255,255,255,0.35)",
  },
};

export default Home;
