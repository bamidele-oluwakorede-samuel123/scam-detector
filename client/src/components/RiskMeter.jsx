// RiskMeter.jsx
// ─────────────────────────────────────────────────────────────
// Animated semicircular gauge that visualizes the risk score.
//
// HOW THE SVG GAUGE WORKS:
// We draw a semicircular arc using SVG <path> and stroke-dasharray.
// - stroke-dasharray defines the "dashes" pattern on the stroke.
// - stroke-dashoffset shifts where the dash starts.
// - By animating dashoffset from the full arc length to the
//   score-proportional offset, we get the filling animation.
//
// The arc is drawn on a 200×120 viewBox. The center is at (100, 110).
// Radius = 80. The arc goes from 180° to 0° (left to right = 0 to 100).
// ─────────────────────────────────────────────────────────────

import React, { useEffect, useState } from "react";

// Total arc length for our semicircle (r=80, half circle = π × r)
const ARC_LENGTH = Math.PI * 80; // ≈ 251.3

// Maps score 0–100 to a color along green → yellow → red
const scoreToColor = (score) => {
  if (score <= 30) return "#63dcaa"; // Safe: teal-green
  if (score <= 60) return "#f5c842"; // Suspicious: amber
  return "#f55a5a"; // Dangerous: red
};

const RISK_LABELS = {
  safe: { label: "SAFE", sub: "No significant scam indicators detected" },
  suspicious: { label: "SUSPICIOUS", sub: "Proceed with caution — verify before acting" },
  dangerous: { label: "DANGEROUS", sub: "High probability of being a scam" },
};

const RiskMeter = ({ score, riskLevel }) => {
  // We animate the score from 0 to the actual value on mount
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    // Animate from 0 to score over ~800ms using requestAnimationFrame
    const duration = 800;
    const start = performance.now();
    const from = 0;
    const to = score;

    const animate = (now) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      // Ease-out cubic: fast at first, slows down at the end
      const eased = 1 - Math.pow(1 - progress, 3);
      setAnimatedScore(Math.round(from + (to - from) * eased));
      if (progress < 1) requestAnimationFrame(animate);
    };

    requestAnimationFrame(animate);
  }, [score]);

  // dashoffset: 0 = full arc filled, ARC_LENGTH = empty arc
  // Score 0 → offset = ARC_LENGTH (nothing filled)
  // Score 100 → offset = 0 (fully filled)
  const offset = ARC_LENGTH - (animatedScore / 100) * ARC_LENGTH;
  const color = scoreToColor(animatedScore);
  const info = RISK_LABELS[riskLevel] || RISK_LABELS.suspicious;

  return (
    <div style={styles.wrapper}>
      {/* SVG Gauge */}
      <div style={styles.svgWrapper}>
        <svg viewBox="0 0 200 120" style={styles.svg}>
          {/* Background arc (always full, gray) */}
          <path
            d="M 20 110 A 80 80 0 0 1 180 110"
            fill="none"
            stroke="rgba(255,255,255,0.06)"
            strokeWidth="12"
            strokeLinecap="round"
          />

          {/* Foreground arc (animated, colored) */}
          <path
            d="M 20 110 A 80 80 0 0 1 180 110"
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={ARC_LENGTH}
            strokeDashoffset={offset}
            style={{
              filter: `drop-shadow(0 0 6px ${color}88)`,
              transition: "stroke 0.3s ease",
            }}
          />

          {/* Tick marks at 0, 50, 100 */}
          {[0, 50, 100].map((val) => {
            const angle = Math.PI - (val / 100) * Math.PI; // 180° to 0°
            const cx = 100 + 80 * Math.cos(angle);
            const cy = 110 - 80 * Math.sin(angle);
            return (
              <circle
                key={val}
                cx={cx}
                cy={cy}
                r="3"
                fill="rgba(255,255,255,0.15)"
              />
            );
          })}

          {/* Score number in center */}
          <text
            x="100"
            y="100"
            textAnchor="middle"
            style={{
              fontFamily: "'Syne', sans-serif",
              fontWeight: 800,
              fontSize: "32px",
              fill: color,
              filter: `drop-shadow(0 0 8px ${color}66)`,
              transition: "fill 0.3s ease",
            }}
          >
            {animatedScore}
          </text>

          {/* /100 label */}
          <text
            x="100"
            y="114"
            textAnchor="middle"
            style={{
              fontFamily: "'DM Sans', sans-serif",
              fontWeight: 400,
              fontSize: "9px",
              fill: "rgba(255,255,255,0.3)",
              letterSpacing: "0.05em",
            }}
          >
            / 100
          </text>
        </svg>

        {/* Scale labels */}
        <div style={styles.scaleLabels}>
          <span style={{ ...styles.scaleLabel, color: "#63dcaa" }}>Safe</span>
          <span style={{ ...styles.scaleLabel, color: "#f55a5a" }}>Danger</span>
        </div>
      </div>

      {/* Risk level label */}
      <div style={styles.labelWrapper}>
        <span
          style={{
            ...styles.riskLabel,
            color: color,
            textShadow: `0 0 20px ${color}66`,
          }}
        >
          {info.label}
        </span>
        <p style={styles.riskSub}>{info.sub}</p>
      </div>
    </div>
  );
};

const styles = {
  wrapper: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    gap: "8px",
    width: "100%",
  },
  svgWrapper: {
    position: "relative",
    width: "220px",
  },
  svg: {
    width: "100%",
    overflow: "visible",
  },
  scaleLabels: {
    display: "flex",
    justifyContent: "space-between",
    paddingTop: "2px",
    paddingLeft: "8px",
    paddingRight: "8px",
  },
  scaleLabel: {
    fontSize: "10px",
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 500,
    letterSpacing: "0.05em",
    opacity: 0.7,
  },
  labelWrapper: {
    textAlign: "center",
    marginTop: "8px",
  },
  riskLabel: {
    fontFamily: "'Syne', sans-serif",
    fontWeight: 800,
    fontSize: "22px",
    letterSpacing: "0.12em",
    display: "block",
    transition: "color 0.3s ease",
  },
  riskSub: {
    color: "rgba(255,255,255,0.45)",
    fontSize: "12px",
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 300,
    margin: "6px 0 0 0",
    lineHeight: "1.5",
    maxWidth: "240px",
  },
};

export default RiskMeter;
