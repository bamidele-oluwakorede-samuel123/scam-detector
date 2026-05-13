// ComparisonView.jsx
// ─────────────────────────────────────────────────────────────
// Displays a side-by-side (or stacked on mobile) comparison
// between what a legitimate version looks like vs the scam version.
//
// WHY THIS MATTERS FOR USERS:
// Telling someone "this is a scam" isn't enough.
// Showing them exactly how legitimate communications differ
// from scam communications builds lasting awareness.
// ─────────────────────────────────────────────────────────────

import React from "react";

const ComparisonView = ({ comparison }) => {
  if (!comparison || (!comparison.legitimate && !comparison.scam)) return null;

  return (
    <div style={styles.wrapper}>
      <span style={styles.sectionLabel}>LEGITIMATE VS SCAM</span>

      <div style={styles.columns}>
        {/* Legitimate column */}
        <div style={styles.col}>
          <div style={styles.colHeader}>
            <span style={styles.legitDot} />
            <span style={{ ...styles.colTitle, color: "#63dcaa" }}>✓ Legitimate</span>
          </div>
          <div style={{ ...styles.colBody, borderColor: "rgba(99, 220, 170, 0.2)" }}>
            <p style={styles.colText}>{comparison.legitimate}</p>
          </div>
        </div>

        {/* VS divider */}
        <div style={styles.divider}>
          <span style={styles.vsLabel}>VS</span>
        </div>

        {/* Scam column */}
        <div style={styles.col}>
          <div style={styles.colHeader}>
            <span style={styles.scamDot} />
            <span style={{ ...styles.colTitle, color: "#f55a5a" }}>✗ Scam</span>
          </div>
          <div style={{ ...styles.colBody, borderColor: "rgba(245, 90, 90, 0.2)" }}>
            <p style={styles.colText}>{comparison.scam}</p>
          </div>
        </div>
      </div>
    </div>
  );
};

const styles = {
  wrapper: {
    display: "flex",
    flexDirection: "column",
    gap: "14px",
    width: "100%",
  },
  sectionLabel: {
    fontFamily: "'Syne', sans-serif",
    fontWeight: 600,
    fontSize: "10px",
    letterSpacing: "0.15em",
    color: "rgba(255,255,255,0.35)",
    textTransform: "uppercase",
  },
  columns: {
    display: "flex",
    gap: "0",
    alignItems: "stretch",
    // On very small screens this wraps to a column via flexWrap
    flexWrap: "wrap",
  },
  col: {
    flex: 1,
    minWidth: "200px",
    display: "flex",
    flexDirection: "column",
    gap: "8px",
  },
  colHeader: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
    marginBottom: "2px",
  },
  legitDot: {
    width: "8px",
    height: "8px",
    borderRadius: "50%",
    background: "#63dcaa",
    flexShrink: 0,
  },
  scamDot: {
    width: "8px",
    height: "8px",
    borderRadius: "50%",
    background: "#f55a5a",
    flexShrink: 0,
  },
  colTitle: {
    fontFamily: "'Syne', sans-serif",
    fontWeight: 700,
    fontSize: "13px",
    letterSpacing: "0.05em",
  },
  colBody: {
    flex: 1,
    background: "rgba(255,255,255,0.03)",
    border: "1px solid",
    borderRadius: "12px",
    padding: "16px",
  },
  colText: {
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 300,
    fontSize: "13.5px",
    color: "rgba(255,255,255,0.65)",
    lineHeight: "1.8",
    margin: 0,
  },
  divider: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    width: "40px",
    flexShrink: 0,
  },
  vsLabel: {
    fontFamily: "'Syne', sans-serif",
    fontWeight: 800,
    fontSize: "11px",
    color: "rgba(255,255,255,0.2)",
    letterSpacing: "0.1em",
  },
};

export default ComparisonView;
