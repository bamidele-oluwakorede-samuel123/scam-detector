// HistoryList.jsx
// ─────────────────────────────────────────────────────────────
// Renders a list of past scan history items.
// Each row shows: truncated input, input type icon,
// risk score badge, risk level, and relative timestamp.
// ─────────────────────────────────────────────────────────────

import React from "react";
import { useNavigate } from "react-router-dom";

const RISK_COLORS = {
  safe: "#63dcaa",
  suspicious: "#f5c842",
  dangerous: "#f55a5a",
};

const TYPE_ICONS = {
  url: "🔗",
  phone: "📞",
  email: "✉️",
  text: "💬",
};

// Converts a Date to a relative string like "2 hours ago"
const timeAgo = (dateString) => {
  const diff = Date.now() - new Date(dateString).getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
};

const HistoryList = ({ scans, loading }) => {
  const navigate = useNavigate();

  if (loading) {
    return (
      <div style={styles.emptyState}>
        <span style={styles.emptyIcon}>⏳</span>
        <p style={styles.emptyText}>Loading history…</p>
      </div>
    );
  }

  if (!scans || scans.length === 0) {
    return (
      <div style={styles.emptyState}>
        <span style={styles.emptyIcon}>🔍</span>
        <p style={styles.emptyText}>No scans yet. Analyze something to see history here.</p>
      </div>
    );
  }

  return (
    <div style={styles.list}>
      {scans.map((scan, i) => {
        const color = RISK_COLORS[scan.riskLevel] || "#fff";
        const icon = TYPE_ICONS[scan.inputType] || "📋";

        return (
          <div
            key={scan._id}
            style={{
              ...styles.row,
              animationDelay: `${i * 50}ms`,
            }}
            onClick={() => navigate(`/result/${scan._id}`)}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === "Enter" && navigate(`/result/${scan._id}`)}
          >
            {/* Left: icon + input preview */}
            <div style={styles.rowLeft}>
              <span style={styles.typeIcon}>{icon}</span>
              <div style={styles.inputPreview}>
                {/* Truncate long input to 60 characters */}
                <span style={styles.inputText}>
                  {scan.input.length > 60 ? scan.input.slice(0, 60) + "…" : scan.input}
                </span>
                <span style={styles.timeAgo}>{timeAgo(scan.createdAt)}</span>
              </div>
            </div>

            {/* Right: score + level */}
            <div style={styles.rowRight}>
              <span
                style={{
                  ...styles.scoreBadge,
                  color,
                  background: `${color}18`,
                  border: `1px solid ${color}44`,
                }}
              >
                {scan.riskScore}
              </span>
              <span
                style={{
                  ...styles.levelLabel,
                  color,
                }}
              >
                {scan.riskLevel.toUpperCase()}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
};

const styles = {
  list: {
    display: "flex",
    flexDirection: "column",
    gap: "8px",
  },
  row: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "14px 18px",
    background: "rgba(255,255,255,0.03)",
    border: "1px solid rgba(255,255,255,0.07)",
    borderRadius: "14px",
    cursor: "pointer",
    transition: "background 0.15s ease, border-color 0.15s ease, transform 0.1s ease",
    animation: "flagSlideIn 0.3s ease both",
    gap: "12px",
  },
  rowLeft: {
    display: "flex",
    alignItems: "center",
    gap: "12px",
    flex: 1,
    minWidth: 0, // Allows text truncation
  },
  typeIcon: {
    fontSize: "18px",
    flexShrink: 0,
  },
  inputPreview: {
    display: "flex",
    flexDirection: "column",
    gap: "2px",
    minWidth: 0,
  },
  inputText: {
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 400,
    fontSize: "13.5px",
    color: "rgba(255,255,255,0.75)",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  timeAgo: {
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 300,
    fontSize: "11px",
    color: "rgba(255,255,255,0.25)",
  },
  rowRight: {
    display: "flex",
    flexDirection: "column",
    alignItems: "flex-end",
    gap: "3px",
    flexShrink: 0,
  },
  scoreBadge: {
    fontFamily: "'Syne', sans-serif",
    fontWeight: 800,
    fontSize: "18px",
    width: "44px",
    height: "32px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    borderRadius: "8px",
  },
  levelLabel: {
    fontFamily: "'Syne', sans-serif",
    fontWeight: 600,
    fontSize: "9px",
    letterSpacing: "0.1em",
    opacity: 0.8,
  },
  emptyState: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    gap: "12px",
    padding: "48px 24px",
    opacity: 0.5,
  },
  emptyIcon: {
    fontSize: "32px",
  },
  emptyText: {
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 300,
    fontSize: "14px",
    color: "rgba(255,255,255,0.5)",
    textAlign: "center",
    margin: 0,
  },
};

export default HistoryList;
