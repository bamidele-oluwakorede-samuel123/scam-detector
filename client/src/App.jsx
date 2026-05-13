// App.jsx
// ─────────────────────────────────────────────────────────────
// Root React component.
//
// RESPONSIBILITIES:
// 1. Set up React Router with all page routes
// 2. Inject global CSS animations into the document
//    (can't use a separate CSS file without ejecting CRA,
//    so we inject a <style> tag programmatically)
// 3. Provide the global font and base styles
// ─────────────────────────────────────────────────────────────

import React, { useEffect } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Home from "./pages/Home";
import Result from "./pages/Result";
import Dashboard from "./pages/Dashboard";

// Global CSS injected into <head>.
// We define keyframe animations here so all components can use them
// via the animation property in their inline style objects.
const GLOBAL_STYLES = `
  *, *::before, *::after {
    box-sizing: border-box;
  }

  body {
    margin: 0;
    padding: 0;
    background: #0a0f1e;
    font-family: 'DM Sans', sans-serif;
    -webkit-font-smoothing: antialiased;
  }

  /* Used by the loading spinner in InputBox and Result */
  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  /* Used by flag items in AnalysisCard and history rows in HistoryList */
  @keyframes flagSlideIn {
    from {
      opacity: 0;
      transform: translateY(8px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  /* Used by the live indicator dot in the hero badge */
  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.5; transform: scale(0.85); }
  }

  /* Used by the type badge in InputBox */
  @keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
  }

  /* Remove default button styles globally */
  button {
    cursor: pointer;
    border: none;
    outline: none;
  }

  /* Textarea focus state — applied globally */
  textarea:focus {
    border-color: rgba(99, 220, 170, 0.4) !important;
    background: rgba(255,255,255,0.06) !important;
    box-shadow: 0 0 0 3px rgba(99, 220, 170, 0.08);
  }

  /* HistoryList row hover — using class for better perf than JS onMouseEnter */
`;

const App = () => {
  // Inject global styles once on mount
  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = GLOBAL_STYLES;
    document.head.appendChild(style);
    // Cleanup on unmount (good practice)
    return () => document.head.removeChild(style);
  }, []);

  return (
    <BrowserRouter>
      <Routes>
        {/* Home: landing + input */}
        <Route path="/" element={<Home />} />

        {/* Result: shown after analysis completes */}
        {/* Two variants:
            /result      → data passed via router state (from Home)
            /result/:id  → fetched from API (direct link or dashboard click) */}
        <Route path="/result" element={<Result />} />
        <Route path="/result/:id" element={<Result />} />

        {/* Dashboard: scan history */}
        <Route path="/dashboard" element={<Dashboard />} />

        {/* Catch-all: redirect unknown routes to home */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
};

export default App;
